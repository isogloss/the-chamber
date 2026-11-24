# Wave 7 Consistency Audit

## Summary

This wave surveyed 387 unique candidate findings (deduped from 36 find-phase agents across 12 scopes x 3 lenses) for internal consistency of THE_CHAMBER on AMD-SVM Zen 4 (family 19h, Ryzen 7 7700X, Windows 10/11 guest, passive-dump sandbox for packed-malware static analysis). After severity-tiered batched verification, 90 findings were CONFIRMED and 10 were REFUTED; no low/nit-tier items were carried in as-reported this wave. The top three concerns are: (1) the pause-world mechanic leaks its 2-second wall-clock gap through TSC, QPC and KUSER_SHARED_DATA, i.e. the dump trigger itself is detectable within any active thread; (2) the whole fingerprint/interception stack is architecturally dead on arrival (chamber_fingerprint.sys loads under its real name with a hardcoded CFPControl device, the FLT filter targets a non-FS object, the target-PID list is never populated, and chamber_shim.dll is embedded but never injected) so every advertised interceptor is a no-op in production; (3) CPU identity is cross-leaf inconsistent (CPUID 0x15/0x16 report non-zero crystal/base-MHz on AMD, 0x80000001E/0x8000001D cache/APIC passthrough disagree with the rewritten 0x1/0xB/0x1F leaves, MSR 0x8B lays the microcode patch in Intel's EDX/high-half layout, and leaf 7 passthrough leaks AVX-512 while the brand pool advertises Zen 3 parts) — a single `cpuid-mismatch` detector of the style every modern packer ships trivially flags the box.

## Findings by severity

### Showstopper (52)

#### cpuid_consistency

- **CPUID 0x15 returns non-zero values; bare-metal AMD Zen 4 7700X returns all zeros** — `driver/vmexit.c:285`
  - observable_via: guest `cpuid(0x15)` returning non-zero EAX/EBX/ECX on AuthenticAMD
  - expected_baseline: all four regs zero on real Zen 4 (Intel-only TSC/crystal leaf)
  - current_behavior: synthesised ratio+crystal values are emitted even when vendor is AMD
  - remediation: gate leaf 0x15 behind a GenuineIntel check and return zero on AMD

- **CPUID 0x16 returns non-zero values; bare-metal AMD Zen 4 7700X returns all zeros** — `driver/vmexit.c:287`
  - observable_via: guest `cpuid(0x16)` returning non-zero MHz fields on AuthenticAMD
  - expected_baseline: all zeros on real Zen 4 (Intel-only base/max/bus MHz leaf)
  - current_behavior: base/max/bus MHz emitted regardless of vendor
  - remediation: zero leaf 0x16 unconditionally on AMD-vendor paths

- **CPUID 0x8000001E EAX passthrough disagrees with CPUID 0xB/0x1F EDX** — `driver/vmexit.c:301`
  - observable_via: APIC-ID in 0x8000001E EAX vs x2APIC-ID in 0xB/0x1F EDX across logical CPUs
  - expected_baseline: both leaves yield the same APIC/x2APIC ID per CPU
  - current_behavior: 0x1/0xB/0x1F are rewritten but 0x8000001E is host-passthrough
  - remediation: synthesise 0x8000001E from the same per-CPU topology table as 0xB/0x1F

#### msr_consistency

- **MSR 0x8B patch level placed in EDX (Intel convention), not EAX (AMD convention)** — `driver/vmexit.c:420`
  - observable_via: guest `rdmsr(0x8B)` with low 32 bits zero and high 32 bits non-zero on AuthenticAMD
  - expected_baseline: AMD encodes patch level in the low 32 bits; EDX is reserved/zero
  - current_behavior: value laid out with the Intel high-half layout even on AMD
  - remediation: place the spoofed revision in EAX and leave EDX zero for AuthenticAMD

- **MSR 0x8B microcode_rev uniformly random 32 bits; never matches released Zen 4 patch ID** — `driver/identity.c:440`
  - observable_via: guest `rdmsr(0x8B)` returning a value outside the published AMD patch set
  - expected_baseline: a Zen 4 Ryzen 7 7700X ships a bounded set of real patch IDs
  - current_behavior: 32 bits of seed-derived entropy, overwhelmingly off the published list
  - remediation: pick from the real AMD B2 patch-ID set; discard any value not on it

- **IA32_PLATFORM_ID (0x17) returns seed-derived random on AuthenticAMD** — `driver/identity.c:442`
  - observable_via: guest `rdmsr(0x17)` succeeding on AMD and returning non-zero
  - expected_baseline: AMD does not implement 0x17; real HW raises #GP
  - current_behavior: shadow value returned unconditionally
  - remediation: inject #GP for MSR 0x17 when vendor is AuthenticAMD

- **MSR 0x8B spoofed in wrong 32-bit half for AMD target** — `driver/identity.c:440`
  - observable_via: guest reading 0x8B and seeing patch bits in EDX
  - expected_baseline: AMD-native readers of 0x8B check EAX
  - current_behavior: shadow stored in the high half
  - remediation: shadow in the low 32 bits for AMD paths

- **MSR 0x8B microcode patch level in high 32 bits (Intel layout) on AMD Zen 4** — `driver/identity.c:440`
  - observable_via: cross-vendor 0x8B layout check used by current anti-cheat / packer stacks
  - expected_baseline: AMD low-half encoded patch level
  - current_behavior: Intel high-half encoding leaks vendor confusion
  - remediation: vendor-gate the layout at shadow construction

- **RDTSCP not intercepted while RDMSR 0xC0000103 is; TSC_AUX paths disagree** — `driver/svm_vmcb.c:336`
  - observable_via: guest comparing `rdtscp` ECX against `rdmsr(0xC0000103)` returns divergent values
  - expected_baseline: both paths yield the same TSC_AUX on a real CPU
  - current_behavior: RDTSCP exposes host TSC_AUX; RDMSR exposes shadow
  - remediation: intercept RDTSCP (or disable TSC_AUX passthrough) and rewrite ECX to shadow

#### timing_roundtrip

- **g_fixed_vmexit_cost hardcoded; guest RDTSC-CPUID-RDTSC delta drifts** — `driver/timing.c:185`
  - observable_via: guest `rdtsc; cpuid; rdtsc` histogram pinned at a single implausible constant
  - expected_baseline: real bare-metal CPUID exit has a per-core, per-leaf variance envelope
  - current_behavior: a single constant cost is subtracted regardless of leaf/core
  - remediation: model per-leaf cost from a bare-metal histogram with gaussian jitter per sample

#### pause_world_sidechannels

- **TSC_OFFSET does not mask 2-second pause window; RDTSC jumps ~2s** — `driver/dump.c:6`
  - observable_via: guest `rdtsc` difference across the pause window reporting >=2s of cycles
  - expected_baseline: no cycle jump across any thread quiescence
  - current_behavior: the pause mechanic freezes the thread but TSC_OFFSET is not adjusted
  - remediation: adjust TSC_OFFSET per vCPU to subtract paused-wall-clock from guest TSC

- **Paused thread shows 2s wall-clock with zero cycle/kernel/user time** — `driver/dump.c:210`
  - observable_via: a self-reporting thread sees QPC advance 2s while KTHREAD cycle counters are frozen
  - expected_baseline: wall-clock and thread-cycle counters advance together on a live CPU
  - current_behavior: pause freezes thread-local counters; wall-clock advances
  - remediation: either keep the thread scheduled (mask cycle), or rebase both on resume

- **QPC and KUSER_SHARED_DATA advance during pause; paused thread sees 2s** — `driver/dump.c:109`
  - observable_via: `QueryPerformanceCounter` delta or `KUSER_SHARED_DATA.SystemTime` delta across the pause
  - expected_baseline: all time sources stay consistent with thread-cycle accounting
  - current_behavior: both sources tick while the thread was stopped
  - remediation: drive QPC and SystemTime off a hypervisor-paused clock during the window

#### driver_hide_completeness

- **chamber_fingerprint.sys publishes hardcoded \Device\CFPControl** — `driver/fingerprint/entry.c:154`
  - observable_via: object-directory enumeration of `\Device` or `\GLOBAL??`
  - expected_baseline: no stable sentinel string for the driver
  - current_behavior: literal `CFPControl` name is a one-shot detection
  - remediation: randomise device name per boot and drop the DosDevices symlink

- **chamber_fingerprint.sys has no KLDR self-hide, section scramble, or PE scrub** — `driver/fingerprint/entry.c:134`
  - observable_via: SystemModuleInformation enumeration showing the real driver base/size/name
  - expected_baseline: donor-renamed and KLDR-unlinked for stealth parity with the hypervisor
  - current_behavior: loads under its real image name with intact PE headers and section table
  - remediation: fold the same KLDR unlink + header scrub the hypervisor driver already uses

- **chamber_fingerprint.sys KLDR entry never renamed** — `driver/fingerprint/entry.c:134`
  - observable_via: `KLDR_DATA_TABLE_ENTRY.BaseDllName` string
  - expected_baseline: donor-driver cloak
  - current_behavior: BaseDllName leaks `chamber_fingerprint.sys`
  - remediation: patch BaseDllName/FullDllName at DriverEntry before any object is created

- **Hardcoded \Device\CFPControl + \DosDevices\CFPControl symlink** — `driver/fingerprint/entry.c:154`
  - observable_via: `NtOpenFile` by sentinel name succeeding
  - expected_baseline: no deterministic symlink
  - current_behavior: both names present verbatim
  - remediation: random name + ephemeral symlink torn down after first launcher handshake

- **Duplicate pci.sys KLDR entry; rename clones donor still present** — `driver/stealth.c:291`
  - observable_via: two KLDR entries sharing `pci.sys` name but different bases
  - expected_baseline: at most one entry per driver name
  - current_behavior: donor rename leaves the original visible
  - remediation: either dedup the KLDR list after rename, or clone a donor name less likely to be enumerated twice

- **Fingerprint driver creates hardcoded \Device\CFPControl + \DosDevices\CFPControl** — `driver/fingerprint/entry.c:154`
  - observable_via: same as above, also from user-mode via `CreateFile(\\\\.\\CFPControl)`
  - expected_baseline: no sentinel device
  - current_behavior: exposed to any unprivileged open
  - remediation: random name, ACL to launcher SID only

- **chamber_fingerprint.sys KLDR entry never renamed; FullDllName leaks** — `driver/fingerprint/entry.c:204`
  - observable_via: `FullDllName` from `ZwQuerySystemInformation(SystemModuleInformation)`
  - expected_baseline: donor path
  - current_behavior: literal install path and image name
  - remediation: patch FullDllName alongside BaseDllName at entry

#### callback_enumerability

- **IC trampoline cannot intercept query of ProcessInstrumentationCallback** — `driver/fingerprint/syscall_rewrite.c:330`
  - observable_via: `NtQueryInformationProcess(ProcessInstrumentationCallback)` returning the kernel trampoline VA
  - expected_baseline: query returns zero or fakes the previous-owner's VA
  - current_behavior: NtQueryInformationProcess is not in the IC syscall dispatch table
  - remediation: add class 40 to the dispatch table and zero/forge the output

- **chamber_fingerprint.sys loads under its real name; no donor-rename** — `driver/fingerprint/entry.c:134`
  - observable_via: callback owner lookup by VA -> module resolving to `chamber_fingerprint.sys`
  - expected_baseline: callbacks owned by a plausible driver
  - current_behavior: three registered callbacks all anchor to the real driver
  - remediation: rename KLDR before registering callbacks so VA->module masks the origin

- **chamber_fingerprint.sys has no stealth; three callbacks resolve to named driver** — `driver/fingerprint/entry.c:204`
  - observable_via: `PsSetCreateProcessNotifyRoutineEx`, `CmRegisterCallback`, `FltRegisterFilter` ownership
  - expected_baseline: each callback owned by donor-renamed module
  - current_behavior: all three enumerate to the sentinel driver
  - remediation: rename + relocate register-trampolines through donor stub

#### smbios_dmi_integrity

- **DMI walker handed RawSMBIOSData header, not DMI stream (off-by-8)** — `driver/fingerprint/syscall_rewrite.c:107`
  - observable_via: guest DMI parse failing or walking past end-of-table
  - expected_baseline: walker begins at `TableData[0]`
  - current_behavior: walker begins at offset 0 of the RawSMBIOSData struct, i.e. inside the 8-byte header
  - remediation: advance the pointer by `sizeof(RAW_SMBIOS_HEADER)` before walking

- **HKLM\SYSTEM\HardwareConfig\{GUID}\LastConfig not intercepted** — `driver/fingerprint/cm_filter.c:125`
  - observable_via: reading `LastConfig` from the registry yields the real bare-metal SMBIOS blob
  - expected_baseline: CM filter rewrites the LastConfig value to the spoofed blob
  - current_behavior: no filter path for that value name
  - remediation: add LastConfig to the CM filter value list

- **DMI patch entry offset off by 8 bytes** — `driver/fingerprint/syscall_rewrite.c:107`
  - observable_via: patched fields appearing 8 bytes shifted from their real DMI offsets
  - expected_baseline: patches land on the right structure fields
  - current_behavior: writes shifted by the RawSMBIOSData header width
  - remediation: fix the base pointer before offset arithmetic

- **DMI walker starves on RawSMBIOSData 8-byte header** — `driver/fingerprint/syscall_rewrite.c:107`
  - observable_via: walker terminating early on a structure-type byte inside the header
  - expected_baseline: all type-01/02/03 records traversed
  - current_behavior: walker reads a bogus type/length pair and stops
  - remediation: start walker at `rawSmbios.TableData`

#### edid_validity

- **Seed-derived serial writes to Range Limits descriptor (off-by-18)** — `driver/fingerprint/edid_template.c:121`
  - observable_via: EDID checksum failure or display-driver range-limit enforcement error
  - expected_baseline: serial-string descriptor at index 3 rewritten
  - current_behavior: serial bytes land in the Range-Limits descriptor
  - remediation: fix descriptor index arithmetic (base+54+18*n, not base+54+18*(n+1))

- **Serial Number monitor descriptor hard-coded constant** — `driver/fingerprint/edid_template.c:71`
  - observable_via: cross-boot comparison showing identical serial
  - expected_baseline: serial unique per boot/seed
  - current_behavior: literal constant string embedded in the template
  - remediation: late-stage splice from the seed

- **Serial-string write targets descriptor 4 instead of 3** — `driver/fingerprint/edid_template.c:114`
  - observable_via: Range-Limits descriptor content visibly non-numeric
  - expected_baseline: descriptor 3 holds serial, descriptor 4 holds ranges
  - current_behavior: index arithmetic lands on descriptor 4
  - remediation: use descriptor index 3 for serial splice

- **Display name descriptor never seeded; literal GENERIC LCD** — `driver/fingerprint/edid_template.c:68`
  - observable_via: `DetailedTimingDescriptor#2` always `GENERIC LCD`
  - expected_baseline: plausible panel model string
  - current_behavior: template constant
  - remediation: pick from a per-vendor model pool using the seed

- **Range-limits descriptor corrupted by serial-write off-by-18** — `driver/fingerprint/edid_template.c:121`
  - observable_via: `monitorsource ranges` from `edid-decode` reporting invalid ranges
  - expected_baseline: descriptor-4 remains a valid Range-Limits block
  - current_behavior: serial-string bytes overwrite min/max vertical/horizontal rates
  - remediation: same as off-by-18 fix above

- **Serial-string nonce splice lands in Range-Limits; invalid VESA EDID** — `driver/fingerprint/edid_template.c:121`
  - observable_via: Windows refusing the EDID as malformed, or `edid-decode` errors
  - expected_baseline: valid EDID 1.4 blob
  - current_behavior: structurally invalid blob
  - remediation: descriptor-index fix + checksum recompute at the end of splice

#### ci_signing_coverage

- **ProcessInstrumentationCallback query (class 40) not intercepted** — `driver/fingerprint/syscall_rewrite.c:330`
  - observable_via: `NtQueryInformationProcess(ProcessInstrumentationCallback)` returning non-zero on a Chamber target
  - expected_baseline: query masked to zero or last-known-good VA
  - current_behavior: class 40 not in the dispatch table
  - remediation: add class 40 handler + shadow IC VA

- **Fingerprint control device name hardcoded CFPControl** — `driver/fingerprint/entry.c:154`
  - observable_via: object directory enumeration
  - expected_baseline: no fixed sentinel
  - current_behavior: literal sentinel string
  - remediation: random per-boot device name

- **NtQueryInformationProcess not in IC syscall dispatch** — `driver/fingerprint/syscall_rewrite.c:330`
  - observable_via: all other NtQueryInformationProcess classes returning raw host values (including class 40)
  - expected_baseline: dispatch covers every sensitive class
  - current_behavior: whole syscall absent from the table
  - remediation: add dispatch stub with per-class branches

- **ProcessInstrumentationCallback settable but never query-filtered** — `driver/fingerprint/instrumentation.c:174`
  - observable_via: set-then-query roundtrip returning the Chamber-installed VA
  - expected_baseline: query returns the prior/pre-Chamber VA
  - current_behavior: shadow persists but the query is unmediated
  - remediation: pair set with a filtered query that returns the saved prior VA

- **chamber_fingerprint.sys no self-rename; SystemModuleInformation walkers** — `driver/fingerprint/entry.c:134`
  - observable_via: `SystemModuleInformation` listing the driver
  - expected_baseline: driver hidden/renamed
  - current_behavior: visible under real name
  - remediation: KLDR-unlink + donor rename

- **ProcessInstrumentationCallback query class 40 self-reflexive detection** — `driver/fingerprint/instrumentation.c:174`
  - observable_via: a packer writing a known cookie into its own IC and reading it back via class 40
  - expected_baseline: reading back the same value it wrote
  - current_behavior: reads back the Chamber trampoline VA
  - remediation: shadow per-PID the guest-written value

#### cross_process_timing

- **DpcTime spike across parked CPUs passed through (class 8)** — `driver/fingerprint/syscall_rewrite.c:146`
  - observable_via: `SystemProcessorPerformanceInformation.DpcTime` jumping during pause
  - expected_baseline: DpcTime of a parked CPU does not exceed idle on an idle system
  - current_behavior: pause-window DPCs count into DpcTime; guest sees spikes
  - remediation: suppress DpcTime deltas across pause windows

- **IdleTime on parked CPUs frozen, contradicting idle premise** — `driver/dump.c:210`
  - observable_via: per-CPU IdleTime delta = 0 during a 2s pause window
  - expected_baseline: parked CPUs accumulate IdleTime proportional to wall-clock
  - current_behavior: parked CPUs accumulate neither idle nor busy time
  - remediation: back-fill IdleTime on resume so it tracks wall-clock

#### hardware_sidechannels

- **LBR virtualization disabled; VMCB lbr_virtualization left zero** — `driver/svm_vmcb.c:314`
  - observable_via: LBR MSRs reading host branch history
  - expected_baseline: guest LBR isolation from host
  - current_behavior: shared LBR state between guest and hypervisor
  - remediation: set `LBR_VIRTUALIZATION_ENABLE` in the VMCB

- **LBR MSRs + DBGCTL passthrough; handler branches leak** — `driver/svm_vmcb.c:268`
  - observable_via: packer snapshotting LBR, forcing a VMEXIT, and finding hypervisor branches in the stack
  - expected_baseline: LBR survives the exit unchanged, or is cleared
  - current_behavior: host handler branches pollute the LBR
  - remediation: enable LBR virt, or stop/clear LBR on exit and restore on vmrun

#### interceptor_completeness

- **cfp_cm_callback dead path: no PID ever added to spoof list** — `driver/fingerprint/cm_filter.c:309`
  - observable_via: CM filter callback never rewriting for any real target
  - expected_baseline: target PIDs populated by the launcher on process start
  - current_behavior: the target-PID list is empty forever; callback early-exits
  - remediation: wire launcher -> IOCTL -> populate PID list on target spawn

- **FltRegisterFilter dead; InstanceSetup NULL; \Device\Ndis not FS volume** — `driver/fingerprint/flt_filter.c:171`
  - observable_via: mini-filter never attaches; MAC rewrite never fires
  - expected_baseline: attach to a real FS volume or use NDIS LWF
  - current_behavior: filter advertises a non-FS target
  - remediation: either drop FLT in favour of an NDIS LWF for NIC spoofing, or move MAC spoof to another surface

- **chamber_shim.dll never injected; IC-driven surfaces dead** — `launcher/ui/Services/DriverLoader.cs:1`
  - observable_via: no ChamberShim module in target process; IC VA unmapped on syscall return
  - expected_baseline: launcher injects the shim before target runs
  - current_behavior: shim is embedded but never loaded
  - remediation: launcher-side CreateRemoteThread + LoadLibrary (or APC injection) at target spawn

- **Fingerprint target PID list never populated** — `driver/fingerprint/target_pid.c:69`
  - observable_via: `cfp_is_target(pid)` always false
  - expected_baseline: list filled on launcher handshake
  - current_behavior: list stays empty
  - remediation: IOCTL from launcher populates PID list on target process creation

- **User-mode shim DLL built and embedded but never injected** — `launcher/ui/App.xaml.cs:198`
  - observable_via: `EnumProcessModules` on target never shows the shim
  - expected_baseline: shim resident in target process
  - current_behavior: shim bytes in launcher resources, no injection
  - remediation: implement the injection step at target launch

- **FltRegisterFilter cannot attach to \Device\Ndis; MAC rewrite dead** — `driver/fingerprint/flt_filter.c:164`
  - observable_via: `FltCreateCommunicationPort` returning attach failure
  - expected_baseline: valid attach path for whatever surface the rewrite targets
  - current_behavior: target is not a legal FS volume
  - remediation: use NDIS LWF for NIC rewrites

- **HV handle_vmmcall no CHAMBER_HCALL_REWRITE_RESULT case** — `driver/vmexit.c:682`
  - observable_via: shim calling the rewrite hypercall and receiving `#UD` or failure sentinel
  - expected_baseline: dispatch handles REWRITE_RESULT and returns rewritten buffer
  - current_behavior: no case for REWRITE_RESULT in vmmcall dispatch
  - remediation: add the case + wire to syscall rewrite path

- **Fingerprint spoof list never populated; CM/FLT/IC callbacks early-exit** — `driver/fingerprint/target_pid.c:44`
  - observable_via: every callback returns `STATUS_SUCCESS` without rewriting
  - expected_baseline: callbacks active for targets
  - current_behavior: all early-exit because `cfp_is_target` is always false
  - remediation: same as above (IOCTL populate)

- **chamber_shim.dll never injected; kernel IC arm points at unmapped VA** — `driver/fingerprint/instrumentation.c:174`
  - observable_via: on IC fire, the target `#PF` into unmapped user VA
  - expected_baseline: shim is mapped; IC hits a real stub
  - current_behavior: IC VA never backed by any image
  - remediation: injection fix + shim provides the IC stub entry

### High (38)

#### cpuid_consistency

- **CPUID 0x80000001 EAX not rewritten; disagrees with 0x1 EAX** — `driver/vmexit.c:240`
  - observable_via: `cpuid(0x80000001).EAX` vs `cpuid(0x1).EAX` family/model/stepping differing
  - expected_baseline: both leaves encode the same CPUID signature
  - current_behavior: 0x1 EAX rewritten to spoofed signature; 0x80000001 EAX passthrough
  - remediation: rewrite 0x80000001 EAX from the same signature table

- **CPU signature model/stepping don't match any real 7700X SKU** — `driver/identity.c:420`
  - observable_via: cross-check against AMD-published Zen 4 signature set
  - expected_baseline: a value from the real Family 19h model/stepping set
  - current_behavior: seed-random model/stepping, mostly impossible
  - remediation: enumerate real SKU signatures; sample only from that set

- **Brand pool includes Zen 3 parts; AVX-512 leaks via CPUID 0x7** — `driver/identity.c:71`
  - observable_via: brand string contains `Ryzen 7 5xxx` but leaf 7 advertises AVX-512
  - expected_baseline: Zen 4 brand paired with Zen 4 feature leaves
  - current_behavior: brand pool mixes Zen 3 and Zen 4 parts
  - remediation: constrain brand pool to Zen 4 SKUs matching the spoofed topology

- **CPUID 0x80000008 ECX NC passthrough mismatches brand core count** — `driver/vmexit.c:297`
  - observable_via: `cpuid(0x80000008).ECX.NC` vs core-count parsed from brand string
  - expected_baseline: matching counts
  - current_behavior: ECX NC is host passthrough; brand is spoofed
  - remediation: rewrite ECX NC from the same topology source as the brand

- **CPUID 0xB/0x1F EAX/EBX passthrough mismatches spoofed core count** — `driver/vmexit.c:213`
  - observable_via: logical procs per level from 0xB/0x1F vs brand/0x80000008
  - expected_baseline: all topology views agree
  - current_behavior: 0xB/0x1F EAX/EBX passthrough on some paths
  - remediation: rewrite EAX/EBX from topology table

- **CPUID 0x1 EBX[23:16] max-logical-procs passthrough mismatches brand** — `driver/vmexit.c:193`
  - observable_via: `cpuid(0x1).EBX[23:16]` vs brand-string core count
  - expected_baseline: matching values
  - current_behavior: EBX[23:16] is host value
  - remediation: rewrite EBX[23:16] from topology table

- **CPUID 0x80000001 ECX overlay can clear TOPO_EXT bit 22** — `driver/vmexit.c:246`
  - observable_via: `cpuid(0x80000001).ECX` with `TOPO_EXT` (bit 22) cleared on a real 7700X
  - expected_baseline: TOPO_EXT set on real Zen 4
  - current_behavior: overlay OR/AND can clear bit 22
  - remediation: force-set TOPO_EXT in the overlay mask

- **CPUID 0x1 EAX model/stepping seed-derived; impossible signatures** — `driver/identity.c:428`
  - observable_via: unknown model/stepping combinations
  - expected_baseline: known signature set
  - current_behavior: free-form seed values
  - remediation: pick from real set

- **Brand pool contains Zen 3 parts; CPUID 0x7 reports Zen 4 AVX-512** — `driver/identity.c:71`
  - observable_via: brand says `5800X`, 0x7 says AVX-512 present
  - expected_baseline: feature leaves match micro-arch
  - current_behavior: brand pool crosses generations
  - remediation: Zen 4-only brand pool

- **Brand pool 7900X/7950X cannot match 7700X 16-LP topology** — `driver/identity.c:71`
  - observable_via: brand says 7950X (32 LP) while 0xB reports 16 LP
  - expected_baseline: brand and topology agree
  - current_behavior: brand pool wider than the topology supports
  - remediation: constrain brand to 8C/16T SKUs

- **CPUID 0x15 non-zero while max_std=0x10** — `driver/vmexit.c:219`
  - observable_via: 0x15 executed although 0x0.EAX=0x10 says it does not exist
  - expected_baseline: a leaf above `max_std` returns zero
  - current_behavior: 0x15 always computed
  - remediation: gate leaf 0x15 behind max_std check

- **CPUID 0x16 non-zero when max_std=0x10** — `driver/vmexit.c:228`
  - observable_via: same as above for 0x16
  - expected_baseline: zero above max_std
  - current_behavior: emits values
  - remediation: gate leaf 0x16

- **CPUID 0x80000001 ECX overlay clears TopologyExtensions while 0xB/0x1F work** — `driver/vmexit.c:246`
  - observable_via: 0x80000001.ECX.bit22 vs 0xB/0x1F operating
  - expected_baseline: TOPO_EXT must be set for 0xB/0x1F to be the authoritative source
  - current_behavior: inconsistent
  - remediation: pin TOPO_EXT in overlay

- **CPUID 0x8000001E EAX passthrough disagrees with 0xB/0x1F EDX** — `driver/vmexit.c:301`
  - observable_via: APIC-ID mismatch across leaves
  - expected_baseline: consistent APIC-ID
  - current_behavior: 0x8000001E passthrough
  - remediation: synthesise 0x8000001E

- **CPUID 0x8000001D cache sizes passthrough; brand/cache mismatch** — `driver/vmexit.c:301`
  - observable_via: L2/L3 sizes from 0x8000001D vs brand
  - expected_baseline: cache sizes consistent with SKU
  - current_behavior: host cache sizes shine through
  - remediation: rewrite 0x8000001D per spoofed SKU

- **Leaf 0x15 synthesises non-zero TSC/crystal on AMD** — `driver/vmexit.c:220`
  - observable_via: 0x15 non-zero on AuthenticAMD
  - expected_baseline: zero on AMD
  - current_behavior: computed value emitted
  - remediation: vendor-gate 0x15 to zero on AMD

- **Leaf 0x16 synthesises non-zero MHz on AMD** — `driver/vmexit.c:229`
  - observable_via: 0x16 non-zero on AuthenticAMD
  - expected_baseline: zero on AMD
  - current_behavior: computed value emitted
  - remediation: vendor-gate 0x16 to zero on AMD

- **Cross-leaf APIC ID mismatch: 1/0xB/0x1F rewritten, 0x8000001E passthrough** — `driver/vmexit.c:301`
  - observable_via: `cpuid(0x1).EBX[31:24]`, `0xB.EDX`, `0x1F.EDX`, `0x8000001E.EAX` disagreeing
  - expected_baseline: same APIC-ID across all
  - current_behavior: 0x8000001E leaks host
  - remediation: unify rewrite source

- **Brand pool 8/12/16-core while topology leaves passthrough host 8-core** — `driver/identity.c:71`
  - observable_via: brand `5900X` (12C) with 16-LP topology from host
  - expected_baseline: brand matches topology
  - current_behavior: inconsistent
  - remediation: constrain brand pool

- **Brand pool mixes Zen 3/4 but leaf 7 passthrough leaks AVX-512** — `driver/vmexit.c:208`
  - observable_via: AVX-512 bits in 0x7.EBX/ECX/EDX on a Zen 3 brand
  - expected_baseline: feature bits match micro-arch
  - current_behavior: leaf 7 passthrough ignores brand
  - remediation: rewrite leaf 7 feature bits per micro-arch

- **rewrite_leaf_80000001 ECX overlay can clear TopologyExtensions** — `driver/vmexit.c:246`
  - observable_via: TOPO_EXT bit 22 cleared after overlay
  - expected_baseline: bit always set on Zen 4
  - current_behavior: cleared under some masks
  - remediation: pin bit in overlay

#### msr_consistency

- **MSR 0x17 returns 64-bit random on AMD guest** — `driver/vmexit.c:428`
  - observable_via: `rdmsr(0x17)` succeeding on AuthenticAMD
  - expected_baseline: `#GP` on AMD
  - current_behavior: random value returned
  - remediation: inject `#GP` for 0x17 on AMD

- **MSR 0xC0000103 TSC_AUX seeded 64-bit random; AMD defines 32-bit** — `driver/identity.c:494`
  - observable_via: upper 32 bits of TSC_AUX non-zero
  - expected_baseline: upper 32 bits reserved/MBZ
  - current_behavior: 64 bits of seed
  - remediation: zero the upper 32 bits

- **MSR 0xC0010015 HWCR always returns 0x10; SmmLock cleared** — `driver/vmexit.c:472`
  - observable_via: `rdmsr(HWCR)` returning 0x10, SmmLock=0 on a UEFI box
  - expected_baseline: SmmLock set on Windows+UEFI
  - current_behavior: hardcoded 0x10
  - remediation: pass-through-with-mask instead of constant

- **Paravirt MSR ranges return 0 instead of #GP** — `driver/vmexit.c:508`
  - observable_via: KVM/Hyper-V paravirt MSRs readable on a supposedly bare-metal CPU
  - expected_baseline: `#GP` on bare metal
  - current_behavior: 0 returned
  - remediation: inject `#GP` for paravirt ranges

- **Unknown-MSR fallback returns 0 instead of #GP** — `driver/vmexit.c:608`
  - observable_via: random MSR probes returning 0 instead of faulting
  - expected_baseline: `#GP` for unknown MSRs
  - current_behavior: silent-zero fallback
  - remediation: inject `#GP` by default

- **Microcode revision not from AMD released patch set** — `driver/identity.c:440`
  - observable_via: patch revision lookup against public list
  - expected_baseline: a real published revision
  - current_behavior: random
  - remediation: pick from published set

- **TSC_AUX latch seed-random, uncorrelated with APIC ID** — `driver/identity.c:494`
  - observable_via: `rdtscp` ECX (TSC_AUX) not matching APIC-ID low bits
  - expected_baseline: Windows convention places APIC-ID in TSC_AUX
  - current_behavior: random
  - remediation: encode APIC-ID in TSC_AUX

- **HWCR returns hardcoded 0x10, contradicts design-doc PASSTHROUGH** — `driver/vmexit.c:472`
  - observable_via: synthetic_values_table says PASSTHROUGH, code returns constant
  - expected_baseline: match the table
  - current_behavior: diverged
  - remediation: implement PASSTHROUGH with mask

- **SMM_ADDR/SMM_MASK return 0 on Windows+UEFI box** — `driver/vmexit.c:585`
  - observable_via: `rdmsr(SMM_ADDR/SMM_MASK)` reading 0 on a UEFI system
  - expected_baseline: non-zero SMM range on a real UEFI box
  - current_behavior: zero
  - remediation: synthesise plausible SMM range

- **MSR 0x8B patch level doesn't match released Zen 4 revision** — `driver/identity.c:440`
  - observable_via: same as above
  - expected_baseline: published revision
  - current_behavior: random
  - remediation: real set

- **TSC_AUX shadow doesn't match spoofed APIC ID** — `driver/identity.c:494`
  - observable_via: cross-check of TSC_AUX against spoofed CPUID APIC-ID
  - expected_baseline: agree
  - current_behavior: disagree
  - remediation: derive TSC_AUX from topology table

- **TSC_AUX shadow 64-bit; upper bits violate reserved MBZ** — `driver/identity.c:494`
  - observable_via: upper 32 bits non-zero
  - expected_baseline: MBZ
  - current_behavior: seeded
  - remediation: mask

- **TSC_AUX shadow returned before guest WRMSR; _valid never checked** — `driver/identity.c:527`
  - observable_via: TSC_AUX read before any WRMSR returning non-architectural seeded value
  - expected_baseline: TSC_AUX reset state is 0 until written
  - current_behavior: seeded value returned unconditionally
  - remediation: honour `_valid` flag; return 0 until first WRMSR

- **HWCR 0x10 omits TscFreqSel while CPUID advertises invariant TSC** — `driver/vmexit.c:472`
  - observable_via: HWCR.TscFreqSel=0 while CPUID 0x80000007.EDX.InvariantTSC=1
  - expected_baseline: TscFreqSel set on modern parts
  - current_behavior: cleared
  - remediation: set TscFreqSel in the constant or move to PASSTHROUGH

- **HWCR handler contradicts synthetic_values_table PASSTHROUGH** — `driver/vmexit.c:460`
  - observable_via: same divergence as above
  - expected_baseline: table-driven
  - current_behavior: hardcoded
  - remediation: table-driven

- **MSR 0x17 random 64-bit; AMD doesn't implement, Intel reserves bits** — `driver/identity.c:442`
  - observable_via: 0x17 readable on AMD
  - expected_baseline: `#GP` on AMD
  - current_behavior: shadow
  - remediation: `#GP`

- **MSR 0x8B spoof violates synthetic_values_table PASSTHROUGH** — `driver/vmexit.c:415`
  - observable_via: table says PASSTHROUGH, code emits shadow with inverted layout
  - expected_baseline: match table
  - current_behavior: diverged
  - remediation: either keep the shadow and update the table, or honour the table

### Medium (0)

No medium-tier findings this wave.

### Low (0)

No low-tier findings this wave.

### Nit (0)

No nit-tier findings this wave.

## Scope coverage

The 12 scopes surveyed by the find phase, one-line summaries:

1. **cpuid_consistency** — cross-leaf agreement of vendor, family/model/stepping, APIC IDs, topology, cache descriptors, feature bits, and brand string for the spoofed Ryzen 7 7700X identity.
2. **msr_consistency** — architectural MSR coverage on AuthenticAMD: 0x8B microcode layout, TSC_AUX, HWCR, SMM range, paravirt ranges, unknown-MSR fault semantics.
3. **timing_roundtrip** — plausibility of the RDTSC-CPUID-RDTSC delta histogram (variance, per-leaf cost, per-core jitter) relative to bare-metal Zen 4.
4. **pause_world_sidechannels** — detectability of the 2-second targeted-DPC pause window via guest TSC, QPC, KUSER_SHARED_DATA, and per-thread cycle counters.
5. **driver_hide_completeness** — stealth of chamber_fingerprint.sys and the hypervisor driver: KLDR naming, PE scrub, section scramble, device/symlink naming.
6. **callback_enumerability** — ownership of PsSetCreateProcessNotifyRoutineEx / CmRegisterCallback / FltRegisterFilter targets resolving back to a sentinel driver.
7. **smbios_dmi_integrity** — DMI walker correctness over RawSMBIOSData, registry LastConfig coverage, and off-by-N errors in patch targeting.
8. **edid_validity** — VESA EDID 1.4 structural validity after serial/model splice and checksum.
9. **ci_signing_coverage** — coverage of NtQueryInformationProcess classes (esp. ProcessInstrumentationCallback / class 40) by the IC trampoline and driver visibility to SystemModuleInformation.
10. **cross_process_timing** — plausibility of per-CPU DpcTime/IdleTime counters from `SystemProcessorPerformanceInformation` across pause windows.
11. **hardware_sidechannels** — LBR virtualization, DBGCTL passthrough, PEBS and other hardware trace channels.
12. **interceptor_completeness** — end-to-end wiring of launcher -> IOCTL -> target-PID list -> CM/FLT/IC callbacks, including shim DLL injection and vmmcall dispatch coverage.

## Methodology

- **Find phase**: 12 scopes x 3 lenses (code-reread, exploit-trace, invariant-check) spawned 36 agents in parallel against `claude/sharp-ritchie-ku155z`. Raw findings were deduped by `(title, file, line)` to 387 unique candidates.
- **Verify phase**: severity-tiered batched verification:
  - showstopper tier: 2-lens (code-reread + exploit-trace) across 60 candidates
  - high tier: 1-lens (exploit-trace) across 40 candidates
  - medium tier: 1-lens (code-reread) across 0 candidates
  - low + nit tiers: 0 candidates carried in as-reported without verification
- **Outcome**: 90 CONFIRMED (52 showstopper, 38 high), 10 REFUTED, 0 low/nit as-reported. Each confirmed finding carries the verify vote ratio (`2/2` where two verifier lenses agreed, `1/1` where the single-lens verifier confirmed).
