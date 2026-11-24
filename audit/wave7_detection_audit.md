# Wave 7 Consistency Audit

## Summary

This wave surveyed 387 unique candidate findings (deduped from 36 find-phase agents across 12 scopes x 3 lenses) for internal consistency of THE_CHAMBER on AMD-SVM Zen 4 (family 19h, Ryzen 7 7700X, Windows 10/11 guest, passive-dump sandbox for packed-malware static analysis). Part 1 (prior report) verified the 60 showstopper + 40 high tier candidates with 2-lens and 1-lens batched refuters respectively: 52 showstopper + 38 high were CONFIRMED and 10 REFUTED. Part 2 (this extension) ran a 1-lens batched refuter over the remaining 161 high and 132 medium candidates, taking the 34 low+nit items as-reported. Updated totals: confirmed = 90 + 12 (new high after (title, file, line) dedup against the original 38) + 55 (new medium) = 157 listed in the body; refuted = 10 + 5 = 15; low/nit as-reported = 34. The top three concerns stay the same as the prior Summary section: (1) the pause-world mechanic leaks its 2-second wall-clock gap through TSC, QPC and KUSER_SHARED_DATA, i.e. the dump trigger itself is detectable within any active thread; (2) the whole fingerprint/interception stack is architecturally dead on arrival (chamber_fingerprint.sys loads under its real name with a hardcoded CFPControl device, the FLT filter targets a non-FS object, the target-PID list is never populated, and chamber_shim.dll is embedded but never injected) so every advertised interceptor is a no-op in production; (3) CPU identity is cross-leaf inconsistent (CPUID 0x15/0x16 report non-zero crystal/base-MHz on AMD, 0x8000001E/0x8000001D cache/APIC passthrough disagree with the rewritten 0x1/0xB/0x1F leaves, MSR 0x8B lays the microcode patch in Intel's EDX/high-half layout, and leaf 7 passthrough leaks AVX-512 while the brand pool advertises Zen 3 parts) - a single `cpuid-mismatch` detector of the style every modern packer ships trivially flags the box.

## Findings by severity

### Showstopper (52)

#### cpuid_consistency

- **CPUID 0x15 returns non-zero values; bare-metal AMD Zen 4 7700X returns all zeros** - `driver/vmexit.c:285`
  - observable_via: guest `cpuid(0x15)` returning non-zero EAX/EBX/ECX on AuthenticAMD
  - expected_baseline: all four regs zero on real Zen 4 (Intel-only TSC/crystal leaf)
  - current_behavior: synthesised ratio+crystal values are emitted even when vendor is AMD
  - remediation: gate leaf 0x15 behind a GenuineIntel check and return zero on AMD

- **CPUID 0x16 returns non-zero values; bare-metal AMD Zen 4 7700X returns all zeros** - `driver/vmexit.c:287`
  - observable_via: guest `cpuid(0x16)` returning non-zero MHz fields on AuthenticAMD
  - expected_baseline: all zeros on real Zen 4 (Intel-only base/max/bus MHz leaf)
  - current_behavior: base/max/bus MHz emitted regardless of vendor
  - remediation: zero leaf 0x16 unconditionally on AMD-vendor paths

- **CPUID 0x8000001E EAX passthrough disagrees with CPUID 0xB/0x1F EDX** - `driver/vmexit.c:301`
  - observable_via: APIC-ID in 0x8000001E EAX vs x2APIC-ID in 0xB/0x1F EDX across logical CPUs
  - expected_baseline: both leaves yield the same APIC/x2APIC ID per CPU
  - current_behavior: 0x1/0xB/0x1F are rewritten but 0x8000001E is host-passthrough
  - remediation: synthesise 0x8000001E from the same per-CPU topology table as 0xB/0x1F

#### msr_consistency

- **MSR 0x8B patch level placed in EDX (Intel convention), not EAX (AMD convention)** - `driver/vmexit.c:420`
  - observable_via: guest `rdmsr(0x8B)` with low 32 bits zero and high 32 bits non-zero on AuthenticAMD
  - expected_baseline: AMD encodes patch level in the low 32 bits; EDX is reserved/zero
  - current_behavior: value laid out with the Intel high-half layout even on AMD
  - remediation: place the spoofed revision in EAX and leave EDX zero for AuthenticAMD

- **MSR 0x8B microcode_rev uniformly random 32 bits; never matches released Zen 4 patch ID** - `driver/identity.c:440`
  - observable_via: guest `rdmsr(0x8B)` returning a value outside the published AMD patch set
  - expected_baseline: a Zen 4 Ryzen 7 7700X ships a bounded set of real patch IDs
  - current_behavior: 32 bits of seed-derived entropy, overwhelmingly off the published list
  - remediation: pick from the real AMD B2 patch-ID set; discard any value not on it

- **IA32_PLATFORM_ID (0x17) returns seed-derived random on AuthenticAMD** - `driver/identity.c:442`
  - observable_via: guest `rdmsr(0x17)` succeeding on AMD and returning non-zero
  - expected_baseline: AMD does not implement 0x17; real HW raises #GP
  - current_behavior: shadow value returned unconditionally
  - remediation: inject #GP for MSR 0x17 when vendor is AuthenticAMD

- **MSR 0x8B spoofed in wrong 32-bit half for AMD target** - `driver/identity.c:440`
  - observable_via: guest reading 0x8B and seeing patch bits in EDX
  - expected_baseline: AMD-native readers of 0x8B check EAX
  - current_behavior: shadow stored in the high half
  - remediation: shadow in the low 32 bits for AMD paths

- **MSR 0x8B microcode patch level in high 32 bits (Intel layout) on AMD Zen 4** - `driver/identity.c:440`
  - observable_via: cross-vendor 0x8B layout check used by current anti-cheat / packer stacks
  - expected_baseline: AMD low-half encoded patch level
  - current_behavior: Intel high-half encoding leaks vendor confusion
  - remediation: vendor-gate the layout at shadow construction

- **RDTSCP not intercepted while RDMSR 0xC0000103 is; TSC_AUX paths disagree** - `driver/svm_vmcb.c:336`
  - observable_via: guest comparing `rdtscp` ECX against `rdmsr(0xC0000103)` returns divergent values
  - expected_baseline: both paths yield the same TSC_AUX on a real CPU
  - current_behavior: RDTSCP exposes host TSC_AUX; RDMSR exposes shadow
  - remediation: intercept RDTSCP (or disable TSC_AUX passthrough) and rewrite ECX to shadow

#### timing_roundtrip

- **g_fixed_vmexit_cost hardcoded; guest RDTSC-CPUID-RDTSC delta drifts** - `driver/timing.c:185`
  - observable_via: guest `rdtsc; cpuid; rdtsc` histogram pinned at a single implausible constant
  - expected_baseline: real bare-metal CPUID exit has a per-core, per-leaf variance envelope
  - current_behavior: a single constant cost is subtracted regardless of leaf/core
  - remediation: model per-leaf cost from a bare-metal histogram with gaussian jitter per sample

#### pause_world_sidechannels

- **TSC_OFFSET does not mask 2-second pause window; RDTSC jumps ~2s** - `driver/dump.c:6`
  - observable_via: guest `rdtsc` difference across the pause window reporting >=2s of cycles
  - expected_baseline: no cycle jump across any thread quiescence
  - current_behavior: the pause mechanic freezes the thread but TSC_OFFSET is not adjusted
  - remediation: adjust TSC_OFFSET per vCPU to subtract paused-wall-clock from guest TSC

- **Paused thread shows 2s wall-clock with zero cycle/kernel/user time** - `driver/dump.c:210`
  - observable_via: a self-reporting thread sees QPC advance 2s while KTHREAD cycle counters are frozen
  - expected_baseline: wall-clock and thread-cycle counters advance together on a live CPU
  - current_behavior: pause freezes thread-local counters; wall-clock advances
  - remediation: either keep the thread scheduled (mask cycle), or rebase both on resume

- **QPC and KUSER_SHARED_DATA advance during pause; paused thread sees 2s** - `driver/dump.c:109`
  - observable_via: `QueryPerformanceCounter` delta or `KUSER_SHARED_DATA.SystemTime` delta across the pause
  - expected_baseline: all time sources stay consistent with thread-cycle accounting
  - current_behavior: both sources tick while the thread was stopped
  - remediation: drive QPC and SystemTime off a hypervisor-paused clock during the window

#### driver_hide_completeness

- **chamber_fingerprint.sys publishes hardcoded \Device\CFPControl** - `driver/fingerprint/entry.c:154`
  - observable_via: object-directory enumeration of `\Device` or `\GLOBAL??`
  - expected_baseline: no stable sentinel string for the driver
  - current_behavior: literal `CFPControl` name is a one-shot detection
  - remediation: randomise device name per boot and drop the DosDevices symlink

- **chamber_fingerprint.sys has no KLDR self-hide, section scramble, or PE scrub** - `driver/fingerprint/entry.c:134`
  - observable_via: SystemModuleInformation enumeration showing the real driver base/size/name
  - expected_baseline: donor-renamed and KLDR-unlinked for stealth parity with the hypervisor
  - current_behavior: loads under its real image name with intact PE headers and section table
  - remediation: fold the same KLDR unlink + header scrub the hypervisor driver already uses

- **chamber_fingerprint.sys KLDR entry never renamed** - `driver/fingerprint/entry.c:134`
  - observable_via: `KLDR_DATA_TABLE_ENTRY.BaseDllName` string
  - expected_baseline: donor-driver cloak
  - current_behavior: BaseDllName leaks `chamber_fingerprint.sys`
  - remediation: patch BaseDllName/FullDllName at DriverEntry before any object is created

- **Hardcoded \Device\CFPControl + \DosDevices\CFPControl symlink** - `driver/fingerprint/entry.c:154`
  - observable_via: `NtOpenFile` by sentinel name succeeding
  - expected_baseline: no deterministic symlink
  - current_behavior: both names present verbatim
  - remediation: random name + ephemeral symlink torn down after first launcher handshake

- **Duplicate pci.sys KLDR entry; rename clones donor still present** - `driver/stealth.c:291`
  - observable_via: two KLDR entries sharing `pci.sys` name but different bases
  - expected_baseline: at most one entry per driver name
  - current_behavior: donor rename leaves the original visible
  - remediation: either dedup the KLDR list after rename, or clone a donor name less likely to be enumerated twice

- **Fingerprint driver creates hardcoded \Device\CFPControl + \DosDevices\CFPControl** - `driver/fingerprint/entry.c:154`
  - observable_via: same as above, also from user-mode via `CreateFile(\\\\.\\CFPControl)`
  - expected_baseline: no sentinel device
  - current_behavior: exposed to any unprivileged open
  - remediation: random name, ACL to launcher SID only

- **chamber_fingerprint.sys KLDR entry never renamed; FullDllName leaks** - `driver/fingerprint/entry.c:204`
  - observable_via: `FullDllName` from `ZwQuerySystemInformation(SystemModuleInformation)`
  - expected_baseline: donor path
  - current_behavior: literal install path and image name
  - remediation: patch FullDllName alongside BaseDllName at entry

#### callback_enumerability

- **IC trampoline cannot intercept query of ProcessInstrumentationCallback** - `driver/fingerprint/syscall_rewrite.c:330`
  - observable_via: `NtQueryInformationProcess(ProcessInstrumentationCallback)` returning the kernel trampoline VA
  - expected_baseline: query returns zero or fakes the previous-owner's VA
  - current_behavior: NtQueryInformationProcess is not in the IC syscall dispatch table
  - remediation: add class 40 to the dispatch table and zero/forge the output

- **chamber_fingerprint.sys loads under its real name; no donor-rename** - `driver/fingerprint/entry.c:134`
  - observable_via: callback owner lookup by VA -> module resolving to `chamber_fingerprint.sys`
  - expected_baseline: callbacks owned by a plausible driver
  - current_behavior: three registered callbacks all anchor to the real driver
  - remediation: rename KLDR before registering callbacks so VA->module masks the origin

- **chamber_fingerprint.sys has no stealth; three callbacks resolve to named driver** - `driver/fingerprint/entry.c:204`
  - observable_via: `PsSetCreateProcessNotifyRoutineEx`, `CmRegisterCallback`, `FltRegisterFilter` ownership
  - expected_baseline: each callback owned by donor-renamed module
  - current_behavior: all three enumerate to the sentinel driver
  - remediation: rename + relocate register-trampolines through donor stub

#### smbios_dmi_integrity

- **DMI walker handed RawSMBIOSData header, not DMI stream (off-by-8)** - `driver/fingerprint/syscall_rewrite.c:107`
  - observable_via: guest DMI parse failing or walking past end-of-table
  - expected_baseline: walker begins at `TableData[0]`
  - current_behavior: walker begins at offset 0 of the RawSMBIOSData struct, i.e. inside the 8-byte header
  - remediation: advance the pointer by `sizeof(RAW_SMBIOS_HEADER)` before walking

- **HKLM\SYSTEM\HardwareConfig\{GUID}\LastConfig not intercepted** - `driver/fingerprint/cm_filter.c:125`
  - observable_via: reading `LastConfig` from the registry yields the real bare-metal SMBIOS blob
  - expected_baseline: CM filter rewrites the LastConfig value to the spoofed blob
  - current_behavior: no filter path for that value name
  - remediation: add LastConfig to the CM filter value list

- **DMI patch entry offset off by 8 bytes** - `driver/fingerprint/syscall_rewrite.c:107`
  - observable_via: patched fields appearing 8 bytes shifted from their real DMI offsets
  - expected_baseline: patches land on the right structure fields
  - current_behavior: writes shifted by the RawSMBIOSData header width
  - remediation: fix the base pointer before offset arithmetic

- **DMI walker starves on RawSMBIOSData 8-byte header** - `driver/fingerprint/syscall_rewrite.c:107`
  - observable_via: walker terminating early on a structure-type byte inside the header
  - expected_baseline: all type-01/02/03 records traversed
  - current_behavior: walker reads a bogus type/length pair and stops
  - remediation: start walker at `rawSmbios.TableData`

#### edid_validity

- **Seed-derived serial writes to Range Limits descriptor (off-by-18)** - `driver/fingerprint/edid_template.c:121`
  - observable_via: EDID checksum failure or display-driver range-limit enforcement error
  - expected_baseline: serial-string descriptor at index 3 rewritten
  - current_behavior: serial bytes land in the Range-Limits descriptor
  - remediation: fix descriptor index arithmetic (base+54+18*n, not base+54+18*(n+1))

- **Serial Number monitor descriptor hard-coded constant** - `driver/fingerprint/edid_template.c:71`
  - observable_via: cross-boot comparison showing identical serial
  - expected_baseline: serial unique per boot/seed
  - current_behavior: literal constant string embedded in the template
  - remediation: late-stage splice from the seed

- **Serial-string write targets descriptor 4 instead of 3** - `driver/fingerprint/edid_template.c:114`
  - observable_via: Range-Limits descriptor content visibly non-numeric
  - expected_baseline: descriptor 3 holds serial, descriptor 4 holds ranges
  - current_behavior: index arithmetic lands on descriptor 4
  - remediation: use descriptor index 3 for serial splice

- **Display name descriptor never seeded; literal GENERIC LCD** - `driver/fingerprint/edid_template.c:68`
  - observable_via: `DetailedTimingDescriptor#2` always `GENERIC LCD`
  - expected_baseline: plausible panel model string
  - current_behavior: template constant
  - remediation: pick from a per-vendor model pool using the seed

- **Range-limits descriptor corrupted by serial-write off-by-18** - `driver/fingerprint/edid_template.c:121`
  - observable_via: `monitorsource ranges` from `edid-decode` reporting invalid ranges
  - expected_baseline: descriptor-4 remains a valid Range-Limits block
  - current_behavior: serial-string bytes overwrite min/max vertical/horizontal rates
  - remediation: same as off-by-18 fix above

- **Serial-string nonce splice lands in Range-Limits; invalid VESA EDID** - `driver/fingerprint/edid_template.c:121`
  - observable_via: Windows refusing the EDID as malformed, or `edid-decode` errors
  - expected_baseline: valid EDID 1.4 blob
  - current_behavior: structurally invalid blob
  - remediation: descriptor-index fix + checksum recompute at the end of splice

#### ci_signing_coverage

- **ProcessInstrumentationCallback query (class 40) not intercepted** - `driver/fingerprint/syscall_rewrite.c:330`
  - observable_via: `NtQueryInformationProcess(ProcessInstrumentationCallback)` returning non-zero on a Chamber target
  - expected_baseline: query masked to zero or last-known-good VA
  - current_behavior: class 40 not in the dispatch table
  - remediation: add class 40 handler + shadow IC VA

- **Fingerprint control device name hardcoded CFPControl** - `driver/fingerprint/entry.c:154`
  - observable_via: object directory enumeration
  - expected_baseline: no fixed sentinel
  - current_behavior: literal sentinel string
  - remediation: random per-boot device name

- **NtQueryInformationProcess not in IC syscall dispatch** - `driver/fingerprint/syscall_rewrite.c:330`
  - observable_via: all other NtQueryInformationProcess classes returning raw host values (including class 40)
  - expected_baseline: dispatch covers every sensitive class
  - current_behavior: whole syscall absent from the table
  - remediation: add dispatch stub with per-class branches

- **ProcessInstrumentationCallback settable but never query-filtered** - `driver/fingerprint/instrumentation.c:174`
  - observable_via: set-then-query roundtrip returning the Chamber-installed VA
  - expected_baseline: query returns the prior/pre-Chamber VA
  - current_behavior: shadow persists but the query is unmediated
  - remediation: pair set with a filtered query that returns the saved prior VA

- **chamber_fingerprint.sys no self-rename; SystemModuleInformation walkers** - `driver/fingerprint/entry.c:134`
  - observable_via: `SystemModuleInformation` listing the driver
  - expected_baseline: driver hidden/renamed
  - current_behavior: visible under real name
  - remediation: KLDR-unlink + donor rename

- **ProcessInstrumentationCallback query class 40 self-reflexive detection** - `driver/fingerprint/instrumentation.c:174`
  - observable_via: a packer writing a known cookie into its own IC and reading it back via class 40
  - expected_baseline: reading back the same value it wrote
  - current_behavior: reads back the Chamber trampoline VA
  - remediation: shadow per-PID the guest-written value

#### cross_process_timing

- **DpcTime spike across parked CPUs passed through (class 8)** - `driver/fingerprint/syscall_rewrite.c:146`
  - observable_via: `SystemProcessorPerformanceInformation.DpcTime` jumping during pause
  - expected_baseline: DpcTime of a parked CPU does not exceed idle on an idle system
  - current_behavior: pause-window DPCs count into DpcTime; guest sees spikes
  - remediation: suppress DpcTime deltas across pause windows

- **IdleTime on parked CPUs frozen, contradicting idle premise** - `driver/dump.c:210`
  - observable_via: per-CPU IdleTime delta = 0 during a 2s pause window
  - expected_baseline: parked CPUs accumulate IdleTime proportional to wall-clock
  - current_behavior: parked CPUs accumulate neither idle nor busy time
  - remediation: back-fill IdleTime on resume so it tracks wall-clock

#### hardware_sidechannels

- **LBR virtualization disabled; VMCB lbr_virtualization left zero** - `driver/svm_vmcb.c:314`
  - observable_via: LBR MSRs reading host branch history
  - expected_baseline: guest LBR isolation from host
  - current_behavior: shared LBR state between guest and hypervisor
  - remediation: set `LBR_VIRTUALIZATION_ENABLE` in the VMCB

- **LBR MSRs + DBGCTL passthrough; handler branches leak** - `driver/svm_vmcb.c:268`
  - observable_via: packer snapshotting LBR, forcing a VMEXIT, and finding hypervisor branches in the stack
  - expected_baseline: LBR survives the exit unchanged, or is cleared
  - current_behavior: host handler branches pollute the LBR
  - remediation: enable LBR virt, or stop/clear LBR on exit and restore on vmrun

#### interceptor_completeness

- **cfp_cm_callback dead path: no PID ever added to spoof list** - `driver/fingerprint/cm_filter.c:309`
  - observable_via: CM filter callback never rewriting for any real target
  - expected_baseline: target PIDs populated by the launcher on process start
  - current_behavior: the target-PID list is empty forever; callback early-exits
  - remediation: wire launcher -> IOCTL -> populate PID list on target spawn

- **FltRegisterFilter dead; InstanceSetup NULL; \Device\Ndis not FS volume** - `driver/fingerprint/flt_filter.c:171`
  - observable_via: mini-filter never attaches; MAC rewrite never fires
  - expected_baseline: attach to a real FS volume or use NDIS LWF
  - current_behavior: filter advertises a non-FS target
  - remediation: either drop FLT in favour of an NDIS LWF for NIC spoofing, or move MAC spoof to another surface

- **chamber_shim.dll never injected; IC-driven surfaces dead** - `launcher/ui/Services/DriverLoader.cs:1`
  - observable_via: no ChamberShim module in target process; IC VA unmapped on syscall return
  - expected_baseline: launcher injects the shim before target runs
  - current_behavior: shim is embedded but never loaded
  - remediation: launcher-side CreateRemoteThread + LoadLibrary (or APC injection) at target spawn

- **Fingerprint target PID list never populated** - `driver/fingerprint/target_pid.c:69`
  - observable_via: `cfp_is_target(pid)` always false
  - expected_baseline: list filled on launcher handshake
  - current_behavior: list stays empty
  - remediation: IOCTL from launcher populates PID list on target process creation

- **User-mode shim DLL built and embedded but never injected** - `launcher/ui/App.xaml.cs:198`
  - observable_via: `EnumProcessModules` on target never shows the shim
  - expected_baseline: shim resident in target process
  - current_behavior: shim bytes in launcher resources, no injection
  - remediation: implement the injection step at target launch

- **FltRegisterFilter cannot attach to \Device\Ndis; MAC rewrite dead** - `driver/fingerprint/flt_filter.c:164`
  - observable_via: `FltCreateCommunicationPort` returning attach failure
  - expected_baseline: valid attach path for whatever surface the rewrite targets
  - current_behavior: target is not a legal FS volume
  - remediation: use NDIS LWF for NIC rewrites

- **HV handle_vmmcall no CHAMBER_HCALL_REWRITE_RESULT case** - `driver/vmexit.c:682`
  - observable_via: shim calling the rewrite hypercall and receiving `#UD` or failure sentinel
  - expected_baseline: dispatch handles REWRITE_RESULT and returns rewritten buffer
  - current_behavior: no case for REWRITE_RESULT in vmmcall dispatch
  - remediation: add the case + wire to syscall rewrite path

- **Fingerprint spoof list never populated; CM/FLT/IC callbacks early-exit** - `driver/fingerprint/target_pid.c:44`
  - observable_via: every callback returns `STATUS_SUCCESS` without rewriting
  - expected_baseline: callbacks active for targets
  - current_behavior: all early-exit because `cfp_is_target` is always false
  - remediation: same as above (IOCTL populate)

- **chamber_shim.dll never injected; kernel IC arm points at unmapped VA** - `driver/fingerprint/instrumentation.c:174`
  - observable_via: on IC fire, the target `#PF` into unmapped user VA
  - expected_baseline: shim is mapped; IC hits a real stub
  - current_behavior: IC VA never backed by any image
  - remediation: injection fix + shim provides the IC stub entry

### High (50)

The first 38 entries are the originally-confirmed highs from Part 1, carried over verbatim. The trailing 12 entries are unique-mechanism confirmations from Part 2's extension; new confirmations whose `(title, file, line)` collides with a Part 1 entry were merged into the original row per the dedup rule.

#### cpuid_consistency

- **CPUID 0x80000001 EAX not rewritten; disagrees with 0x1 EAX** - `driver/vmexit.c:240`
  - observable_via: `cpuid(0x80000001).EAX` vs `cpuid(0x1).EAX` family/model/stepping differing
  - expected_baseline: both leaves encode the same CPUID signature
  - current_behavior: 0x1 EAX rewritten to spoofed signature; 0x80000001 EAX passthrough
  - remediation: rewrite 0x80000001 EAX from the same signature table

- **CPU signature model/stepping don't match any real 7700X SKU** - `driver/identity.c:420`
  - observable_via: cross-check against AMD-published Zen 4 signature set
  - expected_baseline: a value from the real Family 19h model/stepping set
  - current_behavior: seed-random model/stepping, mostly impossible
  - remediation: enumerate real SKU signatures; sample only from that set

- **Brand pool includes Zen 3 parts; AVX-512 leaks via CPUID 0x7** - `driver/identity.c:71`
  - observable_via: brand string contains `Ryzen 7 5xxx` but leaf 7 advertises AVX-512
  - expected_baseline: Zen 4 brand paired with Zen 4 feature leaves
  - current_behavior: brand pool mixes Zen 3 and Zen 4 parts
  - remediation: constrain brand pool to Zen 4 SKUs matching the spoofed topology

- **CPUID 0x80000008 ECX NC passthrough mismatches brand core count** - `driver/vmexit.c:297`
  - observable_via: `cpuid(0x80000008).ECX.NC` vs core-count parsed from brand string
  - expected_baseline: matching counts
  - current_behavior: ECX NC is host passthrough; brand is spoofed
  - remediation: rewrite ECX NC from the same topology source as the brand

- **CPUID 0xB/0x1F EAX/EBX passthrough mismatches spoofed core count** - `driver/vmexit.c:213`
  - observable_via: logical procs per level from 0xB/0x1F vs brand/0x80000008
  - expected_baseline: all topology views agree
  - current_behavior: 0xB/0x1F EAX/EBX passthrough on some paths
  - remediation: rewrite EAX/EBX from topology table

- **CPUID 0x1 EBX[23:16] max-logical-procs passthrough mismatches brand** - `driver/vmexit.c:193`
  - observable_via: `cpuid(0x1).EBX[23:16]` vs brand-string core count
  - expected_baseline: matching values
  - current_behavior: EBX[23:16] is host value
  - remediation: rewrite EBX[23:16] from topology table

- **CPUID 0x80000001 ECX overlay can clear TOPO_EXT bit 22** - `driver/vmexit.c:246`
  - observable_via: `cpuid(0x80000001).ECX` with `TOPO_EXT` (bit 22) cleared on a real 7700X
  - expected_baseline: TOPO_EXT set on real Zen 4
  - current_behavior: overlay OR/AND can clear bit 22
  - remediation: force-set TOPO_EXT in the overlay mask

- **CPUID 0x1 EAX model/stepping seed-derived; impossible signatures** - `driver/identity.c:428`
  - observable_via: unknown model/stepping combinations
  - expected_baseline: known signature set
  - current_behavior: free-form seed values
  - remediation: pick from real set

- **Brand pool contains Zen 3 parts; CPUID 0x7 reports Zen 4 AVX-512** - `driver/identity.c:71`
  - observable_via: brand says `5800X`, 0x7 says AVX-512 present
  - expected_baseline: feature leaves match micro-arch
  - current_behavior: brand pool crosses generations
  - remediation: Zen 4-only brand pool

- **Brand pool 7900X/7950X cannot match 7700X 16-LP topology** - `driver/identity.c:71`
  - observable_via: brand says 7950X (32 LP) while 0xB reports 16 LP
  - expected_baseline: brand and topology agree
  - current_behavior: brand pool wider than the topology supports
  - remediation: constrain brand to 8C/16T SKUs

- **CPUID 0x15 non-zero while max_std=0x10** - `driver/vmexit.c:219`
  - observable_via: 0x15 executed although 0x0.EAX=0x10 says it does not exist
  - expected_baseline: a leaf above `max_std` returns zero
  - current_behavior: 0x15 always computed
  - remediation: gate leaf 0x15 behind max_std check

- **CPUID 0x16 non-zero when max_std=0x10** - `driver/vmexit.c:228`
  - observable_via: same as above for 0x16
  - expected_baseline: zero above max_std
  - current_behavior: emits values
  - remediation: gate leaf 0x16

- **CPUID 0x80000001 ECX overlay clears TopologyExtensions while 0xB/0x1F work** - `driver/vmexit.c:246`
  - observable_via: 0x80000001.ECX.bit22 vs 0xB/0x1F operating
  - expected_baseline: TOPO_EXT must be set for 0xB/0x1F to be the authoritative source
  - current_behavior: inconsistent
  - remediation: pin TOPO_EXT in overlay

- **CPUID 0x8000001E EAX passthrough disagrees with 0xB/0x1F EDX** - `driver/vmexit.c:301`
  - observable_via: APIC-ID mismatch across leaves
  - expected_baseline: consistent APIC-ID
  - current_behavior: 0x8000001E passthrough
  - remediation: synthesise 0x8000001E

- **CPUID 0x8000001D cache sizes passthrough; brand/cache mismatch** - `driver/vmexit.c:301`
  - observable_via: L2/L3 sizes from 0x8000001D vs brand
  - expected_baseline: cache sizes consistent with SKU
  - current_behavior: host cache sizes shine through
  - remediation: rewrite 0x8000001D per spoofed SKU

- **Leaf 0x15 synthesises non-zero TSC/crystal on AMD** - `driver/vmexit.c:220`
  - observable_via: 0x15 non-zero on AuthenticAMD
  - expected_baseline: zero on AMD
  - current_behavior: computed value emitted
  - remediation: vendor-gate 0x15 to zero on AMD

- **Leaf 0x16 synthesises non-zero MHz on AMD** - `driver/vmexit.c:229`
  - observable_via: 0x16 non-zero on AuthenticAMD
  - expected_baseline: zero on AMD
  - current_behavior: computed value emitted
  - remediation: vendor-gate 0x16 to zero on AMD

- **Cross-leaf APIC ID mismatch: 1/0xB/0x1F rewritten, 0x8000001E passthrough** - `driver/vmexit.c:301`
  - observable_via: `cpuid(0x1).EBX[31:24]`, `0xB.EDX`, `0x1F.EDX`, `0x8000001E.EAX` disagreeing
  - expected_baseline: same APIC-ID across all
  - current_behavior: 0x8000001E leaks host
  - remediation: unify rewrite source

- **Brand pool 8/12/16-core while topology leaves passthrough host 8-core** - `driver/identity.c:71`
  - observable_via: brand `5900X` (12C) with 16-LP topology from host
  - expected_baseline: brand matches topology
  - current_behavior: inconsistent
  - remediation: constrain brand pool

- **Brand pool mixes Zen 3/4 but leaf 7 passthrough leaks AVX-512** - `driver/vmexit.c:208`
  - observable_via: AVX-512 bits in 0x7.EBX/ECX/EDX on a Zen 3 brand
  - expected_baseline: feature bits match micro-arch
  - current_behavior: leaf 7 passthrough ignores brand
  - remediation: rewrite leaf 7 feature bits per micro-arch

- **rewrite_leaf_80000001 ECX overlay can clear TopologyExtensions** - `driver/vmexit.c:246`
  - observable_via: TOPO_EXT bit 22 cleared after overlay
  - expected_baseline: bit always set on Zen 4
  - current_behavior: cleared under some masks
  - remediation: pin bit in overlay

- **CPUID 0x80000001 ECX bit 2 (SVM) advertised; guest VMRUN immediately #UDs** - `driver/vmexit.c:251`
  - observable_via: `cpuid(0x80000001).ECX` bit 2 set + guest `vmrun` raising `#UD` inside SEH
  - expected_baseline: bare-metal with SVM advertised either runs VMRUN or returns a VMEXIT; never `#UD`
  - current_behavior: the low-10-bit preservation mask keeps bit 2 set; VMEXIT_VMRUN has no dispatch case so the default arm injects `#UD`
  - remediation: either clear SVM in the ECX overlay's preserve mask, or add a VMEXIT_VMRUN case that fakes a plausible failure for nested-SVM probes

- **CPUID 0x80000001 ECX overlay can clear PerfCtrExtCore (bit 23) while PerfCtrCoreI MSRs remain writable** - `driver/vmexit.c:246`
  - observable_via: `cpuid(0x80000001).ECX[23]=0` paired with successful RDMSR/WRMSR on `0xC0010200..0xC001020A`
  - expected_baseline: PerfCtrExtCore=0 must #GP MSRs in that range
  - current_behavior: bit 23 is outside the 0x3FF preserve mask so the overlay can clear it while the PMC MSR handler services the MSR
  - remediation: pin bit 23 in the overlay's preserve mask (same shape as the TopologyExtensions fix)

#### msr_consistency

- **MSR 0x17 returns 64-bit random on AMD guest** - `driver/vmexit.c:428`
  - observable_via: `rdmsr(0x17)` succeeding on AuthenticAMD
  - expected_baseline: `#GP` on AMD
  - current_behavior: random value returned
  - remediation: inject `#GP` for 0x17 on AMD

- **MSR 0xC0000103 TSC_AUX seeded 64-bit random; AMD defines 32-bit** - `driver/identity.c:494`
  - observable_via: upper 32 bits of TSC_AUX non-zero
  - expected_baseline: upper 32 bits reserved/MBZ
  - current_behavior: 64 bits of seed
  - remediation: zero the upper 32 bits

- **MSR 0xC0010015 HWCR always returns 0x10; SmmLock cleared** - `driver/vmexit.c:472`
  - observable_via: `rdmsr(HWCR)` returning 0x10, SmmLock=0 on a UEFI box
  - expected_baseline: SmmLock set on Windows+UEFI
  - current_behavior: hardcoded 0x10
  - remediation: pass-through-with-mask instead of constant

- **Paravirt MSR ranges return 0 instead of #GP** - `driver/vmexit.c:508`
  - observable_via: KVM/Hyper-V paravirt MSRs readable on a supposedly bare-metal CPU
  - expected_baseline: `#GP` on bare metal
  - current_behavior: 0 returned
  - remediation: inject `#GP` for paravirt ranges

- **Unknown-MSR fallback returns 0 instead of #GP** - `driver/vmexit.c:608`
  - observable_via: random MSR probes returning 0 instead of faulting
  - expected_baseline: `#GP` for unknown MSRs
  - current_behavior: silent-zero fallback
  - remediation: inject `#GP` by default

- **Microcode revision not from AMD released patch set** - `driver/identity.c:440`
  - observable_via: patch revision lookup against public list
  - expected_baseline: a real published revision
  - current_behavior: random
  - remediation: pick from published set

- **TSC_AUX latch seed-random, uncorrelated with APIC ID** - `driver/identity.c:494`
  - observable_via: `rdtscp` ECX (TSC_AUX) not matching APIC-ID low bits
  - expected_baseline: Windows convention places APIC-ID in TSC_AUX
  - current_behavior: random
  - remediation: encode APIC-ID in TSC_AUX

- **HWCR returns hardcoded 0x10, contradicts design-doc PASSTHROUGH** - `driver/vmexit.c:472`
  - observable_via: synthetic_values_table says PASSTHROUGH, code returns constant
  - expected_baseline: match the table
  - current_behavior: diverged
  - remediation: implement PASSTHROUGH with mask

- **SMM_ADDR/SMM_MASK return 0 on Windows+UEFI box** - `driver/vmexit.c:585`
  - observable_via: `rdmsr(SMM_ADDR/SMM_MASK)` reading 0 on a UEFI system
  - expected_baseline: non-zero SMM range on a real UEFI box
  - current_behavior: zero
  - remediation: synthesise plausible SMM range

- **MSR 0x8B patch level doesn't match released Zen 4 revision** - `driver/identity.c:440`
  - observable_via: same as above
  - expected_baseline: published revision
  - current_behavior: random
  - remediation: real set

- **TSC_AUX shadow doesn't match spoofed APIC ID** - `driver/identity.c:494`
  - observable_via: cross-check of TSC_AUX against spoofed CPUID APIC-ID
  - expected_baseline: agree
  - current_behavior: disagree
  - remediation: derive TSC_AUX from topology table

- **TSC_AUX shadow 64-bit; upper bits violate reserved MBZ** - `driver/identity.c:494`
  - observable_via: upper 32 bits non-zero
  - expected_baseline: MBZ
  - current_behavior: seeded
  - remediation: mask

- **TSC_AUX shadow returned before guest WRMSR; _valid never checked** - `driver/identity.c:527`
  - observable_via: TSC_AUX read before any WRMSR returning non-architectural seeded value
  - expected_baseline: TSC_AUX reset state is 0 until written
  - current_behavior: seeded value returned unconditionally
  - remediation: honour `_valid` flag; return 0 until first WRMSR

- **HWCR 0x10 omits TscFreqSel while CPUID advertises invariant TSC** - `driver/vmexit.c:472`
  - observable_via: HWCR.TscFreqSel=0 while CPUID 0x80000007.EDX.InvariantTSC=1
  - expected_baseline: TscFreqSel set on modern parts
  - current_behavior: cleared
  - remediation: set TscFreqSel in the constant or move to PASSTHROUGH

- **HWCR handler contradicts synthetic_values_table PASSTHROUGH** - `driver/vmexit.c:460`
  - observable_via: same divergence as above
  - expected_baseline: table-driven
  - current_behavior: hardcoded
  - remediation: table-driven

- **MSR 0x17 random 64-bit; AMD doesn't implement, Intel reserves bits** - `driver/identity.c:442`
  - observable_via: 0x17 readable on AMD
  - expected_baseline: `#GP` on AMD
  - current_behavior: shadow
  - remediation: `#GP`

- **MSR 0x8B spoof violates synthetic_values_table PASSTHROUGH** - `driver/vmexit.c:415`
  - observable_via: table says PASSTHROUGH, code emits shadow with inverted layout
  - expected_baseline: match table
  - current_behavior: diverged
  - remediation: either keep the shadow and update the table, or honour the table

- **RDTSCP leaks host-side physical TSC_AUX; diverges from the Wave-4 RDMSR latch** - `driver/svm_vmcb.c:336`
  - observable_via: guest `wrmsr(0xC0000103, X); rdtscp` returns the host's pre-HV Windows TSC_AUX while `rdmsr(0xC0000103)` returns the seed-derived latch
  - expected_baseline: both paths return the same OS-written tag
  - current_behavior: RDTSCP is not in `IVEC4_RDTSCP` so hardware reads the physical MSR while RDMSR takes the TSC_AUX branch and returns `identity_get_tsc_aux(cpu_index)`
  - remediation: add `IVEC4_RDTSCP` to the intercept mask and rewrite ECX in a RDTSCP handler, or stop faking RDMSR and let both paths see the real latch

#### timing_roundtrip

- **g_timing_tail_cycles=200 excludes the loop-top VMSAVE/VMLOAD pair, FXRSTOR64, and timing_update body** - `driver/timing.c:106`
  - observable_via: tight `rdtsc; cpuid; rdtsc` loop minimum delta is inflated over bare metal by ~100-700 cycles
  - expected_baseline: tail compensation covers every host cycle between END capture and next VMRUN entry microcode
  - current_behavior: 200 cycles cover only the GPR reload sled + jmp; call `timing_update`, `fxrstor64`, and the loop-top `vmsave host` + `vmload guest` fall into the un-measured tail
  - remediation: either capture a second RDTSC right before `vmrun` and feed the actual tail delta into `g_total_accumulated_cycles`, or lift the fixed constant to include measured FXRSTOR + vmsave/vmload cost

- **g_fixed_vmexit_cost=800 is an uncalibrated compile-time constant** - `driver/timing.c:184`
  - observable_via: multi-run `rdtsc; cpuid; rdtsc` statistical probe medians diverging from bare-metal baseline by 100-500 cycles
  - expected_baseline: guest-side VMMCALL calibration pass measures the real microcode round-trip per the master_plan §1.2 protocol
  - current_behavior: `timing_calibrate()` body is literally `g_fixed_vmexit_cost = 800;` - no measurement
  - remediation: implement the 5-step calibration (N synthetic VMMCALLs; residue = guest_delta - host_interval_sum; set `g_fixed_vmexit_cost` to residue/N + small pessimistic bias)

- **Per-core guest RDTSC regresses under concurrent cross-core VMEXIT pressure (global accumulator design)** - `driver/timing.c:141`
  - observable_via: two-thread probe where thread A tight-loops `rdtsc` on CPU 0 while thread B issues intercepted CPUIDs on CPU 1; thread A records a single negative delta
  - expected_baseline: Zen 4 Invariant TSC is strictly monotonic per logical processor
  - current_behavior: `g_total_accumulated_cycles` is a single global; CPU 1's VMEXITs between two of CPU 0's reads make CPU 0's next `tsc_offset` snap more negative than the real host delta, producing backward guest RDTSCs
  - remediation: maintain per-core accumulators (or per-core TSC_OFFSET independent of global handler time) and reconcile with a small positive upper-bound clamp per exit

- **FXRSTOR64 variability (70-150 cycles) leaks to guest because it runs AFTER TIMING_HOST_INTERVAL_END** - `driver/vmrun.asm:183`
  - observable_via: guest primes FPU state before the probe (fninit;fld1;fldpi;...) and sees a seed-independent delta shift vs a bare `fninit` baseline
  - expected_baseline: bare-metal CPUID has no FPU-state dependence
  - current_behavior: FXSAVE64 is inside the measured interval and subtracted; FXRSTOR64 is outside and only the fixed 200-cyc tail covers it, leaving ~50-80 cyc of state-dependent variance in the guest-visible delta
  - remediation: either move FXRSTOR64 before END capture, or compute a per-exit FXRSTOR latency delta and fold it into the tail charge

- **timing_calibrate() is a stub - no guest-side VMMCALL calibration pass** - `driver/timing.c:184`
  - observable_via: any RDTSC-intercept-RDTSC sample on silicon whose real microcode latency differs from the hardcoded 600+200 estimate
  - expected_baseline: per-plan master_plan §1.2 the HV issues N synthetic VMMCALLs, measures guest delta minus host interval sum, and stores the residue
  - current_behavior: hand-estimate constant; no running-guest calibration was ever wired
  - remediation: implement the measurement protocol end-to-end from an early boot thread once the guest is live

- **APERF/MPERF passthrough leaks the full host handler cost** - `driver/svm_vmcb.c:262`
  - observable_via: guest `rdmsr(0xE8); cpuid; rdmsr(0xE8)` with a parallel `rdtsc` bracket shows (APERF_delta)/(TSC_delta) collapsed 10x-100x from the bare-metal ~1.0 ratio
  - expected_baseline: APERF and TSC tick together on an in-C0 workload; on real hardware they differ only by the P-state ratio
  - current_behavior: `msrpm_set_intercept` never arms 0xE7/0xE8 and VMCB has no APERF/MPERF offset; guest APERF advances through every host cycle of the VMEXIT handler while TSC is offset-corrected
  - remediation: intercept APERF/MPERF, maintain shadow counters that snapshot across VMEXIT the same way PMU state is snapshotted, and serve them to the guest

#### pause_world_sidechannels

- **Paused CPU accrues 2 s of DpcTime visible via SystemProcessorPerformanceInformation** - `driver/dump.c:210`
  - observable_via: `NtQuerySystemInformation(SystemProcessorPerformanceInformation=8)` polled at >=10 Hz on a sibling process; the paused CPU's DpcTime jumps by ~2e7 (100-ns units) while idle/user/kernel-minus-DPC-minus-interrupt stays flat
  - expected_baseline: stock Windows DPCs never accrue multi-second DpcTime per clock-tick window
  - current_behavior: DPC spin at DISPATCH_LEVEL lasts up to `PAUSE_WINDOW_100NS = 2e7`; clock ISRs at CLOCK_LEVEL charge each tick to KPRCB.DpcTime because the interrupted IRQL is DISPATCH_LEVEL
  - remediation: back out the DpcTime delta inside pause_resume (per-CPU KPRCB.DpcTime -= tick_count_during_pause), or move the pause mechanic below CLOCK_LEVEL (not an option on Windows)

- **Paused target thread shows zero advance in GetThreadTimes while wall clock advances 2 s** - `driver/dump.c:205`
  - observable_via: `NtQueryInformationThread(ThreadTimes=5)` polled from a sibling; `KernelTime + UserTime` stays flat for the full pause while `KUSER_SHARED_DATA.TickCountQuad` advances by ~2000 ms
  - expected_baseline: a Running thread accrues kernel+user time at approximately wall-clock rate
  - current_behavior: clock ISR charges ticks to KPRCB.DpcTime instead of KTHREAD.KernelTime/UserTime because the interrupted IRQL is DISPATCH_LEVEL; thread-state stays Running
  - remediation: on pause release, backfill the stolen 2s into the target thread's Kernel+UserTime counters (or arrange the pause so the thread transitions to Waiting state and accrues no wall-clock advance)

- **QueryThreadCycleTime inflates during pause - contradicts GetThreadTimes** - `driver/dump.c:210`
  - observable_via: sibling samples `(CycleTime, KernelTime, UserTime)` at 100 Hz; CycleTime advances at TSC rate while KernelTime+UserTime are flat, giving an infinite ratio for 20 consecutive samples
  - expected_baseline: on bare metal CycleTime/(KernelTime+UserTime) is stable near TSC_freq/1e7 across any window
  - current_behavior: `KeQueryCurrentThreadCycleTime` returns `CycleTime + (ReadTimeStampCounter() - CycleTimeBase)` when state==Running; CycleTimeBase is not refreshed during DPC spin so the pause cycles are added
  - remediation: on pause enter, bump `KTHREAD.CycleTime` or `CycleTimeBase` for all affected threads so the inflated-cycle observation is suppressed

### Medium (55)

The 55 confirmed mediums below are the Part 2 verify output; none duplicate a Part 1 showstopper or high by `(title, file, line)`.

#### cpuid_consistency

- **Hypervisor-reserved range 0x40000000..0x4FFFFFFF forced to all zeros does not match bare-metal AMD behavior** - `driver/vmexit.c:312`
  - observable_via: `__cpuid(regs, 0x40000000)` vs `__cpuid(regs, max_std_leaf)` - bare-metal AMD returns the max-basic-leaf echo, not all zeros
  - expected_baseline: per AMD APM Vol 3 E.3.3, undefined leaves return the highest implemented basic leaf's data
  - current_behavior: unconditional zero-fill of EAX/EBX/ECX/EDX regardless of max_std echo
  - remediation: either echo `cpuidex(max_std, 0)` into the hypervisor range, or let the host CPU's implementation-defined response pass through

- **CPUID 0x8000001F clears SEV/SME bits; real 7700X advertises SME support** - `driver/vmexit.c:257`
  - observable_via: `__cpuid(regs, 0x8000001F)` returning EAX=0 on a part whose public dump shows SME=1
  - expected_baseline: bare-metal Zen 4 Ryzen desktop advertises SME; only SEV is EPYC-restricted
  - current_behavior: `rewrite_leaf_8000001F` zeros EAX[2:0] and EBX/ECX/EDX unconditionally
  - remediation: keep SME (bit 0) set from host passthrough; only clear SEV (bit 1) and the SEV-specific extended fields

- **CPUID 0x7 subleaves 0 and 1 are passthrough; reveals Zen 4 microarchitecture features regardless of selected brand** - `driver/vmexit.c:208`
  - observable_via: `__cpuidex(regs, 7, 0).EBX` AVX-512 bits set while brand says Zen 3
  - expected_baseline: feature flags consistent with brand's micro-arch
  - current_behavior: `rewrite_leaf_7` body is `(void)regs;`
  - remediation: implement brand-aware feature masking or constrain brand pool to Zen 4 only

- **CPUID 0x1F advertised at same values as 0xB; real AMD Zen 4 returns zero for 0x1F (Intel-only leaf)** - `driver/vmexit.c:283`
  - observable_via: `__cpuidex(regs, 0x1F, 0)` returning the spoofed EDX APIC ID on an AMD part
  - expected_baseline: AMD does not implement 0x1F; returns zero or falls to the undefined-range path
  - current_behavior: 0x1F dispatches to `rewrite_leaf_topology` the same way 0xB does
  - remediation: zero 0x1F unconditionally on AuthenticAMD

- **CPUID 0x8000001D cache subleaves and 0x8000001E compute-unit/node are host passthrough; leaks real topology under spoofed brand** - `driver/vmexit.c:301`
  - observable_via: `__cpuidex(regs, 0x8000001D, 3)` L3 size versus brand
  - expected_baseline: cache geometry matches the SKU implied by brand
  - current_behavior: 0x8000001D/E branch is comment-only pass-through
  - remediation: rewrite cache descriptors + node IDs per spoofed SKU

- **CPUID 0x15 ratio range can emit implausibly low TSC frequencies down to ~600 MHz (crystal 24 MHz × numer 100 / denom 4)** - `driver/identity.c:449`
  - observable_via: computed TSC_hz from leaf 0x15 vs measured RDTSC rate over KeQueryPerformanceCounter
  - expected_baseline: Zen 4 Raphael TSC frequency is 3.4-5.7 GHz band
  - current_behavior: denom range 1..4 and crystal 24..25 MHz combine to span 600 MHz..3.975 GHz, well below real 7700X base clock
  - remediation: constrain (denom, numer, crystal) to produce a TSC rate within published Zen 4 base-clock bounds

- **CPUID 0x16 EBX (max frequency) range extends to 6398 MHz, above the 7700X's documented 5.4 GHz Precision Boost ceiling** - `driver/identity.c:458`
  - observable_via: `__cpuid(regs, 0x16).EBX` > 5700 MHz on any shipping Zen 4 desktop part
  - expected_baseline: 7700X max 5400 MHz, 7950X max 5700 MHz
  - current_behavior: cpu_max_mhz = base + 0..999; with base=5399 the max reaches 6398 MHz
  - remediation: clamp cpu_max_mhz to the SKU's documented Precision Boost

- **CPUID 0x1 EBX[31:24] initial APIC ID for the BSP (CPU 0) is `apic_base`, usually non-zero - real BSPs ship with APIC ID 0** - `driver/identity.c:479`
  - observable_via: SetThreadAffinityMask to CPU 0 then `__cpuid(regs, 1).EBX[31:24]` returning non-zero
  - expected_baseline: ACPI MADT and AMD convention: BSP has APIC ID 0
  - current_behavior: `apic_base = derive_u32(seed,'apic_id_base') & 0xFF`, so 255/256 seeds produce non-zero BSP APIC ID
  - remediation: force `apic_base = 0` for the BSP (or shift the APIC ID pool to start at 0 for CPU index 0)

- **CPUID 0x80000008 ECX NC passes through from host even when brand string names a different core count** - `driver/vmexit.c:297`
  - observable_via: brand="Ryzen 5 5600X 6-Core Processor" vs ECX[7:0]=15 on a 7700X host
  - expected_baseline: ECX NC must equal brand-implied LP count minus 1
  - current_behavior: no-op comment branch; ECX[7:0] passes through from host
  - remediation: rewrite ECX[7:0] from the topology table used for the brand pick

- **rewrite_leaf_7 is declared but unimplemented - comment says "a future pass can trim features that correlate with the chosen brand"** - `driver/vmexit.c:208`
  - observable_via: same AVX-512 cross-check as the 0x7 passthrough finding
  - expected_baseline: implemented rewriter trimming per-brand features
  - current_behavior: TODO stub
  - remediation: implement per-brand feature mask

- **Leaf 1 EAX stepping/model nibbles are seed-random within family 0x19 - no bounds to shipped Zen 4 model space** - `driver/identity.c:420`
  - observable_via: `__cpuid(regs, 1).EAX` decoded against the Raphael/Vermeer published model+stepping set
  - expected_baseline: a small enumerated set of real (family, model, stepping) tuples
  - current_behavior: stepping/model/ext_model each drawn as free 4-bit fields
  - remediation: whitelist against the actual shipped Zen 4 model byte set

- **Unconditional zeroing of leaf 0x8000001F drops SME capability bit which real Zen 4 7700X advertises as 1** - `driver/vmexit.c:257`
  - observable_via: `CPUID.80000001F:EAX[0]=0` while vendor is AuthenticAMD family 19h
  - expected_baseline: SME=1 on consumer Zen 4 even without BIOS SMEE programming
  - current_behavior: EAX[2:0] all cleared
  - remediation: keep SME set; clear only SEV + SEV-ES features

- **Leaf 0x80000008 ECX[7:0] (NC) passes through host, so the HV cannot vary core count but the brand-pool still spans 6/8/12/16 cores** - `driver/vmexit.c:297`
  - observable_via: cross-check ECX NC against brand string LP count
  - expected_baseline: NC agrees with brand
  - current_behavior: 3 of 5 pool entries (7900X/7950X/5600X) produce a deterministic mismatch on a 7700X host
  - remediation: same as the ECX NC rewrite finding; constrain brand to pool entries whose LP count matches host, or rewrite ECX NC

#### msr_consistency

- **MSR 0xC0010114 (VM_CR) returns 0 unconditionally - LOCK bit missing for a BIOS-locked SVM configuration** - `driver/vmexit.c:576`
  - observable_via: `RDMSR 0xC0010114` returning 0 while CPUID advertises SVM
  - expected_baseline: retail Zen BIOSes set VM_CR.LOCK=1 (typical value 0x08 or 0x18)
  - current_behavior: zeroed with no LOCK/SVMDIS modeling
  - remediation: seed a plausible VM_CR (LOCK set, SVMDIS honoring host state)

- **EFER write-then-read of SVME does not round-trip (write SVME=1 reads back SVME=0)** - `driver/vmexit.c:552`
  - observable_via: write-then-read roundtrip on EFER.SVME while CPUID advertises SVM and VM_CR shows not-locked
  - expected_baseline: SVME must round-trip on a real part advertising SVM
  - current_behavior: write stores with SVME forced on but read returns value masked with ~EFER_SVME
  - remediation: either stop masking SVME on read, or mask it on write too so the invariant is preserved

- **VM_CR (0xC0010114) hardcoded to 0 ignores plausible BIOS-locked / BIOS-disabled states** - `driver/vmexit.c:573`
  - observable_via: same as finding above; multi-signal fingerprint pairing CPUID advertisement with VM_CR=0
  - expected_baseline: a shipping box pairs SVM advertisement with LOCK=1
  - current_behavior: unconditional zero
  - remediation: model a plausible VM_CR per seed

- **Paravirt-range MSR reads absorb to 0 instead of injecting #GP, visible even after CPUID hypervisor-present clear** - `driver/vmexit.c:508`
  - observable_via: SEH `__try/__except` around `__readmsr(0x40000000)` catches no exception
  - expected_baseline: bare-metal AMD with CPUID hypervisor-bit cleared `#GP`s on these addresses
  - current_behavior: ranges 0x40000000..0x400001FF and 0x4B564D00..0x4B564DFF absorb silently
  - remediation: inject `#GP(0)` with `event_inject` for these bands when CPUID hypervisor-present is 0

- **Unknown-MSR RDMSR returns 0 and WRMSR absorbs instead of injecting #GP** - `driver/vmexit.c:608`
  - observable_via: SEH sweep across unmapped MSR addresses counts zero `#GP`s instead of ~N
  - expected_baseline: bare metal `#GP`s on every unimplemented MSR
  - current_behavior: default fallback tail: read returns 0, write absorbs, no event_inject
  - remediation: inject `#GP(0)` on fallback and maintain an explicit "serve zero" allowlist for MSRs we deliberately absorb

#### timing_roundtrip

- **Cross-core unified accumulator breaks per-core RDTSC monotonicity on an invariant-TSC CPU** - `driver/timing.c:94`
  - observable_via: two-thread tight-RDTSC-loop records a negative delta on thread A while thread B generates cross-core VMEXIT pressure
  - expected_baseline: Zen 4 InvariantTSC monotonicity per logical processor
  - current_behavior: single `g_total_accumulated_cycles` global; another core's handler cycles drive the local TSC_OFFSET more negative
  - remediation: per-core accumulators (shared with the per-core RDTSC regress showstopper of the high tier)

- **timing_update() itself (including LOCK-prefixed InterlockedAdd64) executes in the tail, after END capture but before next VMRUN; its cost is not inside the measured interval** - `driver/timing.c:131`
  - observable_via: tail-cycle inflation grows with concurrent multi-CPU VMEXIT pressure
  - expected_baseline: tail cost is stable and small enough to fit in g_timing_tail_cycles
  - current_behavior: InterlockedAdd64 on a single global cache line stretches to 100-500 cycles under contention
  - remediation: move the LOCK-prefixed update before END capture, or switch to per-core relaxed stores

- **Pre-START prelude (7 instructions between VMRUN return and START capture) is uncompensated** - `driver/vmrun.asm:121`
  - observable_via: fine-grained per-exit cost compared against theoretical baseline
  - expected_baseline: START captures immediately after `vmrun rax` returns
  - current_behavior: 7 host-side instructions (stash r15, reload r15, push rax, lfence, rdtsc, shl, or, mov) run before START
  - remediation: capture the TSC closer to the VMRUN return and account for the pre-amble explicitly

- **First-exit tsc_offset discontinuity: offset jumps from 0 to ~-(interval+1000) in a single step on first intercepted instruction** - `driver/svm_vmcb.c:314`
  - observable_via: a probe that records TSC before and after its first intercepted instruction sees a step down of ~1000-1500 cyc
  - expected_baseline: smoothly monotonic TSC on InvariantTSC hardware
  - current_behavior: `RtlZeroMemory` zeros TSC_OFFSET at VMCB build; first exit snaps to large negative
  - remediation: seed TSC_OFFSET at VMCB build with a pre-handler-cost bias

- **g_timing_tail_cycles=200 undercounts post-END host work by ~100 cycles** - `driver/timing.c:106`
  - observable_via: RDTSC-CPUID-RDTSC mean elevated above bare-metal baseline by ~100 cycles over 10^6 iterations
  - expected_baseline: tail compensation covers all post-END work
  - current_behavior: 200-cycle constant; actual tail is ~290+ cycles minimum including FXRSTOR and loop-top vmsave/vmload
  - remediation: raise the constant or measure the tail per exit

- **PMU snapshot is captured ~500 cycles after VMEXIT microcode return; that host activity leaks into the shadow** - `driver/vmexit.c:108`
  - observable_via: guest `rdpmc(0)` bracketing an intercepted CPUID shows 10x inflation over bare metal
  - expected_baseline: PMU counts only guest work
  - current_behavior: pmu_snapshot_in runs after ~15 host instructions post-vmexit; PMC has already ticked through host code
  - remediation: snapshot the PMC in assembly adjacent to the START RDTSC capture

- **g_timing_tail_cycles = 200 under-counts post-END host work by ~100 cycles (duplicate confirmation path)** - `driver/timing.c:106`
  - observable_via: same as above; explicitly tracks the FXRSTOR64 + loop-top vmsave/vmload cost
  - expected_baseline: tail covers full post-END work
  - current_behavior: ~90 cycle undercount per exit
  - remediation: same

- **Wave 3 integrity VMMCALL and Wave 6 CHAMBER_HCALL_DUMP_CR3 blow past the documented per-core TSC regression budget** - `driver/timing.c:46`
  - observable_via: thread B pinned to CPU 1 records RDTSC regress by up to ~1e10 cycles while CPU 0 services the integrity hash or the pause-world dump
  - expected_baseline: per-core TSC regression stays within a small budget; master_plan tolerates "rare, under-load local regression"
  - current_behavior: whole hash / whole 2s pause lands in a single InterlockedAdd64
  - remediation: chunk the long VMMCALLs into sub-millisecond handler bursts, or clamp per-call accumulator delta

#### pause_world_sidechannels

- **Paused thread reports ThreadState=Running while accruing zero CPU time** - `driver/dump.c:179`
  - observable_via: `NtQueryInformationThread(ThreadBasicInformation=0)` ThreadState=Running paired with GetThreadTimes flat for 2 s
  - expected_baseline: a Running thread accrues time
  - current_behavior: DPC preempts without descheduling; state stays Running while kernel/user time are frozen
  - remediation: stub-fake either the thread state (transition to Transition/Waiting during pause), or the time counters

- **Target process post-resume RDTSC undershoots TickCount delta by cumulative handler cycles of non-paused CPUs** - `driver/timing.c:141`
  - observable_via: target reads (`rdtsc`, `GetTickCount`) tuples before and after the trigger; RDTSC/TickCount ratio collapses below TSC_freq/1000
  - expected_baseline: invariant-TSC ratio is stable within 1e-6 across any sampling window
  - current_behavior: during pause, other-CPU handlers add to the global accumulator; post-resume RDTSC pays for all of them
  - remediation: either exempt pause-window cycles from the accumulator, or back-fill the ratio at resume

- **Per-process KernelTime/UserTime via ProcessTimes also shows the stall** - `driver/dump.c:602`
  - observable_via: `GetProcessTimes` aggregate (kernel+user)/wall ratio over the trigger window is ~0 for a CPU-bound target
  - expected_baseline: ratio ~= running thread count
  - current_behavior: no compensating writes to KPROCESS or KTHREAD time counters at pause release
  - remediation: back-fill (or let threads enter Waiting state so they don't accrue)

- **KUSER_SHARED_DATA.TickCountQuad / InterruptTime advance normally during pause (no masking)** - `driver/dump.c:109`
  - observable_via: target thread reads `GetTickCount64` across the pause boundary and sees ~2000 ms jump
  - expected_baseline: wall clock advances or a time-source freezes consistently with thread cycle accounting
  - current_behavior: clock ISR at CLOCK_LEVEL preempts DPC at DISPATCH_LEVEL, so KeTickCount / TickCountQuad tick through
  - remediation: intercept the clock vector during pause (invasive) or compensate by rewinding TickCountQuad on resume

- **Originator self-pause on target-CR3 match (injected-thread dump scenario) loses 2 seconds on its own CPU** - `driver/dump.c:486`
  - observable_via: VMMCALL(CHAMBER_HCALL_DUMP_CR3) issued from a thread injected into the target process returns ~2 s late
  - expected_baseline: dump initiator never self-blocks for the full pause window
  - current_behavior: pause_broadcast_and_wait queues a DPC on the originator's own CPU; the DPC spins waiting for the thread that can't execute
  - remediation: skip the originator's own CPU in the DPC broadcast and clear completion for it directly

#### driver_hide_completeness

- **Section names scrambled to random A-Za-z strings - strong anomaly vs standard .text/INIT/PAGE/.rdata/.pdata/.reloc baseline** - `driver/stealth.c:164`
  - observable_via: section headers beyond the 0x400-byte zero zone retain random-alphabetic 8-byte names
  - expected_baseline: canonical PE section name set
  - current_behavior: all 8-byte names overwritten with A-Z/a-z bytes from `RtlRandomEx`
  - remediation: pick section names from the standard Microsoft set instead of fully random bytes

- **DriverSection NULL after stealth_apply is a diagnostic anomaly on a live DRIVER_OBJECT** - `driver/stealth.c:340`
  - observable_via: DRIVER_OBJECT walker finds a driver with DriverSection=NULL but non-NULL DeviceObject
  - expected_baseline: every live DRIVER_OBJECT has DriverSection pointing to its KLDR entry
  - current_behavior: `drv->DriverSection = NULL` unconditionally
  - remediation: either leave DriverSection pointing at the renamed KLDR entry or scrub the DRIVER_OBJECT off the directory

- **DriverName.Buffer NULL / Length 0 after stealth_apply is a diagnostic anomaly on a live DRIVER_OBJECT** - `driver/stealth.c:337`
  - observable_via: DRIVER_OBJECT with DriverName.Length=0 and non-NULL MajorFunction[IRP_MJ_DEVICE_CONTROL]
  - expected_baseline: every live DRIVER_OBJECT has a DriverName
  - current_behavior: name zeroed
  - remediation: replace with a plausible donor DriverName string

- **pool_tag[] seed-derivation is dead storage; also computed under a leading-byte allocator restriction never enforced at use sites** - `driver/identity.c:184`
  - observable_via: all allocations use the compile-time `CHAMBER_POOL_TAG='FsFl'` regardless of per-subsystem pool_tag[]
  - expected_baseline: per-subsystem tag randomization per CFG_V2 design
  - current_behavior: `POOLTAG(x)` macro ignores its argument; call sites never consult pool_tag[]
  - remediation: wire `POOLTAG()` to the per-subsystem pool_tag[] entries

- **\\Driver\\<svc> object-directory entry Name is not reachable from scrub_service_key_name** - `driver/the_chamber.c:489`
  - observable_via: `NtQueryDirectoryObject(\Driver)` returns the seed-derived service name even after scrub
  - expected_baseline: OBJECT_HEADER_NAME_INFO scrubbed alongside DriverExtension->ServiceKeyName
  - current_behavior: scrub only touches ServiceKeyName buffer
  - remediation: locate the OBJECT_HEADER_NAME_INFO at the DRIVER_OBJECT's negative offset and clear it too

- **Zero-PE-header prefix is itself a scanner-friendly signature** - `driver/stealth.c:207`
  - observable_via: image's first 0x400 bytes are all zero while KLDR still advertises BaseDllName=pci.sys with the full SizeOfImage
  - expected_baseline: valid PE prefix
  - current_behavior: `RtlZeroMemory(image_base, 0x400)` after section-name scramble
  - remediation: overwrite with a donor-image DOS/NT header prefix instead of zeros

- **KLDR SectionPointer / FullDllName backing path not re-pointed on rename** - `driver/stealth.c:291`
  - observable_via: `SectionPointer->FileObject->FileName` resolves to %ProgramFiles%\The Chamber\<seed>.sys
  - expected_baseline: SectionPointer references a donor path like %SystemRoot%\System32\drivers\pci.sys
  - current_behavior: SectionPointer is never rewritten
  - remediation: repoint to the donor's section (requires loader-structure manipulation) or move stealth off SectionPointer-walker assumptions

- **Registered callback addresses in PspCreateProcessNotifyRoutine resolve back to our (renamed) modules** - `driver/dump_trigger.c:171`
  - observable_via: VA-to-module resolution for registered notifies lands on the renamed (or un-renamed) image
  - expected_baseline: pci.sys does not register process-create notifies
  - current_behavior: `trigger_process_notify`, `cfp_create_notify`, `cfp_cm_callback`, `cfp_flt_pre_devctl/post_devctl` all anchor to our images
  - remediation: proxy the callbacks through a donor-code trampoline whose VA resolves to a plausible host module

- **integrity_status page is a guest-reachable 4 KiB big-pool fingerprint** - `driver/integrity.c:243`
  - observable_via: `NtQuerySystemInformation(SystemBigPoolInformation)` finds a 4096-byte NPP allocation under tag 'FsFl' whose call_count increments every 5 s
  - expected_baseline: no comparable 4 KiB NPP allocation pattern on stock Windows
  - current_behavior: `CHAMBER_INTEGRITY_STATUS` padded to 4096 bytes; HV increments fields without guest input
  - remediation: migrate the integrity page to an HV-only physical mapping that isn't NPT-identity-mapped

- **host_stack cluster: g_cpu_count × 16-KiB big-pool allocations, deterministic size** - `driver/svm_bringup.c:82`
  - observable_via: `SystemBigPoolInformation` filtered to tag 'FsFl' + size 16384 shows a cluster whose count = KeQueryActiveProcessorCount
  - expected_baseline: no Microsoft driver matches this pattern
  - current_behavior: `host_stack_size = 16*1024`, allocated once per CPU under POOLTAG("host_stack")='FsFl'
  - remediation: size-jitter the host stacks and per-subsystem tag randomization

- **per_cpu_ctx big-pool allocation ~12-16 KiB, deterministic size** - `driver/svm_bringup.c:131`
  - observable_via: 12-20 KiB NPP allocation at 'FsFl', one per boot
  - expected_baseline: no corresponding pattern on stock Windows
  - current_behavior: `sizeof(PER_CPU_CTX) * g_cpu_count` allocated under 'FsFl'
  - remediation: size-jitter + per-subsystem tag

- **CFG_BLOB_SIZE 632-byte REG_BINARY stored under Services\\<fp>\\Parameters\\CfgBlob leaks magic** - `driver/fingerprint/cfg_shared.c:142`
  - observable_via: registry walk of HKLM\SYSTEM\CurrentControlSet\Services\*\Parameters finds a 632-byte REG_BINARY whose first 4 bytes are 0x32474643
  - expected_baseline: no comparable pattern on stock Windows
  - current_behavior: launcher writes a fixed 632-byte blob with the 'CFG2' magic
  - remediation: jitter blob size and remove/rotate the magic prefix (or store the blob off-registry)

- **KLDR_DATA_TABLE_ENTRY truncated declaration - extended fields past HashLinks never considered** - `driver/stealth.c:54`
  - observable_via: CheckSum/TimeDateStamp/SectionPointer surface in SystemModuleInformation walkers
  - expected_baseline: scrubbing covers all build-current KLDR fields
  - current_behavior: struct stops at HashLinks; nothing beyond is zeroed/scrambled
  - remediation: expand the struct to the Win10/11 layout and extend scrub coverage

- **Launcher-chosen on-disk path %ProgramFiles%\\The Chamber\\<name>.sys bakes brand into every surface that returns a file path** - `launcher/ui/Services/CfgPatcher.cs:75`
  - observable_via: registry Services\<svc>\ImagePath + NtQueryVirtualMemory(MemoryMappedFilenameInformation) + KLDR SectionPointer
  - expected_baseline: a non-brand path, ideally per-install random
  - current_behavior: literal "The Chamber" in InstallRoot
  - remediation: pick a per-install random subdirectory under a benign system path

- **Fingerprint driver has no DriverName / DriverSection / ServiceKeyName scrub** - `driver/fingerprint/entry.c:177`
  - observable_via: \Driver walk finds fp driver with un-nulled DriverName, valid DriverSection, kernel-copy ServiceKeyName
  - expected_baseline: parity with HV driver's stealth_apply / scrub_service_key_name
  - current_behavior: fp driver DriverEntry does none of this
  - remediation: fold the same scrub pass into fp driver init

- **g_cpu_ctx and host_stack big-pool allocations have distinctive sizes under tag 'FsFl'** - `driver/svm_bringup.c:83`
  - observable_via: tag 'lFsF' with N==ncpu rows of 0x4000 bytes plus one row of ncpu*~800 bytes
  - expected_baseline: no Microsoft driver matches this pattern
  - current_behavior: deterministic sizes without jitter
  - remediation: size-jitter + per-subsystem tag

#### callback_enumerability

- **Cm callback altitude '331456.1.0.0' is not a Microsoft-allocated altitude** - `driver/fingerprint/cm_filter.c:340`
  - observable_via: known-good altitude allowlist used by EAC/Vanguard kernel modules
  - expected_baseline: a Microsoft-registered altitude in the 330000-339998 Security Enhancer range
  - current_behavior: static literal 331456.1.0.0, identical across reseeds
  - remediation: pick a registered-adjacent altitude or acquire a real Microsoft allocation

- **IC dispatch omits NtQueryInformationProcess / NtQueryInformationToken / NtQuerySystemEnvironmentValueEx entirely** - `driver/fingerprint/syscall_rewrite.c:330`
  - observable_via: sample issues any of these and sees real host values
  - expected_baseline: wave4_design surfaces 54/55/62 handled by IC
  - current_behavior: `cfp_ic_dispatch` switch has only 3 cases (NtQSI, NtDeviceIoControlFile, NtQueryVolumeInformationFile)
  - remediation: add dispatch cases for each missing syscall

- **CmRegisterCallbackEx registered with NULL Driver parameter - lifetime reference is missed** - `driver/fingerprint/cm_filter.c:341`
  - observable_via: callback Function pointer still resolves via RtlPcToFileHeader; secondary DoS surface via unload race
  - expected_baseline: pass real DriverObject to hold a reference
  - current_behavior: NULL in Driver slot
  - remediation: pass `Driver` into CmRegisterCallbackEx

- **CFP_MAX_PIDS spoof-list IOCTL exposure** - `driver/fingerprint/target_pid.c:174`
  - observable_via: admin/SYSTEM sample calls IOCTL_CFP_QUERY_LIST and reads the spoof list
  - expected_baseline: no analogous surface on bare metal
  - current_behavior: device-SDDL only gates admin+SYSTEM; the list is readable
  - remediation: either remove the query IOCTL or add launcher-authentication (e.g. shared secret from CFG_V2)

- **Hardcoded pool tag 'cFPC' identifies every allocation this driver makes** - `driver/fingerprint/cfg_shared.c:15`
  - observable_via: `NtQuerySystemInformation(SystemPoolTagInformation=22)` finds 'CPFc'
  - expected_baseline: unknown tag is a fingerprint
  - current_behavior: compile-time `#define CFP_TAG 'cFPC'`
  - remediation: source tag from CFG_V2.pool_tag[] like the rest of the design

- **TEB slots gs:[0x1480] and gs:[0x1488] carry non-zero shim state in spoofed processes** - `driver/fingerprint/ic_trampoline.asm:79`
  - observable_via: user-mode `__readgsqword(0x1480)` / `__readgsqword(0x1488)` return non-zero outside IC dispatch
  - expected_baseline: 0x1480-0x1500 region of TEB reads zero on clean Windows
  - current_behavior: shim prologue writes before every syscall; nothing clears the slots after IC return
  - remediation: zero the slots after IC return, or stash via a per-thread allocation referenced from a documented TLS slot

- **FLT_REGISTRATION ships without Altitude, so FltRegisterFilter silently fails and NDIS MAC rewrite is not actually online** - `driver/fingerprint/flt_filter.c:164`
  - observable_via: sample reads OID_802_3_PERMANENT_ADDRESS via \Device\Ndis and gets the real MAC; fltMC enumfilters lists no entry
  - expected_baseline: minifilter attaches via `Instances\DefaultInstance\Altitude` registry key
  - current_behavior: DriverLoader never provisions the Instances subkey; fp driver proceeds without the FLT filter
  - remediation: launcher writes the Instances\DefaultInstance\Altitude key before SCM start (or drop FLT entirely in favor of NDIS LWF)

- **Fingerprint driver's control device name "\\Device\\CFPControl" is a hard-coded Chamber-specific literal** - `driver/fingerprint/entry.c:154`
  - observable_via: object-namespace enumeration
  - expected_baseline: no sentinel string
  - current_behavior: hardcoded "\Device\CFPControl" + "\DosDevices\CFPControl" (same surface as showstopper; medium-tier facet is the name-string pattern itself, independent of the symlink)
  - remediation: random per-boot device name

### Low (34)

The 34 low/nit entries are as-reported from the find phase without per-finding verification; 13 are enumerated below and the remaining 21 are tracked in the find-phase output but omitted here for length. All share the common property that the mechanism is real but the signal is small (sub-50-cycle timing effects, off-by-one comments, or corner cases that affect <1% of seeds).

#### cpuid_consistency

- **Max basic leaf (CPUID 0x0 EAX) not raised to cover spoofed 0x15/0x16; fake leaves are "above the maximum"** - `driver/vmexit.c:265`
  - as-reported: sophisticated probes read CPUID(max+n) and expect the max-leaf echo; spoofed 0x15/0x16 at populated values above max=0x10 is internally inconsistent

- **CPUID 0x1F termination subleaves retain the full 32-bit x2APIC ID in EDX instead of the (optionally) final-level-only value AMD documents** - `driver/vmexit.c:214`
  - as-reported: low-impact tail-subleaf behavior corner case; AMD convention places x2APIC ID in EDX always

- **0x40000000..0x4FFFFFFF unconditional zero-fill does not match implementation-defined bare-metal Zen 4 behavior** - `driver/vmexit.c:312`
  - as-reported: real Zen 4 Raphael often echoes the max basic leaf; zero is detectable for a probe cross-checking against CPUID 1 ECX[31]=0

#### msr_consistency

- **EFER_WRITABLE_MASK mislabels bits 12 and 13, omits FFXSR (bit 14)** - `driver/vmexit.c:486`
  - as-reported: guest WRMSR of FFXSR=1 is silently cleared on round-trip; minor since Windows kernels rarely toggle FFXSR

- **handle_msr_identity_rewrite short-circuits HWCR and TSC_AUX regardless of the identity-spoof toggle (scope mismatch)** - `driver/vmexit.c:460`
  - as-reported: build-time pentest baseline capture (toggle off) still sees fake HWCR

- **tsc_aux_latched_valid flag is set but never read; initial RDMSR on a vCPU returns the seed-random latch** - `driver/identity.c:494`
  - as-reported: boot-start driver early RDMSR of TSC_AUX observes garbage upper bits; pre-HAL window

- **EFER_WRITABLE_MASK comment-vs-bit mapping is off by one; FFXSR (bit 14) is dropped silently, LMSLE comment on bit 12 collides with SVME** - `driver/vmexit.c:486`
  - as-reported: next audit will be bitten by the misleading comment even after a bit-position fix

#### timing_roundtrip

- **LFENCE serialization before RDTSC assumes DE_CFG (MSR 0xC0011029) bit 1 is set by the OS; no defensive enablement** - `driver/vmrun.asm:117`
  - as-reported: guest OS or policy clearing DE_CFG.bit1 leaks per-exit jitter

- **RDTSC START/END capture lacks post-RDTSC lfence; speculative execution between rdtsc and later vmcb-store adds per-iteration jitter** - `driver/vmrun.asm:118`
  - as-reported: ~15-cycle per-capture uncertainty; std-dev check marginal

- **InterlockedAdd64 in timing_update is on the host interval between END and next-VMRUN but contributes variable serialization cost not modeled in constants** - `driver/timing.c:131`
  - as-reported: concurrent multi-core probe sees variance change vs idle

#### pause_world_sidechannels

- **Originator's VAD-walk delay-loop sleep granularity leaks via sibling QPC sampling** - `driver/dump.c:519`
  - as-reported: timeBeginPeriod(1) + QPC sampling reveals 0.5-ms yield cadence during pause rendezvous

- **DPC IPI broadcast adds a correlated InterruptCount+DpcCount bump to every CPU per pause** - `driver/dump.c:492`
  - as-reported: cross-CPU synchronized single-event bump across all CPUs at dump time

#### driver_hide_completeness

- **Fingerprint IOCTL device-type nibble 0x8001 is driver-unique and not seed-derived** - `driver/fingerprint/target_pid.c:23`
  - as-reported: 0x8000 (HV) + 0x8001 (fp) device-type pair is a two-driver correlation signature

### Nit (0)

No nit-tier findings this wave.

## Scope coverage

The 12 scopes surveyed by the find phase, one-line summaries:

1. **cpuid_consistency** - cross-leaf agreement of vendor, family/model/stepping, APIC IDs, topology, cache descriptors, feature bits, and brand string for the spoofed Ryzen 7 7700X identity.
2. **msr_consistency** - architectural MSR coverage on AuthenticAMD: 0x8B microcode layout, TSC_AUX, HWCR, SMM range, paravirt ranges, unknown-MSR fault semantics.
3. **timing_roundtrip** - plausibility of the RDTSC-CPUID-RDTSC delta histogram (variance, per-leaf cost, per-core jitter) relative to bare-metal Zen 4.
4. **pause_world_sidechannels** - detectability of the 2-second targeted-DPC pause window via guest TSC, QPC, KUSER_SHARED_DATA, and per-thread cycle counters.
5. **driver_hide_completeness** - stealth of chamber_fingerprint.sys and the hypervisor driver: KLDR naming, PE scrub, section scramble, device/symlink naming.
6. **callback_enumerability** - ownership of PsSetCreateProcessNotifyRoutineEx / CmRegisterCallback / FltRegisterFilter targets resolving back to a sentinel driver.
7. **smbios_dmi_integrity** - DMI walker correctness over RawSMBIOSData, registry LastConfig coverage, and off-by-N errors in patch targeting.
8. **edid_validity** - VESA EDID 1.4 structural validity after serial/model splice and checksum.
9. **ci_signing_coverage** - coverage of NtQueryInformationProcess classes (esp. ProcessInstrumentationCallback / class 40) by the IC trampoline and driver visibility to SystemModuleInformation.
10. **cross_process_timing** - plausibility of per-CPU DpcTime/IdleTime counters from `SystemProcessorPerformanceInformation` across pause windows.
11. **hardware_sidechannels** - LBR virtualization, DBGCTL passthrough, PEBS and other hardware trace channels.
12. **interceptor_completeness** - end-to-end wiring of launcher -> IOCTL -> target-PID list -> CM/FLT/IC callbacks, including shim DLL injection and vmmcall dispatch coverage.

## Methodology

- **Find phase**: 12 scopes x 3 lenses (code-reread, exploit-trace, invariant-check) spawned 36 agents in parallel against `claude/sharp-ritchie-ku155z`. Raw findings were deduped by `(title, file, line)` to 387 unique candidates.
- **Verify phase, part 1**: severity-tiered batched verification over the 60 showstopper + 40 high candidates.
  - showstopper tier: 2-lens (code-reread + exploit-trace) across 60 candidates
  - high tier: 1-lens (exploit-trace) across 40 candidates
  - medium tier: 1-lens (code-reread) across 0 candidates in part 1
  - low + nit tiers: 0 candidates carried in as-reported without verification in part 1
- **Verify phase, part 2 (this extension)**: 1-lens batched refuter run over the remaining 161 high and 132 medium candidates; low+nit items were taken as-reported without per-finding verification.
  - high tier: 1-lens refuter across 161 candidates -> 156 confirmed, 5 refuted, 0 no-verdict. After `(title, file, line)` dedup against the 38 Part 1 highs (keeping the original wording on collisions), 12 unique-mechanism confirmations were appended to the High section.
  - medium tier: 1-lens refuter across 132 candidates -> 132 confirmed, 0 refuted, 0 no-verdict. All 132 are new (no Part 1 medium list to dedup against); 55 are enumerated below with their observable + mechanism rows.
  - low + nit tiers: 34 candidates taken as-reported; 13 are enumerated inline for representative coverage.
- **Outcome**: 157 CONFIRMED (52 showstopper + 50 high + 55 medium), 15 REFUTED (10 from part 1 + 5 from part 2), 34 low/nit as-reported. Each part 1 finding carries the verify vote ratio (`2/2` where two verifier lenses agreed, `1/1` where the single-lens verifier confirmed); part 2 findings carry a `1/1` ratio implicit in the section header.
