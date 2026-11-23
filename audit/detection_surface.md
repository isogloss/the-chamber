# THE_CHAMBER detection-surface audit

## Executive summary

THE_CHAMBER would not survive any serious probe. Three independent defects reduce the hypervisor to a self-documenting beacon:
(1) the MSR permission bitmap is allocated zero-filled and never populated, so no MSR intercept actually fires (svm_vmcb.c:34-37, svm_vmcb.c:146, svm_vmcb.c:152-155) -- the EFER / Hyper-V / VM_HSAVE_PA / VM_CR handlers in vmexit.c are dead code;
(2) timing_before_vmrun() is declared and defined but called from nowhere, so vmcb.ctl.tsc_offset is derived from an uninitialized vmrun_entry_tsc = 0 and walks unboundedly negative after every VMEXIT (timing.c:25-28, timing.c:37, vmexit.c:66) -- guest RDTSC visibly runs backwards;
(3) vmrun.asm uses r15 as the ctx pointer across guest execution, but AMD SVM does not save/restore host GPRs across VMRUN/VMEXIT, so a guest that touches r15 (every real guest does) causes the VMEXIT handler to corrupt arbitrary memory at [guest_r15 + 72] (vmrun.asm:17, vmrun.asm:34-46).
On top of that, VMMCALL is intercepted and answers RAX=1 with the version word 0x10000 (vmexit.c:165-168) -- a one-instruction presence probe. The driver, service, device object, symlink, and marker directory all use the literal string "THE_CHAMBER" (the_chamber.h:16-18, the_chamber.inx:37). Verdict: BROKEN.

## Measurement budget

Signal strengths with a probe running against this driver as it stands today.
Scale: HIGH = probe trivially distinguishes, MEDIUM = distinguishes with care, LOW = hard to tell, NONE = indistinguishable.

  - CPUID vendor leaves (0x40000000..)    : LOW (0x40000000..0x40000010 zeroed; 0x40000011..0x4FFFFFFF pass through)
  - CPUID leaf 1 ECX[31]                  : NONE (masked, vmexit.c:81-84)
  - EFER.SVME visibility                  : HIGH (handler written but never fires; MSRPM all-zero)
  - RDTSC VMEXIT latency                  : NONE (RDTSC not intercepted) but see next row
  - RDTSC absolute value / monotonicity   : HIGH (tsc_offset math broken, guest TSC walks backward)
  - SIDT/SGDT base disclosure             : LOW (mirrors host; no second IDT hosted)
  - MSR passthrough (STAR/LSTAR)          : LOW (all MSRs pass through natively; no synthetic values)
  - PsLoadedModuleList                    : LOW-for-string-scan / HIGH-for-Patch-Guard
  - DRIVER_OBJECT enum via NtQuery        : LOW via SystemModuleInformation, HIGH via ObDirectory
  - \Device dir enum                      : HIGH (\Device\THE_CHAMBER and \DosDevices\THE_CHAMBER present)
  - SCM service enumeration               : HIGH (service name literally "the_chamber")
  - Registry service key                  : HIGH (HKLM\...\Services\the_chamber)
  - Driver file on disk                   : HIGH (the_chamber.sys dropped in %12% by INF)
  - Process handle table                  : MEDIUM (any user-mode handle to \\.\THE_CHAMBER)
  - Windows event log (Service Control)   : HIGH (Service Control Manager events 7036/7045)
  - APERF/MPERF frequency skew            : LOW (pass through; no spoofing)
  - Cross-core shared-counter probe       : HIGH (combined with broken tsc_offset -- see gaps)
  - IOMMU / DMA remapping tells           : NONE (not touched)
  - PCI config space tells                : NONE (not touched)
  - Thermal / power MSRs                  : LOW (pass through)
  - IRET / interrupt-shadow exits         : NONE (not intercepted)
  - #DB single-step probe                 : NONE (not intercepted)
  - Patch Guard detection                 : HIGH (PsLoadedModuleList unlink + DriverName null)
  - VMMCALL presence probe (extra class)  : HIGH (handler returns 0x10000 for RAX=1)
  - String banner leakage                 : HIGH ("THE_CHAMBER:" appears in >15 DbgPrintEx calls)

## Per-class findings

### CPUID vendor leaves (0x40000000..)
- **Vector**: userland CPUID with EAX in 0x40000000..0x4FFFFFFF.
- **How it fires**: VMEXIT CPUID (vmexit.c:41) -> handle_cpuid (vmexit.c:73).
- **Our coverage**: vmexit.c:86-92 zeroes EAX/EBX/ECX/EDX for leaf 0x40000000..0x40000010.
- **Residual exposure**: Leaves 0x40000011..0x4FFFFFFF fall into the native __cpuidex path (vmexit.c:79). On bare metal the CPU reflects back the last-computed-leaf or garbage; on THE_CHAMBER the __cpuidex is executed on the host, so the guest sees whatever the host CPU returns for those out-of-range leaves. Detection suites such as pafish and the modern VMAware fork check 0x40000100 and 0x40000080 explicitly. Also, the comparator leaf 0 ("highest basic leaf") is not clamped -- genuine bare-metal returns basic-leaf vendor only; if a future update ever adds a synthetic max-leaf field, the mismatch leaks.
- **Suggested patch**: extend the zero band to the entire reserved range `if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF)`.

### CPUID leaf 1 ECX[31]
- **Vector**: userland CPUID(1).
- **How it fires**: VMEXIT CPUID -> handle_cpuid.
- **Our coverage**: vmexit.c:81-84 clears ECX bit 31.
- **Residual exposure**: None in isolation. However, CPUID(1) still passes through to the host for all other bits (vmexit.c:79), which is fine.
- **Suggested patch**: none.

### EFER.SVME visibility
- **Vector**: RDMSR 0xC0000080 from the guest.
- **How it fires**: should VMEXIT via vmcb->ctl.intercept_vec3 bit 28 (IVEC3_MSR) + MSRPM entry for 0xC0000080.
- **Our coverage**: vmexit.c:120-132 has a handler that masks SVME on read and forces it on write.
- **Residual exposure**: CRITICAL. The intercept vector enables MSR intercepts (svm_vmcb.c:146 `ctl->intercept_vec3 |= IVEC3_CPUID | IVEC3_MSR`), but the MSR permission map is allocated zero-filled and never populated (svm_vmcb.c:34-37 "Both are all-zero (no MSR/IO intercepts beyond the vector-3 blanket)", svm_vmcb.c:63-108 allocation only, svm_vmcb.c:152-155 attachment). AMD64 APM Vol 2 15.11: with IVEC3_MSR set, the MSRPM IS consulted, and bits that are zero DO NOT intercept. Therefore the EFER read handler never fires. RDMSR 0xC0000080 returns the real EFER with bit 12 set.
- **Suggested patch**: add a helper that sets the right bit in g_msrpm_va for a given MSR + direction. For EFER: offset 0 (range 0..1FFF has RDMSR bit at `msr*2` and WRMSR bit at `msr*2+1`), then for MSR 0xC0000080 -> section 2 at MSRPM offset 0x800 (range 0xC0000000..0xC0001FFF), bit index `((0xC0000080 - 0xC0000000)*2) = 0x100` for RDMSR and 0x101 for WRMSR. Set both. Repeat for 0x40000000..0x400000FF, 0xC0010117, 0xC0010114. Call from svm_init_bitmaps before the VMCB build broadcast.

### RDTSC VMEXIT latency / RDTSC absolute value and monotonicity
- **Vector**: RDTSC bracketing an intercepted instruction.
- **How it fires**: In the current driver RDTSC does NOT VMEXIT (IVEC3_RDTSC not set at svm_vmcb.c:146). So guest RDTSC runs natively but the hardware applies vmcb.ctl.tsc_offset.
- **Our coverage**: timing.c computes a signed offset from accumulated handler cycles.
- **Residual exposure**: CRITICAL. timing_before_vmrun (timing.c:25) is defined and declared (timing.h:19) but never called from any .c or .asm file I read. The expected call site around vmrun in vmrun.asm is absent. As a result, g_timing[i].vmrun_entry_tsc stays at its static-initialized zero. timing.c:37 computes `delta = now - 0 = now`. host_cycles_accumulated accumulates the current TSC at every exit (not the exit latency), then timing.c:45 sets `vmcb->ctl.tsc_offset = -accumulated`. After one CPUID exit at roughly 2e9 cycles into boot, guest RDTSC returns ~0; after a second exit it returns `host_tsc - 4e9` and the delta visibly goes backward. The clean-bit clearing at timing.c:48 then forces reload each VMRUN so guest TSC decreases as host TSC increases. A single back-to-back RDTSC pair with no intercepted instructions between them is enough to detect this (second value < first value).
- **Suggested patch**: call timing_before_vmrun as the very last host step before `vmrun rax` in vmrun.asm (easiest: make the C entry caller pass delta through the shadow GPR save). Also change the timing math to track delta only: `delta = now - vmrun_entry_tsc; accumulated += delta; vmcb->ctl.tsc_offset = -accumulated;`. Reset vmrun_entry_tsc before each VMRUN. For hardening add a small random jitter per exit (sub-handler cycles) so detectors looking for exact handler-cycle histograms see noise.

### SIDT/SGDT base disclosure
- **Vector**: userland SIDT/SGDT reads the pseudo-descriptor.
- **How it fires**: hardware; no intercept configured.
- **Our coverage**: implicit -- svm_vmcb.c:177-182 mirrors host IDTR/GDTR into vmcb.save, so hardware returns the real host IDT/GDT.
- **Residual exposure**: SIDT bases returned to the guest match the normal Windows kernel IDT, so this is not a direct hypervisor tell. However, pafish's "scoopyNG"-style Red Pill variant compares SIDT across multiple logical processors and can flag outliers; here all CPUs see the same host IDTR so no outlier is produced. LOW signal.
- **Suggested patch**: none required.

### MSR passthrough (STAR/LSTAR and friends)
- **Vector**: RDMSR of STAR/LSTAR/CSTAR/SFMASK/KernelGSBase etc.
- **How it fires**: should VMEXIT via MSRPM + IVEC3_MSR; in practice does not (see EFER row).
- **Our coverage**: vmexit.c:141-150 default branch passes through via __readmsr/__writemsr.
- **Residual exposure**: Since no MSR is actually intercepted, STAR/LSTAR are read directly and return normal host values. No synthetic replacement is attempted, so no inconsistency can be detected this way. LOW signal.
- **Suggested patch**: none for signal, but if MSRPM is fixed, make sure the default pass-through path in handle_msr survives for STAR/LSTAR so callers see consistent values.

### PsLoadedModuleList
- **Vector**: NtQuerySystemInformation(SystemModuleInformation), or a kernel walker that follows PsLoadedModuleList->Flink.
- **How it fires**: stealth.c:79-106 unlinks the KLDR_DATA_TABLE_ENTRY from InLoadOrderLinks, InMemoryOrderLinks, InInitializationOrderLinks.
- **Our coverage**: stealth.c:93-95 RemoveEntryList calls.
- **Residual exposure**: (a) Patch Guard scans PsLoadedModuleList structural invariants on Windows 10 1703+ and will bugcheck (CRITICAL_STRUCTURE_CORRUPTION, 0x109) with a sub-code pointing at this list; the stealth.c:6-8 comment acknowledges this. On Zen 4 / Win11 this is a matter of 10-60 minutes to BSOD. (b) The PE header and driver image remain in nonpaged pool at their original KLDR_DATA_TABLE_ENTRY->DllBase; a pool scanner that looks for "MZ" + "PE\0\0" + known section names ("INIT", ".text", "PAGE") finds us immediately. (c) The spin-lock protecting the unlink is a function-static `KSPIN_LOCK dummy` initialized per call (stealth.c:74, 126) -- it provides no mutual exclusion between apply and revert or against any other code path that walks the list.
- **Suggested patch**: either (i) stop unlinking and rely on a private `KeFindConfigurationEntry`-style bypass to answer the small number of real queries you want to hide from, or (ii) accept the Patch Guard risk by suppressing PG via a well-known hack (not recommended; adds more detection surface). At minimum, acquire PsLoadedModuleResource (not a static dummy spin-lock) and null out the entry's DllBase, SizeOfImage, and the BaseDllName/FullDllName buffers so a pool scan cannot anchor on them.

### DRIVER_OBJECT enum via NtQuery
- **Vector**: open \Driver\<name> directly, or ObReferenceObjectByName traversal.
- **How it fires**: after stealth_apply, DriverName is zeroed (stealth.c:114-116) and DriverSection is NULLed (stealth.c:117).
- **Our coverage**: stealth.c:112-117.
- **Residual exposure**: The DRIVER_OBJECT itself still lives in the object namespace at its original address. ObReferenceObjectByName with the driver's original name fails after the rename, but a probe that walks \Driver (the directory object) sees the entry still present -- only the DriverName held BY the DRIVER_OBJECT is zeroed, not the OBJECT_HEADER->NameInfo::Name that the directory uses. A probe that opens \Driver via ObOpenObjectByName + ZwQueryDirectoryObject enumerates us. See \Device row -- same story.
- **Suggested patch**: lift the object-header name through ObQueryNameString, locate the OBJECT_DIRECTORY_ENTRY, unhook it from the directory's hash bucket under ObpRootDirectoryMutex. This is risky and PG-adjacent; alternative is to never have created a named object in the first place (use filter-driver IoCreateDeviceSecure with FILE_DEVICE_SECURE_OPEN and a GUID-ish random name set at load).

### \Device dir enum
- **Vector**: ZwOpenDirectoryObject("\\Device") + ZwQueryDirectoryObject, or WinObj.
- **How it fires**: the_chamber.c:337 creates `\Device\THE_CHAMBER`; the_chamber.c:347 creates `\DosDevices\THE_CHAMBER`.
- **Our coverage**: UNCOVERED.
- **Residual exposure**: HIGH. Literal string "THE_CHAMBER" in a Windows namespace is an unambiguous beacon. Any userland tool with SE_DEBUG can enumerate \Device via NtOpenDirectoryObject. Many AVs query the \Device directory on scan.
- **Suggested patch**: randomize the device/symlink name at load (e.g., derive from SystemTime hash); or do not expose a user-mode handle at all and replace IOCTL with a hypercall via VMMCALL from an authenticated usermode agent.

### SCM service enumeration
- **Vector**: EnumServicesStatusEx(SERVICE_DRIVER).
- **How it fires**: INF SERVICE_KERNEL_DRIVER registration at the_chamber.inx:36-45. Service name literally "the_chamber" and DisplayName literally "THE_CHAMBER SVM Instrumentation Service".
- **Our coverage**: UNCOVERED.
- **Residual exposure**: HIGH. Any non-privileged probe can call EnumServicesStatus and see "the_chamber"; "SVM Instrumentation" in the DisplayName is an outright confession.
- **Suggested patch**: install via a benign-looking service name (e.g., mimicking an AMD platform driver: "AmdSvmUtil" has the problem that an actual AMD driver may conflict -- use a random GUID-shaped name per install). Replace DisplayName with something innocuous ("AMD Power Management Helper"). Do NOT keep "SVM" in any of the strings.

### Registry service key
- **Vector**: enumerate HKLM\SYSTEM\CurrentControlSet\Services, or EnumServicesStatus (same key).
- **How it fires**: INF-driven write to HKLM\...\Services\the_chamber.
- **Our coverage**: UNCOVERED.
- **Residual exposure**: HIGH, and persists across reboots. SERVICE_DEMAND_START (the_chamber.inx:43) means it is not autoloaded but the entry itself is visible.
- **Suggested patch**: same as SCM row. Additionally, zero the "ImagePath" value and the Description after service creation if that's compatible with your start model.

### Driver file on disk
- **Vector**: file-system enumeration of %SystemRoot%\System32\drivers, VirusTotal-style file submission.
- **How it fires**: the_chamber.inx:14-15 `DefaultDestDir = 12` which is %SystemRoot%\System32\drivers; the_chamber.inx:21 copies the_chamber.sys there.
- **Our coverage**: UNCOVERED.
- **Residual exposure**: HIGH. Filename "the_chamber.sys" plus "THE_CHAMBER:" string banner in DbgPrintEx (grep the PE for printable strings): dozens of copies of "THE_CHAMBER:" (the_chamber.c:141, 233, 256, 286, 299, etc.; svm_bringup.c:24, 30, 131, 144, 151, 191; svm_vmcb.c:211; vmexit.c:59, 191, 203). A single `strings the_chamber.sys | grep THE_CHAMBER` is a one-line signature.
- **Suggested patch**: (a) rename the installed binary (random name in %12% or load from a non-drivers path via a kernel-mode manual mapper); (b) strip the "THE_CHAMBER:" prefix from every DbgPrintEx, or route to a session-logger that never embeds a brand string; (c) PE-mangle on install so the section names differ from normal WDK output.

### Process handle table
- **Vector**: NtQuerySystemInformation(SystemHandleInformation) or SystemExtendedHandleInformation; filter by object type == File (Device).
- **How it fires**: once a user-mode controller opens \\.\THE_CHAMBER (via CreateFileW("\\\\.\\THE_CHAMBER", ...)), that handle appears in the global handle table.
- **Our coverage**: UNCOVERED (device is IRP-visible).
- **Residual exposure**: MEDIUM. The driver itself opens no user-mode handles; only the controller process does. But the device name is still "THE_CHAMBER" (see \Device row), so handle-table scanners chase the same string.
- **Suggested patch**: fix the device name first; then this problem goes away.

### Windows event log (Service Control)
- **Vector**: System event log, source "Service Control Manager", events 7036 (service state change), 7045 (new service installed), 7001.
- **How it fires**: SCM logs a 7045 when the_chamber.inx installs; a 7036 each time the service transitions running/stopped.
- **Our coverage**: UNCOVERED.
- **Residual exposure**: HIGH for forensic probes; MEDIUM for live detection. Also, every DbgPrintEx call goes to WPP / ETW kernel-logger consumers when enabled. No on-disk log but kernel debugger attach captures them.
- **Suggested patch**: install the service via a route that suppresses the event (there are legitimate ways using SCM privileges -- see kb article around EVENT_TRACE_FLAG_PROCESS_COUNTERS, but it is awkward). Easier: do not install as a persistent service; load manually via ZwLoadDriver from a userland agent that then unloads (no SCM 7045/7036). For debug prints, replace with a per-session guard (compile-time flag) or route through DbgPrintEx with DPFLTR_MASK that is normally disabled.

### APERF/MPERF frequency skew
- **Vector**: read MSR 0xE8 (MPERF) and 0xE7 (APERF) across a timed interval; compute ratio.
- **How it fires**: these are normal MSRs; pass through.
- **Our coverage**: UNCOVERED by design (not special-cased).
- **Residual exposure**: LOW. Without a valid tsc_offset the guest sees TSC drift, but APERF/MPERF are raw host counters that also advance during host handler cycles. The ratio APERF/MPERF should match the real duty cycle, which is what bare metal sees too. A narrow risk: when correlated with a RDTSC-based wall-clock measurement that has been scaled down by (broken) tsc_offset, an attacker sees `MPERF_delta > TSC_delta`, which is physically impossible (MPERF counts at the maximum non-turbo rate, TSC at the invariant rate; their deltas should be close). This is a tell derived from the tsc_offset bug.
- **Suggested patch**: fixes to the tsc_offset path (see RDTSC row) remove the tell. No MSR intercept is needed for APERF/MPERF.

### Cross-core shared-counter probe
- **Vector**: thread A spins on a shared memory counter + RDTSC; thread B triggers an intercepted instruction (CPUID or forced VMEXIT); compare.
- **How it fires**: intercept-time latency shows up as a gap in thread A's RDTSC relative to the memory counter.
- **Our coverage**: tsc_offset is supposed to hide this; it does not (see RDTSC row). Plus there is no scheduling of tsc_offset across cores -- each core's g_timing[i] accumulates independently, so the offsets diverge, and a cross-core RDTSC compare sees two different "clock speeds".
- **Residual exposure**: HIGH. Even after fixing the uninit-TSC bug, per-core tsc_offset drifts relative to other cores. On AMD Zen 4 the TSC is invariant across cores, so a cross-core RDTSC diff should be nearly zero; here it grows linearly with handler load per core.
- **Suggested patch**: distribute a single global accumulated_cycles that is OR-ed into each CPU's tsc_offset after each VMEXIT; or, better, migrate to a fixed per-VMEXIT penalty subtracted uniformly across all CPUs via a per-CPU IPI once the accumulated host cycles cross a threshold.

### IOMMU / DMA remapping tells
- **Vector**: read AMD-Vi capability registers via PCI config space (bus 0, device 0, function 2 per AMD IOMMU spec), or enumerate ACPI IVRS.
- **How it fires**: not touched by this driver.
- **Our coverage**: NONE (and nothing to cover -- we do not enable IOMMU).
- **Residual exposure**: NONE in isolation. Low enough to leave alone.
- **Suggested patch**: none.

### PCI config space tells
- **Vector**: enumerate PCI config via CF8/CFC or MCFG MMIO; look for virtio, VMware, QEMU vendor IDs, or odd hypervisor-shim devices.
- **How it fires**: not touched.
- **Our coverage**: NONE.
- **Residual exposure**: NONE. We are a thin HV; we leave real hardware visible.
- **Suggested patch**: none.

### Thermal / power MSRs
- **Vector**: read AMD MSR 0xC0010063 (PStateStatus), 0xC0010064+ (PStateDef), 0x1B1 (IA32_PACKAGE_THERM_STATUS), or SMN access through NB config.
- **How it fires**: pass-through (see EFER row).
- **Our coverage**: implicit pass-through.
- **Residual exposure**: LOW. These values reflect real host behavior.
- **Suggested patch**: none.

### IRET / interrupt-shadow exits
- **Vector**: perform IRET inside an interrupt-shadow window; probe for unexpected VMEXIT.
- **How it fires**: IVEC3_IRET not set in svm_vmcb.c:146.
- **Our coverage**: UNCOVERED by design (we do not need to intercept IRET).
- **Residual exposure**: NONE (no interception = no latency to observe).
- **Suggested patch**: none.

### #DB single-step probe
- **Vector**: set TF in RFLAGS, step across a CPUID; measure RDTSC inside the #DB handler.
- **How it fires**: #DB is not intercepted (intercept_exceptions = 0 after RtlZeroMemory in svm_vmcb.c:141 -- only CPUID and MSR bits are OR'd into vec3, exceptions untouched). So #DB fires inside the guest as normal.
- **Our coverage**: UNCOVERED, which is correct.
- **Residual exposure**: LOW. Without a VMEXIT on CPUID that is visible via RDTSC (we have CPUID intercepted and tsc_offset applied), a single-step across CPUID sees inflated time only if tsc_offset fails -- which it does. So this is really an amplifier for the RDTSC bug, not a separate class.
- **Suggested patch**: fix tsc_offset; this collapses to NONE.

### Patch Guard detection
- **Vector**: PG itself on Win10 1703+ / Win11.
- **How it fires**: PsLoadedModuleList structural scan + DRIVER_OBJECT integrity.
- **Our coverage**: stealth.c tries to minimize the damage, but the modifications themselves are the detection.
- **Residual exposure**: CRITICAL. BSOD 0x109 (CRITICAL_STRUCTURE_CORRUPTION) within tens of minutes.
- **Suggested patch**: do not unlink from PsLoadedModuleList; use a lighter approach -- change the KLDR_DATA_TABLE_ENTRY->BaseDllName.Buffer to a benign unicode string at a different address (a known-good module name like "ntfs.sys") rather than removing it. PG checks structure not content.

### VMMCALL presence probe (added class -- a primary gap the spec did not list)
- **Vector**: execute VMMCALL with RAX=1 inside __try/__except.
- **How it fires**: IVEC4_VMMCALL is set at svm_vmcb.c:150. handle_vmmcall (vmexit.c:160-180) returns `vmcb->save.rax = THE_CHAMBER_VERSION` (0x00010000) for RAX=1.
- **Our coverage**: this IS the leak.
- **Residual exposure**: CRITICAL. On bare metal, VMMCALL from CPL=0 generates #UD (or on some AMD parts, an INVALID_OPCODE depending on EFER.SVME visibility to decoder). Here it returns a cooperative version word -- a one-instruction unambiguous positive.
- **Suggested patch**: inject #UD into the guest instead of silently answering. Set up `vmcb->ctl.event_inject = 0x80000006` (vector 6 = #UD, type 3 = exception, valid bit set) and do NOT advance RIP; let the guest handler run. If a hypercall channel is required for a trusted controller, gate it on a per-session nonce passed in a non-RAX register (e.g., require RDX == (secret XOR RSP-bits) before answering, else inject #UD).

### String banner leakage (added class)
- **Vector**: `strings the_chamber.sys | grep -i chamber`.
- **How it fires**: 20+ literal "THE_CHAMBER:" prefixes embedded by DbgPrintEx. Each is a stable, searchable byte sequence in the .rdata section.
- **Our coverage**: UNCOVERED.
- **Residual exposure**: HIGH for YARA / signature-based scanning.
- **Suggested patch**: wrap DbgPrintEx in a macro `CHAMBER_LOG(...)` that is `#define`d away in release builds; strip all prefix strings on release. Also remove the "the_chamber" filename references from the pool-tag text ('ChTH' at the_chamber.h:15 reads backwards as "THCh" and is specific -- change to something generic like 'MsAl').

## Prioritized gap list

Ranked by (signal strength) * (probability a real suite probes it). Higher number = more urgent.

1. **MSR intercepts dead code (MSRPM all zero while IVEC3_MSR set).** HIGH signal * CERTAIN probe. svm_vmcb.c:30-37, 146, 152-155; vmexit.c:106-154. The entire MSR cluster handler is never executed. EFER.SVME directly visible, Hyper-V MSR range not hidden, VM_HSAVE_PA readable. Fix: populate MSRPM at init for EFER (0xC0000080), Hyper-V range (0x40000000..0x400000FF), VM_HSAVE_PA (0xC0010117), VM_CR (0xC0010114), both RDMSR and WRMSR bits.

2. **TSC offset math uses uninitialized vmrun_entry_tsc = 0.** HIGH signal * CERTAIN probe. timing.c:25-28 (defined), timing.h:19 (declared), vmrun.asm (NEVER called). After any VMEXIT the guest RDTSC visibly runs backward. Fix: call timing_before_vmrun() right before `vmrun rax` in the asm, and change delta math to `delta = now - entry` after accumulated starts from 0.

3. **VMMCALL answers the presence probe.** HIGH signal * COMMON probe (pafish-category tools test it). vmexit.c:160-180. Fix: inject #UD unless an authenticated nonce is presented; strip the version word.

4. **r15 as cross-VMRUN ctx pointer in vmrun.asm.** This is a correctness bug, not a detection vector per se, but it causes instability which is in itself detectable. vmrun.asm:17, 34-46. Fix: at VMEXIT time, recover ctx by reading `[host_rsp - K]` where K was pre-pushed, or via a per-CPU `__readgsqword` trampoline. KVM-AMD and most thin HVs push a self-pointer onto the host stack before `vmrun` and pop it on exit.

5. **Patch Guard will bugcheck on the PsLoadedModuleList unlink.** HIGH * CERTAIN on Win11. stealth.c:93-95. Fix: do not unlink; instead rename BaseDllName in place to a known-good string and leave the list intact.

6. **"THE_CHAMBER" literal in \Device, \DosDevices, service, registry key, filename.** HIGH * CERTAIN. the_chamber.h:16-18, the_chamber.inx:37-50. Fix: randomize names at install time.

7. **DbgPrintEx banner string "THE_CHAMBER:" x20+ embedded in the .rdata.** HIGH * CERTAIN for static scans. the_chamber.c:141, 233, 256, 286, 299; svm_bringup.c:24, 30, 131, 144, 151, 191; svm_vmcb.c:211; vmexit.c:59, 191, 203. Fix: compile-out in release; replace prefix with a generic token or nothing.

8. **Crash marker directory on disk.** MEDIUM * COMMON. the_chamber.h:18 `\??\C:\THE_CHAMBER\last_session.marker`. The directory itself is a branded path. Fix: move to `%TEMP%\ms-amd-svm.marker` or similar.

9. **Service installed as persistent SCM entry with "SVM Instrumentation" description.** HIGH * CERTAIN for forensic review. the_chamber.inx:40-41. Fix: generic DisplayName; or non-persistent manual load/unload via ZwLoadDriver from a userland agent.

10. **CPUID vendor leaves 0x40000011..0x4FFFFFFF uncovered.** MEDIUM * MEDIUM. vmexit.c:86. Fix: widen the zero band to 0x4FFFFFFF.

## Verdict

**BROKEN.**

- Static correctness: MSR interception is wired at the VMCB intercept bit but never completed in the MSR permission map (svm_vmcb.c:30-37, 146, 152-155). The handler at vmexit.c:106-154 is dead code for the MSRs the design claims to cover.
- Timing: timing_before_vmrun is declared (timing.h:19), defined (timing.c:25-28), and not called by any .c or .asm file in the tree. vmcb.ctl.tsc_offset is derived from zero-initialized state and causes guest RDTSC to visibly regress after every VMEXIT (timing.c:36-45). This is a one-RDTSC-pair live tell.
- GPR save/restore: vmrun.asm:17 sets r15 = ctx on entry and then at vmrun.asm:34-46 uses r15 as the ctx base inside the VMEXIT bottom-half. AMD SVM does not save/restore host GPRs across VMRUN; guest r15 at the moment of VMEXIT is loaded into the host register file on exit. If the guest ever writes r15 (every serious guest will), the save stores go to arbitrary memory. This will crash the machine quickly under load.
- Even if all three bugs were fixed, the detection surface above the "driver file / service / \Device / string banner / VMMCALL version word" layer is wide open and would trip pafish/VMAware/InviZzzible without additional work.

Would not pass a current detection suite. Would not survive Patch Guard. Would not run reliably long enough for a detection suite to finish.

Save time by fixing MSRPM and r15 first; those are the two issues that keep the driver from being evaluable at all.
