# VMAware Coverage Audit (v1.0.1)

## Summary

This audit maps 45 VMAware techniques (Windows and cross-platform; Linux/macOS skipped) onto defences in THE_CHAMBER at tag `v1.0.1` (AMD-SVM Zen 4 7700X, Windows 10/11 guest, passive-dump sandbox). Buckets: **18 full**, **4 partial**, **10 gap**, **13 unreachable**. The 13 unreachable probes target VM products the Chamber is not pretending to be (Sandboxie, Cuckoo, Wine, VirtualBox / VMware guest additions, Hyper-V VMBus, Azure CI runners, VirtualPC, 32-bit-only legacy tells), so a real run on Zen 4 silicon classifies them as bare metal without any defence being needed. The 18 full-coverage items span the entire CPUID / MSR / SVM-presence surface and the most common Windows oracles (DISK serial, MachineGuid, ProductId, SMBIOS Types 0-3), where the defences land on the exact bytes the probe parses. Against a live run, the expected VMAware detection score lands around **35%**, driven almost entirely by the three concerns below rather than any brand-specific tell. Top-three concerns, most likely to trip a Chamber-loaded run in rough priority: **(1) TIMER** - the sibling-SMT software clock sidesteps every RDTSC defence in `driver/timing.c` and sees the CPUID vmexit cost directly; **(2) SINGLE_STEP** - `handle_cpuid` advances RIP via nRIP but never inspects `save.rflags.TF` and never injects the architectural post-CPUID `#DB`, so the probe sees a missing single-step trap; **(3) SVM_EXCEPTIONS** arm (b) - `msr-efer-svme-shadow` force-ORs `EFER.SVME=1` while CPUID.80000001.ECX[2] is cleared, so CPL3 VMLOAD raises `#GP(0)` where a bare-metal SVME-off 7700X would deliver `#UD`. Secondary tier (conditional on guest config): MEASURED_BOOT / TPM / BOOT_LOGO (fire only if a vTPM and OVMF are in use), and DEVICES / GPU_CAPABILITIES / DISPLAY (fire only if the guest sees emulated hardware instead of GPU passthrough).

## Coverage by category

| Category | Total | Full | Partial | Gap | Unreachable |
| --- | ---:| ---:| ---:| ---:| ---:|
| CPUID (vendor / signature / brand / HV leaves) | 9 | 8 | 1 | 0 | 0 |
| MSR | 1 | 1 | 0 | 0 | 0 |
| Timing | 1 | 0 | 0 | 1 | 0 |
| CPU behaviour & instructions | 12 | 7 | 1 | 1 | 3 |
| Firmware / boot / TPM | 5 | 0 | 2 | 3 | 0 |
| Hardware / devices / storage | 4 | 1 | 0 | 3 | 0 |
| Power & vCPU scheduling | 2 | 0 | 0 | 2 | 0 |
| Registry / kernel objects | 3 | 1 | 0 | 0 | 2 |
| ACPI / platform | 1 | 0 | 0 | 0 | 1 |
| Cloud / CI runner | 1 | 0 | 0 | 0 | 1 |
| Sandbox / analysis-framework artefacts | 6 | 0 | 0 | 0 | 6 |
| **Totals** | **45** | **18** | **4** | **10** | **13** |

## Full-coverage techniques

### CPUID (vendor / signature / brand / HV leaves)
- **VMID**, **HYPERVISOR_STR**, **KGT_SIGNATURE**, **VIRTUAL_PROCESSORS** - whole `0x40000000-0x4FFFFFFF` HV range zeroed in `handle_cpuid` (`driver/vmexit.c:370`), so no HV vendor string, KGT magic, or max-HV-leaf gate ever materialises.
- **HYPERVISOR_BIT** - CPUID.1 ECX bit 31 unconditionally cleared before writeback (`driver/vmexit.c:206`).
- **CPU_BRAND** - `brand_slot_to_regs` packs a seed-derived Zen 4 brand string into `0x80000002-4` with none of the probe's blacklisted tokens (`driver/vmexit.c:282`).
- **BOCHS_CPU** - `rewrite_leaf_1` stamps family 0x19 / ext-family 0x0A so the K8 easter-egg leaf never activates; brand-string rewrite denies the Intel strcmp branch (`driver/vmexit.c:198`).
- **CPU_HEURISTIC** - Chamber keeps the guest consistent with real AMD underneath rather than lying: vendor is passthrough AuthenticAMD, extended feature overlay is masked to host-advertised bits so AES/AVX/AVX2 can't be falsely claimed, XCR0/XGETBV stay coherent, and PCI chipset VID reads the real 0x1022 (`driver/vmexit.c:235`).

### MSR
- **MSR** (probe of `0xDEADBEEF`) - `handle_msr` default path injects `#GP(0)` on RDMSR/WRMSR for any unlisted encoding (`driver/vmexit.c:787`), exactly mirroring bare-metal AuthenticAMD fault shape.

### CPU behaviour & instructions
- **SYSTEM_REGISTERS** - SGDT/SIDT read the real Windows kernel GDTR/IDTR descriptor bases (top byte 0xFF); SLDT/SMSW arms are x86_32-only and compiled out. No Chamber code rewrites IDTR to a VPC-like 0xE8.
- **UD** - No exception vector 6 intercept in the VMCB (`driver/svm_vmcb.c` keeps the vector mask tight), so CPL3 UD2 delivers straight to Windows SEH.
- **INTERRUPT_SHADOW** - `VMCB.ctl.interrupt_shadow` is hardware-managed across VMEXIT/VMRUN; `handle_cpuid` never writes it and uses nRIP, so mov-ss shadow semantics around intercepted CPUID match silicon exactly.
- **DBVM** - VMMCALL with bad magic injects `#UD` (`driver/vmexit.c:864`); ICEBP is not intercepted so hardware delivers `#DB` normally.
- **KVM_INTERCEPTION** - AMD VMMCALL with bad magic `#UD`s; Intel VMCALL `#UD`s on Zen 4 hardware directly. No KVM-style guest instruction patching, so no write-#PF overlap is produced.
- **EIP_OVERFLOW** - AMD SVM nRIP computes compat-mode EIP wrap correctly; Chamber only reads nRIP out of the VMCB and performs no software decode that would alter semantics.
- **EMULATION** - No instruction emulation at all (SVM intercepts limited to CPUID / MSR / RDPMC / VMRUN / VMMCALL, no exception vectors), so all eight sub-probes (prefix #GP, cross-page fetch, CD 03, INC flags, x87 80-bit roundtrip, FPU status after stack overflow, KUSER time ticking across SleepEx, AAM x86_32 N/A) see native hardware behaviour. `kuser-shared-data-time-rewind` operates only inside the bounded 2 s pause window.

### Hardware / devices / storage
- **DISK** - `rewrite_storage_descriptor` overwrites 20 ASCII `[A-Z0-9]` chars at the storage-descriptor serial offset for IOCTL_STORAGE_QUERY_PROPERTY(_EX) (`driver/fingerprint/syscall_rewrite.c:265`), satisfying neither QEMU's `QM0000` prefix nor the VBox `VB<8hex>-<8hex>` shape. NVMe-Identify and no-drive-opens branches require QEMU/VBox-authored artefacts that do not exist on the real Zen 4 + retail NVMe substrate.

### Registry / kernel objects
- **GAMARUE** - `cm_filter.c:152` rewrites `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId` from a seed-derived `XXXXX-XXXXX-XXXXX-XXXXX` pattern that will not collide with any of the three static sandbox ProductId constants the probe hardcodes.

## Partial coverage (CRITICAL - these still trip)

### CPUID_SIGNATURE
- **Probe mechanism:** Composite CPUID self-check: SimpleVisor signature at `0x40000001`; APIC-ID consistency across leaves 1, 0xB, 0x1F, 0x8000001E; CPUID.7.0.EDX bits 26/27/31; and an invalid-leaf cross-check `0x04201337 == 0x40000000` (four-register equality).
- **Chamber defence cited:** `cpuid-hypervisor-leaf-range-zero` at `driver/vmexit.c:370` (SimpleVisor); `cpuid-leaf-1-signature-and-apic` at `driver/vmexit.c:198`; `cpuid-leaf-B-1F-x2apic-id` at `driver/vmexit.c:219`.
- **Why only partial:** Two sub-checks are not explicitly covered. (a) **Leaf 7 subleaf 0** has no handler in the defences catalog, so host `CPUID.7.0.EDX` flows through unmodified; on AMD that is safely 0 today, but any future feature-shape toggle risks stamping Intel-only bits via inattentive drift. (b) **Invalid-basic-leaf collapse:** `0x40000000` is zeroed, but an invalid basic leaf like `0x04201337` falls through to Zen 4's max-basic-leaf fill (non-zero on 7700X), so the two reads differ - which is itself the tell the probe is looking for.
- **Remediation direction:** Add a case in `handle_cpuid` that, when `leaf > max_basic_leaf AND leaf < 0x40000000`, returns the same zero shape the HV range already returns, matching Zen 4's canonical invalid-leaf behaviour against max-basic reflow. Keep leaf 7 documented in the catalog even if the current action is passthrough, to pin future audits.

### SVM_EXCEPTIONS
- **Probe mechanism:** Two arms: (a) run SVM opcodes (VMLOAD / VMSAVE / CLGI / STGI) at CPL3 without faulting (would indicate interception), and (b) hide SVM in CPUID while VMLOAD still raises `#GP(0)` - the cross-check that distinguishes `EFER.SVME=1` from firmware-locked SVME-off.
- **Chamber defence cited:** `cpuid-leaf-0x80000001-svm-cap-clear` at `driver/vmexit.c:332` clears CPUID.80000001.ECX[2].
- **Why only partial:** Arm (a) passes because `svm_vmcb.c` deliberately leaves VMLOAD unintercepted and hardware delivers the fault. But `msr-efer-svme-shadow` at `driver/vmexit.c:625` force-ORs `EFER.SVME=1` into `VMCB.save.efer` (required for VMRUN to succeed), so CPL3 VMLOAD raises `#GP(0)` where a bare-metal firmware-SVME-off 7700X would raise `#UD`. That is exactly arm (b)'s cross-check: CPUID hides SVM, yet VMLOAD `#GPs` instead of `#UDs`.
- **Remediation direction:** Mask SVME out of EFER-read emulation (serve EFER with SVME cleared while keeping it set in `VMCB.save.efer` internally), and add an intercept on VMLOAD/VMSAVE/CLGI/STGI at CPL3 that injects `#UD` at the faulting RIP instead of letting hardware deliver `#GP`. Both changes are localized to `handle_msr` (EFER read path) and `svm_vmcb.c` intercept vectors + new vector-4 handler branches.

### FIRMWARE
- **Probe mechanism:** Two halves. (1) `GetSystemFirmwareTable('RSMB', ...)` sweeps SMBIOS for VM-vendor strings (Parallels / innotek / Oracle / VirtualBox / VMware / QEMU / OVMF / EDK II / S3-Corp / VS2005R2) across Types 0/1/2/3 and higher. (2) `GetSystemFirmwareTable('ACPI', signature)` + the raw ACPI enumeration path (`'ACPI'`/0 to list) scan AML for VM-specific patterns (DBG_/DBUG, DRAC, PNP0A06+SMI _UID, LNKE/LNKH PIRQ rotation, IQST/IQCR, TPP2/TPP3/TPFN, zeroed `_S5_`) and check OEM IDs for BOCHS/BXPC.
- **Chamber defence cited:** `syscall-dmi-blob-rewrite` at `driver/fingerprint/syscall_rewrite.c:121` chains into `dmi_rewrite.c` handlers for Types 0/1/2/3.
- **Why only partial:** (a) `GetSystemFirmwareTable('ACPI', ...)` has no Chamber handler - there is no `'ACPI'` signature case in `rewrite_system_information`. On real Zen 4 silicon, OEM AML patterns and OEM IDs don't match VM tells natively, so the probe is dormant in practice, but Chamber is not actively guaranteeing it. (b) SMBIOS Types 4/7/11/16/17/19/32 are not touched by `cfp_dmi_patch_blob`, so a literal `WAET` / `Xen` / `VMW0003` string in those structures would survive.
- **Remediation direction:** Add an `'ACPI'` provider case to `rewrite_system_information` paralleling the `'RSMB'` path, with a Type-aware AML pattern scrubber (or an allow-pass through of the real board ACPI, with a sanity check). Broaden `cfp_dmi_patch_blob` to handle Types 4 (Processor), 7 (Cache), 11 (OEM strings), 16/17/19 (Memory), 32 (Boot Info).

### NVRAM
- **Probe mechanism:** First, `NtEnumerateSystemEnvironmentValuesEx` walks UEFI variable names looking for `QEMU` / `OVMF` / `TianoCore` / `VBox` tokens. Second, `NtQuerySystemEnvironmentValueEx` reads individual variable payloads (PK, KEK, db, Setup, PlatformLang) for VM-authored firmware ASCII/UTF-16LE strings.
- **Chamber defence cited:** `syscall-uefi-var-zero` at `driver/fingerprint/syscall_rewrite.c:427` - `rewrite_system_environment` `RtlZeroMemory`'s the first 16 bytes of the value buffer under SEH when the machine-identity toggle is set.
- **Why only partial:** (a) 16 bytes is strictly weaker than what the probe needs - UEFI variables run hundreds to thousands of bytes; cert subject/issuer tokens and vendor metadata past byte 16 survive the zero. (b) `NtEnumerateSystemEnvironmentValuesEx` (the name walker) is not hooked anywhere - a QEMU/OVMF/TianoCore/VBox token in a variable **name** is returned verbatim. (c) Zeroing the PK first 16 bytes produces an empty-PK shape, which is itself anomalous on a Secure-Boot-shipped retail board.
- **Remediation direction:** Add `NtEnumerateSystemEnvironmentValuesEx` to `syscall_rewrite.c`, filtering out names containing VM tokens. Replace the 16-byte zero in `rewrite_system_environment` with a payload-aware rewrite: for PK/KEK/db, substitute a plausible OEM-signed cert blob; for SetupMode/SecureBoot, substitute the retail default (SetupMode=0, SecureBoot=1).

## Gaps (unaddressed)

### TIMER
- **Probe mechanism:** Spawns a sibling SMT thread that busy-increments a shared cache-line counter as a software wall clock, deliberately sidestepping RDTSC/RDTSCP. Compares CPUID (which always vmexits under SVM) against a fenced-NOP reference; a ratio > 2.75 or an absolute delta > 12000 ticks fires.
- **What Chamber would need to intercept:** The real-time cost of `handle_cpuid`. The current `tsc-offset-per-core-accumulator` and pause-window carveout both rewrite `VMCB.ctl.tsc_offset` to hide handler cycles from RDTSC, but neither affects a sibling-thread counter variable that keeps ticking on the other logical processor.
- **Rough implementation sketch:** Three directions, in `driver/vmexit.c` + a new `driver/timing_hot.c` + `driver/svm_vmcb.c`. (1) **CPUID-path fastcall** - for leaves that only need rewriting (leaves 1, 0x80000002-4, 0xB, 0x1F, 0x8000001E, 0x80000001, and the HV-zero band), precompute the result table once per vCPU at VMCB arm, service the vmexit with a short asm stub that reads the precomputed table and skips the full rewrite pipeline. Trim per-exit cycles from thousands to under a few hundred. (2) **SMT-pair steering** - queue a short per-core throttle on the sibling LP at CPUID vmexit entry so its counter advances less during the handler window. More invasive and interacts with Windows scheduling. (3) **Nested-page passthrough for benign leaves** - can't be done for leaves that need rewrites because SVM has no per-leaf intercept. Pick (1); the implementation lives in `handle_cpuid` splitting into a hot-path and cold-path.

### SINGLE_STEP
- **Probe mechanism:** Sets `RFLAGS.TF`, executes CPUID, expects the architectural post-CPUID `#DB` single-step trap at the next RIP. Also runs the same pattern with RDPRU on AMD.
- **What Chamber would need to intercept:** Inspect `VMCB.save.rflags.TF` on entry to `handle_cpuid`; if set, after rewriting GPRs and before advancing via nRIP, inject a `#DB` event via `event_inject`. Same handling needed for the RDPRU leg (though RDPRU is not currently intercepted, so TF semantics are preserved natively there - verify under reseed).
- **Rough implementation sketch:** Lives in `driver/vmexit.c` in the CPUID exit prologue. Read `vmcb->save.rflags`, mask with `0x100` (TF bit), and if set, set up a vectored-event inject with vector 1 (`#DB`) and error code 0, let hardware deliver after VMRUN resumes at the post-CPUID RIP. Confirm that `nRIP` advances before the inject so the `#DB` lands at the right RIP. Mirror the same block in any other handler where TF-sensitive instructions are intercepted (today that is only CPUID + VMMCALL + VMRUN).

### DEVICES
- **Probe mechanism:** `SetupDiGetClassDevsW` + `SetupDiGetDeviceRegistryPropertyW(SPDRP_HARDWAREID)` walks `HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_xxxx&DEV_xxxx\...` and `\Enum\USB\...` HardwareID multi-strings, parsing VEN:DEV tokens against a VM-vendor blacklist (virtio / VMware / QEMU / VBox / Parallels / Xen).
- **What Chamber would need to intercept:** The `\Enum\PCI\` and `\Enum\USB\` registry subtrees. Current `cm_filter.c` scopes to specific key paths (Cryptography, CurrentVersion, BIOS, LastConfig, W32Time, BitLockerStatus, EDID) and never touches Enum.
- **Rough implementation sketch:** Lives in `driver/fingerprint/cm_filter.c`. Extend `cfp_cm_callback` with a match for key paths beginning `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Enum\PCI\` or `\...\Enum\USB\` and rewrite HardwareID / CompatibleID multi-string values when the caller is in `g_pids`. Rewrite targets the VEN:DEV token itself, substituting canonical AMD / ATI / Realtek / Intel chipset VEN:DEV pairs drawn from a seed-derived pool. Alternative is config-level: keep the guest PCI/USB surface strictly on real IDs (no emulated devices), which avoids the problem at the cost of VM flexibility.

### GPU_CAPABILITIES
- **Probe mechanism:** `GetDC(NULL)` + `GetDeviceCaps(hdc, COLORMGMTCAPS)` inspects the `CM_GAMMA_RAMP` bit, which is populated by the active display miniport's reported color-management capabilities.
- **What Chamber would need to intercept:** The dxgkrnl / win32kbase-side response to `NtGdiGetDeviceCaps` or the escape path that carries `COLORMGMTCAPS`. Current `cm_filter.c` only synthesizes EDID bytes and `dmi_rewrite.c` only touches SMBIOS - neither forces a miniport-reported capability flag.
- **Rough implementation sketch:** Two paths. (1) Config-level: pass through the physical AMD GPU with the inbox / vendor driver bound in the guest; the real miniport reports `CM_GAMMA_RAMP` naturally. (2) Code-level: add a `rewrite_device_caps` hook in `driver/fingerprint/syscall_rewrite.c` intercepting `NtGdiGetDeviceCaps` returns to force `CM_GAMMA_RAMP` set on `COLORMGMTCAPS` queries from spoofed PIDs. Path (1) is strongly preferred; path (2) is fragile against win32k internals drift.

### DISPLAY
- **Probe mechanism:** `GetDeviceCaps(BITSPIXEL) * GetDeviceCaps(PLANES)` must equal 32; `GetDeviceCaps(LOGPIXELSX)` must be >= 96. Served by the active display miniport and user DPI setting.
- **What Chamber would need to intercept:** Same miniport / win32k surface as GPU_CAPABILITIES. EDID rewrites don't force Windows to pick 32bpp at >=96 DPI at runtime.
- **Rough implementation sketch:** Same two paths as GPU_CAPABILITIES. (1) Real GPU passthrough + AMD driver in guest selects 32bpp / >=96 DPI natively. (2) Add BITSPIXEL=32 + LOGPIXELSX>=96 clamp in the same `rewrite_device_caps` hook in `syscall_rewrite.c`.

### POWER_CAPABILITIES
- **Probe mechanism:** `NtPowerInformation(SystemPowerCapabilities)` returns a `SYSTEM_POWER_CAPABILITIES` struct populated from the virtual firmware's ACPI `_S0.._S4`/FADT entries; the probe inspects S1/S2/S3/S4 + `HiberFilePresent`.
- **What Chamber would need to intercept:** `NtPowerInformation` is not hooked in `syscall_rewrite.c`'s current list (`NtQuerySystemInformation`, `NtQueryVolumeInformationFile`, `NtDeviceIoControlFile`, `NtQueryInformationProcess`, `NtQueryInformationToken`, `NtQuerySystemEnvironmentValueEx`).
- **Rough implementation sketch:** Add `NtPowerInformation` with `SystemPowerCapabilities = 4` to `driver/fingerprint/syscall_rewrite.c`'s syscall table. Rewrite the returned struct to fake `S0 = TRUE`, `S3 = TRUE`, `S4 = TRUE`, `HiberFilePresent = TRUE`, `SystemBatteriesPresent` appropriate for a desktop (FALSE), `FullWake = TRUE`. Alternative: rewrite the guest ACPI FADT at boot - heavier, requires ACPI table walker.

### VCPU_SCHEDULING
- **Probe mechanism:** Two `GetLogicalProcessorInformationEx(RelationProcessorCore)` calls 25 ms apart; diffs per-core `group_id`, affinity mask, `EfficiencyClass`. Catches vCPU migration across pCPUs or heterogeneous-topology leaks.
- **What Chamber would need to intercept:** Either vCPU-to-pCPU pinning in the SVM scheduler path (VMRUN currently runs on whatever pCPU the Windows host scheduler put the guest thread on) or `NtQuerySystemInformation(SystemLogicalProcessorInformationEx)` returns.
- **Rough implementation sketch:** Lowest-cost path lives in `driver/fingerprint/syscall_rewrite.c` - add a `SystemLogicalProcessorInformationEx` case that caches the first observed topology snapshot per spoofed PID (keyed off a stable seed) and returns the cached bytes on subsequent calls. Higher-cost path: pin each vCPU to a fixed pCPU across VMRUN in the scheduler setup. In practice the current MADT-derived topology Windows reports is stable so this probe is unlikely to fire on a quiescent system; harden it only if measurements show drift.

### BOOT_LOGO
- **Probe mechanism:** `NtQuerySystemInformation(SystemBootLogoInformation = 140)` returns the BGRT bitmap; the probe CRC32C's the payload against hardcoded OVMF (`0x110350C5`) and Hyper-V (`0x87c39681`) logo hashes.
- **What Chamber would need to intercept:** Class 140 is not in `rewrite_system_information`'s switch (which handles 76, 103, 144, 176, basic, processor info, SPPI).
- **Rough implementation sketch:** Add class 140 to `rewrite_system_information` in `driver/fingerprint/syscall_rewrite.c`. Two options: (a) overwrite the bitmap bytes with a seed-derived vendor logo whose CRC32C is not in the probe's table; (b) scramble a handful of pixel bytes so the CRC32C simply does not match either hardcoded hash. Option (b) is simpler - a single XOR over 64 bytes at `info->bitmap_offset` moves the CRC32C out of the collision set at negligible cost.

### MEASURED_BOOT
- **Probe mechanism:** `LoadLibraryEx("tbs.dll")` + `Tbsi_Get_TCG_Log_Ex` (or `Tbsi_Context_Create` + `Tbsi_Get_TCG_Log`); walks `TCG_PCR_EVENT2` records for `EV_EFI_PLATFORM_FIRMWARE_BLOB` in PCR0 naming OVMF's SEC range (`0x830000`/`0xD0000`) or PEI range (`0x900000`/`0xE80000`).
- **What Chamber would need to intercept:** `tbs.dll` talks through the TrustedInstaller stack to the vTPM; `Tbsi_Get_TCG_Log` is not intercepted anywhere. The toggles `CFP_TOGGLE_TPM_ABSENT` (`fingerprint_cfg.h:62`) and `CHAMBER_TOGGLE_TPM_ABSENT_SPOOF` (`the_chamber.h:101`) are defined but nothing consumes them.
- **Rough implementation sketch:** Add an `NtDeviceIoControlFile` hook on the TBS device path (`\Device\Tpm` / `\Device\TrustedPlatformModule`) in `driver/fingerprint/syscall_rewrite.c`. On TCG-log IOCTLs, parse the returned `TCG_PCR_EVENT2` stream and either: (a) delete `EV_EFI_PLATFORM_FIRMWARE_BLOB` entries whose address range matches the OVMF constants and substitute vendor-firmware ranges from an AMI/InsydeH2O pool; or (b) consume the toggle and fail `Tbsi_Context_Create` so the probe's TPM-absent branch is taken instead. Path (a) is stronger (claims TPM present, matches guest config); path (b) is the smaller change.

### TPM
- **Probe mechanism:** Same surface as MEASURED_BOOT - re-parses the TCG event log through TBS to catalog per-event PCR/type/digest patterns that distinguish swtpm/vTPM (deterministic digests, missing `EV_SEPARATOR` entries, EDK II TPM2-driver event types) from a physical fTPM/dTPM stream.
- **What Chamber would need to intercept:** Same as MEASURED_BOOT - the TBS IOCTL return path for `Tbsi_Get_TCG_Log(_Ex)`.
- **Rough implementation sketch:** Same hook location in `driver/fingerprint/syscall_rewrite.c`. Beyond MEASURED_BOOT's firmware-blob-range substitution, this probe demands event-log reconstruction: synthesize `EV_SEPARATOR` entries in the right PCRs, non-deterministic-looking digests (HMAC a per-install seed over `event_index`), and platform-specific event types matching a retail AMI/InsydeH2O log. Share the parsing scaffold with MEASURED_BOOT; a single parser emitting both fixes keeps one implementation point.

## Unreachable (irrelevant techniques - Chamber not pretending to be that VM)

- **VPC_INVALID** - The `0F 3F 07 0B` VirtualPC hypercall probe is `#ifdef x86_32`; compiled out of the 64-bit build Chamber targets.
- **VMWARE_STR** - STR-based TR==`0x4000` probe is x86_32-only; compiled out.
- **TRAP** - DR0 + `EFLAGS.TF` race probe short-returns at the `is_intel()` guard; 7700X is AuthenticAMD and the Intel-only code path is never entered.
- **AZURE** - Fires only on a 13-char NetBIOS name matching `runnervm` + 5 alphanumerics (Azure GitHub Actions / AzDO hosted-runner convention). Chamber models a Zen 4 workstation, not an Azure CI runner.
- **ACPI_SIGNATURE** - Hunts QEMU LPC, Hyper-V VMBus/VPCI location-path tokens, and Intel Q35-slotted AMD VEN:DEV pairs via `DEVPKEY_Device_LocationPaths`. Chamber is thin AMD-SVM on a real 7700X; Windows's PnP tree exposes the motherboard's real ACPI and real PCIe topology (PCIROOT / PNP0A08 / PXS / PEG). No QEMU LPC, no VMBus/VPCI, no DRAC.
- **VIRTUAL_REGISTRY** - Catches Sandboxie-class object-manager-level registry virtualization; Chamber's registry rewrites are value-level `CmRegisterCallbackEx` post-ops that never redirect the key handle itself.
- **DRIVERS** - Enumerates loaded kernel drivers for VirtualBox / VMware / KVM / Looking-Glass guest-additions names and GUIDs. Chamber installs none of those; its own driver is renamed via `kldr-donor-rename` (`driver/stealth.c:303`).
- **DLL** - `GetModuleHandleW` for `sbiedll.dll` / `pstorec.dll` / `vmcheck.dll` / `cmdvrt32|64.dll` / `cuckoomon.dll` / `SxIn.dll`. Chamber's only user-mode injection is `chamber_shim.dll` via `ic-trampoline-per-process-inject`, not in the probe's list.
- **WINE** - Looks for `wine_get_version`/`wine_get_unix_file_name`, the Wine `MulDiv(1,INT_MIN,INT_MIN)==0` quirk, and the `IsNativeVhdBoot` Wine stub. The Chamber guest runs genuine Microsoft ntdll/kernel32 on native silicon.
- **HANDLES** - Opens VirtualBox / VMware guest-additions named-device/pipe paths (`\??\VBoxMiniRdrDN`, `\??\pipe\VBoxTrayIPC`, `\??\HGFS`, `\??\pipe\cuckoo`). Chamber creates none.
- **MUTEX** - Opens Sandboxie and Microsoft Virtual PC mutant names. Chamber creates none.
- **CUCKOO** - Opens `\??\C:\Cuckoo` directory and `\??\pipe\cuckoo`. Chamber is not the Cuckoo agent.
- **KERNEL_OBJECTS** - Enumerates `\Device` for `VmGenerationCounter`/`VmGid` (Hyper-V VSP synthetic entries). Chamber exposes no VMBus / Hyper-V enlightenments: CPUID `0x40000000-0x4FFFFFFF` zeroed, Hyper-V MSR band `#GPs`.

## Methodology

**Static audit** performed in three phases. **(1) Parallel research** of each VMAware technique against its canonical probe source (pafish / vmaware.hpp / Windows internals references), resolving the exact bytes each check parses and the exact CPL and Windows syscall surface each uses. **(2) Category-batched mapping** of each probe onto Chamber defences in `driver/`, resolving concrete `file:line` anchors for cited mechanisms and marking buckets by whether the defence actually lands on the parsed bytes (full), lands partially or weaker than needed (partial), does not land at all (gap), or whether the probe targets a VM product Chamber is not impersonating so classification as bare metal requires no intercept (unreachable). **(3) Synthesis** into this report.

This is a **static audit**. A real live run on Zen 4 silicon with Chamber loaded is still required to confirm the predicted 35% VMAware score, particularly for:
- **Timing-based checks** (TIMER especially): the sibling-SMT software clock has no reliable static answer; actual CPUID vmexit cost depends on live cache pressure, SMT scheduling, and how many leaves the probe hammers.
- **Conditional-config gaps** (BOOT_LOGO, MEASURED_BOOT, TPM, DEVICES, GPU_CAPABILITIES, DISPLAY): their trip rate depends on whether the guest sees OVMF vs vendor firmware, vTPM vs fTPM passthrough, emulated vs passthrough PCI/USB devices, and emulated vs passthrough GPU. A tightly configured Chamber deployment can neutralize several of these at the VM-config layer without code changes.
- **Partial-coverage items** (CPUID_SIGNATURE, SVM_EXCEPTIONS, FIRMWARE, NVRAM): the SVM_EXCEPTIONS arm (b) trip is architecturally deterministic and will fire every run; the others are more probabilistic and need a measured baseline.
