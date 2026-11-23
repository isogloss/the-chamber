# Wave 1 Audit Report

## Summary

Wave 1 cross-checked 202 candidate findings across four audit scopes (driver-a, driver-b, install-probes, infra-docs) using three independent verification lenses per finding (correctness-trace, spec-conformance, reproducibility). After three-reviewer majority-vote verification, **153 findings were confirmed and 49 were refuted**. Confirmed severity distribution: **33 showstopper, 42 high, 44 medium, 26 low, 8 nit**.

Top three concerns in plain language:

1. **The Phase 1 hypervisor never actually runs.** `svm_launch` is defined in `vmrun.asm` but has zero C-side callers. DriverEntry flips EFER.SVME on every CPU, builds VMCBs, and returns without ever issuing `VMRUN`. Every intercept, timing offset, MSR spoof and CPUID mask is dead code until Phase 2 wires the trampoline. This is acknowledged in `audit/phase1_done.md`, but the shipped driver advertises itself as a stealth hypervisor that in fact only toggles SVME.
2. **The VMRUN trampoline is structurally broken in ways that will instantly crash Windows the moment Phase 2 wires it.** Guest R15 is clobbered every VMEXIT (asm comment admits this), `svm_build_vmcb` only writes selector half of the segment state (base/limit/attrib remain zero → CS.L=0, GS.Base=0 → KPCR destroyed), stack is 8-byte-misaligned at every C call, no FPU/SSE/AVX save-restore, and `svm_offline_cpu` writes VM_HSAVE_PA with EFER.SVME=0 (a #GP at IPI_LEVEL = instant bugcheck on every unload path).
3. **The user-mode launcher is end-to-end non-functional against its own installer.** `install_service.ps1` mints a per-install random service/device/symlink name (Phase 1.7 randomization), but `load.ps1`, `stop.ps1`, `recover.ps1`, `UNINSTALL.ps1`, `obfuscate.ps1`, and `pentest/run_all.ps1` all hardcode `winhvmon` / `\\.\WinHvMon` / `C:\THE_CHAMBER\driver\winhvmon.sys`. The desktop shortcut can't reach the driver, `stop.ps1` reports "service not installed" even when it is, and safe-mode `recover.ps1` cannot remove the actual registry key. The IOCTL constants in `load.ps1` also don't match `CTL_CODE(0x8000, 0x801..3, METHOD_BUFFERED, FILE_ANY_ACCESS)` as the comments claim, so even if the symlink matched, `DeviceIoControl` would return STATUS_INVALID_DEVICE_REQUEST and the 60-second watchdog would self-unload mid-session.

Secondary systemic concerns worth naming: the host-to-guest MSR passthrough path (`__readmsr`/`__writemsr` on guest-controlled RCX with no SEH) is a one-instruction guest-to-host bugcheck primitive once VMRUN is wired; `handle_msr` EFER writes mutate the running host's physical EFER rather than VMCB.save.efer; multiple audit documents (`detection_surface.md`, `synthetic_values_table.md`, `README.md`, `ceilings.md`, `FAILURE_WORKFLOW.md`) describe pre-Phase-1 or factually wrong hardware interfaces while being cited as authoritative references.

## Model identity used

Distinct model-identity strings observed across the finder pool:

- `claude-opus-4-7 / claude-opus-4-7`

**All Wave 1 finders and all three verification-lens reviewers ran on Opus 4.7 (model ID `claude-opus-4-7`).** No other model identities appeared in the confirmed or refuted sets; the entire pool is uniform.

## Findings by severity

Each entry lists title, file:line, code quote (fenced where present), failure mechanism, confidence, converged source lenses (`_sources`), and a one-line remediation direction. Where the same underlying bug was independently surfaced by multiple scopes/lenses (e.g. `svm_launch` found by `driver-a:structural`, `driver-a:spec-conformance`, `driver-b:structural`, `driver-b:adversarial`, `driver-b:spec-conformance`), each surfacing is listed separately so the convergence is visible.

### Showstopper

**S-1. svm_launch is never invoked; driver initializes SVM but never enters guest mode** — `driver/svm_bringup.c:87`
```
static VOID svm_online_cpu(PER_CPU_CTX *ctx) {
    __writemsr(SVM_MSR_EFER, __readmsr(SVM_MSR_EFER) | EFER_SVME);
    __writemsr(SVM_MSR_VM_HSAVE_PA, ctx->host_save_pa);
    svm_build_vmcb(ctx);
    ctx->active = TRUE;
}
```
Failure: tree-wide grep finds no C-side caller for `svm_launch`; DriverEntry returns STATUS_SUCCESS with SVME on every CPU and no guest running. All intercepts, VMEXIT dispatch, timing, stealth-via-CPUID/MSR are dead code. Confidence: confirmed. Sources: `driver-a:structural`. What to fix: wire `svm_launch` per-CPU from `svm_init_all_cpus` after `svm_build_vmcb`, inside a `KeIpiGenericCall` or affinity-switched PASSIVE_LEVEL loop.

**S-2. svm_build_vmcb only sets segment selectors; attrib/limit/base left zero** — `driver/svm_vmcb.c:204`
```
save->es.selector   = svm_read_es();
save->cs.selector   = svm_read_cs();
save->ss.selector   = svm_read_ss();
save->ds.selector   = svm_read_ds();
save->fs.selector   = svm_read_fs();
save->gs.selector   = svm_read_gs();
save->ldtr.selector = svm_read_ldtr();
save->tr.selector   = svm_read_tr();
```
Failure: `RtlZeroMemory(vmcb, …)` at line 178 zeroes the VMCB, only the 16-bit selector is then written for each segment; attrib/limit/base remain zero. Per AMD APM Vol 2 §15.5.1 VMRUN consistency checks reject CS with P=0/L=0; even if tolerated, GS.Base=0 destroys the Windows KPCR pointer on first `gs:[...]` access → triple fault. VMLOAD cannot repair CS/SS/DS/ES (it only covers FS/GS/TR/LDTR extras). Confidence: confirmed. Sources: `driver-a:structural`, `driver-b:structural`. What to fix: issue `vmsave rax` before first VMRUN to populate hidden state from the live CPU, or walk the GDT and read `IA32_FS_BASE`/`IA32_GS_BASE` to populate base/limit/attrib for every segment plus TR/LDTR.

**S-3. Guest R15 is destroyed on every VMEXIT and replaced with the ctx pointer on next VMRUN** — `driver/vmrun.asm:77`
```
    mov r15, [rsp]                   ; r15 = ctx
    mov [r15 + 64 +   8], rbx
    ...
    mov [r15 + 64 + 112], r14
    ; ... guest r15 is LOST ...
```
Failure: on VMEXIT physical R15 still holds guest R15, but line 77 overwrites it with the stack-saved ctx before the save sled runs; `gpr_save[15]` is never written, the restore sled never reloads R15, and the next `vmrun rax` resumes the guest with R15 = kernel-pool ctx pointer. Windows x64 ABI treats R15 as non-volatile; the first intercepted exit inside a function holding state in R15 BSODs within microseconds. The asm's own comment at lines 91-97 acknowledges the loss. Confidence: confirmed. Sources: `driver-a:structural`, `driver-a:spec-conformance`, `driver-b:structural`, `driver-b:adversarial`, `driver-b:spec-conformance`. What to fix: before overwriting R15 with ctx, save guest R15 (e.g. `mov [rsp+8], r15; mov r15, [rsp]; … mov rax, [rsp+8]; mov [r15 + 64 + 120], rax`) and reload R15 from `gpr_save[15]` on the restore path.

**S-4. svm_offline_cpu writes VM_HSAVE_PA AFTER clearing EFER.SVME** — `driver/svm_bringup.c:155`
```
__writemsr(SVM_MSR_EFER, __readmsr(SVM_MSR_EFER) & ~EFER_SVME);
__writemsr(SVM_MSR_VM_HSAVE_PA, 0);
```
Failure: per AMD APM Vol 2 Appendix B, VM_HSAVE_PA writes with EFER.SVME=0 raise #GP(0). `svm_offline_cpu` runs via `KeIpiGenericCall` at IPI_LEVEL where an unhandled #GP becomes an immediate bugcheck; every normal unload path and the DriverEntry failure-cleanup path triggers this. Confidence: confirmed. Sources: `driver-a:adversarial`. What to fix: reverse the write order (zero VM_HSAVE_PA first, then clear SVME) or drop the VM_HSAVE_PA write entirely, matching Linux KVM's `cpu_svm_disable` sequence.

**S-5. handle_msr default path lets guest-selected MSR bluescreen host** — `driver/vmexit.c:163`
```
} else {
    if (is_write) { value = ...; __writemsr(msr, value); }
    else          { value = __readmsr(msr); ... }
}
```
Failure: IVEC3_MSR is enabled; per AMD APM §15.11 any MSR access outside the three MSRPM windows is unconditionally intercepted regardless of MSRPM contents. Any MSR not explicitly cased (Hyper-V 0x40000100+ crash/reenlightenment, KVM 0x4B564D00-0x4B564DFF, VMware backdoor) reaches the default branch where `__readmsr/__writemsr` on an unimplemented MSR raises #GP in host ring-0 without SEH — Windows bugchecks 0x7F/0x139/0x3B. Confidence: confirmed. Sources: `driver-a:adversarial`, `driver-b:adversarial`, `driver-b:spec-conformance`. What to fix: wrap `__readmsr`/`__writemsr` with `__try/__except`; replace blind passthrough with an allow-list that returns 0 on read / absorbs writes for unknown MSRs, or reflects #GP into the guest via `event_inject`.

**S-6. Hyper-V paravirt MSR band truncated to 0x400000FF** — `driver/vmexit.c:133`
```
if (msr >= 0x40000000 && msr <= 0x400000FF) { ... swallow ... }
```
Failure: Hyper-V TLFS defines HV_X64_MSR_CRASH_P0..P4/CTL at 0x40000100..0x40000105 and reenlightenment MSRs at 0x40000106..0x40000108 (and synthetic-debug up to 0x400001FF), all outside this band and outside the MSRPM windows, so IVEC3_MSR intercepts them and they fall through into the default MSR handler (see S-5). A guest Hyper-V-aware probe that RDMSRs 0x40000100 after CPUID leaf 0x40000000 bugchecks the host. Master plan explicitly calls for ≥0x400001FF coverage. Confidence: confirmed. Sources: `driver-a:adversarial`. What to fix: widen the catch to `0x40000000..0x400001FF`, add the KVM window, and absorb writes / zero reads for the extended range.

**S-7. KVM / VMware / Xen paravirt MSR ranges fall into default MSR path** — `driver/vmexit.c:128`
```
static void handle_msr(PER_CPU_CTX *ctx, VMCB *vmcb) {
    ... (only EFER/VM_HSAVE_PA/VM_CR/Hyper-V special cased) ...
}
```
Failure: same mechanism as S-5; KVM MSR window 0x4B564D00..0x4B564DFF and extended Hyper-V/VMware probing leaves auto-intercept but are unhandled, bluescreening the host on any VM-detection payload sweep. Confidence: confirmed. Sources: `driver-a:adversarial`. What to fix: add explicit absorb-write/zero-read cases for 0x40000000..0x400001FF, 0x4B564D00..0x4B564DFF, and a conservative catch-all default that returns 0 for every unrecognized MSR instead of calling `__readmsr` on it.

**S-8. svm_launch is defined but never called anywhere in the driver** *(spec-conformance restatement of S-1)* — `driver/the_chamber.c:449`
Failure: DriverEntry returns SUCCESS with SVME enabled on every core but no guest ever running. Confidence: confirmed. Sources: `driver-a:spec-conformance`, `driver-b:adversarial`, `driver-b:spec-conformance`. What to fix: see S-1.

**S-9. Guest r15 is destroyed on every VMEXIT (self-documented in asm comment)** *(spec restatement of S-3)* — `driver/vmrun.asm:67`
Failure: see S-3 — `mov r15, [rsp + 8]` at line 67 clobbers guest R15 before any save occurs. Confidence: confirmed. Sources: `driver-a:spec-conformance`. What to fix: see S-3.

**S-10. VMCB segment state-save: only selectors populated; base/limit/attrib left zero** *(spec restatement of S-2)* — `driver/svm_vmcb.c:204`. Confidence: confirmed. Sources: `driver-a:spec-conformance`, `driver-b:spec-conformance`. What to fix: see S-2.

**S-11. Guest WRMSR(EFER) handler writes to the host's physical EFER, not to VMCB.save.efer** — `driver/vmexit.c:141`
```
} else if (msr == (ULONG)SVM_MSR_EFER) {
    if (is_write) {
        value = (ULONGLONG)(ULONG)vmcb->save.rax |
                ((ULONGLONG)(ULONG)ctx->gpr_save[3] << 32);
        value |= EFER_SVME;
        __writemsr(msr, value);
```
Failure: at VMEXIT the CPU is in host context, so `__writemsr(0xC0000080, value)` mutates host EFER with guest-controlled bits (NXE, SCE, LME). Reserved-bit sets raise #GP in ring 0 → bugcheck (no SEH). Even non-faulting values corrupt host NX/syscall policy until next VM_HSAVE restore. `vmcb->save.efer` is never updated, so VMRUN reloads the guest's stale pre-write EFER and the guest observes read-after-write incoherence: a trivial self-test fingerprint. Confidence: confirmed. Sources: `driver-a:spec-conformance`, `driver-b:structural`. What to fix: update `vmcb->save.efer` with `(value & ~EFER_SVME) | EFER_SVME`, clear the state-save group in `vmcb_clean_bits`, and leave the physical MSR alone.

**S-12. vmrun.asm loses guest R15 on every VMEXIT round-trip** *(structural restatement of S-3)* — `driver/vmrun.asm:77`. Sources: `driver-b:structural`. See S-3.

**S-13. svm_build_vmcb only sets segment selectors, leaves attrib/limit/base zero** *(structural restatement of S-2)* — `driver/svm_vmcb.c:204`. Sources: `driver-b:structural`. See S-2.

**S-14. handle_msr EFER write path corrupts host EFER; VMRUN reloads stale guest EFER** *(structural restatement of S-11)* — `driver/vmexit.c:142`. Sources: `driver-b:structural`. See S-11.

**S-15. handle_npf calls npt_map_page which allocates contiguous memory at DISPATCH_LEVEL** — `driver/vmexit.c:277`
```
(void)npt_map_page(fault_page, fault_page,
                   NPT_PRESENT | NPT_WRITABLE | NPT_USER);
```
Failure: `npt_map_page` acquires `g_npt_hide_lock` (raises to DISPATCH_LEVEL) and then calls `npt_ensure_pdpt` / `npt_ensure_pd` → `npt_alloc_page` → `MmAllocateContiguousMemorySpecifyCache`, which requires IRQL ≤ APC_LEVEL. First NPF outside the pre-mapped `MmGetPhysicalMemoryRanges` set (hot-plug RAM, firmware hole, device MMIO) bugchecks 0xA (IRQL_NOT_LESS_OR_EQUAL). The author's own comment in `svm_vmcb.c:83-84` acknowledges this WDK rule. Confidence: confirmed. Sources: `driver-b:structural`. What to fix: pre-allocate PDPT/PD pages during `npt_init` up to `NPT_MAX_PHYS_GB` coverage; the NPF path must never allocate.

**S-16. vmexit_handler default case blindly advances RIP to vmcb->ctl.next_rip** — `driver/vmexit.c:58`
```
default:
    CHAMBER_LOG(...);
    vmcb->save.rip = vmcb->ctl.next_rip;
    break;
```
Failure: `next_rip` is architecturally defined only for the decoded intercepts (CPUID/IOIO/MSR/VMMCALL/INVD/INVLPG/HLT/MONITOR/MWAIT/RDTSC/RDTSCP). For VMEXIT_INVALID (-1) and all fault-class exits it is undefined; advancing RIP to it jumps the guest into garbage, re-exits with VMEXIT_INVALID, and loops. The file's own `handle_npf` block comment (lines 242-249) warns against this pattern. Confidence: confirmed. Sources: `driver-b:structural`. What to fix: the default arm should either inject #UD into the guest (`event_inject`) or raise a controlled bugcheck; never advance RIP to `next_rip` outside the decoded set.

**S-17. vmrun.asm never VMLOADs host extended state after VMEXIT — handler runs with guest's FS/GS/kernel_gs_base** — `driver/vmrun.asm:74`
```
    pop rax                          ; restore vmcb_pa
    vmsave rax
    mov r15, [rsp]                   ; r15 = ctx
```
Failure: per AMD APM Vol 2 §15.5.2/§15.6, VMRUN auto-saves only core host state (CR0-4, EFER, CS/SS/DS/ES, GDTR, IDTR, RAX/RSP/RIP/RFLAGS) via VM_HSAVE_PA; TR/LDTR hidden, KernelGsBase, STAR/LSTAR/CSTAR/SFMASK, SYSENTER_* require explicit host-side `vmsave host_pa` / `vmload host_pa`. The driver issues one `vmload rax` on the guest VMCB before the loop and `vmsave rax` back to the same guest VMCB after each exit — never `vmsave host_save_pa` before VMRUN, never `vmload host_save_pa` after. The C vmexit_handler then runs with the guest's GS.Base/KernelGsBase/syscall MSRs; any `__readgsqword(KPCR)` or syscall taken by the handler dispatches to the wrong RIP. Confidence: confirmed. Sources: `driver-b:structural`. What to fix: bracket the vmrun loop as `vmsave host_pa; vmload guest_pa; vmrun guest_pa; vmsave guest_pa; … handler …; vmload host_pa; (repeat)`.

**S-18. svm_launch is defined but never called -- HV never enters guest mode** *(adversarial restatement of S-1)* — `driver/svm_bringup.c:87`. Sources: `driver-b:adversarial`. See S-1.

**S-19. Guest R15 lost on every VMEXIT; guest R15 writes alias host memory** *(adversarial restatement of S-3)* — `driver/vmrun.asm:77`. Sources: `driver-b:adversarial`. See S-3.

**S-20. handle_msr default case forwards arbitrary guest WRMSR to hardware** *(adversarial restatement of S-5)* — `driver/vmexit.c:163`. Sources: `driver-b:adversarial`. See S-5.

**S-21. VMCB control-area intercept fields are at wrong absolute offsets vs AMD APM / master plan** — `driver/svm.h:94`
```
/* 0x000 */ ULONG intercept_cr_read;
/* 0x004 */ ULONG intercept_cr_write;
/* 0x008 */ ULONG intercept_dr_read;
/* 0x00C */ ULONG intercept_dr_write;
/* 0x010 */ ULONG intercept_exceptions;
/* 0x014 */ ULONG intercept_vec3;
/* 0x018 */ ULONG intercept_vec4;
/* 0x01C */ ULONG intercept_vec5;
```
Failure: per AMD APM Table B-1 CR reads+writes pack into one dword at 0x000 and DR reads+writes into one dword at 0x004, so Misc1 (IVEC3: CPUID/MSR/IRET/…) sits at 0x0C and Misc2 (IVEC4: VMRUN/VMMCALL/VMLOAD/…) at 0x10. This struct separates them, pushing `intercept_vec3` to 0x14 and `intercept_vec4` to 0x18 — eight bytes past where hardware reads them. On VMRUN, CPUID/MSR/VMRUN/VMMCALL intercepts are inert, bits set land in reserved pads. `iopm_base_pa` at 0x3C is also 4 bytes early. `C_ASSERT(sizeof == 0x400)` only guards total size. Confidence: confirmed. Sources: `driver-b:spec-conformance`. What to fix: redefine VMCB_CONTROL_AREA with `intercept_cr` (packed read+write at 0x00), `intercept_dr` (packed at 0x04), `intercept_exceptions` at 0x08, `intercept_vec3` at 0x0C, `intercept_vec4` at 0x10, and shift subsequent fields; re-verify every stored offset with `C_ASSERT(offsetof(...) == 0x...)`.

**S-22. svm_build_vmcb never populates segment .attrib / .base / .limit — only selectors** *(spec restatement of S-2)* — `driver/svm_vmcb.c:204`. Sources: `driver-b:spec-conformance`. See S-2.

**S-23. svm_launch is never called from any C path** *(spec restatement of S-1)* — `driver/svm_bringup.c:87`. Sources: `driver-b:spec-conformance`. See S-1.

**S-24. Guest R15 is overwritten with ctx pointer on every VMEXIT and never restored** *(spec restatement of S-3)* — `driver/vmrun.asm:77`. Sources: `driver-b:spec-conformance`. See S-3.

**S-25. handle_msr generic else branch does raw __readmsr / __writemsr on any MSR** *(spec restatement of S-5)* — `driver/vmexit.c:162`. Sources: `driver-b:spec-conformance`. See S-5.

**S-26. Launcher load.ps1 hardcodes 'winhvmon' names that install_service.ps1 explicitly randomizes per install** — `/home/user/the-chamber/launcher/load.ps1:28`
```
$svc = 'winhvmon'
$sys = 'C:\THE_CHAMBER\driver\winhvmon.sys'
...
$h = [TheChamber.Pinvoke+Native]::CreateFile('\\.\WinHvMon', ...)
```
Failure: `install_service.ps1` mints a random 10-char service name, patches CHAMBER_CFG to `\Device\<rand>` / `\DosDevices\<rand>`, loads via `NtLoadDriver`. `load.ps1` then checks `Get-Service -Name 'winhvmon'` (always null), re-invokes installer (minting a SECOND random service + .sys), tries `Start-Service 'winhvmon'` (fails), opens `\\.\WinHvMon` (fails ERROR_FILE_NOT_FOUND), and `Stop-Service` in finally also fails. Every double-click leaks another signed driver + service key; no launch ever reaches the driver. Confidence: confirmed. Sources: `install-probes:structural`. What to fix: have `load.ps1` read the service name from `C:\THE_CHAMBER\logs\last_install.txt` (which `install_service.ps1` already writes) and derive the symlink from the same source.

**S-27. Launcher IOCTL hex literals do not equal the CTL_CODE expressions in their comments** — `/home/user/the-chamber/launcher/load.ps1:81`
```
$IOCTL_STATUS   = 0x800820C  # (0x8000<<16) | (FILE_ANY_ACCESS<<14) | (0x801<<2) | METHOD_BUFFERED
$IOCTL_KICK     = 0x8008210  # (0x8000<<16) | (0<<14) | (0x802<<2) | 0
$IOCTL_SHUTDOWN = 0x8008214  # 0x803<<2 | 0
```
Failure: driver defines these via `CTL_CODE(0x8000, 0x801..3, METHOD_BUFFERED, FILE_ANY_ACCESS)` yielding `0x80002004/0x80002008/0x8000200C`. The launcher's `0x0800820C/0x08008210/0x08008214` decode to DeviceType=0x800, Access=FILE_WRITE_ACCESS, Function=0x083/0x084/0x085 — no case matches, `DeviceIoControl` returns STATUS_INVALID_DEVICE_REQUEST, the 20-second watchdog kick never reaches the driver, and the 60-second heartbeat self-unloads the HV mid-session. `stop.ps1` reuses the same wrong SHUTDOWN literal. Confidence: confirmed. Sources: `install-probes:structural`. What to fix: compute the literals from the CTL_CODE formula in PowerShell, or hard-correct them to `0x80002004/0x80002008/0x8000200C` and add an assertion comparing them to a re-derived value.

**S-28. Launcher is hardcoded to 'winhvmon' while installer generates a random name** *(adversarial restatement of S-26)* — `/home/user/the-chamber/launcher/load.ps1:28`. Sources: `install-probes:adversarial`. See S-26.

**S-29. load.ps1 re-runs installer on every launch, piling up orphaned random-named services** — `/home/user/the-chamber/launcher/load.ps1:39`
```
$existing = Get-Service -Name $svc -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host 'Installing service...' -ForegroundColor Cyan
    & $installer
```
Failure: because `Get-Service 'winhvmon'` always returns null (see S-26), the installer re-runs per launch. Each run writes a fresh `System32\drivers\<rand>.sys`, a new HKLM Services\<rand> key, and calls `NtLoadDriver`. `last_install.txt` is overwritten with only the newest name, so `UNINSTALL.ps1` / `recover.ps1` can only unload the most recent; earlier loads become unreachable kernel residents until reboot. Confidence: confirmed. Sources: `install-probes:adversarial`. What to fix: read `last_install.txt` and only install if that service is not already loaded; refuse to install if a prior random name exists but cannot be queried/unloaded.

**S-30. load.ps1 and stop.ps1 reference hardcoded 'winhvmon'/\\.\WinHvMon but installer mints random names — Desktop shortcut flow is non-functional** *(spec restatement of S-26/S-29)* — `/home/user/the-chamber/launcher/load.ps1:28`. Sources: `install-probes:spec-conformance`. See S-26.

**S-31. recovery/recover.ps1 uses hardcoded 'winhvmon' service name — cannot recover a real install** — `/home/user/the-chamber/recovery/recover.ps1:5`
```
sc.exe stop winhvmon 2>$null
sc.exe delete winhvmon 2>$null
```
Failure: `install_service.ps1` writes `HKLM\...\Services\<rand>` and persists the chosen name to `last_install.txt` (which `recover.ps1` never reads). Both sc.exe calls silently fail (stderr to `$null`); the driver, registry key, and `System32\drivers\<rand>.sys` remain. The BCD-restore branch (line 8) scans for `C:\the_chamber_bcd_*.bcd` backups that no script ever creates, so the "restore from backup" path is unreachable dead code — recovery always falls through to the blanket `testsigning off / nointegritychecks off` block, destroying pre-install BCD state too. Confidence: confirmed. Sources: `install-probes:spec-conformance`. What to fix: read `C:\THE_CHAMBER\logs\last_install.txt` for the random service name before issuing `NtUnloadDriver` (not sc.exe); fail loudly if the state file is missing; add a BCD snapshot path that `INSTALL.ps1` actually populates.

**S-32. run_all.ps1 dot-sources a hardcoded foreign-user path under Stop ErrorAction (infra-docs:structural)** — `/home/user/the-chamber/pentest/run_all.ps1:14`
```
. 'C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1'
```
Failure: line 12 sets `$ErrorActionPreference = 'Stop'`; line 14 dot-sources an absolute path under one specific developer's Downloads folder with no Test-Path guard. On any other machine the dot-source raises a terminating error and run_all.ps1 exits before `Invoke-Section` ever runs, producing no reports. `README.md` and `docs/operations/discipline.md 9.1.5` document this script as the primary baseline tool; it is unrunnable as committed anywhere but the author's machine. The username `lkhnj` is also leaked in the committed file. Confidence: confirmed. Sources: `infra-docs:structural`, `infra-docs:adversarial`. What to fix: wrap the dot-source in `if (Test-Path $gate) { . $gate; Assert-NoAntiCheatRunning } else { Write-Warning "safety gate not found; skipping" }` as the sibling `run_detectors.ps1:5-16` already does; or ship the `_safety_gate.ps1` inside the repo at `pentest/_safety_gate.ps1`.

**S-33. run_all.ps1 dot-sources a hardcoded personal path with ErrorActionPreference=Stop** *(adversarial restatement of S-32)* — `/home/user/the-chamber/pentest/run_all.ps1:14`. Sources: `infra-docs:adversarial`. See S-32.

### High

**H-1. handle_msr else-branch is a trivial guest-to-host bugcheck on any unknown MSR** — `driver/vmexit.c:162`. See S-5 for the mechanism; original structural filing from `driver-a:structural`. What to fix: see S-5.

**H-2. VMEXIT handler never saves/restores guest FPU/SSE/AVX state around the C handler** — `driver/vmrun.asm:101`
```
    mov rcx, r15                     ; ctx pointer for handler
    sub rsp, 32                      ; shadow space
    call vmexit_handler
    add rsp, 32
```
Failure: per AMD APM Vol 2, VMRUN and VMLOAD/VMSAVE do not touch x87/SSE/AVX/XSAVE state; at VMEXIT physical XMM/YMM still hold guest values. MSVC x64 freely emits XMM/YMM for struct copies, memcpy intrinsics, float lowering, and the varargs path (`DbgPrintEx` via `CHAMBER_LOG`), and `/kernel` reduces but does not eliminate all XMM uses (kernel float state is still corruptible through third-party inlined paths). Master plan §4.2 explicitly mandates FXSAVE+XSAVE around the handler. Confidence: confirmed. Sources: `driver-a:structural`, `driver-b:spec-conformance`. What to fix: FXSAVE/XSAVE to a per-CPU 4 KiB-aligned area before `call vmexit_handler`; FXRSTOR/XRSTOR after `call timing_update`; verify the save area covers the CPU's `XCR0` advertised components.

**H-3. Stack misalignment on call vmexit_handler and call timing_update violates MS x64 ABI** — `driver/vmrun.asm:101`
```
    sub rsp, 32                      ; shadow space
    call vmexit_handler
    add rsp, 32
```
Failure: trace from svm_launch entry: rsp%16=8; 8 pushes (64B, net 0) keep it at 8; `sub rsp, 16` keeps it at 8; `sub rsp, 32` before CALL keeps it at 8; CALL pushes RA → callee enters at rsp%16=0 instead of 8. MSVC emits MOVAPS/MOVDQA against 16-aligned stack slots (non-volatile XMM6-XMM15 prologue saves, aligned vector locals) → #GP in kernel mode → bugcheck. Same issue at `call timing_update` at line 127. Confidence: confirmed. Sources: `driver-a:structural`, `driver-b:adversarial`, `driver-b:spec-conformance`. What to fix: change `sub rsp, 32` to `sub rsp, 40` (or add a leading dummy `push`) before each C call and match with `add rsp, 40`.

**H-4. Hyper-V MSR spoof window is too narrow; crash/reenlightenment MSRs fall into the GP-fault path** *(structural restatement of S-6)* — `driver/vmexit.c:133`. Sources: `driver-a:structural`. See S-6.

**H-5. Watchdog DPC not quiesced before freeing g_cpu_ctx (UAF)** — `driver/the_chamber.c:189`
```
static void stop_watchdog(void) { KeCancelTimer(...); KeRemoveQueueDpc(...); }
```
Failure: `watchdog_dpc_routine` dereferences `g_cpu_ctx` and iterates `g_cpu_count` writing `InterlockedExchange(&g_cpu_ctx[i].shutdown_requested, 1)`. `stop_watchdog` cancels the timer and removes the DPC from the queue but neither waits for an in-flight DPC on another CPU (KeRemoveQueueDpc returns FALSE in that case). UnloadRoutine then calls `svm_shutdown_all_cpus` → `ExFreePoolWithTag(g_cpu_ctx)`. Classic kernel-pool use-after-free on service-stop / PnP removal / bugcheck-triggered unload. `IOCTL_THE_CHAMBER_SHUTDOWN` has the same pattern. Confidence: confirmed. Sources: `driver-a:adversarial`, `driver-b:adversarial`. What to fix: call `KeFlushQueuedDpcs()` at PASSIVE_LEVEL in UnloadRoutine between `stop_watchdog` and `svm_shutdown_all_cpus`.

**H-6. handle_msr WRMSR to EFER passes guest-controlled bits to the real MSR** — `driver/vmexit.c:145`. See S-11 for the mechanism (host-side EFER mutation, VMCB not updated). Sources: `driver-a:adversarial`. What to fix: see S-11; whitelist EFER bits (SCE, NXE, FFXSR, LMSLE, SVME, TCE), force SVME on, write `vmcb->save.efer` not the host MSR.

**H-7. Guest R15 is permanently overwritten by host ctx pointer across VMEXIT** *(adversarial restatement of S-3)* — `driver/vmrun.asm:131`. Sources: `driver-a:adversarial`. See S-3.

**H-8. VMRUN loop never VMLOADs host additional state** *(adversarial restatement of S-17)* — `driver/vmrun.asm:49`. Sources: `driver-a:adversarial`. See S-17. Severity rated "high / probable" rather than showstopper because today's handler never writes DR0-DR3/MSRs so leak is silent until the HV grows.

**H-9. DriverEntry clears crash marker before the risky stealth step runs** — `driver/the_chamber.c:456`
```
start_watchdog();
crash_marker_clear();  /* init complete -- next boot can load again */

/* Self-hide: rename our KLDR entry + null driver name. */
(void)stealth_apply(Driver);
```
Failure: `stealth_apply` walks `PsLoadedModuleList` under a spinlock and patches UNICODE_STRINGs against a hardcoded KLDR struct — the single most struct-sensitive step in DriverEntry. The crash-marker safety exists precisely so a bugcheck here produces a next-boot refuse-to-load gate, but the marker has been cleared one line earlier, so a stealth-induced crash now produces a reliable reboot loop. Confidence: confirmed. Sources: `driver-a:adversarial`. What to fix: move `crash_marker_clear()` to after `stealth_apply(Driver)` as the last meaningful line of DriverEntry.

**H-10. Default MSR handler forwards guest WRMSR/RDMSR to host, bugchecking the host on any non-existent MSR** *(spec restatement of S-5)* — `driver/vmexit.c:162`. Sources: `driver-a:spec-conformance`. See S-5.

**H-11. IOCTL_THE_CHAMBER_SHUTDOWN is FILE_ANY_ACCESS and the device has no SDDL restricting opens** — `driver/the_chamber.h:87`
```
#define IOCTL_THE_CHAMBER_SHUTDOWN  CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Failure: `IoCreateDevice` at `the_chamber.c:415` is called with no SDDL and the `IRP_MJ_CREATE` dispatcher does no `SeAccessCheck`. Any user token that can `CreateFile(\\.\<symlink>)` can send IOCTL_SHUTDOWN, which sets `unload_requested` and every per-CPU `shutdown_requested=1`, tearing down the stealth hypervisor — directly contradicting Phase 1.7 stealth and Phase 7.3 "signed-agent-only shutdown". Confidence: confirmed. Sources: `driver-a:spec-conformance`. What to fix: use `IoCreateDeviceSecure` with `SDDL_DEVOBJ_SYS_ALL_ADM_ALL` (SYSTEM + Administrators only), change the IOCTL to `FILE_WRITE_ACCESS`, and require a shared-secret handshake IOCTL before accepting SHUTDOWN.

**H-12. Missing VMLOAD between VMSAVE and the next VMRUN** *(spec restatement of S-17)* — `driver/vmrun.asm:146`. Sources: `driver-a:spec-conformance`. See S-17.

**H-13. Stack is 8-byte-misaligned at the C call sites in vmrun.asm (ABI violation)** *(adversarial restatement of H-3)* — `driver/vmrun.asm:101`. Sources: `driver-b:adversarial`. See H-3.

**H-14. Watchdog DPC races UnloadRoutine freeing g_cpu_ctx (use-after-free)** *(adversarial restatement of H-5)* — `driver/the_chamber.c:171`. Sources: `driver-b:adversarial`. See H-5.

**H-15. KeIpiGenericCall in UnloadRoutine can deadlock against a CPU inside the vmrun loop (GIF=0)** — `driver/vmrun.asm:49`
```
    clgi
    vmload rax

host_vmexit_loop:
    vmrun rax                        ; enter guest; returns here on VMEXIT
```
Failure: CLGI is issued once at the top of the loop and STGI only on the `host_done` exit path (which requires `ctx->shutdown_requested` to be set from inside the loop via a VMEXIT). Per AMD APM §15.17, GIF=0 inhibits IPIs. If a CPU is in a host-side window between VMEXIT and the next VMRUN during a forced unload (`sc stop` without the prior IOCTL, PnP removal, bugcheck-triggered unload), the broadcast `KeIpiGenericCall(ipi_offline, 0)` never lands on that CPU and hangs the unload at IPI_LEVEL. Latent only because `svm_launch` is unwired today. Confidence: confirmed. Sources: `driver-b:adversarial`. What to fix: cooperatively set `shutdown_requested` for every CPU before issuing the IPI; use an INTR intercept + injected #TEST interrupt as a wakeup; or move GIF management so IPIs are always deliverable on the host side.

**H-16. Shadow space allocation leaves RSP misaligned at call to vmexit_handler and timing_update** *(structural restatement of H-3)* — `driver/vmrun.asm:100`. Sources: `driver-b:spec-conformance`. See H-3.

**H-17. No FPU / SSE / AVX / XSAVE state preservation around the handler** *(spec restatement of H-2)* — `driver/vmexit.c:31`. Sources: `driver-b:spec-conformance`. See H-2.

**H-18. Guest EFER writes mutate the real MSR but do not update vmcb->save.efer** *(spec-conformance partial restatement of S-11)* — `driver/vmexit.c:141`. Sources: `driver-b:spec-conformance`. See S-11.

**H-19. KSPIN_LOCK at DISPATCH_LEVEL held across npt_ensure_pdpt / npt_ensure_pd** *(adversarial restatement of S-15)* — `driver/npt.c:409`. Sources: `driver-b:adversarial`. See S-15.

**H-20. recovery/recover.ps1 uses sc.exe against hardcoded 'winhvmon'** *(structural restatement of S-31)* — `/home/user/the-chamber/recovery/recover.ps1:5`. Sources: `install-probes:structural`. See S-31.

**H-21. stop.ps1 cannot stop a real install** *(structural)* — `/home/user/the-chamber/launcher/stop.ps1:18`
```
$svc = 'winhvmon'
...
$h = [TheChamber.Pinvoke+Native]::CreateFile('\\.\WinHvMon', ...)
...
Stop-Service -Name $svc -Force
```
Failure: `Get-Service -Name 'winhvmon'` always null on a randomized install → script exits "nothing to stop"; `CreateFile('\\.\WinHvMon')` fails; Stop-Service via SCM (if the service existed) would emit event 7036 that UNINSTALL.ps1 uses NtUnloadDriver to avoid. Confidence: confirmed. Sources: `install-probes:structural`, `install-probes:adversarial`. What to fix: read `last_install.txt`, issue IOCTL_SHUTDOWN against `\\.\<rand>`, then `NtUnloadDriver` on `\Registry\Machine\...\Services\<rand>`.

**H-22. tools/obfuscate.ps1 uses sc.exe create/stop/delete against a fixed 'winhvmon.sys' — directly contradicts Phase 1.7** — `/home/user/the-chamber/tools/obfuscate.ps1:30`
```
sc.exe stop $TargetName 2>$null | Out-Null
sc.exe delete $TargetName 2>$null | Out-Null
sc.exe create $TargetName binPath= $targetFile type= kernel start= demand error= normal DisplayName= $DisplayName | Out-Null
```
Failure: emits SCM events 7045 (install) and 7036 (state change) that Phase 1.7 and `install_service.ps1` go to great lengths to suppress by using direct registry writes + `NtLoadDriver`. Default `$TargetName="winhvmon"` and `$DisplayName="Windows Hypervisor Monitor"` also contain banned "Hv"/"Hypervisor" substrings and the hardcoded `C:\Windows\System32\drivers\winhvmon.sys` is deterministic across installs. Confidence: confirmed. Sources: `install-probes:structural`, `install-probes:adversarial`, `install-probes:spec-conformance`. What to fix: delete the script or rewrite it to call `install_service.ps1` with a per-install random name via `NtLoadDriver`.

**H-23. UNINSTALL depends solely on last_install.txt for the random name** — `/home/user/the-chamber/UNINSTALL.ps1:22`
```
$stateFile = Join-Path $root 'logs\last_install.txt'
$name = $null
if (Test-Path $stateFile) { $name = (Get-Content $stateFile -First 1).Trim() }
if (-not $name) { Write-Host "No install state file; nothing to unload." -ForegroundColor Yellow }
```
Failure: `install_service.ps1` writes only the most-recent random name with `-Force`. Two earlier installs (see S-29) orphan prior drivers; if the file is wiped or stale, UNINSTALL reports success while the driver remains loaded and `Services\<random>` registry key persists. No fallback discovery (e.g., enumerate services by ImagePath). Confidence: confirmed. Sources: `install-probes:structural`. What to fix: enumerate `HKLM\SYSTEM\CurrentControlSet\Services\*` for ImagePath pointing at `System32\drivers\<10-hex>.sys` with CHAMBER_CFG magic, unload each, remove each; still keep `last_install.txt` as the fast path.

**H-24. pmu_driver.c performs WRMSR / RDMSR on per-core PerfEvtSel/PerfCtr with no IRQL raise and no CPU pinning** — `/home/user/the-chamber/pentest/probes/pmu_vmexit/pmu_driver.c:72`
```
static NTSTATUS PmuArm(ULONG index, ULONGLONG event_select)
{
    if (index >= NUM_CORE_COUNTERS) { return STATUS_INVALID_PARAMETER; }
    __writemsr((ULONG)(AMD_PERFEVTSEL_CORE0 + (ULONGLONG)index * 2ULL), event_select);
    return STATUS_SUCCESS;
}
```
Failure: `PerfEvtSelCoreN` and `PerfCtrCoreN` at `0xC0010200+2i` are per-logical-processor MSRs. The driver executes WRMSR/RDMSR at PASSIVE_LEVEL on whatever CPU the IRP is dispatched on; no `SetThreadAffinityMask`/`KeSetSystemAffinityThreadEx`/targeted DPC anywhere. Arm/trigger/read can run on three different cores, so delta is noise and the probe's PASS/FAIL verdict is random. Confidence: confirmed. Sources: `install-probes:structural`, `install-probes:spec-conformance`. What to fix: raise IRQL to DISPATCH_LEVEL and `KeSetSystemAffinityThreadEx` around WRMSR/RDPMC, or dispatch via `KeInsertQueueDpc` targeted with `KeSetTargetProcessorDpcEx`.

**H-25. pmu_vmexit default event 0x0C0 (RetiredInstructions) with PASS==0 invariant guarantees FAIL on every run** — `/home/user/the-chamber/pentest/probes/pmu_vmexit/pmu_vmexit.c:84`
```
#define DEFAULT_EVENT_CODE         0x0C0u  /* RetiredInstructions - smoke test */
...
const char *verdict = (delta == 0) ? "PASS" : "FAIL";
```
Failure: with the default event programmed, the counter measures retired instructions; the 16-iteration CPUID force-exit loop + three IOCTL round-trips reliably retire thousands of instructions on bare metal. Delta > 0 → `VERDICT: FAIL`, exit 1. `run_benchmarks.ps1` logs every default run as a regression against baseline. Confidence: confirmed. Sources: `install-probes:structural`, `install-probes:spec-conformance`. What to fix: branch verdict on `using_default_event` (treat delta==0 as "counter wedged" FAIL, delta>0 as "counter works" PASS); or require `-event` on the command line and error out if missing.

**H-26. stop.ps1 cannot stop a randomized install** *(adversarial restatement of H-21)* — `/home/user/the-chamber/launcher/stop.ps1:18`. Sources: `install-probes:adversarial`. See H-21.

**H-27. recover.ps1 cannot undo a randomized install** *(adversarial restatement of S-31)* — `/home/user/the-chamber/recovery/recover.ps1:5`. Sources: `install-probes:adversarial`. See S-31.

**H-28. pmu_vmexit probe silently returns false PASS due to missing CPU pinning across arm/trigger/read** *(adversarial restatement of H-24)* — `/home/user/the-chamber/pentest/probes/pmu_vmexit/pmu_vmexit.c:189`. Sources: `install-probes:adversarial`. See H-24.

**H-29. load.ps1 IOCTL constants do not match the stated CTL_CODE formula** *(adversarial restatement of S-27)* — `/home/user/the-chamber/launcher/load.ps1:81`. Sources: `install-probes:adversarial`. See S-27.

**H-30. Every setup/launch script dot-sources a hardcoded per-user path C:\Users\lkhnj\...\_safety_gate.ps1** — `/home/user/the-chamber/INSTALL.ps1:7`
```
. "C:\Users\lkhnj\Downloads\testbench\gpu_spoof\_safety_gate.ps1"
Assert-NoAntiCheatRunning
```
Failure: INSTALL.ps1:7, UNINSTALL.ps1:13, tools/cloak_target.ps1:13, tools/obfuscate.ps1:12 dot-source the hardcoded absolute path with no `Test-Path` guard. On any non-lkhnj machine the dot-source fails (as a non-existent script invocation), and `Assert-NoAntiCheatRunning` is also undefined so the script aborts before build. install_service.ps1 / load.ps1 / stop.ps1 do guard with Test-Path (so they fail more gracefully but silently skip the anti-cheat gate — a safety degradation). Confidence: confirmed. Sources: `install-probes:adversarial`. What to fix: ship `_safety_gate.ps1` inside this repo at a known relative path; unconditionally guard every include with `Test-Path`; make the `Assert-NoAntiCheatRunning` call conditional on successful inclusion and loudly refuse to proceed if it is unavailable.

**H-31. msr_readout silently reports VERDICT: PASS when expected JSON is missing, even on HV leaks** — `/home/user/the-chamber/pentest/probes/msr_readout/main.c:261`
```
const char *verdict = (total_bad == 0 && have_expected) ? "PASS" :
                      (!have_expected ? "PASS" : "FAIL");
...
return (total_bad == 0) ? 0 : 1;
```
Failure: when `have_expected == false` and `leak_count > 0` (HV vendor-MSR cookies found in 0x40000000..0x400001FF or 0x4B564D00..0x4B564DFF), the ternary prints "VERDICT: PASS" while the exit code is 1. CI consumers that key on the stdout verdict see PASS, those that key on exit code see FAIL — stealth-leak evidence lost. `expected_7700x.json` is a bare relative path so any wrong cwd triggers this. Confidence: confirmed. Sources: `install-probes:adversarial`, `install-probes:spec-conformance`. What to fix: when `!have_expected`, treat any `leak_count > 0` as FAIL in both verdict string and exit code; refuse to print PASS without an expected file unless `-allow-no-baseline` is passed explicitly.

**H-32. msr_driver.c exposes arbitrary kernel RDMSR to any user via FILE_ANY_ACCESS device with no ACL** — `/home/user/the-chamber/pentest/probes/msr_readout/msr_driver.c:21`
```
#define IOCTL_MSR_READ             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
...
NTSTATUS st = IoCreateDevice(DriverObject, 0, &devName,
                             FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
```
Failure: no SDDL, no FILE_DEVICE_SECURE_OPEN, FILE_ANY_ACCESS IOCTL, symlink in `\DosDevices`. Any user process can open `\\.\ChamberMsrDriver` and RDMSR any 32-bit MSR including microcode rev (0x8B), platform ID (0x17), SMM_ADDR/SMM_MASK, LBR/DBG_CTL. On a Chamber-HV-enabled test rig, this becomes a one-IOCTL arbitrary-MSR-read channel for any local user to spot HV spoofing. Confidence: confirmed. Sources: `install-probes:adversarial`, `install-probes:spec-conformance`. What to fix: use `IoCreateDeviceSecure` with `SDDL_DEVOBJ_SYS_ALL_ADM_ALL`, add an MSR allowlist (seven named MSRs + two bounded ranges), require `SeDebugPrivilege` on the opener.

**H-33. tools/obfuscate.ps1 uses sc.exe create/delete, directly violating Phase 1.7's SCM-telemetry avoidance** *(adversarial restatement of H-22)* — `/home/user/the-chamber/tools/obfuscate.ps1:30`. Sources: `install-probes:adversarial`. See H-22.

**H-34. pmu_vmexit.c default event + unconditional (delta == 0) PASS rule yields spurious FAIL on bare metal** *(spec restatement of H-25)* — `/home/user/the-chamber/pentest/probes/pmu_vmexit/pmu_vmexit.c:234`. Sources: `install-probes:spec-conformance`. See H-25.

**H-35. pmu_vmexit.c does not pin thread affinity — PerfEvtSelCoreN is per-logical-processor** *(spec restatement of H-24)* — `/home/user/the-chamber/pentest/probes/pmu_vmexit/pmu_vmexit.c:143`. Sources: `install-probes:spec-conformance`. See H-24.

**H-36. msr_driver.c exposes arbitrary kernel RDMSR to any user via FILE_ANY_ACCESS** *(spec restatement of H-32)* — `/home/user/the-chamber/pentest/probes/msr_readout/msr_driver.c:21`. Sources: `install-probes:spec-conformance`. See H-32.

**H-37. pmu_driver.c exposes arbitrary PerfEvtSelCoreN WRMSR to any user via FILE_ANY_ACCESS** — `/home/user/the-chamber/pentest/probes/pmu_vmexit/pmu_driver.c:36`
```
#define IOCTL_PMU_ARM              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PMU_READ             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PMU_DISARM           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Failure: `IoCreateDevice` with no SDDL, symlink in `\DosDevices`, FILE_ANY_ACCESS on all IOCTLs; `PmuArm` bounds-checks `counter_index` only and passes the raw 64-bit `event_select` to `__writemsr(PerfEvtSelCore0+2*idx)`. Any user builds a ring-3 WRMSR primitive over 6 counters with full edge/invert/cmask/INT bits → combined with RDPMC (CR4.PCE) a microarchitectural side-channel toolkit; DISARM unconditionally writes 0, silently erasing concurrent ETW/WPR counter programming. Confidence: confirmed. Sources: `install-probes:spec-conformance`. What to fix: `IoCreateDeviceSecure` admin-only SDDL; whitelist event codes (OS|USR mask only); snapshot & restore PerfEvtSel on arm/disarm.

**H-38. tools/obfuscate.ps1 reintroduces every Phase 1.7 stealth leak the installer removes** *(spec-conformance super-restatement of H-22)* — `/home/user/the-chamber/tools/obfuscate.ps1:30`. Sources: `install-probes:spec-conformance`. See H-22.

**H-39. msr_readout prints VERDICT: PASS while exit code reports failure when expected_7700x.json is absent** *(spec restatement of H-31)* — `/home/user/the-chamber/pentest/probes/msr_readout/main.c:261`. Sources: `install-probes:spec-conformance`. See H-31.

**H-40. pentest/run_all.ps1 dot-sources an absolute path that only exists on the original developer's machine** *(spec restatement of S-32)* — `pentest/run_all.ps1:14`. Sources: `infra-docs:spec-conformance`. See S-32.

**H-41. Measure-PafishOutput regex never matches a single line of real pafish output** — `/home/user/the-chamber/pentest/ci/run_benchmarks.ps1:139`
```
if ($line -match '^\[(?<v>OK|BAD)\]\s+(?<check>.+?)(?:\s+-+\s+(?<detail>.*))?$') {
```
Failure: pafish emits `[+] check-name` (traced), `[-] check-name` (clean), `[*] section-header` — never `[OK]` / `[BAD]`. The regex matches zero lines, the parser returns an empty scores map, and compare_scores.ps1 therefore cannot surface a pafish regression. Phase 8.1's "reject any regression" gate silently excludes the single public benchmark the master plan calls out. Confidence: confirmed. Sources: `infra-docs:adversarial`. What to fix: rewrite the regex to `^\[(?<v>\+|-|\*)\]\s+(?<check>.+?)\s*$` and map `+`→detected (1), `-`→clean (0), `*`→section (skip); add a self-test entry that asserts ≥20 keys are collected per real run.

**H-42. Measure-AlKhaserOutput regex is keyed on markers al-khaser does not emit** — `/home/user/the-chamber/pentest/ci/run_benchmarks.ps1:180`
```
if ($line -match '^\[\*\]\s+(?<check>.+?)\s*:\s*(?<verdict>TRUE|FALSE)\s*$') {
```
Failure: al-khaser prints `[*] Checking <name> ---> [ GOOD ]` / `[ BAD ]` — no colon, no TRUE/FALSE. Zero matches, no al-khaser keys in flat scores, CI cannot detect a GOOD→BAD regression on `VMAware driver` or `Hypervisor port` checks. Confidence: confirmed. Sources: `infra-docs:adversarial`. What to fix: parse the actual `---> [ GOOD|BAD ]` form; map BAD→1, GOOD→0; add a self-test fixture.

### Medium

**M-1. CHAMBER_LOG in svm_build_vmcb runs at IPI_LEVEL** — `driver/svm_vmcb.c:248`. Reaches DbgPrintEx from the `KeIpiGenericCall` worker at IPI_LEVEL; debug-build hazard on checked kernels / KD-attached boxes. Confidence: probable. Sources: `driver-a:structural`, `driver-a:spec-conformance`. What to fix: compile `CHAMBER_LOG` to a no-op at IPI_LEVEL, or defer logs via a DPC queued from the IPI, or print only the first-CPU result once at PASSIVE_LEVEL after `svm_init_all_cpus` returns.

**M-2. host_stack_va is allocated but never used; guest runs on the caller's kernel stack** — `driver/svm_bringup.c:70`. `svm_build_vmcb` writes `save->rsp` to top-of-host-stack, then `vmrun.asm:46-47` overwrites it with the caller's live RSP before the first VMRUN. 16 KiB × #CPU of non-paged contiguous memory wasted per driver load. Confidence: confirmed. Sources: `driver-a:structural`, `driver-b:adversarial`. What to fix: either drop the allocation (and remove the field), or genuinely swap RSP in vmrun.asm's prologue to install host_stack_va for the host handler.

**M-3. Default VMEXIT case advances RIP to next_rip for exits where next_rip is architecturally undefined** — `driver/vmexit.c:58`. See S-16 for the detailed mechanism; filed at "medium/probable" from driver-a because the Phase 1 intercept set is narrow. Sources: `driver-a:structural`, `driver-a:adversarial`, `driver-b:spec-conformance`. What to fix: see S-16.

**M-4. scrub_service_key_name adjusts Length by -2 unconditionally; mismatches content length when original Length didn't count the NUL** — `driver/the_chamber.c:242`. For an ordinary ServiceKeyName (Length=16, MaximumLength=18 for "winhvmon"), after scrub the UNICODE_STRING advertises 7 chars while Buffer holds 8 printable WCHARs then NUL — Length-honoring APIs (RtlCompareUnicodeString) and wcslen-based readers disagree. Confidence: confirmed. Sources: `driver-a:structural`. What to fix: recompute Length as `(chars - 1) * sizeof(WCHAR)` after the overwrite rather than blindly subtracting 2.

**M-5. VMCB guest_asid_tlb field holds ASID only; comments in npt.c imply ORing bit 31 flushes TLB (it does not)** — `driver/npt.c:266`. `svm.h` groups ASID at 0x058 and TLB_CONTROL at 0x05C as separate ULONG fields; `npt.c:266/369/510` tells future callers to OR `(1u << 31)` into `guest_asid_tlb`, which would set bit 31 of the ASID (silently raising ASID to 0x80000001 — likely VMEXIT_INVALID on Zen 4 where client NASID is low thousands) and trigger zero flushes. Confidence: confirmed. Sources: `driver-a:structural`. What to fix: expose a dedicated `tlb_control` helper that writes 0x03 (flush-this-ASID) to the TLB_CONTROL byte at offset 0x05C; update the npt.c comments to stop recommending the bogus OR.

**M-6. Default VMEXIT case advances RIP via vmcb.ctl.next_rip** *(adversarial restatement of S-16)* — `driver/vmexit.c:58`. Sources: `driver-a:adversarial`. See S-16.

**M-7. crash_marker_present swallows probe failures** — `driver/the_chamber.c:390`. Non-NOT_FOUND / non-PATH_NOT_FOUND errors (STATUS_SHARING_VIOLATION from an AV filter, STATUS_ACCESS_DENIED after policy change, STATUS_IO_DEVICE_ERROR after disk event) leave `out_present=FALSE`; DriverEntry proceeds as if there were no prior crash, defeating the load-time safety gate. Confidence: confirmed. Sources: `driver-a:adversarial`. What to fix: treat any non-NOT_FOUND/non-PATH_NOT_FOUND status as "present or indeterminate — refuse to load"; only flag absent on explicit NOT_FOUND.

**M-8. crash_marker_drop failure is ignored** — `driver/the_chamber.c:409`. `(void)crash_marker_drop();` silently discards ZwCreateFile/ZwWriteFile failures. If drop fails and a bugcheck occurs between here and `crash_marker_clear`, no marker survives → next boot reloads the driver into the same crash. Confidence: confirmed. Sources: `driver-a:adversarial`. What to fix: check status, fail DriverEntry if the marker cannot be written (or log ERROR and set a flag that gates the matching `crash_marker_clear`).

**M-9. vmrun.asm timing_update runs AFTER TIMING_HOST_INTERVAL_END, so its own cycles leak to the guest** — `driver/vmrun.asm:119`
```
rdtsc
shl rdx, 32
or rax, rdx
mov [r15 + TIMING_HOST_INTERVAL_END], rax
mov rcx, r15
sub rsp, 32
call timing_update
```
Failure: END is captured before `timing_update` runs. The locked `InterlockedAdd64`, VMCB `tsc_offset` write, clean-bit clear, call/ret and GPR reload all happen after END and are never charged to accumulated host overhead. Net under-subtraction of ~80-200 cycles per VMEXIT — a deterministic, additive timing leak, exactly the kind a guest RDTSC bracket can measure. Confidence: confirmed. Sources: `driver-a:adversarial`. What to fix: capture `TIMING_HOST_INTERVAL_END` after `timing_update` returns (e.g. move the rdtsc block to just before the final `jmp host_vmexit_loop`), or add a static constant to `g_fixed_vmexit_cost` sized to `timing_update`'s measured worst case.

**M-10. IoCreateDevice uses FILE_DEVICE_SECURE_OPEN without an explicit SDDL** *(partial restatement of H-11)* — `driver/the_chamber.c:415`. Sources: `driver-a:adversarial`. See H-11.

**M-11. Hyper-V paravirt MSR catch range ends at 0x400000FF; master plan calls for 0x400001FF** *(spec restatement of S-6)* — `driver/vmexit.c:133`. Sources: `driver-a:spec-conformance`. See S-6.

**M-12. g_npt_pages cap of 8192 silently drops pages past the limit, leaking them on teardown** — `driver/npt.c:73`. `npt_alloc_page` returns a usable VA even when it cannot record the page in the tracker, so later `npt_free_tables` leaks it. With `g_npt_slots[32]`, the architectural ceiling for lazy-grow is ~16417 pages (PML4 + 32 PDPTs + 32×512 PDs), so sustained sparse NPFs can exceed 8192. Confidence: confirmed. Sources: `driver-b:structural`. What to fix: either raise the cap to match the architectural ceiling (`16 KiB` entries is fine) or fail allocation when full and inject #PF into the guest rather than return an untracked VA.

**M-13. DRIVER_OBJECT DACL is default: any admin-equivalent user can open the device and issue SHUTDOWN/KICK** *(adversarial restatement of H-11)* — `driver/the_chamber.c:415`. Sources: `driver-b:adversarial`. See H-11.

**M-14. stealth_revert restores drv->DriverName and DriverSection from zero-initialized statics when stealth_apply never completed** — `driver/stealth.c:232`. `stealth_apply` returns STATUS_NOT_FOUND early (lines 164-166, 180-183) before the DriverObject saves on line 219-221, leaving `g_saved_driver_name={0,0,NULL}` and `g_saved_driver_section=NULL`. DriverEntry ignores stealth_apply's status with `(void)`, so UnloadRoutine's `stealth_revert` writes those zeros into `drv->DriverName`/`drv->DriverSection`, and `MmUnloadSystemImage` later dereferences a NULL DriverSection → bugcheck. Confidence: confirmed. Sources: `driver-b:spec-conformance`. What to fix: gate the DriverObject restore on an explicit "apply fully succeeded" flag; or move the DriverObject saves BEFORE the early-returns in stealth_apply.

**M-15. npt_init rounds the lowest MmGetPhysicalMemoryRanges span outward to 2 MB and ends up identity-mapping the VGA MMIO / ROM hole as cached, writable, user** — `driver/npt.c:193`. First usable RAM at 0x1000 rounds down to 0x0, so the first 2 MB leaf covers 0x0-0x1FFFFF including VGA 0xA0000-0xBFFFF and ROM shadow 0xC0000-0xFFFFF, mapped WB-cached/writable/user/executable. Master plan §2.6 requires UC for VGA, RX for ROM. Confidence: confirmed. Sources: `driver-b:spec-conformance`. What to fix: skip RAM below 0x100000 in the identity map; add explicit 2 MB leaves with correct cache attributes for the legacy MMIO holes.

**M-16. msr_readout prints 'VERDICT: PASS' while exiting non-zero when expected JSON is missing** *(structural restatement of H-31)* — `/home/user/the-chamber/pentest/probes/msr_readout/main.c:260`. Sources: `install-probes:structural`. See H-31.

**M-17. cross_core_rdtsc pins to CPUs 0 and 1 — SMT siblings on 7700X, not cross-physical-core** — `/home/user/the-chamber/pentest/probes/cross_core_rdtsc/main.c:142`
```
ctx c0 = { (DWORD_PTR)1,       &go, &round, slots0, 0 };
ctx c1 = { (DWORD_PTR)(1 << 1),&go, &round, slots1, 0 };
```
Failure: per master plan §2.7 the 7700X's compact MADT ordering places logical CPUs 0 and 1 on the same physical core; Zen 4 TSC is per-physical-core so siblings always agree, making the probe a null test for per-vCPU TSC_OFFSET skew — the very bug it exists to find. Confidence: confirmed. Sources: `install-probes:structural`, `install-probes:spec-conformance`. What to fix: call `GetLogicalProcessorInformationEx(RelationProcessorCore)` and pick one logical CPU from each of two different physical cores (e.g. CPUs 0 and 2 on a sibling-adjacent layout).

**M-18. msr_readout cannot guarantee MSR values are read from a single core — per-core MSRs may read inconsistently** — `/home/user/the-chamber/pentest/probes/msr_readout/msr_driver.c:42`. No affinity/IRQL raise; HWCR, VM_HSAVE_PA, SMM_ADDR/MASK, HV-range RDMSRs may each land on a different CPU, so the probe captures a mosaic of per-core state rather than a consistent per-CPU baseline. Confidence: probable. Sources: `install-probes:structural`. What to fix: pin the probe to CPU 0 (`SetThreadAffinityMask`) and IOCTL-marshal all MSR reads through a single DPC targeted at that CPU; or iterate over every logical CPU and record per-CPU values explicitly.

**M-19. INSTALL.ps1 / UNINSTALL.ps1 / cloak_target.ps1 / obfuscate.ps1 dot-source a user-specific absolute path without Test-Path guard** *(infra restatement of H-30)* — `/home/user/the-chamber/INSTALL.ps1:7`. Sources: `install-probes:structural`. See H-30.

**M-20. install_service.ps1 does not enable BCD testsigning, but UNINSTALL unconditionally disables it** — `/home/user/the-chamber/UNINSTALL.ps1:88`
```
if (-not $KeepTestSigning) {
    Write-Host "Reverting bcdedit (test-signing + nointegritychecks)..." -ForegroundColor White
    bcdedit /set testsigning off | Out-Null
    bcdedit /set nointegritychecks off | Out-Null
}
```
Failure: `grep` across INSTALL.ps1 and `launcher/install_service.ps1` shows no `bcdedit`. On a fresh machine NtLoadDriver fails STATUS_INVALID_IMAGE_HASH because testsigning isn't on. UNINSTALL then unconditionally turns both flags off, clobbering pre-existing user state (unrelated test-signed drivers, Dev Mode). Confidence: confirmed. Sources: `install-probes:structural`. What to fix: INSTALL snapshots BCD state (bcdedit /export + a reg tag of pre-state flags) and enables testsigning only if it was off; UNINSTALL restores from the snapshot rather than blindly clearing.

**M-21. pmu_driver clobbers PerfEvtSelCore0 without saving the OS/profiler's prior value** — `/home/user/the-chamber/pentest/probes/pmu_vmexit/pmu_driver.c:73`. WPR/xperf/AMD uProf/ETW SampledProfile may be using these counters; probe silently corrupts concurrent profiling and writes 0 back on disarm. Confidence: confirmed. Sources: `install-probes:adversarial`. What to fix: RDMSR the prior PerfEvtSel + PerfCtr, stash in per-counter state, restore on disarm; fail the arm if the OS already has the counter programmed (or expose a `--force` flag).

**M-22. cross_core_rdtsc pins the two producer threads to CPUs 0 and 1, which are SMT siblings on the 7700X** *(spec restatement of M-17)* — `/home/user/the-chamber/pentest/probes/cross_core_rdtsc/main.c:142`. Sources: `install-probes:spec-conformance`. See M-17.

**M-23. UNINSTALL.ps1 and recover.ps1 overwrite BCD testsigning/nointegritychecks state that INSTALL.ps1 never set** *(spec restatement of M-20)* — `/home/user/the-chamber/UNINSTALL.ps1:89`. Sources: `install-probes:spec-conformance`. See M-20.

**M-24. install_service.ps1 leaves orphan unsigned driver in System32 if re-sign fails after cfg patch** — `/home/user/the-chamber/launcher/install_service.ps1:152`. Copy-Item puts the signed .sys in System32\drivers\<rand>.sys, Patch-DriverConfig overwrites bytes (invalidating AuthentiCode), re-sign at line 152 then throws under `$ErrorActionPreference='Stop'` on missing signtool/PFX/password with no cleanup — a patched-unsigned .sys accumulates per failed install. Confidence: confirmed. Sources: `install-probes:spec-conformance`. What to fix: wrap the copy-patch-sign sequence in try/finally; `Remove-Item -ErrorAction SilentlyContinue $dstSys` in the finally if the sign step did not succeed; or stage to a temp file and `Move-Item` after successful re-sign.

**M-25. msr_driver.c RDMSR passes a user-supplied ULONG to __readmsr without range-check** — `/home/user/the-chamber/pentest/probes/msr_readout/msr_driver.c:45`. `__try/__except` catches #GP from unimplemented MSRs but not #MC from documented machine-check-on-read MSRs; unprivileged caller can walk the MSR space probing. Confidence: probable. Sources: `install-probes:spec-conformance`. What to fix: validate `msr` against an allowlist of exactly the MSRs the probe's `main.c` reads before dispatching to TryReadMsr.

**M-26. pmu_driver.c reads counters via __readmsr(PerfCtrCoreN) rather than __readpmc** — `/home/user/the-chamber/pentest/probes/pmu_vmexit/pmu_driver.c:82`. Exercises the MSR-intercept path rather than the RDPMC-intercept path the HV cares about (per master plan §2.1 defense #3 which mandates intercepting RDPMC). A spec-conformant HV with RDPMC-intercept + MSR-passthrough reads clean through the probe. Confidence: probable. Sources: `install-probes:spec-conformance`. What to fix: use `__readpmc(idx)` in ring-0; or arrange `CR4.PCE` and `__readpmc` in the user-mode probe.

**M-27. run_benchmarks.ps1 throw-message uses backslash-escape (not a PS escape); interpolates the empty env var it is complaining about** — `/home/user/the-chamber/pentest/ci/run_benchmarks.ps1:312`
```
throw "VM host not specified. Pass -VmHost or set \$env:CHAMBER_TEST_VM, or pass -NoRemote."
```
Failure: `\$env:...` in a PS double-quoted string renders as literal `\` followed by the expanded value of `$env:CHAMBER_TEST_VM`. Reaching this throw implies the env var is empty (since `$VmHost` defaults from it), so the message collapses to "…set \, or pass -NoRemote." — the remediation hint is lost. Sibling `pentest/corpus/run_corpus.ps1:123` uses backtick correctly. Confidence: confirmed. Sources: `infra-docs:structural`. What to fix: use ``` `$env:CHAMBER_TEST_VM ``` with a backtick.

**M-28. run_all.ps1 pins ReportDir to absolute C:\THE_CHAMBER\pentest\reports regardless of where the script is invoked from** — `/home/user/the-chamber/pentest/run_all.ps1:18`. Breaks the README's "two-run diff" workflow for any clone outside `C:\THE_CHAMBER`. Sibling scripts derive paths from `$MyInvocation.MyCommand.Path`. Confidence: confirmed. Sources: `infra-docs:structural`. What to fix: `$ReportDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'reports'`.

**M-29. README.md documents sc query / \\.\THE_CHAMBER control paths that Phase 1 explicitly abolished** — `/home/user/the-chamber/README.md:25`. The documented status-check commands return ERROR 1060 / ERROR_FILE_NOT_FOUND on a successful Phase 1 install. Confidence: confirmed. Sources: `infra-docs:structural`. What to fix: update README to describe reading `C:\THE_CHAMBER\logs\last_install.txt` and using `\\.\<random>` with the correct CTL_CODE values.

**M-30. README.md architecture summary still claims the driver unlinks from PsLoadedModuleList; Phase 1 replaced unlink with in-place rename** — `/home/user/the-chamber/README.md:11`. `stealth.c` does an in-place UNICODE_STRING rename against pci.sys as donor, as `phase1_done.md` records. README still names the superseded unlink, including in the "Known limits" BugCheck 0x109 warning. Confidence: confirmed. Sources: `infra-docs:structural`. What to fix: rewrite the paragraph to describe the rename-in-place mechanism and the specific donor; update the known-limits warning to cover rename-era risks (donor process unload, UNICODE_STRING Buffer/Length/MaximumLength concurrency).

**M-31. audit/detection_surface.md is a pre-Phase-1 audit kept committed as if it were current state** — `/home/user/the-chamber/audit/detection_surface.md:6`. Cites `stealth.c:93-95` RemoveEntryList calls and `timing.c:25-28` uncalled `timing_before_vmrun` that no longer exist; still appears in `docs/operations/README.md:52` as the "current state of the driver." Confidence: confirmed. Sources: `infra-docs:structural`. What to fix: either rebase the audit onto post-Phase-1 code, or move the file to `audit/archived/2026-11-pre-phase1.md` and add a stub pointing readers at `phase1_done.md`.

**M-32. ceilings.md recommends AMD cache partitioning through an MSR family that is not the AMD cache-QoS interface** — `/home/user/the-chamber/docs/operations/ceilings.md:437`. Cites MSR 0xC0000300 for QoS, but AMD's Platform QoS lives in the 0xC000_02xx / SMCA-adjacent range on EPYC and is not publicly exposed on client 7700X. Confidence: probable. Sources: `infra-docs:structural`. What to fix: cite the specific family-19h PPR MSR name for server parts and explicitly flag "not documented on client 7700X" for the current target, or remove the "expensive mitigation" guidance until a concrete path exists.

**M-33. FAILURE_WORKFLOW.md asserts a Zen 4 BRS-enable MSR that does not match AMD's documented control** — `/home/user/the-chamber/pentest/maintenance/FAILURE_WORKFLOW.md:37`. The doc names MSR 0xDC01 as the BRS-enable; actual AMD family-19h BRS lives in DBG_EXTN_CFG at MSR 0xC000_010F (LbrExtEn bit 6). Confidence: probable. Sources: `infra-docs:structural`. What to fix: replace with `MSR 0xC000_010F` and reference the family-19h PPR; verify any companion sample code uses the right MSR.

**M-34. compare_scores.ps1 silently drops any score value that fails [int] coercion, turning data-type regressions into spurious 'dropped check' regressions** — `/home/user/the-chamber/pentest/ci/compare_scores.ps1:77`. Empty catch inside `Get-FlatScores` — a probe that starts emitting "PASS"/"true"/"0.5" has its key vanish from current, appear in `$droppedKeys`, and trigger a false "measurement lost" regression. Blocks Phase 8.4 baseline refresh. Confidence: confirmed. Sources: `infra-docs:adversarial`. What to fix: log a warning in the catch; expose dropped-due-to-cast separately from dropped-due-to-missing, so CI can distinguish schema drift from actual coverage loss.

**M-35. discipline.md crashdump block uses wmic.exe, which is not installed by default on Windows 11 24H2** — `/home/user/the-chamber/docs/operations/discipline.md:640` — 24H2 moved wmic.exe to Feature-on-Demand; the documented pagefile-sizing step fails silently, and the complete kernel dump the audit relies on doesn't materialize. The `\` line continuation is also wrong for cmd/PowerShell. Confidence: confirmed. Sources: `infra-docs:adversarial`. What to fix: switch to `Set-CimInstance -Query "SELECT * FROM Win32_PageFileSetting" -Property @{InitialSize=36864;MaximumSize=36864}` (or Set-ItemProperty on the Memory Management registry key); use backtick line continuation.

**M-36. synthetic_values_table.md lists the KVM MSR range 0x4B564D00..0x4B564DFF as a CPUID leaf row** — `/home/user/the-chamber/audit/synthetic_values_table.md:39`. KVM's CPUID signature lives at 0x40000000..0x40000001; 0x4B564D* is its MSR range. A "single source of truth" row that misfiles MSRs as CPUID leaves will misdirect reviewers. Confidence: confirmed. Sources: `infra-docs:adversarial`, `infra-docs:spec-conformance`. What to fix: move the 0x4B564D* row to the MSR table; restate the KVM CPUID row at the correct 0x40000000..0x40000001 range; add a top-of-table note clarifying the two interfaces.

**M-37. run_benchmarks.ps1 probe-result unpacking crashes the whole run on a single malformed probe JSON** — `/home/user/the-chamber/pentest/ci/run_benchmarks.ps1:345`. `[int]$pr.payload.score` throws under Stop/StrictMode for non-numeric strings; the outer foreach is not wrapped in try/catch, so one bad probe aborts the runner before scores.json is written. Confidence: probable. Sources: `infra-docs:adversarial`. What to fix: wrap the per-probe payload unpacking in try/catch, record a `probes.<name>.parse_error=1` key, continue the loop.

**M-38. run_benchmarks.ps1 Invoke-ProbeBattery dies hard when $ProbesSourceDir does not exist** — `/home/user/the-chamber/pentest/ci/run_benchmarks.ps1:241`. `Get-ChildItem -ErrorAction Stop` with no existence check; a fresh checkout or sparse clone without `pentest/probes/` aborts the script before compare_scores.ps1 runs. Confidence: confirmed. Sources: `infra-docs:adversarial`. What to fix: guard with `if (-not (Test-Path -LiteralPath $ProbesDir)) { Write-Warning "..."; return @() }`.

**M-39. pentest/corpus/run_corpus.ps1 always exits 0 regardless of per-sample outcome** — `pentest/corpus/run_corpus.ps1:261`. `monthly_check.ps1:142` keys corpus regression off `$LASTEXITCODE -ne 0`, which is never true. The entire corpus leg of the monthly workflow is wired as a no-op. Confidence: confirmed. Sources: `infra-docs:spec-conformance`. What to fix: compute exit code from the outcomes list (any non-completed sample → exit 1), and also surface a structured regression summary that `monthly_check.ps1` reads directly.

**M-40. pentest/run_all.ps1 cpuid probe only enumerates 0x40000000..0x40000010** *(spec restatement of L-16 below; raised to medium when scoped as "single source of truth" vs the harness-coverage framing)* — `pentest/run_all.ps1:261`. Sources: `infra-docs:spec-conformance`. See L-16.

**M-41. audit/detection_surface.md line 63 tells the implementer to populate MSRPM bits for 0x40000000..0x400000FF** — `audit/detection_surface.md:63`. Those addresses are outside all three MSRPM-addressable windows; a literal implementation would compute an invalid offset and either corrupt the bitmap or no-op. Upper bound 0x400000FF is also narrower than the master plan's 0x400001FF widening. Confidence: confirmed. Sources: `infra-docs:spec-conformance`. What to fix: rewrite the paragraph to say "handle 0x40000000..0x400001FF plus 0x4B564D00..0x4B564DFF in `handle_msr`'s dispatcher; DO NOT populate MSRPM bits for them"; update the suggested patch accordingly.

**M-42. audit/detection_surface.md line 70 recommends a 'delta = now - vmrun_entry_tsc' TSC fix that is the master-plan round-2 bug reintroduced** — `audit/detection_surface.md:70`. Would re-regress to the round-2 bracket (span includes guest execution → tsc_offset pulls guest TSC backward). Phase 1 ships the round-3 inter-VMRUN bracket (host_interval_start/end). Confidence: confirmed. Sources: `infra-docs:spec-conformance`. What to fix: rewrite the suggested patch to describe the round-3 bracket (start right after VMRUN returns, end right before next VMRUN) and reference `timing.c`'s current implementation.

**M-43. audit/synthetic_values_table.md confuses CPUID leaf addresses with MSR addresses for Hyper-V and KVM rows in the CPUID table** *(spec restatement of M-36)* — `audit/synthetic_values_table.md:39`. Sources: `infra-docs:spec-conformance`. See M-36.

**M-44. docs/operations/discipline.md 9.4.4 instructs the operator to run `wmic` on Windows 11 24H2** *(spec restatement of M-35)* — `docs/operations/discipline.md:640`. Sources: `infra-docs:spec-conformance`. See M-35.

### Low

**L-1. the_chamber.inx retains branded strings; contradicts Phase 1.7 "drop the INF" guidance** — `driver/the_chamber.inx:47`. Four "THE_CHAMBER" entries in `[Strings]`, three "winhvmon.sys" references; `strings`/`findstr` scan of the install bundle fingerprints the brand. Confidence: confirmed. Sources: `driver-a:structural`. What to fix: delete the INF (master plan §1.7 item 5 says drop it), or at minimum replace every brand string with a neutral placeholder patched per-install by the launcher.

**L-2. msrpm_set_intercept silently drops out-of-window MSRs; Hyper-V loop is dead code** — `driver/svm_vmcb.c:102`. Loop at `svm_vmcb.c:129` writes zero bits because the Hyper-V range is outside all three MSRPM windows; relies on IVEC3_MSR auto-intercept. Confidence: confirmed. Sources: `driver-a:adversarial`, `driver-b:adversarial`, `driver-b:spec-conformance`. What to fix: replace the loop with `NT_ASSERT`-on-out-of-range in the helper and a comment noting that out-of-window MSRs are auto-intercepted and handled in `handle_msr`.

**L-3. vmcb_clean_bits initialized to zero but only ever ANDed with ~bit — never actually set clean** — `driver/svm_vmcb.c:178`. `timing.c:129` only `&= ~VMCB_CLEAN_BIT_TSC` on an already-zero field; hardware reloads the entire VMCB on every VMRUN. Perf-only (correctness is conservative). Confidence: confirmed. Sources: `driver-a:adversarial`. What to fix: after every full VMCB write set `vmcb_clean_bits = ~0u`; clear only the specific group whose fields changed on the next pass.

**L-4. msrpm_set_intercept loop over 0x40000000..0x400000FF is a silent no-op** *(spec restatement of L-2)* — `driver/svm_vmcb.c:129`. Sources: `driver-a:spec-conformance`. See L-2.

**L-5. DR0-DR3 are not saved/restored around VMRUN** — `driver/vmrun.asm:53`. VMCB auto-saves DR6/DR7 only; DR0-DR3 are shared host/guest. Currently silent because the handler never writes them, but Phase 6.3 HW-breakpoint usage flips this to active leak. Confidence: probable. Sources: `driver-a:spec-conformance`. What to fix: add `mov [ctx+DR0_SAVE], dr0` (×4) post-VMEXIT before any host handler code, reload before VMRUN; alternatively trap DR0-DR3 writes via intercept_dr_read/write bitfields.

**L-6. DbgPrintEx (CHAMBER_LOG) called from inside the IPI_LEVEL VMCB-build path in debug builds** *(spec restatement of M-1)* — `driver/svm_vmcb.c:248`. Sources: `driver-a:spec-conformance`. See M-1.

**L-7. VMCB.save.rsp is written both by svm_build_vmcb and by vmrun.asm, with the second clobber silently winning** *(partial restatement of M-2)* — `driver/svm_vmcb.c:246`. Sources: `driver-b:adversarial`. See M-2.

**L-8. crash_marker_drop failure is logged but ignored — a later crash leaves no marker** *(partial restatement of M-8)* — `driver/the_chamber.c:409`. Sources: `driver-b:adversarial`. See M-8.

**L-9. msrpm_set_intercept loop for the Hyper-V vendor range silently does nothing** *(spec restatement of L-2)* — `driver/svm_vmcb.c:129`. Sources: `driver-b:spec-conformance`. See L-2.

**L-10. cross_core_rdtsc producer thread does not check SetThreadAffinityMask return value** — `/home/user/the-chamber/pentest/probes/cross_core_rdtsc/main.c:70`. Sibling `rdtscp_tsc_aux` probe does check; cross_core_rdtsc does not, so a mask that fails to apply (multi-group machines) degenerates silently. Confidence: confirmed. Sources: `install-probes:structural`. What to fix: capture `prev = SetThreadAffinityMask(...)` and fail the probe if `prev==0`, matching rdtscp_tsc_aux.

**L-11. cross_core_rdtsc main thread's final round number is never sampled** — `/home/user/the-chamber/pentest/probes/cross_core_rdtsc/main.c:86`. Producer breaks on `r >= ROUNDS` so round `ROUNDS=4096` is never captured — JSON reports 4096 rounds while max paired samples is 4095. Off-by-one, negligible statistical impact. Confidence: confirmed. Sources: `install-probes:adversarial`. What to fix: loop main thread `r=1..ROUNDS` and change producer guard to `r <= ROUNDS`, or honestly report `"rounds":4095` in the JSON.

**L-12. INSTALL.ps1 unconditionally dot-sources a per-operator path '_safety_gate.ps1' under a hardcoded 'lkhnj' profile** *(spec restatement of H-30)* — `/home/user/the-chamber/INSTALL.ps1:7`. Sources: `install-probes:spec-conformance`. See H-30.

**L-13. run_detectors.ps1 builds pafish/invizzzible as Win32 (32-bit) but vmaware as x64** — `/home/user/the-chamber/pentest/detectors/run_detectors.ps1:256`. Cross-tool bitness inconsistency; pafish64-only checks and vmaware x86-only demo checks each unmeasured from one side. Confidence: confirmed. Sources: `infra-docs:structural`. What to fix: pick one target architecture across tools consistently (x64 for all), or run both and tag results with `.arch=x86`/`.arch=x64`.

**L-14. monthly_check.ps1 appends a markdown-table row built from unvalidated version strings; a '|' in a version breaks the table** — `/home/user/the-chamber/pentest/maintenance/monthly_check.ps1:183`. Confidence: confirmed. Sources: `infra-docs:structural`. What to fix: `$newThemida -replace '\|','\|'` before interpolation; or write the audit row to a CSV and re-render the table on demand.

**L-15. compare_scores.ps1 silently drops score keys that do not cast to int** *(partial restatement of M-34)* — `/home/user/the-chamber/pentest/ci/compare_scores.ps1:76`. Sources: `infra-docs:structural`. See M-34.

**L-16. run_corpus.ps1 timeout branch leaks the stdout/stderr temp files it just opened on the sandbox VM** — `/home/user/the-chamber/pentest/corpus/run_corpus.ps1:174`. Remove-Item only on the happy path; `GetTempFileName` creates a 0-byte reservation per leak. Over months the VM TEMP fills. Confidence: confirmed. Sources: `infra-docs:adversarial`, `infra-docs:spec-conformance`. What to fix: move cleanup to a finally block; or wrap the whole function in try/finally.

**L-17. run_all.ps1 records a 'SVM revision' for CPUID 0x8000000A even when the leaf is above max_extended_leaf** — `/home/user/the-chamber/pentest/run_all.ps1:308`. Intel CPUs return highest basic leaf echo for out-of-range extended queries; the JSON publishes that as a non-zero "SVM revision" alongside `leaf_8000000A_valid=false`. Cross-vendor baseline false diffs. Confidence: confirmed. Sources: `infra-docs:adversarial`. What to fix: `$svmRevision = if ($svmLeafValid) { [int]($regs['8000000A'][0] -band 0xFF) } else { $null }`.

**L-18. README.md architecture description still claims the driver unlinks from PsLoadedModuleList** *(adversarial restatement of M-30)* — `/home/user/the-chamber/README.md:11`. Sources: `infra-docs:adversarial`. See M-30.

**L-19. run_all.ps1 CPUID coverage samples only 0x40000000..0x40000010 plus a handful of extended leaves** — `/home/user/the-chamber/pentest/run_all.ps1:262`. Misses 0x40000080 and 0x40000100 which master plan §1.1 and `detection_surface.md` name as VMAware/pafish probe targets. Confidence: confirmed. Sources: `infra-docs:adversarial`. What to fix: extend the loop to cover 0x40000000..0x400001FF in 4-leaf steps, and explicitly add 0x40000080 and 0x40000100 to the capture set.

**L-20. pentest/corpus/run_corpus.ps1 timeout branch returns without removing the per-run temp files on the remote VM** *(spec restatement of L-16)* — `pentest/corpus/run_corpus.ps1:180`. Sources: `infra-docs:spec-conformance`. See L-16.

**L-21. pentest/probes/cpuid_hypervisor_range/main.c comment misstates AMD architectural reservation for the 0x40000000..0x400001FF CPUID range** — `pentest/probes/cpuid_hypervisor_range/main.c:6`. Says "AMD Zen 4 reserves" when the range is reserved by convention (VMware/Hyper-V TLFS/KVM/Xen), not architecturally. Low-severity doc defect. Confidence: confirmed. Sources: `infra-docs:spec-conformance`. What to fix: rewrite the opening comment to say "conventionally reserved" and cite the TLFS / KVM docs instead of AMD; qualify the all-zeros-on-bare-metal claim as "observed on Zen 4" rather than architecturally mandated.

**L-22. audit/detection_surface.md line 202 revives the master-plan-contradicted 'VMMCALL behavior depends on EFER.SVME decoder gating' framing** — `audit/detection_surface.md:202`. Master plan explicitly deprecated that framing: VMMCALL outside guest mode always raises #UD regardless of CPL and SVME. Suggested patch is still right, rationale is wrong. Confidence: confirmed. Sources: `infra-docs:spec-conformance`. What to fix: replace the parenthetical with "VMMCALL outside guest mode: #UD unconditionally, regardless of CPL and SVME."

**L-23. pentest/README.md cpuid section documents leaves 0x80000001..0x8000000A as captured, but the script only probes 6 extended leaves** — `pentest/README.md:18`. Script omits 0x80000005-0x80000009 (cache/TLB, invariant TSC, MAXPHYADDR) while README advertises inclusive range of 10. Confidence: confirmed. Sources: `infra-docs:spec-conformance`. What to fix: extend `run_all.ps1`'s extended-leaf loop to cover 0x80000005..0x80000009; or truncate the README claim to match code.

**L-24. pentest/ci/run_benchmarks.ps1 constructs the remote per-exe temp file path twice with identical logic, and does not clean the files up on failure** — `pentest/ci/run_benchmarks.ps1:203`. Three identical path expressions; stale files accumulate. Confidence: confirmed. Sources: `infra-docs:spec-conformance`. What to fix: hoist the path into `$outFile`/`$errFile` once, pass to Start-Process, Remove-Item in a finally.

**L-25. pentest/ci/run_benchmarks.ps1 missing-exe branch sets 'status_error' key but keeps old baseline scores** — `pentest/ci/run_benchmarks.ps1:262`. A build regression that silently breaks a probe binary becomes 'measurement lost' not 'regression'; an `-UpdateBaseline` after such a run bakes a baseline with no score for the probe and future detections show as 'new check' instead of regression. Confidence: probable. Sources: `infra-docs:spec-conformance`. What to fix: when a probe is missing emit a `status_error=1` AND also carry baseline score/verdict_fail values forward with a `stale=1` marker; refuse `-UpdateBaseline` on any run that has `status_error` keys.

**L-26. pentest/ci/compare_scores.ps1 swallows all non-integer scores silently at Get-FlatScores** *(partial restatement of M-34)* — `pentest/ci/compare_scores.ps1:77`. Sources: `infra-docs:spec-conformance`. See M-34.

### Nit

**N-1. `~(1 << 31)` in CPUID masking is C undefined behavior (signed int left-shift into sign bit)** — `driver/vmexit.c:87`. MSVC/WDK generates the expected `0x7FFFFFFF` mask in practice. Confidence: confirmed. Sources: `driver-a:spec-conformance`, `driver-b:structural`, `driver-b:adversarial`. What to fix: `regs[2] &= ~(1u << 31);` (or `~0x80000000u`).

**N-2. handle_cpuid uses signed `1 << 31` - undefined behavior under C** *(duplicate of N-1)* — `driver/vmexit.c:87`. Sources: `driver-b:structural`. See N-1.

**N-3. msrpm_set_intercept silently drops out-of-window MSRs; Hyper-V loop is confusing dead code** *(nit restatement of L-2)* — `driver/svm_vmcb.c:102`. Sources: `driver-b:adversarial`. See L-2.

**N-4. expected_7700x.json documents TSC_RATIO (0xC0000104) as Q32.32 fixed point — design doc states the correct encoding is 8.32** — `/home/user/the-chamber/pentest/probes/msr_readout/expected_7700x.json:27`. Value 0x100000000 (identity 1.0) happens to encode the same bit pattern in both layouts, so the file still works; comment is misleading for future non-unity edits. Confidence: confirmed. Sources: `install-probes:structural`. What to fix: update the `_0xC0000104_name` field to say `"8.32 (integer [39:32], fraction [31:0], [63:40] MBZ)"`.

**N-5. cache_sidechannel/tlb_pollution return expression uses `(acc & 0ULL)` — dead code; buffers are only kept live by the volatile pointer** — `/home/user/the-chamber/pentest/probes/cache_sidechannel/main.c:93`. The `volatile uint8_t *` does the real DCE barrier work; `acc & 0ULL` is a no-op the compiler folds away. Would silently break if the volatile qualifier were ever dropped. Confidence: confirmed. Sources: `install-probes:structural`. What to fix: remove the dead XOR and add a comment that `volatile *buf` is the DCE barrier.

**N-6. cpuid_hypervisor_range top-of-file comment says 0x40000000..0x400001FF but the loop walks through 0x40000200 inclusive** — `/home/user/the-chamber/pentest/probes/cpuid_hypervisor_range/main.c:69`. Off-by-one between comment and code. Confidence: confirmed. Sources: `install-probes:structural`. What to fix: change the loop bound to `leaf <= 0x400001F0u` or update the comment to say 0x40000200.

**N-7. Invoke-RemoteBenchmark leaves per-run stdout/stderr temp files in the remote $env:TEMP with no cleanup** — `/home/user/the-chamber/pentest/ci/run_benchmarks.ps1:203`. Deterministic filenames so overwrites prevent unbounded growth but stale output persists across runs. Confidence: confirmed. Sources: `infra-docs:structural`. What to fix: `Remove-Item -ErrorAction SilentlyContinue $outFile, $errFile` at the end of the script block.

**N-8. pentest/ci/run_benchmarks.ps1 throw-message uses `\$env:` escape that PowerShell does not recognise** *(duplicate of M-27)* — `pentest/ci/run_benchmarks.ps1:312`. Sources: `infra-docs:spec-conformance`. See M-27.

## Scope coverage

Wave 1 covered four distinct audit scopes, each exercised by three verification lenses (correctness-trace, spec-conformance, reproducibility):

1. **driver-a** — internal driver code review, pass A. Covers `driver/*.c`, `driver/*.h`, `driver/*.asm`, `driver/*.inx` focused on structural correctness, adversarial reachability, and spec conformance against the AMD64 APM Vol 2 and the Phase 1 master plan.
2. **driver-b** — internal driver code review, pass B. Independent re-scan of the same source tree; convergence with driver-a strongly reinforces the showstopper findings (svm_launch unwired, VMCB segment state, R15 loss, handle_msr passthrough, VMLOAD missing) and surfaces additional structural bugs (VMCB intercept-field offsets, NPT alloc-at-DISPATCH, default RIP advance).
3. **install-probes** — `launcher/`, `INSTALL.ps1`, `UNINSTALL.ps1`, `recovery/`, `tools/`, and the pentest probe helpers in `pentest/probes/` (both the user-mode C and the kernel helper drivers). Finds the entire user-visible launch/stop/recover flow non-functional against the Phase 1.7 randomized installer, plus arbitrary-MSR / arbitrary-PerfEvtSel kernel primitives exposed over FILE_ANY_ACCESS devices.
4. **infra-docs** — `pentest/run_all.ps1`, `pentest/ci/run_benchmarks.ps1`, `pentest/ci/compare_scores.ps1`, `pentest/corpus/run_corpus.ps1`, `pentest/maintenance/monthly_check.ps1`, `pentest/detectors/run_detectors.ps1`, and the operational / audit docs under `docs/operations/` and `audit/`. Finds the CI harness regex parsers silently matching nothing for pafish/al-khaser (so regressions are undetectable), the primary baseline script hard-tied to one developer's home directory, and multiple design docs describing pre-Phase-1 behavior while being cited as authoritative.

## Appendix A: Verification vote detail

For each confirmed finding, the three lens verdicts are listed as `{lens}: {refuted true|false} — {one-sentence reasoning}`. Entries follow the same numbering as the "Findings by severity" section above.

**S-1** — correctness-trace: refuted=false — quoted code matches `svm_bringup.c:87` exactly; grep finds zero C-side callers for `svm_launch`; `audit/phase1_done.md` corroborates Phase-2-deferred wiring, so the \"never enters guest\" claim is factual. spec-conformance: refuted=false — DriverEntry returns SUCCESS with SVME set and no VMRUN, violating the Phase-1 purpose stated in the master plan even where the audit tags it a Phase 2 deliverable. reproducibility: refuted=false — the project's own audit log explicitly concedes the behavior is deferred, so the mission-defeating no-op is reliably reproducible.

**S-2** — correctness-trace: refuted=false — `RtlZeroMemory` + selector-only writes leave attrib/base/limit zero; VMLOAD only covers FS/GS/TR/LDTR; AMD §15.5.1 consistency check would fail CS. spec-conformance: refuted=false — struct and spec confirm attrib/limit/base must be populated; code never populates them. reproducibility: refuted=false — grep across driver/ shows only `gdtr`/`idtr` base/limit are set.

**S-3** — correctness-trace: refuted=false — `mov r15, [rsp]` at line 77 clobbers guest R15 before any save; comment on 91-97 explicitly acknowledges. spec-conformance: refuted=false — VMCB save area does not round-trip R15; AMD specifies hypervisor is responsible for R15 continuity. reproducibility: refuted=false — reload loop lines 132-144 omits R15; guest resumes with ctx pointer in R15.

**S-4** — correctness-trace: refuted=false — AMD APM Appendix B says WRMSR to VM_HSAVE_PA with SVME=0 raises #GP; IPI_LEVEL + unhandled #GP = bugcheck. spec-conformance: refuted=false — Linux KVM zeroes VM_HSAVE_PA FIRST, then clears SVME; ordering inverted here. reproducibility: refuted=false — DriverEntry failure-cleanup path reaches this code.

**S-5** — correctness-trace: refuted=false — IVEC3_MSR set, APM §15.11 forces intercept for out-of-MSRPM-window addresses; default else does raw `__readmsr/__writemsr` with no SEH. spec-conformance: refuted=false — any guest RDMSR of KVM/Hyper-V/VMware probe MSR reaches default branch and faults host. reproducibility: refuted=false — `mov ecx, 0x4B564D00; rdmsr` from guest bugchecks host.

**S-6** — correctness-trace: refuted=false — Hyper-V TLFS 0x40000100+ (CRASH_P0..CTL, reenlightenment) fall outside `0x400000FF` cap. spec-conformance: refuted=false — master plan line 765 mandates ≥0x400001FF. reproducibility: refuted=false — HV-aware probe reading 0x40000100 bugchecks.

**S-7** — correctness-trace: refuted=false — KVM 0x4B564D* also outside all MSRPM windows and auto-intercepts; same default-path crash. spec-conformance: refuted=false — AMD APM §15.11 confirms unconditional intercept. reproducibility: refuted=false (voter 3 omitted `refuted` field but reasoning aligns with other voters that this reproduces; counted as not-refuted).

**S-8** — all three lenses refuted=false — svm_launch has no C caller; the Phase-2-deferred framing is acknowledged by `phase1_done.md` but severity still matches "hypervisor never runs".

**S-9** — all three lenses refuted=false — same mechanism as S-3; code quote and comment admission confirmed verbatim at `vmrun.asm:67`.

**S-10** — all three lenses refuted=false — same mechanism as S-2 across spec and structural lenses.

**S-11** — correctness-trace: refuted=false — `__writemsr` targets host EFER post-VMEXIT; `vmcb->save.efer` is never written; VMRUN reloads stale guest EFER. spec-conformance: refuted=false — AMD APM confirms host context during VMEXIT handler. reproducibility: refuted=false — intercept confirmed set in `svm_vmcb.c:126`, write is reachable from any guest WRMSR(EFER).

**S-12/S-13/S-14** — all lenses refuted=false — driver-b independent restatements of S-3/S-2/S-11, verified at same line numbers.

**S-15** — correctness-trace: refuted=false — `KeAcquireSpinLock` raises IRQL to DISPATCH; `MmAllocateContiguousMemorySpecifyCache` requires PASSIVE per MSDN; first NPF in MMIO/hot-plug region bugchecks 0xA. spec-conformance: refuted=false — WDK doc and author's own comment in `svm_vmcb.c:83-84` agree. reproducibility: refuted=false — NPF handler is the only reachable path.

**S-16** — correctness-trace: refuted=false — APM §15.9 reserves `next_rip` to the decoded intercept set; the file's own `handle_npf` comment at 242-249 documents this exact restriction. spec-conformance: refuted=false — VMRUN intercept at `svm_vmcb.c:187` reaches this default with no case. reproducibility: refuted=false — writing garbage from `next_rip` into RIP produces undefined control flow.

**S-17** — correctness-trace: refuted=false — AMD §15.5.2 explicit on VMLOAD-managed state; no `vmsave host_pa` / `vmload host_pa` pair anywhere in `vmrun.asm`. spec-conformance: refuted=false — master plan §VMLOAD/VMSAVE confirms the bracket is required. reproducibility: refuted=false — guest FS/GS state remains in host handler.

**S-18/S-19/S-20** — all lenses refuted=false — driver-b adversarial restatements of S-1/S-3/S-5.

**S-21** — correctness-trace: refuted=false — struct layout quoted; APM Table B-1 and master plan §3.0 line 502 confirm IVEC3 must be at 0x0C, IVEC4 at 0x10; this struct places them at 0x14/0x18. spec-conformance: refuted=false — `C_ASSERT` only checks total size. reproducibility: refuted=false — `svm_build_vmcb` writes CPUID/MSR into fields that hardware does not read.

**S-22/S-23/S-24/S-25** — all lenses refuted=false — driver-b spec-conformance restatements of S-2/S-1/S-3/S-5 at same line numbers.

**S-26** — correctness-trace: refuted=false — quoted lines exact, installer confirmed to mint random name and persist to `last_install.txt`. spec-conformance: refuted=false — three failure chains (Test-Path, Get-Service, CreateFile) all target names installer never creates. reproducibility: refuted=false — desktop shortcut flow non-functional on any real install.

**S-27** — correctness-trace: refuted=false — driver header `the_chamber.h:85-87` evaluates to 0x80002004/8/C; launcher literals evaluate differently; dispatcher falls through to STATUS_INVALID_DEVICE_REQUEST. spec-conformance: refuted=false — comment-vs-literal mismatch is unambiguous. reproducibility: refuted=false — watchdog kick never reaches driver, 60s heartbeat self-unloads.

**S-28/S-29/S-30/S-31** — all lenses refuted=false — install-probes restatements of S-26 and S-31 across adversarial and spec-conformance lenses; `last_install.txt` existence and the never-read path in recover.ps1 confirmed.

**S-32/S-33** — all lenses refuted=false — `run_all.ps1:14` quoted verbatim; `$ErrorActionPreference='Stop'` makes dot-source of missing file a terminating error; sibling `run_detectors.ps1:5-16` demonstrates the correct Test-Path guard.

**H-1** — correctness-trace, spec-conformance, reproducibility: all refuted=false — same evidence as S-5 (driver-a:structural version of the finding).

**H-2** — correctness-trace: refuted=false — grep confirms no FXSAVE/XSAVE/FXRSTOR/XRSTOR anywhere in driver/. spec-conformance: refuted=false — master plan §4.2 mandates the save/restore around the handler. reproducibility: refuted=true (single voter) — argued that `/kernel` restricts MSVC's XMM emission, but the other two lenses (structural + spec) rated it confirmed on the broader argument that MSVC/kernel paths still touch XMM via several routes (inlined memcpy on large structs, DbgPrintEx varargs classification); majority confirms.

**H-3** — correctness-trace: refuted=false — alignment math traced step by step; result rsp%16=8 at CALL, violating ABI. spec-conformance: refuted=false — same trace against ABI spec. reproducibility: refuted=false — MSVC movaps/movdqa on 16-aligned stack slots #GP at kernel privilege.

**H-4** — all lenses refuted=false — driver-a:structural restatement of S-6.

**H-5** — correctness-trace: refuted=false — WDK documents `KeRemoveQueueDpc` returns FALSE without waiting for an in-flight DPC. spec-conformance: refuted=false — `KeFlushQueuedDpcs` at PASSIVE_LEVEL in UnloadRoutine is the standard WDK fix. reproducibility: refuted=false — watchdog DPC writes `g_cpu_ctx[i].shutdown_requested` on potentially-freed pool.

**H-6** — all lenses refuted=false — same mechanism as S-11, adversarial framing.

**H-7/H-8** — all lenses refuted=false — driver-a:adversarial restatements of S-3/S-17; H-8 notes latency depends on `svm_launch` being wired.

**H-9** — correctness-trace: refuted=false — line order in `the_chamber.c:455-459` has `crash_marker_clear` before `stealth_apply`. spec-conformance: refuted=false — crash-marker comment at 406-408 states its purpose is exactly to guard against stealth-step bugcheck. reproducibility: refuted=false — on a KLDR-layout drift, bugcheck in stealth_apply leaves no marker → boot loop.

**H-10/H-11/H-12** — all lenses refuted=false — driver-a:spec-conformance restatements of S-5/H-11/S-17.

**H-13/H-14** — all lenses refuted=false — driver-b:adversarial restatements of H-3/H-5.

**H-15** — correctness-trace: refuted=true (voter 1) argued GIF behavior differs and INTR is not intercepted so the IPI is delivered through guest IDT; voter 2 (spec-conformance) and voter 3 (reproducibility) both refuted=false, matching the finding's own GIF/CLGI-across-host-window analysis. Majority confirms.

**H-16/H-17/H-18** — all lenses refuted=false — driver-b:spec-conformance restatements of H-3/H-2/S-11.

**H-19** — all lenses refuted=false — driver-b:adversarial restatement of S-15; same WDK IRQL violation.

**H-20/H-21** — all lenses refuted=false — install-probes structural+adversarial restatements of S-31 and stop.ps1 mismatch.

**H-22** — all lenses refuted=false — sc.exe create/delete emits event 7045/7036, which install_service.ps1 explicitly suppresses via NtLoadDriver per Phase 1.7.

**H-23** — all lenses refuted=false — `last_install.txt` is the only discovery mechanism; no fallback; stale state file silently leaves driver loaded.

**H-24** — correctness-trace: refuted=false — grep across probe suite confirms pmu_vmexit uniquely lacks SetThreadAffinityMask. spec-conformance: refuted=false — AMD APM confirms PerfEvtSelCore/PerfCtrCore are per-logical-processor. reproducibility: refuted=false — three IOCTLs on a non-pinned thread can land on three different CPUs.

**H-25** — all lenses refuted=false — `/kernel` would still measure thousands of retired instructions over the 16 CPUID loop + 3 IOCTL round-trips.

**H-26/H-27/H-28/H-29** — all lenses refuted=false — install-probes:adversarial restatements of H-21/S-31/H-24/S-27.

**H-30** — correctness-trace: refuted=false — INSTALL.ps1:7 quoted verbatim; dot-source + Assert-NoAntiCheatRunning combo aborts on any non-lkhnj machine. spec-conformance: refuted=false — install_service.ps1/load.ps1/stop.ps1 do guard with Test-Path, which also silently skips the safety check. reproducibility: refuted=false — path is user-specific; artifact is not operator-independent.

**H-31** — correctness-trace: refuted=false — ternary logic traced; mismatches=0 when !have_expected; leak_count still incremented in HV-range scan. spec-conformance: refuted=false — HV_LEAK lines printed to stdout regardless. reproducibility: refuted=false — bare-relative-path for `expected_7700x.json` triggers on any wrong cwd.

**H-32** — correctness-trace: refuted=false — IoCreateDevice with no SDDL + FILE_ANY_ACCESS; symlink in \DosDevices; dispatcher does zero validation. spec-conformance: refuted=true (single voter 2 argued probe is adversary-simulation harness and not a HV component, so no spec violation); voters 1 and 3 refuted=false on the "arbitrary-MSR-read primitive" structural concern. Majority confirms.

**H-33** — all lenses refuted=false — install-probes:spec-conformance restatement of H-22.

**H-34/H-35/H-36** — all lenses refuted=false — spec restatements of H-25/H-24/H-32.

**H-37** — correctness-trace: refuted=false — IOCTLs confirmed FILE_ANY_ACCESS; PmuArm accepts 64-bit event_select unchecked. spec-conformance: refuted=false — AMD APM and Windows WDK default-device-DACL doc. reproducibility: refuted=false — DISARM unconditionally writes 0.

**H-38/H-39/H-40** — all lenses refuted=false — install-probes:spec-conformance / infra-docs:spec-conformance restatements of H-22/H-31/S-32.

**H-41** — correctness-trace: refuted=false — pafish OSS output uses `[+]/[-]/[*]`, never `[OK]/[BAD]`. spec-conformance: refuted=false — regex matches zero real lines, parser returns empty dict. reproducibility: refuted=false — empty pafish scores confirmed via line 319 flow into $publicBenchmarks.

**H-42** — all lenses refuted=false — same mechanism; al-khaser output is `---> [ GOOD ]/[ BAD ]`.

**M-1 through M-44** — in the interest of report compactness, verdict triples are summarized rather than per-sentence recited. Across all 44 medium findings: zero had all three voters refuted=true; the only split-vote entries in this band are **M-7 (crash_marker_present)** where voter-1 raised a minor nuance about the Phase-1 marker lifecycle but majority held confirmed; **M-26 (RDMSR vs RDPMC)** where voter 1 argued the probe matches its documented contract (correctness-trace) while voters 2-3 confirmed the architectural mismatch against master plan §2.1; and **M-37 (probe-result unpacking)** where a voter noted `[int](ConvertFrom-Json null)` coerces benignly but string-typed scores still terminate the loop — majority confirmed. The rest are unanimous refuted=false.

**L-1 through L-26** — all unanimous refuted=false with the exception of **L-11 (cross_core_rdtsc off-by-one)**, where a single voter (reproducibility) noted the probe's minimum-sample threshold still produces a statistically valid median at 4095 samples, but confirmed the JSON claim of 4096 is nominally wrong — majority confirmed, severity low. The rest match evidence directly.

**N-1 through N-8** — all unanimous refuted=false. These are stylistic / doc / paper-trail defects that the reviewers all agreed are real but inconsequential at runtime (`~(1 << 31)` compiles to the intended mask on MSVC; `acc & 0ULL` is folded away; off-by-one loop bound on cpuid_hypervisor_range probes one extra harmless leaf; etc.).

## Appendix B: Discarded during verification

The following 49 candidate findings were surfaced by at least one lens but **refuted by the majority** of the three verification lenses. They are preserved here with the death reason so reviewers can audit the verification decisions.

1. **KeAcquireSpinLock called from the NPF VMEXIT handler at an undefined IRQL** — `driver/npt.c:409`. Refuted 3-0. Reason: the finding's premise that `svm_launch` runs from an IPI worker is wrong; `svm_launch` is not wired at all; even when wired, host CR8/IRQL semantics and the `svm_bringup`/handler-level comments do not match the finding's IRQL-leak mechanism.
2. **POOLTAG(x) macro silently discards runtime pool_tag_override** — `driver/the_chamber.h:42`. Refuted 2-1. Reason: the pool_tag_override field is explicitly documented as reserved/unused, the Phase 1.7 randomization is intended compile-time via `/D`, and `install_service.ps1` does not write the field at all.
3. **svm_shutdown_all_cpus clears EFER.SVME on all CPUs without a path to drain any in-flight VMRUN** — `driver/svm_bringup.c:153`. Refuted 3-0. Reason: the described GIF interaction is backwards (VMRUN sets GIF=1 for guest; VMEXIT clears it to 0 host-side). Per-CPU `ipi_offline` runs on each CPU via KeIpiGenericCall where GIF=1 — no cross-CPU partial-teardown race exists as framed; the real hazard (deadlock, H-15) is separately filed.
4. **DriverSection = NULL + no crash-marker on bugcheck window** — `driver/stealth.c:225`. Refuted 2-1. Reason: the crash-marker is explicitly scoped to DriverEntry-phase crashes; `MmGetSystemRoutineAddress` et al walk PsLoadedModuleList, not DriverSection, so the NULL-deref secondary mechanism doesn't fire in realistic kernel paths.
5. **handle_vmmcall reads guest RBX from gpr_save[1] which can lag** — `driver/vmexit.c:208`. Refuted 3-0. Reason: vmrun.asm unconditionally saves RBX to `gpr_save[1]` before calling the handler; the race is purely future-hypothetical, not present.
6. **CPU hotplug: processors brought online after init have no VMCB and no SVM enablement** — `driver/svm_bringup.c:107`. Refuted 2-1. Reason: the stated target is bare-metal 7700X consumer desktop which does not support ACPI CPU hotplug; `KeIpiGenericCall` only broadcasts to currently-active CPUs; the "off-by-one zero-init slot" concern is incoherent (allocation is exactly sized).
7. **svm_init_all_cpus failure path reenters svm_shutdown_all_cpus** — `driver/svm_bringup.c:130`. Refuted 2-1. Reason: on cold CPUs, clearing already-clear SVME is a no-op; VM_HSAVE_PA=0 is architecturally accepted (not a #GP primitive per APM §15.30); this is hardening noise, not a confirmed defect.
8. **tsc_offset accumulator never wrapped; overflow is UB on signed negation** — `driver/timing.c:125`. Refuted 3-0. Reason: ~90+ years to reach INT64_MIN at 4 GHz if 100% of cycles were host overhead; MSVC does not exploit signed-overflow UB; `-INT64_MIN` wraps deterministically to the intended bit pattern on x64.
9. **vmexit.c handle_cpuid depends on next_rip being populated on Zen 4** — `driver/vmexit.c:120`. Refuted 3-0. Reason: NRIP_SAVE has been architecturally present on every AMD SVM part since Family 10h (2007); the hypothetical "loaded on Zen 3 or older" platform is outside the design target.
10. **scrub_service_key_name uses rdtsc at DISPATCH-safe IRQL but writes 2 bytes per step even when chars is 1** — `driver/the_chamber.c:242`. Refuted 3-0. Reason: Windows I/O manager always produces WCHAR-granular (even-byte) `MaximumLength`; odd-byte case is architecturally unreachable on any supported OS path, and the leaked byte is the high byte of a WCHAR which is 0x00 for ASCII names.
11. **NPT identity map hard-capped at 128 GB silently drops ranges on larger systems** — `driver/npt.c:203`. Refuted 3-0. Reason: `MmGetPhysicalMemoryRanges` enumerates RAM only (not MMIO holes); LAPIC/IOAPIC/ACPI live well below 4 GB; the fault-recovery path handles lazy growth (which the finding itself admits is OK).
12. **VMCB field layout omits TLB_CONTROL at offset 0x05C and the NPT hide code's TLB-flush recipe would corrupt GuestASID** — `driver/svm.h:109`. Refuted 2-1. Reason: no code currently performs `guest_asid_tlb |= (1u << 31)`; `pad_05c` reserves the correct 4 bytes so total VMCB size/alignment is correct; npt_hide_range/unhide_range have no callers; the described BSOD is contingent on Phase 1.6 being wired.
13. **CPUID stealth masks only leaf 1 ECX[31]; leaves SVM capability bits exposed in leaves 0x80000001 / 0x8000000A** — `driver/vmexit.c:85`. Refuted 2-1. Reason: bare-metal AMD systems with SVM supported in CPUID + EFER.SVME=0 is the normal OS state; masking SVM bits would make the HV diverge from bare-metal and be more detectable, not less.
14. **g_chamber_cfg carries the literal 'CFG_' magic word in a named section, leaking a stealth-anchor string** — `driver/the_chamber.h:64`. Refuted 3-0. Reason: Phase 1.7 bans "WinHvMon"/"THE_CHAMBER"/"Hv"; "CFG_" is a generic non-identifying marker required by the launcher's own locator mechanism, so randomizing it would break the design.
15. **svm_shutdown_all_cpus deadlocks if any CPU is in guest mode (GIF=0 blocks IPI)** — `driver/vmrun.asm:49`. Refuted 3-0. Reason: svm_launch is currently unwired; the finding admits latency; the core race described (shared IRQL semantics across CPUs via CR8) is architecturally wrong — this is subsumed into the correctly-scoped H-15 instead.
16. **svm_offline_cpu clears VM_HSAVE_PA to 0 and EFER.SVME before memory free - crashes if still in guest** — `driver/svm_bringup.c:153`. Refuted 3-0. Reason: svm_offline_cpu runs via IPI at IPI_LEVEL in host mode, not guest mode; once SVME is cleared, VMRUN is disabled; the real bug (S-4) is a different mechanism with the opposite ordering.
17. **handle_msr else-branch forwards arbitrary guest WRMSR to hardware** *(pre-verification duplicate wording of S-5 with a different severity framing; the final-form S-5 passed, this earlier phrasing was refuted on the "today unreachable" caveat the alternate phrasing added)* — refuted 3-0.
18. **stealth_apply/revert modify DriverObject fields outside the spinlock** — `driver/stealth.c:219`. Refuted 2-1 (first filing); the real defect (M-14) covers the save-path corruption from early returns in stealth_apply rather than a concurrency hazard between apply/revert, since apply and revert run serialized on load/unload only.
19. **FPU/SSE/AVX state not saved across VMEXIT; handler corrupts guest vector state** — `driver/vmexit.c:31`. Refuted 2-1 (driver-b:adversarial earlier filing of H-2); other two lenses rated the same mechanism as confirmed and the final H-2 carries the finding.
20. **NPT slot table capacity (32) + handle_npf ignores npt_map_page failure -> adversarial infinite NPF** — `driver/vmexit.c:277`. Refuted 2-1. Reason: 32 PML4 slots cover 16 TB and ring-0 guest adversaries are explicitly out of scope per master plan Phase 10; the described exploit requires crafted ring-0 probing of 32 distinct 512 GB regions.
21. **svm_shutdown_all_cpus clears EFER.SVME without checking whether the CPU was ever brought online** — `driver/svm_bringup.c:153`. Refuted 3-0. Reason: concurrent SVM hypervisors cannot coexist architecturally; clearing already-clear SVME is a no-op; proposed `if (!ctx->active) return;` guard doesn't address the real failure path described.
22. **stealth_apply serializes KLDR fields under g_stealth_lock but modifies DriverObject fields outside the lock** — `driver/stealth.c:219`. Refuted 3-0. Reason: stealth_apply and stealth_revert are strictly serialized by the OS driver lifecycle (load/unload); no concurrent invocation can occur today; this is Phase-5 forward-looking hardening.
23. **handle_vmmcall shutdown case does not advance RIP, VMMCALL re-fires forever** — `driver/vmexit.c:219`. Refuted 3-0. Reason: the code DOES advance RIP (fall-through to `vmcb->save.rip = vmcb->ctl.next_rip;`); the revised mechanism after self-correction mutates into a different hypothetical that doesn't apply either.
24. **VMCB tsc_offset grows without bound and is written as 2's-complement negative via ULONGLONG** — `driver/timing.c:125`. Refuted 3-0. Reason: host TSC and accumulator advance by the same Δ during a long VMEXIT, so guest TSC = host - accumulated stays smooth; the "guest sees backward step on a billion-cycle exit" mechanism is wrong; the design explicitly tolerates small over-pad.
25. **IrpDeviceControl accepts user SystemBuffer without ProbeForRead/ProbeForWrite** — `driver/the_chamber.c:263`. Refuted 3-0. Reason: DO_BUFFERED_IO makes SystemBuffer a kernel-mode copy; ProbeForRead/ProbeForWrite are not required; the current IOCTL surface is correctness-OK.
26. **No VMLOAD / VMSAVE / CLGI / STGI / SKINIT intercepts** — `driver/svm_vmcb.c:187`. Refuted 2-1. Reason: ring-0 guest adversary is out of scope per master plan Phase 10; §4.1 explicitly permits non-interception of these with hardware #GP delivery to CPL>0, which is the project's declared threat boundary.
27. **handle_npf fault_gpa fetch uses byte-exact exit_info_2 but the mapping path strips alignment incorrectly** — `driver/vmexit.c:251`. Refuted 2-1. Reason: the finding's own body concedes the 2 MB re-alignment "still works"; MMIO cache-attribute concern is a separate Phase-6 TODO; `NPT_UNCACHED` isn't even defined yet.
28. **Default VMEXIT handler advances RIP via next_rip for fault-class exits where next_rip is undefined** — `driver/vmexit.c:58`. Refuted 2-1 (duplicate framing of S-16, the earlier phrasing was tagged as "latent only" and the dedicated spec-conformance filing superseded it with the "VMRUN is actually intercepted today" mechanism); S-16 carries the confirmed defect.
29. **the_chamber.inx retains "winhvmon" and "THE_CHAMBER" brand strings baked into any .cat / INF deploy** — `driver/the_chamber.inx:20`. Refuted 2-1. Reason: Phase 1 exit criterion scopes strings-scan to the compiled .sys, not source INF; `audit/phase1_done.md` explicitly lists the INF as an accepted non-goal because NtLoadDriver bypasses it. (L-1 carries the related `[Strings]` branding concern at a different line, which did pass.)
30. **IVEC3_IRET definition is at bit 20 but IVEC3_INTN at bit 21 overlaps the correct AMD INT_N position** — `driver/svm.h:52`. Refuted 3-0. Reason: the macros ARE correct per AMD APM §3.7; the finding concedes the macro is right and only flags reviewer-ergonomics that the label could camouflage a separate layout bug (which is covered by S-21).
31. **install_service.ps1 Patch-DriverConfig finds CHAMBER_CFG by linear byte scan for magic+version — first match wins, no bounds check against the PE section** — `launcher/install_service.ps1:98`. Refuted 3-0. Reason: 8-byte composite marker (`CFG_` + version 1 = 8 specific bytes) was deliberately chosen for low collision risk; no concrete collision in a real driver build is demonstrated; author even comments on the choice.
32. **install_service.ps1 Patch-DriverConfig takes the first magic-version match but the magic may appear in debug sections** — `launcher/install_service.ps1:97`. Refuted 3-0. Reason: duplicate of #31; same collision argument applies, and release-stripped drivers don't retain the kind of stray `\x01\x00\x00\x00` ASCII adjacencies the finding imagines.
33. **install_service.ps1 ships a plaintext PFX password and relies on a PFX path the repo never produces** — `launcher/install_service.ps1:145`. Refuted 3-0. Reason: `driver/build.ps1` lines 135-156 DO create `C:\THE_CHAMBER\recovery\the_chamber_test.pfx` via `New-SelfSignedCertificate`; the real defect the finding brushes against is a password mismatch (build.ps1 exports with `THE_CHAMBER`, install_service.ps1 passes `build-test`) which is a correctness bug worth filing separately but not the one this finding claims.
34. **msr_readout hypervisor-range scan stops at 0x400001FF, narrower than the §3.1 'at least ...' guidance** — `pentest/probes/msr_readout/main.c:234`. Refuted 3-0. Reason: master plan §3.1 explicitly specifies "at least 0x400001FF" as the floor; wider ranges are optional paranoia; probe is at the spec's floor and is spec-conformant.
35. **cross_core_rdtsc pairing algorithm consumes BOTH indices on seq equality, dropping half the matches** — `pentest/probes/cross_core_rdtsc/main.c:173`. Refuted 3-0. Reason: this is a correct two-pointer intersection of sorted non-repeating sequences; nothing is dropped; the finding's own body concedes "fine for correctness of each produced pair" before pivoting to a separate small-sample statistical concern.
36. **msr_driver.c and pmu_driver.c README both tell operators to use sc.exe create/start** — `pentest/probes/msr_readout/README.md:32`. Refuted 2-1. Reason: Master plan §1.7 scope applies to the HV driver, not test-harness probes explicitly declared out of scope for stealth; the "Chamber" substring in test-driver names is not a §1.7 ban.
37. **pentest/README.md advertises the harness as 'read-only' and 'changes nothing on the system'** — `pentest/README.md:5`. Refuted 2-1. Reason: the very next sentence in the README describes the report outputs — "read-only" in context means "does not modify system state (no driver load, no registry, no network)", which the harness honors.
38. **PentestCpuId allocates RW then VirtualProtects to X; fails under ACG** — `pentest/run_all.ps1:128`. Refuted 3-0. Reason: `Invoke-Section` wraps the body in try/catch and converts any exception into a structured error record; ACG-driven Win32Exception only degrades that one section rather than taking the whole run down.
39. **run_corpus.ps1 kills a timed-out target asynchronously but starts the next sample immediately** — `pentest/corpus/run_corpus.ps1:172`. Refuted 3-0. Reason: `Process.Kill()` halts user-mode thread execution before the syscall returns; two protector instances cannot concurrently execute; only process-object cleanup is async, which does not affect protector-vs-protector overlap.
40. **monthly_check.ps1 mutates the parsed JSON object in place then serializes; comment ordering/schema markers not guaranteed to round-trip** — `pentest/maintenance/monthly_check.ps1:119`. Refuted 3-0. Reason: version strings flow through `[string]`-typed parameters; PowerShell preserves PSCustomObject insertion order in both WinPS 5.1 and PS 7; `_schema` and `_notes` round-trip cleanly.
41. **Invoke-RemoteBenchmark deadlocks on any benchmark that produces more than a pipe buffer of stdout** — `pentest/ci/run_benchmarks.ps1:203`. Refuted 2-1. Reason: `Start-Process -RedirectStandardOutput <file>` writes directly to file handles via STARTUPINFO, not to anonymous pipes with a parent-side reader — no pipe buffer to fill; the described deadlock mechanism applies to System.Diagnostics.Process with `RedirectStandardOutput=$true`, not to this call.
42. **run_corpus.ps1 enumerates hidden/system files with -Force and will execute .DS_Store / desktop.ini / thumbs.db as a corpus binary** — `pentest/corpus/run_corpus.ps1:67`. Refuted 2-1. Reason: execution uses `Start-Process -NoNewWindow` which goes through CreateProcess (not ShellExecute); non-PE files simply fail as `invoke_error`; desktop.ini CLSID-via-Explorer vector is not reachable from Start-Process.
43. **pre-commit hook in discipline.md 9.6.3 enforces synthetic-values-table sync against two driver files only** — `docs/operations/discipline.md:821`. Refuted 3-0. Reason: `handle_msr` lives in `driver/vmexit.c` which the regex already covers; master plan's Phase 3.2/3.3 additions go in `vmexit.c`, not in a new file.
44. **run_detectors.ps1 picks up a stale pre-existing exe when msbuild runs a no-op incremental build** — `pentest/detectors/run_detectors.ps1:170`. Refuted 3-0. Reason: `$rest` is derived from `$all` which already filters by `LastWriteTime -ge $Since`; a stale pre-existing exe is excluded; function correctly returns `$null` on no-op builds.
45. **Build-Solution in pentest/detectors/run_detectors.ps1 hardcodes /p:Platform=Win32** — `pentest/detectors/run_detectors.ps1:256`. Refuted 2-1. Reason: Pafish/InviZzzible canonically ship as 32-bit tools; measuring them as published (x86 under WoW64) matches the "0% against pafish" acceptance criterion the master plan actually sets.
46. **pentest/corpus/run_corpus.ps1 timeout path kills the child without waiting for stdio flush** — `pentest/corpus/run_corpus.ps1:173`. Refuted 3-0. Reason: `Start-Process -RedirectStandardOutput <file>` writes directly to a file; TerminateProcess destroys the child's user-mode CRT buffers but no amount of parent-side WaitForExit can recover them (the child itself must flush); there is no parent-side pipe to drain.
47. **pentest/detectors/run_detectors.ps1 Invoke-Tool timeout branch does not WaitForExit after taskkill** — `pentest/detectors/run_detectors.ps1:329`. Refuted 3-0. Reason: file-redirection model (not pipe redirection); the described truncation class does not apply.
48. **pentest/maintenance/monthly_check.ps1 blindly trusts protector_versions.json schema** — `pentest/maintenance/monthly_check.ps1:119`. Refuted 3-0. Reason: existing schema (themida/vmprotect/enigma × version/last_checked_utc/installer_url) matches what the script accesses; Step 1 traversal under StrictMode would throw before any write if fields were missing, so "corrupt file / mid-run failure" scenarios do not reproduce.
49. **audit/full_audit_v2.md is a stub with every section heading followed by '(filled at end)'** — `audit/full_audit_v2.md:8`. Refuted 2-1. Reason: the file is explicitly labeled "Full-audit skeleton" and "DRAFT -- partial"; it appears only under `docs/operations/README.md`'s "Related" section (not the "Reading order"), so a correctly-following operator is not misdirected to empty content.

---

**End of Wave 1 Audit Report.**
