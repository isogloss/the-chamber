# THE_CHAMBER — Project Status (post-Wave-3)

## Posture

Passive-dump AMD-SVM hypervisor for static analysis of packed malware
samples (Themida, VMProtect, Enigma, custom crypters). Runs on
Ryzen 7 7700X (Zen 4, family 19h) with a Windows 10/11 guest. Capture
mechanism is Phase 6.2 pause-the-world via VMMCALL. No breakpoints,
no inline hooks, no active-debug surface.

## Master-plan coverage

| Phase | Scope | Status |
|---|---|---|
| 1   | Baseline fixes (CPUID zero band, TSC bracket, PsLoadedModuleList rename, stealth strings strip) | **shipped** (Wave 1 + Wave 1.5 audit fixes) |
| 2   | Microarch stealth (PMU shadow, svm_launch wiring, dedicated host stack) | **shipped** (Wave 2) |
| 3   | MSR coverage (VM_CR / SMM_ADDR / SMM_MASK / TSC_RATIO / paravirt bands) | **shipped** (Wave 2) |
| 4   | Instruction stealth (RDTSCP no-migration, trojan-instruction non-interception, no-inline-patch doc, FPU save around handler) | **shipped** (Wave 2 + Wave 1.5 H-2) |
| 5.1 | Refcounted intercept arm/disarm | **skipped** — no dynamic intercepts |
| 5.2 | Pool-scanner evasion (PE scramble + zero) | **shipped** (Wave 3; R8 alphabet broadened) |
| 5.3 | `\Driver\<name>` discoverability | **documented** (Wave 3; design uses launcher-randomized symlink) |
| 5.4 | ObRegisterCallbacks evasion | **shipped** (Wave 3; dump path uses pointer-ref only) |
| 5.5 | ETW silence | **skipped** — analysis-only machine |
| 5.6 | PatchGuard coexistence | **documented** — Phase 1 rename-in-place + no SSDT/IDT/GDT edits |
| 5.7 | HVCI awareness | **documented** — deployment prerequisite (HVCI off) |
| 6.1 | NPT hook latency | **out of scope** (passive-dump refocus) |
| 6.2 | Pause-the-world snapshot | **partial — see Known Bugs** |
| 6.3 | HW breakpoint invisibility | **out of scope** |
| 6.4 | TLS capture | **out of scope** |
| 7.1 | HV memory introspection resistance | **shipped (gated)** — `CHAMBER_HV_INTROSPECTION_RESIST` compile flag, default off |
| 7.2 | Integrity self-check | **shipped** (Wave 3; R5 .text bounds latched from live PE headers) |
| 7.3 | Watchdog with agent heartbeat | **shipped** (Wave 3; R4 ordering fixed) |
| 8   | Pentest harness + probes | **shipped** (Wave 1 Phase 8; Wave 1.5/1.6 CI parser + probe correctness fixes) |
| 9   | Operational discipline docs | **shipped** (Wave 1 Phase 9) |
| 10  | Honest ceilings | **shipped** (Wave 1 Phase 10 + ceilings.md EPYC-only QoS correction) |

## Known bugs (Wave 4 fix list)

| ID | Where | Severity | Mechanism |
|---|---|---|---|
| R1 / R6 | `driver/dump.c:382` + `:130` | showstopper | `KeIpiGenericCall` is a rendezvous primitive; spinning in the callback deadlocks the originator. Current fix drops the spin — pause-the-world is best-effort, with a race window against still-running vCPUs. R6 adds that `vmcb->save.cr3` is stale at IPI time because CR3 writes aren't intercepted. Proper fix: targeted DPC per matching CPU with in-DPC spin, or dedicated per-CPU HV rendezvous threads that signal on a condition. |
| R2 | `driver/npt.c` ↔ `driver/integrity.c` | high (opt-in only) | `npt_hide_hv_image` hides every driver page, including `integrity_dpc_routine`'s own text. DPC dispatch from guest context then NPFs and bugchecks. Default off; opt-in breaks on contact. Fix: hide-exclude list for guest-callable pages, or host the hcall emitter in a separate untouched page. |
| Wave-2 S-1 follow-up | n/a | n/a | svm_launch IS wired (Wave 2). Phase 2.0 shutdown path is one-way: `host_done` clears EFER.SVME and halts the CPU in cli/hlt — the caller is in guest mode by then and cannot be returned to. Clean unload requires per-CPU HV rendezvous threads. |

## Build / install prerequisites

1. Windows 10 22H2 or Windows 11 (any 22H2+) on Ryzen 7 7700X (or any AM5 Zen 4 part; 7950X/7900X also work with 16/12 cores respectively).
2. **HVCI off** (`msinfo32` → Virtualization-based security). HVCI rejects test-signed and EV-only-signed drivers; enabling it needs WHQL or Microsoft attestation signing.
3. **Test-signing on** if using the self-signed cert (`bcdedit /set testsigning on` + reboot). `INSTALL.ps1` now snapshots BCD state and `UNINSTALL.ps1` reverts per-flag so unrelated boot flags are preserved.
4. `signtool.exe` on PATH, PFX at `recovery/the_chamber_test.pfx` (built by `driver/build.ps1` first run via `New-SelfSignedCertificate`).
5. Pentest shim gate at `pentest/_safety_gate.ps1` (shipped in-repo as of Wave 1.6).

## Operator checklist (first run)

1. `powershell -File INSTALL.ps1` — mints a per-install random service name, patches `CHAMBER_CFG` in the on-disk driver, signs with the dev cert, enables BCD flags only if they were off, records `logs/last_install.txt`.
2. `powershell -File launcher\load.ps1` — reads `last_install.txt`, derives `\\.\<rand>`, re-derives the three IOCTL codes via the `CTL_CODE` formula (STATUS=`0x80002004`, KICK=`0x8000A008`, SHUTDOWN=`0x8000A00C`), opens the device with `GENERIC_READ|GENERIC_WRITE` so the I/O manager's access check accepts KICK/SHUTDOWN, starts the 20s watchdog kick loop.
3. Driver prints no DbgPrint output in release (NDEBUG). To observe from WinDbg: rebuild with `/D"CHAMBER_DEBUG"` in `driver/build.ps1:78`.
4. To trigger a pause-the-world dump: user-mode operator tool (not shipped — see `dump.h:40-70`) issues VMMCALL with `RAX=CHAMBER_HCALL_DUMP_CR3`, `RBX=THE_CHAMBER_HYPERCALL_MAGIC`, `RCX=target CR3`, `RDX=output VA`, `RSI=output size`. Driver walks target VADs via `ZwQueryVirtualMemory` after attach, emits TLV records.
5. `powershell -File launcher\stop.ps1` — issues IOCTL_SHUTDOWN (0x8000A00C) then polls `\\.\<rand>` for ERROR_FILE_NOT_FOUND (max 10s) to confirm driver tore down before calling NtUnloadDriver.
6. `powershell -File UNINSTALL.ps1` — reads `last_install.txt` with a registry-enumeration fallback (walks `HKLM\SYSTEM\CurrentControlSet\Services\<[a-z][a-z0-9]{9}>` for ImagePaths with the CHAMBER_CFG 8-byte magic), unloads via NtUnloadDriver, reverts only BCD flags the installer recorded as touched.

## What the HV actively hides from the guest

- **CPUID leaves 0x40000000..0x4FFFFFFF** return zero (hypervisor-brand zero band; Phase 1.1).
- **CPUID leaf 1 ECX[31]** forced to 0 (hypervisor-present bit; Phase 1.1).
- **MSRs**: EFER has SVME masked on read, SVME forced on write to `vmcb->save.efer`; VM_CR / VM_HSAVE_PA / SMM_ADDR / SMM_MASK return 0; TSC_RATIO returns 8.32 fixed-point 1.0 (`0x0000_0001_0000_0000`); Hyper-V 0x40000000-0x400001FF and KVM 0x4B564D00-0x4B564DFF ranges absorb-write / zero-read; VMware backdoor MSRs land in the default allowlist-absorb branch. All reads/writes under SEH.
- **PerfEvtSelCore0..5 WRMSR** intercepted; guest-armed counters are shadowed across VMEXIT and RDPMC returns the shadow snapshot.
- **TSC_OFFSET** adjusted every VMEXIT by (host_interval_end - host_interval_start + fixed_vmexit_cost + tail_cycles); guest RDTSC sees bare-metal-looking deltas across intercepted instructions (within the Phase 10 ceiling — cross-core RDTSC under concurrent VMEXIT pressure can step backward by ~(other-CPU accumulated host cycles)).

## What the HV does NOT hide

- SMT siblings: the hot-handler thread competes with its SMT pair for execution-unit bandwidth on the physical core. Phase 2.7 mitigation is to disable SMT in BIOS for the analysis rig.
- Branch predictor state: handler branching pollutes BTB. Minimized by code audit; no IBPB issued per handler.
- Thermal MSRs: not spoofed (Phase 2.9).
- Memory barrier timing: handler cycle budget enforced, no barriers in hot path; a tight MFENCE loop still shows HV load vs. bare metal.
- Cache / TLB side-channels: handler working set minimized but not flushed pre-VMRUN (Phase 2.2 item 3 is behind a "paranoia mode" flag not enabled).

## Branded-string scan (release build)

Repo grep for `THE_CHAMBER | WinHvMon | winhvmon | Hypervisor Monitor | chamber` across `driver/*.c` returns only:
- Preprocessor macro names (`THE_CHAMBER_HYPERCALL_MAGIC`, `IOCTL_THE_CHAMBER_*`, `THE_CHAMBER_VERSION`) — resolve at compile time to numeric constants, not strings.
- `/* comment */` text — not compiled into the binary.
- `#include "the_chamber.h"` directives — preprocessor only.
- `CHAMBER_LOG(...)` calls — expand to `((void)0)` under NDEBUG (`build.ps1:78`).

The compiled `.sys` carries no brand strings in `.rdata`. Pool tag is `'FsFl'` (CHAMBER_POOL_TAG default), mimicking Filter-Manager allocations.

## Non-goals, honestly stated

- **Clean unload under load.** svm_launch is wired one-way: once a CPU is in guest mode, the only in-driver teardown is `UnloadRoutine`'s `svm_shutdown_all_cpus`, which uses `KeIpiGenericCall(ipi_offline)` to clear EFER.SVME on each CPU. If any CPU is deep in a long VMRUN at the moment of broadcast, the IPI waits for VMEXIT; H-15 cooperative shutdown_requested latching limits exposure, but the primitive is not bulletproof. See Phase 7.3 and `vmrun.asm:host_done` (cli+hlt loop on shutdown).
- **Resumable analysis across reboots.** No capture state persists. Operator re-arms the dump after each boot.
- **Deployment outside the analysis rig.** HVCI on a target machine rejects the driver. Attestation signing (Microsoft Partner Center) is the production route; test-signing is local-dev only.
- **Protection against ring-0 adversaries.** Guest ring-0 can `INVD` or write random bytes to physical RAM including the HV's code. Phase 10 scoping stands.
