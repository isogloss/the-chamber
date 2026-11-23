# chamber_fingerprint.sys

Second kernel driver, separate from `the_chamber.sys`. Handles per-process
query spoofing for the machine-identity surfaces that are reached from user
mode rather than through CPUID/MSR.

The hypervisor driver (`the_chamber.sys`, AMD-SVM) owns CPU-identity surfaces
and its own self-fingerprint. This driver owns every documented user-mode
query that samples use to fingerprint the host OS, firmware, storage, display,
network adapters, and TPM.

Both drivers consume the same 632-byte `CHAMBER_CFG_V2` blob, derived from a
single 32-byte master seed that the launcher persists in
`%APPDATA%\The Chamber\seed_state.json`. The seed only changes when the user
clicks **Randomize Seed**. Across reboots, the seed stays stable, so a sample
that correlates values across bootups sees a coherent machine; across seeds,
every observable field changes, so two installs look like two different
computers. The signing identity (cert, driver file hash) is intentionally not
seeded.

## Load order

1. `the_chamber.sys` loads first via `NtLoadDriver` from the launcher.
   It brings up SVM, writes CFG v2 into its own `.cfg` section, and starts
   intercepting CPUID / MSR.
2. `chamber_fingerprint.sys` loads second via the same launcher path.
   DriverEntry reads its own copy of CFG v2 from
   `\Registry\Machine\System\CurrentControlSet\Services\<svc>\Parameters\CfgBlob`
   (populated by the launcher's patcher, byte-identical to what the HV side
   holds), registers CM / FLT / IC / Ps callbacks, exposes a control device
   for the operator, and goes dormant until a PID is armed.

## Arming model

The operator (the launcher process, or a sample runner the operator attaches
to) opens the control device and sends `IOCTL_CFP_ADD_PID` with its own PID
plus every sample PID it wants spoofed. All callbacks are PID-filtered against
that list: unlisted processes see the real system. This keeps the rewrite cost
off the kernel's hot path for every other process and keeps PG-visible
behaviour minimal (callbacks are already an allowed surface for registered
filter drivers).

A matching `IOCTL_CFP_REMOVE_PID` drops a PID. A `PsSetCreateProcessNotifyRoutineEx`
hook sweeps the list on process exit so a dying sample does not leak into a
new PID collision.

## Intercept mechanism per surface

Mechanism names come from the Wave 4 design document, Section 2.

| Mechanism | Covered surfaces                                      | File                  |
|-----------|-------------------------------------------------------|-----------------------|
| CM        | 24-34, 48, 56-58, 61                                  | `cm_filter.c`         |
| FLT       | 45 (NDIS IOCTLs via `\Device\Ndis`)                   | `flt_filter.c`        |
| IC        | 18-23, 35-44, 46-47, 50-55, 59-60, 62                 | `syscall_rewrite.c`   |
| Ps        | per-process arming / disarming of IC                  | `instrumentation.c`   |
| CFG       | 63-73 (HV self, handled in `the_chamber.sys`)         | (out of scope here)   |
| WFP       | surface 44 (NSI direct) — folded into IC path         | (out of scope here)   |
| GAP       | 49 (D3DKMT), 59-60 (TPM EK), documented, mitigated    | (out of scope here)   |

All mechanisms use documented Windows kernel APIs:

- `CmRegisterCallbackEx` — standard registry filter, sanctioned EDR surface.
- `FltRegisterFilter` — standard minifilter, sanctioned.
- `PsSetCreateProcessNotifyRoutineEx` — standard process lifecycle notify.
- `NtSetInformationProcess` with `ProcessInstrumentationCallback` —
  documented syscall-return callback, used by Wine, Specter, and modern
  anti-cheat. Sets `KPROCESS.InstrumentationCallback`; kernel dispatches on
  every syscall return. Not an inline hook.

## PG safety

PatchGuard hashes code pages and a small set of system structures (SSDT, IDT,
GDT, KeServiceDescriptorTable, MSR targets). It does **not** hash:

- Registered callback lists (CmCallbackList, FltFilterList, process notify
  table).
- `KPROCESS.InstrumentationCallback`. This is per-process state, written via
  a documented syscall, and PG leaves it alone. Hooks installed this way are
  the mechanism Wine and anti-cheat vendors use precisely because PG does
  not touch them.
- Minifilter instance context.

Nothing in this driver patches a function prologue, rewrites a system table,
or edits a page that PG covers. The HV driver's self-defence already proved
the surface is clean on Zen 4.

## Scope boundary

- No SSDT patching, no IDT patching, no inline function hooks.
- No active debugging. The HV side's VMMCALL pause-the-world is the capture
  path.
- Packet shaping and DNS spoofing are explicitly out of scope — the design
  covers identity queries only, not traffic.
- D3DKMT adapter name (design surface 49) and TPM EK (surfaces 59-60) are
  accepted gaps with documented mitigations.

## Files

- `entry.c` — `DriverEntry`, control device, callback registration, teardown.
- `cfg_shared.c` — CFG v2 loader (registry → kernel memory) + `get_override`.
- `cm_filter.c` — `CmRegisterCallbackEx` handler for the registry surfaces.
- `flt_filter.c` — `FltRegisterFilter` + pre-op for NDIS IOCTLs.
- `instrumentation.c` — process-attach hook installs IC on spoof-list PIDs.
- `ic_trampoline.asm` — x64 ASM trampoline the user-mode IC shim calls into.
- `syscall_rewrite.c` — syscall-return rewriters per `NtQuerySystemInformation` class.
- `dmi_rewrite.c` — SMBIOS Type 0/1/2/3 in-place field patcher.
- `edid_template.c` — 128-byte EDID template with seed splice + checksum.
- `target_pid.c` — IOCTL spoof-list management.
- `build.ps1` — WDK build glue, mirrors `driver/build.ps1`.
- `fingerprint_cfg.h` — thin wrapper pulling in `../the_chamber.h` for `CHAMBER_CFG_V2`.
