# THE_CHAMBER

A Windows-native thin hypervisor that demotes the running OS to an AMD-V (SVM) guest and intercepts specific CPUID + MSR reads so the guest sees bare-metal-looking values. Built for Ryzen Zen 4 (7700X).

## Architecture

- **Kernel driver** (built as `build_output.sys`, installed under a per-install random name) loads via `NtLoadDriver` with a random service key written directly to the registry (no `sc.exe create`, no SCM 7045 event).
- On start it builds a per-CPU VMCB with Nested Page Table identity map, enables SVM in EFER, and issues VMRUN. Current Windows continues as guest.
- A short VMEXIT handler services CPUID (leaf 1 ECX[31] cleared, leaves 0x40000000..0x4FFFFFFF zeroed), MSR reads (EFER.SVME cleared in the guest view, Hyper-V / KVM / VMware / Xen enlightenment ranges return 0), VMMCALL (private hypercall for unload), and NPF (nested page faults retried without advancing RIP; growable NPT behind a monitor table).
- A TSC-offset accumulator (`timing.c`) brackets host handler cycles between VMEXIT return and the next VMRUN (round-3 bracket) and subtracts them from a shared global so a guest RDTSC-around-CPUID probe reads bare-metal-looking deltas.
- A self-hide module (`stealth.c`) renames the driver's `KLDR_DATA_TABLE_ENTRY->BaseDllName` in place against a donor module (`pci.sys`, falling back to `acpi.sys` / `msrpc.sys`) rather than unlinking from `PsLoadedModuleList`, and nulls `DriverName` / `DriverSection`, so SystemModuleInformation enumerators do not see us.

## First-time setup

1. Open an elevated PowerShell.
2. Run `C:\THE_CHAMBER\INSTALL.ps1`.
3. Reboot when prompted (needed for `bcdedit /set testsigning on` to take effect; already applied in an earlier step if you followed the prep flow).

INSTALL.ps1 compiles the driver with your installed WDK, signs it with the self-signed cert at `recovery\the_chamber_test.pfx`, registers the service, and drops a desktop shortcut.

## Daily use

- **Activate**: double-click the `THE_CHAMBER` desktop shortcut. A launcher window appears. The driver loads, a watchdog starts kicking every 20 s.
- **Deactivate**: close the launcher window or run `launcher\stop.ps1`.
- **Status**: read the per-install random device-object name from `C:\THE_CHAMBER\logs\last_install.txt` and open `\\.\<random>` (the fixed `\\.\THE_CHAMBER` path was removed in Phase 1). The driver exposes three IOCTLs: `KICK` (`0x80002004`), `STATUS` (`0x80002008`), `SHUTDOWN` (`0x8000200C`); send them with `DeviceIoControl`. `sc query` does not work: `install_service.ps1` writes the service registry key directly via `NtLoadDriver` and never goes through the SCM.

## Pen-test

`pentest\run_all.ps1 -Label <name>` captures CPUID + MSR + WMI + PnP + firmware + driver + TPM + Secure Boot + MeasuredBoot + memory snapshots to `pentest\reports\<timestamp>_<Label>_*.json` + a summary.md. Run once as `-Label before_load`, activate THE_CHAMBER, run again as `-Label after_load`, compare the two summaries.

## Uninstall

`UNINSTALL.ps1` — stops + deletes the service, removes the desktop shortcut, reverts bcdedit test-signing to off (unless `-KeepTestSigning` is passed).

## Recovery

If the system fails to boot normally after activation:

1. Boot into Safe Mode (F8 during boot, or Shift+Restart → Troubleshoot → Startup Settings).
2. Run `C:\THE_CHAMBER\recovery\recover.ps1` from an elevated PowerShell. It stops + deletes the service, restores the BCD backup, clears the crash marker.

A BCD backup was taken by the pre-install prep script and lives at `recovery\bcd_pre_install.bcd`.

## Known limits

- **Kernel Patch Protection (Patch Guard)** scans `PsLoadedModuleList` structural invariants on some newer Windows builds. Phase 1 replaced the earlier unlink with an in-place `UNICODE_STRING` rename against a donor (`pci.sys`), which avoids the structural 0x109 BugCheck that the unlink pattern used to trip. Residual risk: the donor module unloading at the wrong moment, or a concurrent reader seeing a half-written `BaseDllName` (Buffer / Length / MaximumLength are swapped under `g_stealth_lock`, but KD-attached kernels and some PG sweeps scan without taking that lock). Running at ring -1 reduces but does not eliminate exposure.
- **Secure Boot must stay off** for the self-signed driver to load.
- **Test Mode watermark** appears on the desktop while test-signing is enabled.
- **TSC offset** accumulator hides handler time from guest RDTSC but a sufficiently sophisticated probe (e.g. cross-core shared counter instead of RDTSC) can still measure VMEXIT latency. Mitigation: minimize the set of intercepted instructions; keep the handler short.

## Files

```
C:\THE_CHAMBER\
├── INSTALL.ps1
├── UNINSTALL.ps1
├── README.md
├── driver\        — kernel driver sources + build.ps1
├── launcher\      — load/stop/shortcut scripts
├── tools\         — install_wdk.ps1, obfuscate.ps1
├── pentest\       — run_all.ps1 + README.md + reports/
├── recovery\      — bcd backup + recover.ps1
└── logs\          — install logs
```
