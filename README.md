# THE_CHAMBER

A Windows-native thin hypervisor that demotes the running OS to an AMD-V (SVM) guest and intercepts specific CPUID + MSR reads so the guest sees bare-metal-looking values. Built for Ryzen Zen 4 (7700X).

## Architecture

- **Kernel driver** (`driver/the_chamber.sys`) loads via SCM as `DEMAND_START`.
- On start it builds a per-CPU VMCB with Nested Page Table identity map, enables SVM in EFER, and issues VMRUN. Current Windows continues as guest.
- A short VMEXIT handler services CPUID (leaf 1 ECX[31] cleared, leaves 0x40000000..0x40000010 zeroed), MSR reads (EFER.SVME cleared in the guest view, Hyper-V enlightenment range returns 0), VMMCALL (private hypercall for unload), and NPF (nested page faults logged).
- A TSC-offset accumulator (`timing.c`) subtracts cumulative host handler time from the VMCB's TSC offset so a guest RDTSC-around-CPUID probe reads bare-metal-looking deltas.
- A self-hide module (`stealth.c`) unlinks the driver image from `PsLoadedModuleList` and clears `DriverName`/`DriverSection` so SystemModuleInformation enumerators do not see us.

## First-time setup

1. Open an elevated PowerShell.
2. Run `C:\THE_CHAMBER\INSTALL.ps1`.
3. Reboot when prompted (needed for `bcdedit /set testsigning on` to take effect; already applied in an earlier step if you followed the prep flow).

INSTALL.ps1 compiles the driver with your installed WDK, signs it with the self-signed cert at `recovery\the_chamber_test.pfx`, registers the service, and drops a desktop shortcut.

## Daily use

- **Activate**: double-click the `THE_CHAMBER` desktop shortcut. A launcher window appears. The driver loads, a watchdog starts kicking every 20 s.
- **Deactivate**: close the launcher window or run `launcher\stop.ps1`.
- **Status**: `sc query the_chamber` or send `IOCTL_THE_CHAMBER_STATUS` (0x8008210C) to `\\.\THE_CHAMBER`.

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

- **Kernel Patch Protection (Patch Guard)** scans `PsLoadedModuleList` structural invariants on some newer Windows builds. Our unlink creates a mismatch PG may eventually detect; worst case this triggers a BugCheck with KeBugCheck code 0x109. Running at ring -1 reduces but does not eliminate the exposure.
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
