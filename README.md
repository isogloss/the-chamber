# The Chamber

A research sandbox for static analysis of packed Windows malware.

The Chamber demotes Windows to a guest under an AMD‑V (SVM) thin hypervisor, spoofs every surface a packed sample probes before unpacking, and dumps the unpacked process when it reaches its original entry point — passively, without debugger hooks, breakpoints, or anything a typical anti‑debug check looks for. One signed binary, run once, no scripts.

---

## Requirements

| Component | What it needs |
|-----------|---------------|
| CPU       | AMD Ryzen Zen 4 (family 19h, model 61h — 7700X / 7900X / 7950X). Earlier Zen parts load but the identity pool only ships Zen 4 shapes. |
| OS        | Windows 10 21H2+ or Windows 11, 64‑bit. Test‑signing on; Secure Boot off; HVCI off while the chamber is active. |
| Privilege | Administrator at install, standard user at runtime. |
| Disk      | ~300 MB (launcher + driver + embedded shim DLL). |

---

## Install & run

1. Download `thechamber.exe` from the latest GitHub release.
2. Right‑click → Run as Administrator. The first launch enables test‑signing, backs up the BCD, and installs the two kernel drivers (HV + fingerprint). It will prompt for a reboot once.
3. On every run after that, double‑click `thechamber.exe`. No PowerShell. No scripts. The single binary carries everything it needs.

---

## Using it

The launcher has three screens.

### Splash

Pure black. Just the hooded figure and the words *THE CHAMBER*. Renders while the drivers come up and the identity system primes itself.

### Randomize seed

The entire fingerprint surface of the machine — CPUID values, MSR patch level, SMBIOS strings, MAC addresses, EDID, MachineGuid, ProductId, InstallDate, DigitalProductId, timezone bias, HID mouse jitter, 73 spoofed surfaces in total — is derived from a 32‑byte master seed. The seed persists across reboots (DPAPI‑encrypted under the installing user) and only rotates when you click **Randomize**. That click rolls new bytes, re‑derives every identity, and stages them for the next session. The machine the sample sees is now a different machine.

The modal appears before any driver loads. Whatever you confirm here is what the sample will fingerprint.

### Operator panel

A small WPF window with two tabs.

**Status**  the live HV service name, the random‑suffix fingerprint device, the per‑boot VMEXIT count, and watchdog pings.

**Dump**  the trigger surface.

---

## Dump triggers

Five passive triggers, selected per‑PID from the Dump tab. None of them touch the target: no API hooks, no breakpoints, no debug port attach, no handle open. The chamber is invisible to `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess(ProcessDebugPort)`, PEB `BeingDebugged` / `NtGlobalFlag`, and the full `KernelDebuggerInformation` surface — those classes are all spoofed or spoof‑gated on the HV side before the guest sees them.

| Trigger | Fires when | Use for |
|---------|------------|---------|
| **Manual**           | Operator clicks the button                               | Interactive capture at any point |
| **Write‑to‑execute** | An NPT page in the target CR3 goes writable → executable | Standard unpacking: the stub writes the real code into a buffer then jumps to it |
| **OEP**              | The guest RIP in the target CR3 matches an operator‑configured VA | Packers whose OEP you already know from a baseline |
| **Write threshold**  | N bytes get written to a single 4 KiB page range         | Partial decompressors that stage the payload across many small writes |
| **Payload received** | A WFP shim observes bytes from a remote source land in the target's memory | Droppers that fetch their payload before unpacking |

A trigger can fire **multiple times per session** (write‑to‑execute especially — the packed binary unpacks the loader first, then the loader unpacks the payload). Each fire writes a separate dump record to the operator‑chosen output directory.

### How the dump works

When a trigger fires, the HV queues one targeted DPC per logical CPU. Every DPC runs at DISPATCH_LEVEL on its own CPU, reads live CR3, and parks itself if it matches the target. The originator CPU self‑skips so the walk can run at PASSIVE_LEVEL. Each parked CPU brackets its spin with RDTSC and charges the delta to its own `vmcb->ctl.tsc_offset`, bypassing the per‑exit clamp, so guest RDTSC on resume continues as if no pause happened. Before releasing the park, the originator rewinds `KUSER_SHARED_DATA.TickCountQuad / InterruptTime / SystemTime / QpcInterruptTimeBias` to their pre‑pause values. Non‑paused sibling processes measure no gap.

The dump walks the target's VAD tree via `KeStackAttachProcess`, writes raw bytes to the operator buffer, and returns. No `OpenProcess`, no handle, no PE reconstruction — raw pages with a thin TLV header so you can carve the modules yourself in IDA / Ghidra / Binary Ninja.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ thechamber.exe  (C# WPF, .NET 8, self‑contained publish)         │
│                                                                   │
│   splash → randomize → operator panel                             │
│      │          │                                                  │
│      ▼          ▼                                                  │
│   SeedService     — DPAPI‑encrypted master seed, 73 derivations    │
│   CfgPatcher      — writes 632‑byte CHAMBER_CFG_V2 into the driver │
│   AuthenticodeSigner — re‑signs the driver with the embedded cert  │
│   DriverLoader    — NtLoadDriver, no SCM (avoids 7045)             │
│   DumpService     — IOCTL dispatch, PID push, shim staging         │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼  (NtLoadDriver)
┌──────────────────────────────────────────────────────────────────┐
│ the_chamber.sys  (kernel; WDK + MSVC x64 + MASM)                 │
│                                                                   │
│   svm_bringup / svm_vmcb / vmrun.asm                               │
│   vmexit.c   — CPUID / MSR / NPF / VMMCALL dispatch                │
│   identity.c — per‑vCPU spoofed identity primed from CHAMBER_CFG_V2│
│   npt.c      — nested page tables, growable                        │
│   timing.c   — per‑core TSC_OFFSET accumulator + pause bypass      │
│   stealth.c  — in‑place KLDR rename against a donor module         │
│   integrity.c— periodic text‑page hash (Phase 7 self‑defense)      │
│   dump.c     — targeted‑DPC pause, KUSER rewind, VAD walk          │
│   dump_trigger.c — 5 trigger kinds                                 │
└──────────────────────────────────────────────────────────────────┘
                              │   (shared 632‑byte CFG blob)
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ chamber_fingerprint.sys  (kernel; separate load)                  │
│                                                                   │
│   cm_filter.c    — registry callback: MachineGuid, ProductId,      │
│                    InstallDate, DigitalProductId, EDID, BitLocker, │
│                    NtpServer, SystemCodeIntegrity, SecureBoot      │
│   dmi_rewrite.c  — SMBIOS Type 0/1/2/3 string + UUID rewrite       │
│   edid_template.c— VESA‑valid synthesised EDID                      │
│   instrumentation.c — ProcessInstrumentationCallback trampolines   │
│   syscall_rewrite.c — per‑syscall return‑value rewrites            │
│   target_pid.c   — per‑process spoof list, IOCTL‑populated         │
│                                                                   │
│  ...loads into the operator's targeted PID via a user‑mode         │
│  chamber_shim.dll (also embedded in thechamber.exe) that is        │
│  mapped at post‑create and wired into the IC trampoline.           │
└──────────────────────────────────────────────────────────────────┘
```

---

## Repository layout

```
/
├── README.md                        — you are here
├── INSTALL.ps1 / UNINSTALL.ps1      — legacy scripts; superseded by thechamber.exe
├── driver/                          — the_chamber.sys sources
│   ├── the_chamber.c/.h             — DriverEntry, IOCTL dispatch
│   ├── svm_bringup.c svm_vmcb.c     — per‑CPU VMCB setup, VMRUN loop
│   ├── vmrun.asm                    — asm stubs for VMRUN / FXSAVE64
│   ├── vmexit.c                     — CPUID/MSR/NPF/VMMCALL dispatch
│   ├── identity.c/.h                — spoofed CPU identity from seed
│   ├── crypt.c/.h                   — SHA‑256‑based seed derivation
│   ├── npt.c/.h                     — nested page tables
│   ├── timing.c/.h                  — TSC_OFFSET accumulator + pause bypass
│   ├── stealth.c/.h                 — KLDR rename against donor module
│   ├── integrity.c/.h               — text‑page hash watchdog
│   ├── dump.c/.h dump_trigger.c/.h  — passive dump + 5 trigger kinds
│   ├── build.ps1                    — WDK build script
│   └── fingerprint/                 — chamber_fingerprint.sys sources
│       ├── entry.c                   — DriverEntry + control device
│       ├── cfg_shared.c              — CHAMBER_CFG_V2 reader
│       ├── identity_apply.c          — applies seed to runtime globals
│       ├── cm_filter.c               — CmRegisterCallbackEx hooks
│       ├── dmi_rewrite.c             — SMBIOS rewrites
│       ├── edid_template.c           — VESA‑valid EDID synthesiser
│       ├── flt_filter.c              — filesystem minifilter stub
│       ├── instrumentation.c         — IC trampoline install
│       ├── syscall_rewrite.c         — syscall‑return rewrites
│       ├── ic_trampoline.asm         — user‑mode trampoline
│       ├── target_pid.c              — per‑PID spoof list
│       └── build.ps1
├── launcher/
│   ├── shim/                         — chamber_shim.dll (user‑mode, embedded)
│   │   ├── chamber_shim.cpp/.h/.def
│   │   ├── chamber_shim.asm          — IC trampoline body
│   │   └── build.ps1
│   └── ui/                           — thechamber.exe (C# WPF, .NET 8)
│       ├── App.xaml / App.xaml.cs
│       ├── Views/                    — Splash, Randomize, Operator, DumpTab
│       ├── Services/                 — SeedService, CfgPatcher, DriverLoader,
│       │                               DumpService, AuthenticodeSigner, …
│       ├── Model/                    — DerivedIdentity, DumpRecord, TriggerConfig
│       ├── Interop/                  — P/Invoke bindings
│       ├── Themes/ / Resources/      — WPF styles + embedded assets
│       └── TheChamber.csproj
├── pentest/                          — detection probes + sample corpus hooks
│   ├── probes/                       — one probe per detection surface
│   └── detectors/
├── recovery/                         — BCD backup, self‑signed cert, recover.ps1
├── tools/                            — install_wdk.ps1 + build helpers
└── .github/workflows/release.yml     — GitHub Actions release pipeline
```

---

## Building from source

The pre‑built binary on the Releases page is the normal route. If you want to build yourself:

### Kernel drivers

```powershell
# Requires WDK 10 + Visual Studio 2022 Build Tools
cd driver
.\build.ps1          # produces driver\build_output\the_chamber.sys
cd fingerprint
.\build.ps1          # produces chamber_fingerprint.sys
```

### User‑mode shim

```powershell
cd launcher\shim
.\build.ps1          # produces chamber_shim.dll (x64)
```

### Launcher

```powershell
cd launcher\ui
dotnet publish -c Release -r win-x64 --self-contained
# produces thechamber.exe with the driver, fp driver, and shim embedded
```

### Signing

A self‑signed certificate with Subject literally *The Chamber* lives at `recovery\the_chamber_test.pfx`. The launcher re‑signs the driver in place before `NtLoadDriver`. No vendor is impersonated — Subject, timestamps and Enhanced Key Usage are the chamber's own.

### Release pipeline

`.github/workflows/release.yml` runs the four builds above, bundles the outputs as embedded resources in the launcher project, publishes a self‑contained x64 build, and attaches `thechamber.exe` to a GitHub release when a tag is pushed.

---

## Known limitations

- **Patch Guard.** The in‑place `BaseDllName` rewrite against a donor module (`pci.sys` → `acpi.sys` → `msrpc.sys` → `storport.sys` → `tcpip.sys` → `ndis.sys` → `disk.sys` → `partmgr.sys`) avoids the 0x109 BugCheck the earlier unlink pattern tripped. A sufficiently aggressive PG sweep on a future Windows build could still pick up the mismatch.
- **Secure Boot must be off.** The chamber's driver cert is self‑signed. Production Microsoft Attestation signing is out of scope for a research build.
- **Test Mode watermark** shows on the desktop while test‑signing is enabled. Toggle it off with `UNINSTALL.ps1` or `bcdedit /set testsigning off` and a reboot.
- **KTHREAD back‑fill** (`KernelTime` / `UserTime` / `Cycle` on the paused thread) is not rewound. The fields live at per‑build ntoskrnl offsets; rolling a runtime offset table is pending.
- **Shim injection on already‑running targets.** `PsSetLoadImageNotifyRoutine` fires on load, not retroactively, so if the operator targets a process whose image set is already fully mapped, `IOCTL_CFP_ADD_PID` still arms but the IC trampoline resolves to an unmapped VA until the process loads another module.
- **KUSER rewind vs CLOCK_LEVEL.** The originator's rewind of `KUSER_SHARED_DATA` runs at PASSIVE_LEVEL and can be transiently torn by the clock ISR on a sibling CPU. A second rewind pass bounds the window to microseconds.

---

## Safety and scope

The Chamber is a defensive research tool for **static analysis of packed malware samples in an isolated sandbox**. It's passive by design — it observes and dumps, it does not debug. The identity spoofing exists so hostile samples unpack normally instead of bailing early; the dump mechanism exists so an analyst can reach the real bytes. Do not use it for anything else.

The repository holds no malware. Test samples belong to the researcher.

---

## Branch & contribution

Active development on `claude/sharp-ritchie-ku155z`. Releases cut from tags matching `v*.*.*`. Issues and discussion on GitHub. The project is a single‑maintainer research effort; please open an issue before sending a PR.
