# The Chamber — Release Installation Guide

Everything the launcher needs ships inside a single signed executable,
`thechamber.exe`, built and signed by the GitHub Actions release
pipeline on every `v*` tag. This document walks a first-time operator
from the download to a live Operator panel.

> **Scope.** The Chamber is a defensive cybersecurity research
> hypervisor for a dedicated analysis rig running Windows 10 22H2 or
> Windows 11 on an AMD Ryzen 7 7700X (Zen 4) host. It is a
> passive-dump sandbox — no inline hooks, no active debugging, no on-
> disk mutation of samples. See `README.md` for the architectural
> posture and `audit/project_status.md` for the current feature
> coverage.

---

## 1. Prerequisites (one-time, per machine)

| What | Why | How |
|---|---|---|
| **HVCI off** | HVCI rejects self-signed or test-signed drivers; signing with it on needs Microsoft WHQL / Partner Center attestation. | `msinfo32` → *Virtualization-based security*. If any row reads "Running", disable VBS: *Core isolation* in Windows Security → *Memory integrity* → Off, then reboot. |
| **Test-signing on** | Allows Windows to load the self-signed driver + shim. The launcher flips this automatically on first run if it is off. | Automatic. (If you prefer to do it manually: `bcdedit /set testsigning on` as an admin, then reboot.) |
| **AMD Zen 4 CPU** | `the_chamber.sys` is AMD-SVM. | 7700X / 7950X / 7900X all work. Intel VMX is out of scope. |

---

## 2. Download

Pick the latest release from
<https://github.com/isogloss/the-chamber/releases>. The assets are:

| Asset | What it is |
|---|---|
| `thechamber.exe` | Single-file, self-contained launcher. Embeds both driver `.sys` blobs, the user-mode shim DLL, and the public portion of the signing cert. ~40 MB. |
| `thechamber.exe.sha256` | SHA-256 line (`<hash> *thechamber.exe`) matching the release's exe. |
| `the_chamber_sign.cer` | Public portion of the self-signed cert used to sign `thechamber.exe` and the drivers. Import this into `LocalMachine\Root` and `LocalMachine\TrustedPublisher` only if you want to skip the test-signing path entirely (advanced; usually unnecessary). |

Verify the download before you run it:

```powershell
# From the folder you downloaded the files into.
$expected = (Get-Content .\thechamber.exe.sha256).Split(' ')[0]
$actual   = (Get-FileHash .\thechamber.exe -Algorithm SHA256).Hash.ToLower()
if ($expected -ne $actual) { Write-Error 'hash mismatch -- do not run' }
```

---

## 3. First-time run

1. **Right-click → Run as administrator.** The embedded manifest
   also asks for UAC elevation; you will see two prompts total.

2. **Splash → BCD check.** If test-signing is off, the launcher offers
   to turn it on and schedule a 30-second reboot:

   > Current boot configuration is not compatible with The Chamber:
   >   * testsigning  : OFF   (needed: ON)
   >
   > Flip them and schedule a 30-second reboot?
   > The current state is snapshotted so UNINSTALL.ps1 can revert.

   Hit **Yes**. The reboot runs after 30 seconds; the launcher exits.
   On the next boot, re-run `thechamber.exe`.

3. **Seed modal.** On first run the launcher mints a fresh 32-byte
   master seed and persists it DPAPI-wrapped under
   `%AppData%\TheChamber\seed.bin`. The seed stays stable across
   reboots; it only re-rolls when you click **Randomize seed** in the
   modal. Press **Proceed** to continue.

4. **Patch, sign, load.** The launcher:
   * extracts both embedded driver blobs + the shim DLL to
     `%ProgramFiles%\The Chamber\`
   * writes the derived 632-byte `CHAMBER_CFG_V2` identity blob into
     the HV driver's `.cfg` section
   * recomputes the PE checksum and re-signs via `SignerSignEx2` with
     the cached cert at `%ProgramData%\TheChamber\cert\the_chamber.pfx`
     (generated on first run if absent)
   * writes the identical blob under
     `HKLM\SYSTEM\CurrentControlSet\Services\<fp_svc>\Parameters\CfgBlob`
     (REG_BINARY) so `chamber_fingerprint.sys` sees the same identity
   * calls `NtLoadDriver` for the HV first, then the fingerprint driver
   * opens the HV control device and swaps to the Operator window

5. **Operator panel.** The live window shows `vmexits total` + rate,
   both service names, image paths, and a *Shutdown* button that
   tears the drivers down in reverse (fingerprint first, then HV)
   and quits the launcher.

---

## 4. Known limitations

* **HVCI must be off.** The drivers are test-signed; HVCI only
  accepts WHQL / Microsoft-attested chains. See the
  Prerequisites table for how to disable.

* **One reboot the first time test-signing was off.** The BCD flag
  only takes effect after the host reboots. The launcher schedules
  that reboot and exits cleanly; nothing is lost.

* **Reboot is required to re-roll the seed under the HV.** The HV
  reads its CFG blob at `DriverEntry`. Clicking *Randomize seed*
  while the drivers are loaded persists a new seed on disk, but the
  existing driver instance still holds the old identity. Click the
  Operator panel's *Shutdown* button first, then relaunch.

* **Analysis rig only.** The Chamber is explicitly not for deployment
  on production endpoints; the HV takes over SVM on every core and
  its unload path is one-way under load (see
  `audit/project_status.md` → *Non-goals*).

* **Shim DLL dispatch is minimal.** `chamber_shim.dll` currently
  hot-paths three syscall surfaces (`NtQuerySystemInformation`
  classes 103 / 144 / 176, `NtQueryValueKey`,
  `NtDeviceIoControlFile`). Every other syscall passes through at
  zero cost. Growing the dispatch table is a planned follow-up.

* **PG safety.** Every intercept point is a documented Windows API
  (`CmRegisterCallbackEx`, `FltRegisterFilter`,
  `ProcessInstrumentationCallback`, AMD-SVM VMEXIT). No SSDT patches,
  no inline hooks, no `KeServiceDescriptorTable` edits.

---

## 5. Uninstall

Run `UNINSTALL.ps1` from the repo (or the folder the launcher
extracts to), elevated. It:

1. Issues `IOCTL_SHUTDOWN` to the HV device and polls for the symlink
   to disappear.
2. `NtUnloadDriver` for the fingerprint driver, then the HV driver.
3. Reverts every BCD flag the installer snapshotted (test-signing,
   nointegritychecks, etc.) and nothing else.
4. Removes both service subkeys from
   `HKLM\SYSTEM\CurrentControlSet\Services`.
5. Deletes `%ProgramFiles%\The Chamber\`.

The persisted seed under `%AppData%\TheChamber\` and the cached cert
under `%ProgramData%\TheChamber\` are left in place by default so a
re-install keeps the same identity + signing chain. Delete them
manually if you want a fully clean slate.

---

## 6. Where to get help

* `README.md` — architectural tour.
* `audit/project_status.md` — current coverage and non-goals.
* `audit/wave4_design.md` — fingerprint design contract.
* GitHub Issues — tracker on the repo.
