# launcher/ui — The Chamber launcher (WPF .NET 8)

Single-exe loader for `the_chamber.sys` and `chamber_fingerprint.sys`.
Owns the persistent-seed identity: the computer looks totally different
across bootups (every process-observable fingerprint is seed-derived),
but the identity only changes when the operator hits **Randomize all** —
not on boot.

## Build

Prerequisites: Visual Studio 2022 17.8+ or the .NET 8 SDK on Windows x64.
WPF compilation needs the Windows targeting pack, which comes with the
`Microsoft.NET.Sdk` reference for `net8.0-windows`.

```powershell
# Dev build (fast, multi-file, runs out of bin\Debug).
dotnet build launcher\ui\TheChamber.csproj -c Debug

# Smoke run (requires elevation; a non-elevated process shows a dialog
# and quits at the admin check).
dotnet run --project launcher\ui\TheChamber.csproj -c Debug
```

## Publish (shipping single exe)

```powershell
dotnet publish launcher\ui\TheChamber.csproj `
    -c Release `
    -r win-x64 `
    --self-contained true `
    /p:PublishSingleFile=true `
    /p:IncludeNativeLibrariesForSelfExtract=true `
    -o out\
```

The output is `out\thechamber.exe`, around 75 MB once the WPF runtime,
the .NET 8 host, the embedded drivers (added by the packaging wave),
and the chamber image are packed. The single-file host self-extracts
to `%LOCALAPPDATA%\Temp\.net\thechamber\...` on first launch.

## Driver bytes

Driver images are picked up from these paths when they exist and
packed into the exe at build time:

| Logical resource                         | Path                                             |
|------------------------------------------|--------------------------------------------------|
| `TheChamber.Drivers.the_chamber.sys`     | `driver/build/the_chamber.sys`                   |
| `TheChamber.Drivers.chamber_fingerprint.sys` | `driver/fingerprint/build/chamber_fingerprint.sys` |
| `TheChamber.Certs.the_chamber.cer`       | `recovery/the_chamber_test.cer`                  |

Any `<EmbeddedResource>` carries `Condition="Exists(...)"` so the
project builds cleanly before Agents B and C freeze their driver
output. `CfgPatcher` detects the empty-bytes case and writes a text
sidecar beside the destination `.sys` so the operator can at least
read the derived fields.

## Runtime layout

| What                               | Where                                     |
|------------------------------------|-------------------------------------------|
| Seed state (DPAPI-wrapped)         | `%AppData%\TheChamber\seed.bin`           |
| BCD snapshot (pre-change)          | `%AppData%\TheChamber\bcd_snapshot.txt`   |
| Patched driver image               | `%ProgramFiles%\The Chamber\<service>.sys`|
| Service subkey                     | `HKLM\SYSTEM\CurrentControlSet\Services\<service>` |
| Device symlink                     | `\\.\<device_suffix>`                     |

Both `<service>` and `<device_suffix>` are seed-derived; a new seed
re-rolls the names on the next load.

## Launch flow

1. Elevate (manifest requires admin).
2. Query BCD for `testsigning` and HVCI / `hypervisorlaunchtype`.
   If `testsigning` is off or HVCI is on, snapshot BCD, flip the
   flags, and schedule a 30-second reboot. The flags must be right
   before `NtLoadDriver` will accept the self-signed image.
3. Load or create the seed. First launch mints a CSPRNG seed; every
   subsequent launch reads `%AppData%\TheChamber\seed.bin`. No
   automatic re-roll ever happens.
4. Show the Randomize modal. Per-tab "randomize group" buttons bump
   the identity or HV salt; "randomize all" mints a new master seed
   and resets both salts to 0. Proceed commits.
5. `CfgPatcher` locates `CHAMBER_CFG_V2` in the driver image, writes
   the derived 632-byte blob at the design-Section-3 field offsets,
   recomputes the PE checksum (`ImageHlp!CheckSumMappedFile`), and
   drops the output into `%ProgramFiles%\The Chamber\<service>.sys`.
6. `DriverLoader` writes the service subkey directly (bypassing the
   SCM 7045 trail), enables SeLoadDriverPrivilege via
   `RtlAdjustPrivilege`, calls `NtLoadDriver`, and polls
   `CreateFileW("\\.\<device_suffix>")` until the driver publishes
   its symlink.
7. `OperatorWindow` takes over and polls `IOCTL_STATUS` at 1 Hz
   while firing `IOCTL_KICK` every 20 s. Shutdown walks
   `IOCTL_SHUTDOWN -> NtUnloadDriver -> registry delete` in order.

## Non-goals in this wave

- **Driver signing is deferred.** The packaging wave wires in the
  signing step after Agents B and C freeze their output.
- **Re-sign on patch is deferred.** `CfgPatcher.PatchAndWriteAsync`
  writes the PE checksum but the catalog / Authenticode step lives
  in `tools/sign.ps1` and runs post-patch.
- **No Intel brand strings.** The CPU brand pool is AMD-only until
  the full feature-flag rewrite in a future wave; an Intel brand on
  a Zen 4 host would break CPUID consistency.
- **TPM EK.** Architecturally impossible to spoof credibly; the
  `tpm_absent_spoof` toggle has the interceptor report "no TPM".

## Style

- C# 12, nullable enabled, `async`/`await` for every I/O path.
- Dark brutalist theme in `Themes/TheChamberTheme.xaml`: mono
  typography, flat 1-px borders, two-accent palette.
- The UI never formats the seed, salt, or raw blob with placeholder
  copy — everything on screen is the value the driver actually
  gets.
