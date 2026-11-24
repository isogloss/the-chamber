using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using TheChamber.Interop;

namespace TheChamber.Services;

/// <summary>
/// Writes the seed-named service registry key, enables
/// SeLoadDriverPrivilege, calls NtLoadDriver, and opens the resulting
/// <c>\\?\&lt;device_suffix&gt;</c> symlink. Mirrors the PowerShell
/// loader in <c>launcher/install_service.ps1</c>; the goal is to avoid
/// an SCM 7045 and never touch sc.exe. NtUnloadDriver is also exposed
/// for the Operator window's Shutdown button.
///
/// Wave 5 extension: this class now also installs the second driver —
/// <c>chamber_fingerprint.sys</c> — alongside the_chamber.sys. The two
/// drivers share a single CFG v2 blob derived from the master seed; the
/// HV driver (the_chamber.sys) reads its copy from its own <c>.cfg</c>
/// section (patched in by <see cref="CfgPatcher"/> before NtLoadDriver),
/// and the fingerprint driver reads its copy from
/// <c>HKLM\SYSTEM\CurrentControlSet\Services\&lt;fp_svc&gt;\Parameters\CfgBlob</c>
/// (REG_BINARY, 632 bytes) — see
/// <c>driver/fingerprint/cfg_shared.c:cfp_read_cfgblob</c>.
/// </summary>
public sealed class DriverLoader
{
    public string? LoadedServiceName { get; private set; }
    public string? LoadedDevicePath { get; private set; }
    public string? LoadedImagePath { get; private set; }

    // --- Second driver (chamber_fingerprint.sys) ---
    public string? LoadedFingerprintServiceName { get; private set; }
    public string? LoadedFingerprintImagePath { get; private set; }

    /// <summary>
    /// Full NT path (<c>\\.\&lt;suffix&gt;</c>) of the fingerprint driver's
    /// control device, populated by
    /// <see cref="QueryFingerprintDeviceNameAsync"/> on the first query
    /// and cached for later <see cref="OpenFingerprintDeviceAsync"/> calls.
    /// Null until the query lands successfully. The suffix is per-boot
    /// random (see driver/fingerprint/entry.c:build_random_name), so
    /// there is no stable literal the launcher can hard-code; the
    /// property is set exactly once per driver load and cleared by
    /// <see cref="UnloadFingerprintAsync"/>.
    /// </summary>
    public string? LoadedFingerprintDevicePath { get; private set; }

    // Query-once memoization: QueryFingerprintDeviceNameAsync is idempotent
    // and returns the cached suffix on the second and later calls. A
    // SemaphoreSlim serialises concurrent first-time queries — DumpService
    // can race the UI's status poller against a trigger arm, and without
    // serialisation both would see a null cache, both would issue the
    // IOCTL, and the slower winner would overwrite the earlier one with
    // the same value (safe but wasteful).
    private readonly SemaphoreSlim _fpNameQueryLock = new(1, 1);

    // CFG-derived fingerprint device suffix. Snapshotted from
    // cfgBlob[60..72] during InstallAndLoadFingerprintAsync; used as the
    // STATUS_NOT_SUPPORTED fallback in QueryFingerprintDeviceNameAsync
    // when the HV driver declines to publish the fp driver's chosen name.
    private string? _fpDeviceSuffixFromCfg;

    public async Task<SafeFileHandle> InstallAndLoadAsync(
        string serviceName,
        string imagePath,
        string deviceSuffix)
    {
        // The service subkey is scoped to this logon; a reboot wipes
        // handles but the key stays, which is fine — install_service.ps1
        // has worked that way for several waves.
        var regPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
        using (var key = Registry.LocalMachine.CreateSubKey(regPath, writable: true))
        {
            if (key is null)
            {
                throw new IOException($"Unable to create {regPath}");
            }
            // ImagePath uses the NT-namespace prefix that NtLoadDriver
            // expects; a regular DOS path works for new builds but the
            // documented contract is \??\<drive>\path.
            var nt = @"\??\" + imagePath;
            key.SetValue("ImagePath", nt, RegistryValueKind.ExpandString);
            key.SetValue("Type", 1, RegistryValueKind.DWord);          // kernel driver
            key.SetValue("Start", 3, RegistryValueKind.DWord);          // SERVICE_DEMAND_START
            key.SetValue("ErrorControl", 1, RegistryValueKind.DWord);   // SERVICE_ERROR_NORMAL
            key.SetValue("DisplayName", serviceName, RegistryValueKind.String);
        }

        // RtlAdjustPrivilege rather than AdjustTokenPrivileges so we
        // skip the "Special Privilege Assigned" (4672) that the token
        // path tends to trip on EV-audit policies.
        _ = NativeMethods.RtlAdjustPrivilege(
            NativeMethods.SeLoadDriverPrivilege,
            true,
            false,
            out _);

        var ntServicePath = $@"\Registry\Machine\System\CurrentControlSet\Services\{serviceName}";
        var us = new NativeMethods.UNICODE_STRING();
        NativeMethods.RtlInitUnicodeString(ref us, ntServicePath);

        var st = await Task.Run(() => NativeMethods.NtLoadDriver(ref us)).ConfigureAwait(false);
        if (st != 0 && st != NativeMethods.STATUS_IMAGE_ALREADY_LOADED)
        {
            throw new Win32Exception(
                (int)NativeMethods.RtlNtStatusToDosError((uint)st),
                $"NtLoadDriver failed with NTSTATUS 0x{(uint)st:X8}");
        }

        LoadedServiceName = serviceName;
        LoadedImagePath = imagePath;
        LoadedDevicePath = $@"\\.\{deviceSuffix}";

        // Give the driver a moment to come up the first time; in practice
        // DriverEntry is synchronous, but the symlink registration races
        // the IO manager publishing the device object.
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (true)
        {
            try
            {
                return OpenDevice();
            }
            catch (FileNotFoundException) when (DateTime.UtcNow < deadline)
            {
                await Task.Delay(100).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Load the second (fingerprint) driver. It uses the same NtLoadDriver
    /// contract as <see cref="InstallAndLoadAsync"/>, but additionally writes
    /// the already-patched 632-byte CFG v2 blob under the service's
    /// <c>Parameters\CfgBlob</c> value (REG_BINARY) so that
    /// <c>chamber_fingerprint!cfp_cfg_load</c> can pick it up at
    /// <c>DriverEntry</c>. The fingerprint driver's control device is
    /// published under a per-boot random DOS suffix (see
    /// <c>driver/fingerprint/entry.c:build_random_name</c>) — the former
    /// static literal <c>\\.\CFPControl</c> is obsolete and must not
    /// appear anywhere in the launcher. The suffix is not known at this
    /// call site; the launcher learns it off the HV control handle via
    /// <see cref="QueryFingerprintDeviceNameAsync"/>, which is why no
    /// device handle is returned from here. Call this AFTER the HV
    /// driver has loaded; the fingerprint driver depends on CFG v2
    /// being readable from registry and on a live SVM environment for
    /// its hypercall callback into the HV side.
    /// </summary>
    /// <param name="serviceName">
    /// Seed-minted service name for <c>chamber_fingerprint.sys</c>. Must be
    /// distinct from the HV driver's service name.
    /// </param>
    /// <param name="imagePath">
    /// On-disk path to the already-patched (CFG offsets overwritten) and
    /// re-signed <c>chamber_fingerprint.sys</c>.
    /// </param>
    /// <param name="cfgBlob">
    /// The 632-byte CHAMBER_CFG_V2 blob, byte-identical to what the
    /// <see cref="CfgPatcher"/> wrote into the HV driver's <c>.cfg</c>
    /// section. The two drivers MUST see the same bytes or a fingerprint
    /// surface queried through CPUID (HV) and through
    /// NtQuerySystemInformation (fingerprint) diverges.
    /// </param>
    public async Task InstallAndLoadFingerprintAsync(
        string serviceName,
        string imagePath,
        byte[] cfgBlob)
    {
        if (cfgBlob is null || cfgBlob.Length != CfgPatcher.CfgTotalLength)
        {
            throw new ArgumentException(
                $"CfgBlob must be exactly {CfgPatcher.CfgTotalLength} bytes; got " +
                (cfgBlob?.Length.ToString() ?? "null") + ".",
                nameof(cfgBlob));
        }

        // Cache the device suffix the fp driver will derive from the same
        // CFG blob (offset 60, 12 ASCII bytes — see CfgPatcher.OffDeviceSuffix
        // and driver/fingerprint/entry.c:build_cfg_name). The HV driver has
        // no way to cross-query the fp driver's chosen suffix in kernel
        // mode, so IOCTL_CFP_GET_DEVICE_NAME returns STATUS_NOT_SUPPORTED;
        // on that sentinel the launcher opens \\.\<SuffixFromCfg> directly.
        // Both sides produce the same 12 bytes because both derive from
        // the same seed, so no runtime handshake is required.
        var suffixSpan = new ReadOnlySpan<byte>(cfgBlob, 60, 12);
        var suffixEnd = suffixSpan.IndexOf((byte)0);
        if (suffixEnd < 0) suffixEnd = suffixSpan.Length;
        _fpDeviceSuffixFromCfg = suffixEnd > 0
            ? System.Text.Encoding.ASCII.GetString(suffixSpan.Slice(0, suffixEnd))
            : null;

        // Service subkey — same shape as the HV driver's, plus a
        // Parameters subkey holding the CFG v2 blob the fingerprint
        // driver reads at DriverEntry.
        var regPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
        using (var key = Registry.LocalMachine.CreateSubKey(regPath, writable: true))
        {
            if (key is null)
            {
                throw new IOException($"Unable to create {regPath}");
            }
            var nt = @"\??\" + imagePath;
            key.SetValue("ImagePath", nt, RegistryValueKind.ExpandString);
            key.SetValue("Type", 1, RegistryValueKind.DWord);
            key.SetValue("Start", 3, RegistryValueKind.DWord);
            key.SetValue("ErrorControl", 1, RegistryValueKind.DWord);
            key.SetValue("DisplayName", serviceName, RegistryValueKind.String);
        }

        var paramsPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}\Parameters";
        using (var pk = Registry.LocalMachine.CreateSubKey(paramsPath, writable: true))
        {
            if (pk is null)
            {
                throw new IOException($"Unable to create {paramsPath}");
            }
            // CfgBlob is REG_BINARY; the driver's cfp_read_cfgblob rejects
            // any other type with STATUS_INVALID_PARAMETER.
            pk.SetValue("CfgBlob", cfgBlob, RegistryValueKind.Binary);
        }

        _ = NativeMethods.RtlAdjustPrivilege(
            NativeMethods.SeLoadDriverPrivilege,
            true,
            false,
            out _);

        var ntServicePath = $@"\Registry\Machine\System\CurrentControlSet\Services\{serviceName}";
        var us = new NativeMethods.UNICODE_STRING();
        NativeMethods.RtlInitUnicodeString(ref us, ntServicePath);

        var st = await Task.Run(() => NativeMethods.NtLoadDriver(ref us)).ConfigureAwait(false);
        if (st != 0 && st != NativeMethods.STATUS_IMAGE_ALREADY_LOADED)
        {
            throw new Win32Exception(
                (int)NativeMethods.RtlNtStatusToDosError((uint)st),
                $"NtLoadDriver(chamber_fingerprint) failed with NTSTATUS 0x{(uint)st:X8}");
        }

        LoadedFingerprintServiceName = serviceName;
        LoadedFingerprintImagePath = imagePath;
    }

    public SafeFileHandle OpenDevice()
    {
        if (LoadedDevicePath is null)
        {
            throw new InvalidOperationException("Driver not loaded; no device path.");
        }

        var h = NativeMethods.CreateFileW(
            LoadedDevicePath,
            NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE,
            NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
            IntPtr.Zero,
            NativeMethods.OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (h.IsInvalid)
        {
            var err = Marshal.GetLastWin32Error();
            if (err == NativeMethods.ERROR_FILE_NOT_FOUND)
            {
                throw new FileNotFoundException("Device symlink not published yet.");
            }
            throw new Win32Exception(err, $"CreateFileW({LoadedDevicePath}) failed.");
        }
        return h;
    }

    /// <summary>
    /// Learn and cache the fingerprint driver's per-boot random DOS
    /// device suffix. The HV driver and the fingerprint driver share
    /// one CFG v2 blob, so the HV side is authoritative: this method
    /// opens a fresh HV control handle, sends
    /// <see cref="DumpIoctls.IoctlGetFingerprintDeviceName"/>, and
    /// stores the result in <see cref="LoadedFingerprintDevicePath"/>.
    /// Idempotent — the second call returns the cached value without
    /// issuing another IOCTL. Returns null if the fingerprint driver
    /// has not been loaded (<see cref="LoadedFingerprintServiceName"/>
    /// is null) so a caller can treat fingerprint integration as
    /// strictly optional.
    /// </summary>
    public async Task<string?> QueryFingerprintDeviceNameAsync()
    {
        if (LoadedFingerprintServiceName is null)
        {
            // Fingerprint driver is not loaded; nothing to resolve.
            return null;
        }
        if (LoadedFingerprintDevicePath is not null)
        {
            return LoadedFingerprintDevicePath;
        }

        await _fpNameQueryLock.WaitAsync().ConfigureAwait(false);
        try
        {
            // Re-check after taking the lock; another thread may have
            // completed the query while we were waiting on the semaphore.
            if (LoadedFingerprintDevicePath is not null)
            {
                return LoadedFingerprintDevicePath;
            }

            var resolved = await Task.Run(() =>
            {
                using var hv = OpenDevice();
                var outSize = Marshal.SizeOf<DumpIoctls.FingerprintDeviceNameResponse>();
                var outBuf = Marshal.AllocHGlobal(outSize);
                try
                {
                    // Zero-fill: ByValTStr marshalling reads up to the
                    // first NUL from the returned buffer, so a stale
                    // tail cannot bleed into the managed string.
                    for (var i = 0; i < outSize; ++i)
                    {
                        Marshal.WriteByte(outBuf, i, 0);
                    }

                    if (!NativeMethods.DeviceIoControl(
                            hv,
                            DumpIoctls.IoctlGetFingerprintDeviceName,
                            IntPtr.Zero, 0,
                            outBuf, (uint)outSize,
                            out var returned, IntPtr.Zero))
                    {
                        // STATUS_NOT_SUPPORTED (0xC00000BB, mapped to
                        // ERROR_NOT_SUPPORTED=50) is the explicit "HV
                        // driver cannot cross-query the fp driver's
                        // suffix in kernel mode; fall back to the one
                        // you already derived from CFG" sentinel. Both
                        // sides derive the same 12 bytes from the same
                        // seed, so the CFG-derived path opens the same
                        // device the fp driver created. Any other
                        // failure is a real IOCTL error.
                        var err = Marshal.GetLastWin32Error();
                        if (err == NativeMethods.ERROR_NOT_SUPPORTED &&
                            !string.IsNullOrEmpty(_fpDeviceSuffixFromCfg))
                        {
                            return @"\\.\" + _fpDeviceSuffixFromCfg;
                        }
                        throw new Win32Exception(
                            err,
                            "IOCTL_CFP_GET_DEVICE_NAME failed.");
                    }
                    if (returned < (uint)Marshal.SizeOf<uint>() * 2)
                    {
                        // Header did not fit; the driver has a protocol
                        // mismatch we cannot recover from here.
                        throw new InvalidOperationException(
                            "IOCTL_CFP_GET_DEVICE_NAME: short response.");
                    }
                    var resp = Marshal.PtrToStructure<DumpIoctls.FingerprintDeviceNameResponse>(outBuf);
                    var len = (int)Math.Min(resp.SuffixLengthChars, 128);
                    if (len <= 0 || string.IsNullOrEmpty(resp.Suffix))
                    {
                        // Driver returned success with an empty suffix:
                        // treat the same as NOT_SUPPORTED and use the
                        // CFG-derived value (applies to the random
                        // fallback case when the fp driver's CFG was
                        // unreadable but the launcher's was fine).
                        if (!string.IsNullOrEmpty(_fpDeviceSuffixFromCfg))
                        {
                            return @"\\.\" + _fpDeviceSuffixFromCfg;
                        }
                        throw new InvalidOperationException(
                            "IOCTL_CFP_GET_DEVICE_NAME: empty suffix.");
                    }
                    // Trim on the explicit length — the driver does not
                    // null-terminate, and ByValTStr relies on ambient NUL.
                    // Take whichever is shorter.
                    var raw = resp.Suffix;
                    if (raw.Length > len) raw = raw.Substring(0, len);
                    return @"\\.\" + raw;
                }
                finally
                {
                    Marshal.FreeHGlobal(outBuf);
                }
            }).ConfigureAwait(false);

            LoadedFingerprintDevicePath = resolved;
            return resolved;
        }
        finally
        {
            _fpNameQueryLock.Release();
        }
    }

    /// <summary>
    /// Open a handle to the fingerprint driver's control device. The
    /// path is resolved lazily via
    /// <see cref="QueryFingerprintDeviceNameAsync"/> on the first call,
    /// then cached in <see cref="LoadedFingerprintDevicePath"/>. Throws
    /// <see cref="InvalidOperationException"/> if the fingerprint
    /// driver is not loaded. The caller owns the returned handle and
    /// must dispose it (DumpService opens one per IOCTL, mirroring
    /// <see cref="OpenDevice"/>'s discipline).
    /// </summary>
    public async Task<SafeFileHandle> OpenFingerprintDeviceAsync()
    {
        var path = LoadedFingerprintDevicePath
                   ?? await QueryFingerprintDeviceNameAsync().ConfigureAwait(false);
        if (string.IsNullOrEmpty(path))
        {
            throw new InvalidOperationException(
                "Fingerprint driver not loaded or its device name has not been resolved.");
        }

        var h = NativeMethods.CreateFileW(
            path,
            NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE,
            NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
            IntPtr.Zero,
            NativeMethods.OPEN_EXISTING,
            0,
            IntPtr.Zero);

        if (h.IsInvalid)
        {
            var err = Marshal.GetLastWin32Error();
            if (err == NativeMethods.ERROR_FILE_NOT_FOUND)
            {
                // The ephemeral DOS symlink may have been torn down after
                // the first IOCTL_CFP_ARM_PID handshake (see entry.c:
                // g_first_handshake_done). Invalidate the cache so the
                // next call re-queries and either refreshes the suffix
                // or surfaces the real failure.
                LoadedFingerprintDevicePath = null;
                throw new FileNotFoundException(
                    "Fingerprint device symlink not available; re-query required.");
            }
            throw new Win32Exception(err, $"CreateFileW({path}) failed.");
        }
        return h;
    }

    public async Task UnloadAsync(SafeFileHandle? device)
    {
        // Unload in reverse order of load: fingerprint first (it depends on
        // HV being up for its hypercall callback), then the_chamber.sys.
        await UnloadFingerprintAsync().ConfigureAwait(false);

        if (LoadedServiceName is null) return;

        // Ask the driver to walk down first; NtUnloadDriver will then do
        // the final tear-down. Ordering matters because the driver's
        // Unload routine runs integrity_shutdown() before pool frees.
        if (device is not null && !device.IsClosed && !device.IsInvalid)
        {
            try
            {
                _ = DeviceIoControl.Shutdown(device);
            }
            catch
            {
                // Best effort; the driver will tear down on NtUnloadDriver
                // regardless.
            }
            device.Dispose();
        }

        var ntServicePath =
            $@"\Registry\Machine\System\CurrentControlSet\Services\{LoadedServiceName}";
        var us = new NativeMethods.UNICODE_STRING();
        NativeMethods.RtlInitUnicodeString(ref us, ntServicePath);

        await Task.Run(() => NativeMethods.NtUnloadDriver(ref us)).ConfigureAwait(false);

        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(
                $@"SYSTEM\CurrentControlSet\Services\{LoadedServiceName}",
                throwOnMissingSubKey: false);
        }
        catch (IOException)
        {
            // Key removal is best effort; UNINSTALL.ps1 sweeps anyway.
        }

        LoadedServiceName = null;
        LoadedDevicePath = null;
        LoadedImagePath = null;
    }

    /// <summary>
    /// Unload the fingerprint driver only. Called from
    /// <see cref="UnloadAsync"/> first so the HV side can still service
    /// its final shutdown hypercall while the fingerprint driver is
    /// still alive to watch for it. Safe to call when the fingerprint
    /// driver was never loaded.
    /// </summary>
    public async Task UnloadFingerprintAsync()
    {
        if (LoadedFingerprintServiceName is null) return;

        var ntServicePath =
            $@"\Registry\Machine\System\CurrentControlSet\Services\{LoadedFingerprintServiceName}";
        var us = new NativeMethods.UNICODE_STRING();
        NativeMethods.RtlInitUnicodeString(ref us, ntServicePath);

        await Task.Run(() => NativeMethods.NtUnloadDriver(ref us)).ConfigureAwait(false);

        try
        {
            Registry.LocalMachine.DeleteSubKeyTree(
                $@"SYSTEM\CurrentControlSet\Services\{LoadedFingerprintServiceName}",
                throwOnMissingSubKey: false);
        }
        catch (IOException)
        {
            // Best effort.
        }

        LoadedFingerprintServiceName = null;
        LoadedFingerprintImagePath = null;
        // Clearing the cached device path belongs here, not in
        // UnloadAsync's trailer: the device path is tied to the
        // fingerprint driver's current load, and leaving a stale suffix
        // live past NtUnloadDriver would let OpenFingerprintDeviceAsync
        // hand back a handle to whatever device object had since
        // re-used that name.
        LoadedFingerprintDevicePath = null;
    }
}
