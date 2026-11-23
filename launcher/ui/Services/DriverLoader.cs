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
    /// <c>DriverEntry</c>. The fingerprint driver's control device is a
    /// fixed-name symlink published inside the driver
    /// (<c>\\.\CFPControl</c>), so no device handle is returned here — the
    /// operator can open it on demand. Call this AFTER the HV driver has
    /// loaded; the fingerprint driver depends on CFG v2 being readable
    /// from registry and on a live SVM environment for its hypercall
    /// callback into the HV side.
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
    }
}
