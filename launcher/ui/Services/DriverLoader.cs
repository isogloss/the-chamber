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
/// </summary>
public sealed class DriverLoader
{
    public string? LoadedServiceName { get; private set; }
    public string? LoadedDevicePath { get; private set; }
    public string? LoadedImagePath { get; private set; }

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
}
