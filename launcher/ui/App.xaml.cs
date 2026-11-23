using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using TheChamber.Services;
using TheChamber.Views;

namespace TheChamber;

/// <summary>
/// Launcher entry point. Flow:
///   1. Show splash.
///   2. Require admin + x64; refuse a WOW64 host.
///   3. Query BCD state (testsigning, HVCI). Offer to flip if blocked.
///   4. Load persisted seed or mint one (user action only; see SeedService).
///   5. Open the Randomize modal; user hits Proceed.
///   6. Extract both embedded drivers, patch CHAMBER_CFG v2, re-sign,
///      write to Program Files.
///   7. NtLoadDriver the HV driver first, then NtLoadDriver the
///      fingerprint driver (reads the same CFG blob from registry).
///   8. Open HV device, swap to the Operator window.
/// </summary>
public partial class App : Application
{
    private SplashWindow? _splash;
    private SeedService? _seed;
    private BcdService? _bcd;
    private CfgPatcher? _patcher;
    private DriverLoader? _loader;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // WPF swallows exceptions on the dispatcher thread by default; route
        // them to our own handler so we actually see them in a dialog rather
        // than the "unresponsive" state.
        DispatcherUnhandledException += OnDispatcherException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainException;

        _splash = new SplashWindow();
        _splash.Show();

        try
        {
            await DriveAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            // _splash may already be closed and nulled by DriveAsync.
            // MessageBox.Show demands a non-null owner, so pass whatever
            // is live.
            Window? owner = _splash is { IsLoaded: true } ? _splash : null;
            var text = $"Startup aborted:\n\n{ex.Message}";
            if (owner is null)
            {
                MessageBox.Show(text, "The Chamber", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            else
            {
                MessageBox.Show(owner, text, "The Chamber",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
            Shutdown(1);
        }
    }

    private async Task DriveAsync()
    {
        _splash!.SetStatus("checking host");

        if (!IsElevated())
        {
            MessageBox.Show(
                _splash,
                "The Chamber launcher must run elevated. The embedded manifest\n" +
                "normally forces UAC; if you see this dialog, the manifest was\n" +
                "stripped or UAC is off. Right-click the exe and \"Run as\n" +
                "administrator\" to continue.",
                "The Chamber",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            Shutdown(2);
            return;
        }

        if (!Environment.Is64BitProcess)
        {
            MessageBox.Show(_splash, "x64 only.", "The Chamber", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(2);
            return;
        }

        _bcd = new BcdService();
        _seed = new SeedService();
        _patcher = new CfgPatcher();
        _loader = new DriverLoader();

        _splash.SetStatus("reading seed");
        await _seed.LoadOrCreateAsync().ConfigureAwait(true);

        _splash.SetStatus("querying bcd");
        var bcd = await _bcd.ReadAsync().ConfigureAwait(true);

        if (!bcd.TestSigningOn || bcd.HvciOn)
        {
            // The guest won't accept our self-signed driver without
            // testsigning, and it won't let us load an unsigned driver
            // under HVCI. Offer to flip both and reboot.
            var detail = BuildBcdBlockMessage(bcd);
            var r = MessageBox.Show(
                _splash,
                detail,
                "The Chamber: boot configuration",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (r != MessageBoxResult.Yes)
            {
                Shutdown(3);
                return;
            }

            await _bcd.SnapshotAsync().ConfigureAwait(true);
            if (!bcd.TestSigningOn)
            {
                await _bcd.SetTestSigningAsync(true).ConfigureAwait(true);
            }
            if (bcd.HvciOn)
            {
                await _bcd.SetHvciAsync(false).ConfigureAwait(true);
            }

            MessageBox.Show(
                _splash,
                "Boot flags adjusted. The system must reboot for the changes to\n" +
                "take effect. Launch The Chamber again after the reboot.",
                "The Chamber",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            await _bcd.ScheduleRebootAsync(30).ConfigureAwait(true);
            Shutdown(0);
            return;
        }

        // Hand off to the randomize window. Its DialogResult decides whether
        // we actually load the driver.
        _splash.SetStatus("waiting for operator");

        var rw = new RandomizeWindow(_seed)
        {
            Owner = _splash,
        };
        var ok = rw.ShowDialog() == true;
        if (!ok)
        {
            Shutdown(0);
            return;
        }

        await _seed.SaveAsync().ConfigureAwait(true);

        _splash.SetStatus("patching driver image");
        var hvBytes = LoadEmbeddedDriverOrPlaceholder("TheChamber.Drivers.the_chamber.sys");
        var fpBytes = LoadEmbeddedDriverOrPlaceholder("TheChamber.Drivers.chamber_fingerprint.sys");
        var derived = _seed.DeriveAll();
        var targetPath = _patcher.ComputeTargetPath(derived.ServiceName);

        // Patch HV driver. Returns both the path and the 632-byte CFG blob
        // (byte-exact) so the second driver can be arranged to read the
        // same bytes from its own Parameters\CfgBlob value.
        var hvResult = await _patcher
            .PatchAndWriteAsync(hvBytes, derived, targetPath)
            .ConfigureAwait(true);
        await _patcher.ResignAsync(hvResult.Path).ConfigureAwait(true);

        // Fingerprint driver: distinct service name (seed-derived so each
        // install differs). The on-disk filename reuses the fingerprint
        // service name for symmetry with the_chamber.sys path layout.
        var fpServiceName = _seed.DeriveFingerprintServiceName();
        var fpTargetPath = _patcher.ComputeTargetPath(fpServiceName);
        var fpResult = await _patcher
            .PatchAndWriteAsync(fpBytes, derived, fpTargetPath)
            .ConfigureAwait(true);
        await _patcher.ResignAsync(fpResult.Path).ConfigureAwait(true);

        _splash.SetStatus("loading hv driver");
        var device = await _loader
            .InstallAndLoadAsync(derived.ServiceName, hvResult.Path, derived.DeviceSuffix)
            .ConfigureAwait(true);

        _splash.SetStatus("loading fingerprint driver");
        await _loader
            .InstallAndLoadFingerprintAsync(fpServiceName, fpResult.Path, fpResult.CfgBlob)
            .ConfigureAwait(true);

        _splash.SetStatus("live");

        var op = new OperatorWindow(_loader, device);
        op.Show();

        _splash.Close();
        _splash = null;
    }

    private static string BuildBcdBlockMessage(BcdState s)
    {
        var lines = new System.Text.StringBuilder();
        lines.AppendLine("Current boot configuration is not compatible with The Chamber:");
        lines.AppendLine();
        if (!s.TestSigningOn)
        {
            lines.AppendLine("  * testsigning  : OFF   (needed: ON)");
        }
        if (s.HvciOn)
        {
            lines.AppendLine("  * HVCI         : ON    (needed: OFF)");
        }
        lines.AppendLine();
        lines.AppendLine("Flip them and schedule a 30-second reboot?");
        lines.AppendLine("The current state is snapshotted so UNINSTALL.ps1 can revert.");
        return lines.ToString();
    }

    private static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        var p = new WindowsPrincipal(id);
        return p.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static byte[] LoadEmbeddedDriverOrPlaceholder(string logicalName)
    {
        var asm = Assembly.GetExecutingAssembly();
        using var s = asm.GetManifestResourceStream(logicalName);
        if (s is null)
        {
            // Build-time: drivers are not embedded yet. The CfgPatcher can
            // still exercise its code path against a placeholder so the
            // launcher is testable end-to-end while Agents B and C work.
            return Array.Empty<byte>();
        }
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    private void OnDispatcherException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Debug.WriteLine(e.Exception);
        MessageBox.Show(
            $"Unhandled UI exception:\n\n{e.Exception.Message}",
            "The Chamber",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void OnDomainException(object sender, UnhandledExceptionEventArgs e)
    {
        Debug.WriteLine(e.ExceptionObject);
    }
}
