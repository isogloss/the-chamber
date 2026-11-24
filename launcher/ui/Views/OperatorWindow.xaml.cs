using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32.SafeHandles;
using TheChamber.Interop;
using TheChamber.Services;

namespace TheChamber.Views;

/// <summary>
/// Post-load panel. Polls IOCTL_STATUS on a 1 Hz timer, fires a
/// background IOCTL_KICK every 20 s to keep the driver watchdog happy,
/// and renders CPU count / active CPUs / VMEXIT count / last heartbeat
/// / service and device name. The Shutdown button runs the DriverLoader
/// teardown and closes the window.
/// </summary>
public partial class OperatorWindow : Window
{
    private readonly DriverLoader _loader;
    private SafeFileHandle? _device;
    private readonly DispatcherTimer _statusTimer;
    private readonly System.Timers.Timer _kickTimer;
    private readonly DumpService _dumpService;
    private DateTime _lastOkUtc;
    private ulong _lastVmexits;

    public OperatorWindow(DriverLoader loader, SafeFileHandle device)
    {
        _loader = loader;
        _device = device;
        _dumpService = new DumpService(loader);
        InitializeComponent();

        _statusTimer = new DispatcherTimer(DispatcherPriority.Normal)
        {
            Interval = TimeSpan.FromSeconds(1),
        };
        _statusTimer.Tick += (_, _) => PollStatus();

        _kickTimer = new System.Timers.Timer(20_000);
        _kickTimer.Elapsed += (_, _) => KickOnce();

        Loaded += (_, _) =>
        {
            FooterText.Text = $"service {_loader.LoadedServiceName}   device {_loader.LoadedDevicePath}";
            RenderRow("hv service", _loader.LoadedServiceName ?? "?");
            RenderRow("device path", _loader.LoadedDevicePath ?? "?");
            RenderRow("hv image", _loader.LoadedImagePath ?? "?");
            RenderRow("fp service", _loader.LoadedFingerprintServiceName ?? "(not loaded)");
            RenderRow("fp image", _loader.LoadedFingerprintImagePath ?? "(not loaded)");
            PollStatus();
            _statusTimer.Start();
            _kickTimer.Start();

            // Hand the Dump tab a live service once the driver is up.
            // DumpTab opens its own control-device handles per IOCTL
            // through DumpService, so no handle is shared across tabs.
            DumpTabContent.AttachService(_dumpService);

            // Push chamber_shim.dll bytes into the fingerprint driver
            // as soon as the service is wired, so the first PID the
            // operator selects does not have to wait on the shim. The
            // call is a no-op when the fp driver did not load, and
            // idempotent on the driver side, so repeat loads are safe.
            _ = System.Threading.Tasks.Task.Run(async () =>
            {
                try
                {
                    await _dumpService.PushShimImageAsync().ConfigureAwait(false);
                }
                catch
                {
                    // Optional surface; errors show up on first ADD_PID
                    // if they are blocking there.
                }
            });
        };

        Closed += async (_, _) => await OnClosedAsync().ConfigureAwait(false);
    }

    private void PollStatus()
    {
        if (_device is null || _device.IsClosed || _device.IsInvalid)
        {
            SetLiveness(false, "device closed");
            return;
        }

        try
        {
            var s = DeviceIoControl.Status(_device);
            _lastOkUtc = DateTime.UtcNow;

            var rate = s.VmexitCount > _lastVmexits
                ? s.VmexitCount - _lastVmexits
                : 0;
            _lastVmexits = s.VmexitCount;

            StatusPanel.Children.Clear();
            RenderRow("hv service", _loader.LoadedServiceName ?? "?");
            RenderRow("device path", _loader.LoadedDevicePath ?? "?");
            RenderRow("hv image", _loader.LoadedImagePath ?? "?");
            RenderRow("fp service", _loader.LoadedFingerprintServiceName ?? "(not loaded)");
            RenderRow("fp image", _loader.LoadedFingerprintImagePath ?? "(not loaded)");
            RenderRow("version", $"0x{s.Version:X8}");
            RenderRow("cpu count", s.CpuCount.ToString());
            RenderRow("active cpus", $"{s.ActiveCpus} / {s.CpuCount}");
            RenderRow("vmexits total", s.VmexitCount.ToString("N0"));
            RenderRow("vmexits / sec", rate.ToString("N0"));
            RenderRow("last heartbeat", _lastOkUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));

            SetLiveness(true, "live");
        }
        catch (Exception ex)
        {
            SetLiveness(false, ex.Message);
        }
    }

    private void KickOnce()
    {
        try
        {
            if (_device is { IsClosed: false, IsInvalid: false })
            {
                DeviceIoControl.Kick(_device);
            }
        }
        catch
        {
            // Swallow; the status poll will re-report the failure.
        }
    }

    private void SetLiveness(bool ok, string text)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(() => SetLiveness(ok, text));
            return;
        }
        LivenessText.Text = text.ToLowerInvariant();
        if (ok)
        {
            LivenessDot.Fill = (Brush)Application.Current.FindResource("ChamberAccent");
            LivenessText.Foreground = (Brush)Application.Current.FindResource("ChamberFg");
        }
        else
        {
            LivenessDot.Fill = (Brush)Application.Current.FindResource("ChamberWarn");
            LivenessText.Foreground = (Brush)Application.Current.FindResource("ChamberWarn");
        }
    }

    private void RenderRow(string label, string value)
    {
        var g = new Grid { Margin = new Thickness(0, 3, 0, 3) };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var l = new TextBlock
        {
            Text = label,
            Style = (Style)Application.Current.FindResource("ChamberLabel"),
            VerticalAlignment = VerticalAlignment.Center,
        };
        var v = new TextBlock
        {
            Text = value,
            Style = (Style)Application.Current.FindResource("ChamberValue"),
            VerticalAlignment = VerticalAlignment.Center,
        };

        Grid.SetColumn(l, 0);
        Grid.SetColumn(v, 1);
        g.Children.Add(l);
        g.Children.Add(v);
        StatusPanel.Children.Add(g);
    }

    private async void OnShutdown(object sender, RoutedEventArgs e)
    {
        var r = MessageBox.Show(
            this,
            "Shut down the hypervisor and unload the driver?",
            "The Chamber",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (r != MessageBoxResult.Yes) return;

        _statusTimer.Stop();
        _kickTimer.Stop();

        try
        {
            await _loader.UnloadAsync(_device).ConfigureAwait(true);
            _device = null;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Unload reported: {ex.Message}", "The Chamber");
        }

        Application.Current.Shutdown(0);
    }

    private async Task OnClosedAsync()
    {
        _statusTimer.Stop();
        _kickTimer.Stop();
        _kickTimer.Dispose();

        if (_device is not null && !_device.IsClosed)
        {
            try { await _loader.UnloadAsync(_device).ConfigureAwait(false); }
            catch { }
            _device = null;
        }

        // In case the window is X'd while the app is still live, bring
        // the whole process down so the UAC-elevated handle is released.
        if (Application.Current is not null)
        {
            Application.Current.Dispatcher.Invoke(() => Application.Current.Shutdown(0));
        }
    }
}
