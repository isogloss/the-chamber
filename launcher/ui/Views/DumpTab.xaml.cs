using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using TheChamber.Model;
using TheChamber.Services;

namespace TheChamber.Views;

/// <summary>
/// The Wave 6 Dump tab. Owns the process picker (with 2 s refresh),
/// the output-directory field (persisted to dump_prefs.json), the five
/// trigger radios and their action buttons, and the history ListView.
/// Every action routes through <see cref="DumpService"/>; failures are
/// shown as friendly MessageBoxes. After a successful arm or dump the
/// history is refreshed.
/// </summary>
public partial class DumpTab : UserControl
{
    private DumpService? _service;
    private readonly DispatcherTimer _processRefreshTimer;
    private readonly ObservableCollection<HistoryRow> _history = new();
    private TriggerConfig _config = new();

    private static string DefaultOutputDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "TheChamber",
        "dumps");

    private static string PrefsPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "TheChamber",
        "dump_prefs.json");

    public DumpTab()
    {
        InitializeComponent();
        HistoryList.ItemsSource = _history;

        _processRefreshTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(2),
        };
        _processRefreshTimer.Tick += (_, _) => RefreshProcesses();

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    /// <summary>
    /// Called by the hosting window once the DriverLoader has produced
    /// a live control device. Until this fires the tab stays navigable
    /// but every arm/dump button short-circuits with a message box.
    /// </summary>
    public void AttachService(DumpService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        // History only becomes meaningful once the device is up.
        _ = RefreshHistoryAsync();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        _config = LoadConfig();
        OutputDirBox.Text = string.IsNullOrWhiteSpace(_config.LastOutputDir)
            ? DefaultOutputDir
            : _config.LastOutputDir;

        if (_config.LastOep is ulong oep)
            OepBox.Text = "0x" + oep.ToString("X", CultureInfo.InvariantCulture);
        if (_config.LastThresholdBytes is uint thr)
            ThresholdBox.Text = thr.ToString(CultureInfo.InvariantCulture);

        // Restore the previously selected radio.
        switch (_config.Kind)
        {
            case TriggerKind.WriteToExecute: TrigWx.IsChecked = true; break;
            case TriggerKind.Oep: TrigOep.IsChecked = true; break;
            case TriggerKind.WriteThreshold: TrigThreshold.IsChecked = true; break;
            case TriggerKind.PayloadReceived: TrigPayload.IsChecked = true; break;
            default: TrigManual.IsChecked = true; break;
        }

        RefreshProcesses();
        _processRefreshTimer.Start();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        _processRefreshTimer.Stop();
        SaveConfig();
    }

    // --- Process list refresh ---

    private void OnRefreshProcesses(object sender, RoutedEventArgs e) => RefreshProcesses();

    private void RefreshProcesses()
    {
        // Preserve selection across refreshes.
        var prev = (ProcessCombo.SelectedItem as ProcessItem)?.Pid;

        List<ProcessItem> items;
        try
        {
            var procs = Process.GetProcesses();
            items = new List<ProcessItem>(procs.Length);
            foreach (var p in procs)
            {
                string name;
                try { name = p.ProcessName + ".exe"; }
                catch { name = "?.exe"; }
                int pid;
                try { pid = p.Id; }
                catch { pid = 0; }
                if (pid <= 0) continue;
                items.Add(new ProcessItem((uint)pid, name));
            }
        }
        catch (Exception ex)
        {
            ProcessHint.Text = $"process enumeration failed: {ex.Message}";
            return;
        }

        items.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));

        ProcessCombo.ItemsSource = items;
        if (prev is uint pr)
        {
            ProcessCombo.SelectedItem = items.FirstOrDefault(i => i.Pid == pr);
        }
    }

    // --- Output directory ---

    private void OnBrowseOutputDir(object sender, RoutedEventArgs e)
    {
        // A local Microsoft.Win32.OpenFolderDialog replacement would
        // normally live in Services/, but to keep the tab self-
        // contained we fall back to a FolderBrowserDialog hosted in
        // WPF via Shell32. If that is unavailable we accept a typed
        // path and let the service create it on demand.
        var dlg = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "the chamber: dump output directory",
            InitialDirectory = string.IsNullOrWhiteSpace(OutputDirBox.Text)
                ? DefaultOutputDir
                : OutputDirBox.Text,
        };
        if (dlg.ShowDialog(Window.GetWindow(this)) == true)
        {
            OutputDirBox.Text = dlg.FolderName;
            _config.LastOutputDir = dlg.FolderName;
            SaveConfig();
        }
    }

    // --- Trigger radio bookkeeping ---

    private void OnTriggerChecked(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;

        var manual = TrigManual.IsChecked == true;
        var wx = TrigWx.IsChecked == true;
        var oep = TrigOep.IsChecked == true;
        var thr = TrigThreshold.IsChecked == true;
        var payload = TrigPayload.IsChecked == true;

        BtnDumpNow.IsEnabled = manual;
        BtnArmWx.IsEnabled = wx;
        BtnArmOep.IsEnabled = oep;
        BtnArmThreshold.IsEnabled = thr;
        BtnArmPayload.IsEnabled = payload;

        OepBox.IsEnabled = oep;
        ThresholdBox.IsEnabled = thr;

        _config.Kind = manual ? TriggerKind.Manual
            : wx ? TriggerKind.WriteToExecute
            : oep ? TriggerKind.Oep
            : thr ? TriggerKind.WriteThreshold
            : payload ? TriggerKind.PayloadReceived
            : TriggerKind.Manual;
    }

    // --- Action handlers ---

    private async void OnDumpNow(object sender, RoutedEventArgs e)
    {
        var sel = GetSelectedProcessOrWarn();
        if (sel is null) return;
        if (!GuardService()) return;

        var dir = ResolveOutputDir();
        try
        {
            var record = await _service!.DumpNowAsync(sel.Pid, dir).ConfigureAwait(true);
            // The service returns a record with a bare PID in Target;
            // dress it up with the process name before the UI shows it.
            var pretty = new DumpRecord
            {
                Timestamp = record.Timestamp,
                Target = $"{sel.Name} ({sel.Pid})",
                Trigger = record.Trigger,
                Bytes = record.Bytes,
                Path = record.Path,
            };
            _history.Insert(0, HistoryRow.From(pretty));
        }
        catch (Exception ex)
        {
            Fail("dump now failed", ex);
            return;
        }
        await RefreshHistoryAsync().ConfigureAwait(true);
    }

    private async void OnArmWx(object sender, RoutedEventArgs e)
    {
        var sel = GetSelectedProcessOrWarn();
        if (sel is null) return;
        if (!GuardService()) return;
        try
        {
            await _service!.ArmWxAsync(sel.Pid).ConfigureAwait(true);
        }
        catch (Exception ex) { Fail("arm write-to-execute failed", ex); return; }
        await RefreshHistoryAsync().ConfigureAwait(true);
    }

    private async void OnArmOep(object sender, RoutedEventArgs e)
    {
        var sel = GetSelectedProcessOrWarn();
        if (sel is null) return;
        if (!GuardService()) return;

        if (!TryParseOep(OepBox.Text, out var oep))
        {
            MessageBox.Show(Window.GetWindow(this),
                "OEP must be a hex value (optionally prefixed with 0x).",
                "The Chamber", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        _config.LastOep = oep;
        SaveConfig();

        try
        {
            await _service!.ArmOepAsync(sel.Pid, oep).ConfigureAwait(true);
        }
        catch (Exception ex) { Fail("arm oep failed", ex); return; }
        await RefreshHistoryAsync().ConfigureAwait(true);
    }

    private async void OnArmThreshold(object sender, RoutedEventArgs e)
    {
        var sel = GetSelectedProcessOrWarn();
        if (sel is null) return;
        if (!GuardService()) return;

        if (!uint.TryParse(ThresholdBox.Text, NumberStyles.Integer,
                CultureInfo.InvariantCulture, out var bytes) || bytes == 0)
        {
            MessageBox.Show(Window.GetWindow(this),
                "Threshold must be a positive integer number of bytes.",
                "The Chamber", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        _config.LastThresholdBytes = bytes;
        SaveConfig();

        try
        {
            await _service!.ArmWriteThresholdAsync(sel.Pid, bytes).ConfigureAwait(true);
        }
        catch (Exception ex) { Fail("arm write-threshold failed", ex); return; }
        await RefreshHistoryAsync().ConfigureAwait(true);
    }

    private async void OnArmPayload(object sender, RoutedEventArgs e)
    {
        var sel = GetSelectedProcessOrWarn();
        if (sel is null) return;
        if (!GuardService()) return;

        try
        {
            await _service!.ArmPayloadAsync(sel.Pid).ConfigureAwait(true);
        }
        catch (Exception ex) { Fail("arm payload failed", ex); return; }
        await RefreshHistoryAsync().ConfigureAwait(true);
    }

    private async void OnDisarmAll(object sender, RoutedEventArgs e)
    {
        if (!GuardService()) return;
        try
        {
            await _service!.DisarmAllAsync().ConfigureAwait(true);
        }
        catch (Exception ex) { Fail("disarm all failed", ex); return; }
        await RefreshHistoryAsync().ConfigureAwait(true);
    }

    // --- History ---

    private async void OnRefreshHistory(object sender, RoutedEventArgs e)
        => await RefreshHistoryAsync().ConfigureAwait(true);

    private async Task RefreshHistoryAsync()
    {
        if (_service is null) return;
        try
        {
            var rows = await _service.QueryHistoryAsync().ConfigureAwait(true);
            _history.Clear();
            foreach (var r in rows) _history.Add(HistoryRow.From(r));
        }
        catch (Exception ex)
        {
            // Don't nag the operator on a background refresh; surface
            // in the process hint line instead.
            ProcessHint.Text = $"history refresh: {ex.Message}";
        }
    }

    private void OnOpenHistoryItem(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.Tag is string path && !string.IsNullOrWhiteSpace(path))
        {
            try
            {
                // explorer.exe /select,<path> highlights the file in a
                // new Explorer window without launching the file itself.
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = $"/select,\"{path}\"",
                    UseShellExecute = true,
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show(Window.GetWindow(this),
                    $"Could not open {path}: {ex.Message}",
                    "The Chamber", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
    }

    // --- Helpers ---

    private ProcessItem? GetSelectedProcessOrWarn()
    {
        if (ProcessCombo.SelectedItem is ProcessItem p) return p;
        MessageBox.Show(Window.GetWindow(this),
            "Select a target process first.",
            "The Chamber", MessageBoxButton.OK, MessageBoxImage.Information);
        return null;
    }

    private bool GuardService()
    {
        if (_service is not null) return true;
        MessageBox.Show(Window.GetWindow(this),
            "The hypervisor control device is not available.",
            "The Chamber", MessageBoxButton.OK, MessageBoxImage.Warning);
        return false;
    }

    private string ResolveOutputDir()
    {
        var d = OutputDirBox.Text;
        if (string.IsNullOrWhiteSpace(d)) d = DefaultOutputDir;
        _config.LastOutputDir = d;
        SaveConfig();
        return d;
    }

    private void Fail(string title, Exception ex)
    {
        MessageBox.Show(Window.GetWindow(this),
            $"{title}: {ex.Message}",
            "The Chamber", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void OnThresholdPreviewText(object sender, TextCompositionEventArgs e)
    {
        // Integer-only entry for the threshold box; letters and symbols
        // are swallowed, which keeps the Arm button from needing a
        // friendly-error path for most typos.
        foreach (var c in e.Text)
        {
            if (c < '0' || c > '9') { e.Handled = true; return; }
        }
    }

    private static bool TryParseOep(string raw, out ulong oep)
    {
        oep = 0;
        if (string.IsNullOrWhiteSpace(raw)) return false;
        var s = raw.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out oep);
    }

    private static TriggerConfig LoadConfig()
    {
        try
        {
            if (File.Exists(PrefsPath))
            {
                var json = File.ReadAllText(PrefsPath);
                var c = JsonSerializer.Deserialize<TriggerConfig>(json);
                if (c is not null) return c;
            }
        }
        catch
        {
            // Preferences are best-effort; fall back to defaults.
        }
        return new TriggerConfig { LastOutputDir = DefaultOutputDir };
    }

    private void SaveConfig()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PrefsPath)!);
            var json = JsonSerializer.Serialize(_config,
                new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(PrefsPath, json);
        }
        catch
        {
            // Non-fatal; the next launch just restores defaults.
        }
    }

    /// <summary>ComboBox row model.</summary>
    private sealed class ProcessItem
    {
        public uint Pid { get; }
        public string Name { get; }
        public string Display => $"{Name} ({Pid})";
        public ProcessItem(uint pid, string name) { Pid = pid; Name = name; }
        public override string ToString() => Display;
    }

    /// <summary>ListView row model. Pre-formats bytes + timestamp so
    /// the GridView bindings don't need StringFormat converters.</summary>
    private sealed class HistoryRow
    {
        public string TimestampText { get; init; } = string.Empty;
        public string Target { get; init; } = string.Empty;
        public string Trigger { get; init; } = string.Empty;
        public string BytesText { get; init; } = string.Empty;
        public long Bytes { get; init; }
        public string Path { get; init; } = string.Empty;

        public static HistoryRow From(DumpRecord r) => new()
        {
            TimestampText = r.Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            Target = r.Target,
            Trigger = r.Trigger,
            Bytes = r.Bytes,
            BytesText = FormatBytes(r.Bytes),
            Path = r.Path,
        };

        private static string FormatBytes(long bytes)
        {
            if (bytes <= 0) return "0";
            if (bytes < 1024) return bytes.ToString("N0", CultureInfo.InvariantCulture);
            if (bytes < 1024L * 1024) return (bytes / 1024.0).ToString("F1", CultureInfo.InvariantCulture) + " KiB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / (1024.0 * 1024)).ToString("F1", CultureInfo.InvariantCulture) + " MiB";
            return (bytes / (1024.0 * 1024 * 1024)).ToString("F2", CultureInfo.InvariantCulture) + " GiB";
        }
    }
}
