using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TheChamber.Model;
using TheChamber.Services;

namespace TheChamber.Views;

/// <summary>
/// Modal field picker. Renders every CHAMBER_CFG v2 field under the
/// current seed. Three tabs — Machine identity / HV identity / Toggles —
/// each with its own "Randomize group" button (increments the matching
/// group salt). A global "Randomize all" mints a new seed and resets
/// both salts. Proceed commits the state and signals the launcher to
/// patch + load.
/// </summary>
public partial class RandomizeWindow : Window
{
    private readonly SeedService _seed;

    public RandomizeWindow(SeedService seed)
    {
        _seed = seed;
        InitializeComponent();
        Refresh();
    }

    private void Refresh()
    {
        var id = _seed.DeriveAll();
        RenderSeedPreview();
        RenderIdentityScalars(id);
        RenderMacList(id);
        RenderDiskList(id);
        RenderVolumeList(id);
        RenderHvScalars(id);
        RenderToggles();
        IdSaltText.Text = _seed.IdentitySalt.ToString();
        HvSaltText.Text = _seed.HvSalt.ToString();
    }

    private void RenderSeedPreview()
    {
        var hex = _seed.SeedHex;
        // Split into two balanced lines of 32 hex chars with spaces every
        // two bytes for readability.
        var top = Spaced(hex.AsSpan(0, 32));
        var bot = Spaced(hex.AsSpan(32, 32));
        SeedHexA.Text = top;
        SeedHexB.Text = bot;
    }

    private static string Spaced(ReadOnlySpan<char> hex)
    {
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < hex.Length; i += 2)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(hex.Slice(i, 2));
        }
        return sb.ToString();
    }

    private void RenderIdentityScalars(DerivedIdentity id)
    {
        IdentityScalars.Children.Clear();
        AddRow(IdentityScalars, "computer name", id.ComputerName);
        AddRow(IdentityScalars, "cpu brand", id.CpuBrandString);
        AddRow(IdentityScalars, "smbios uuid", id.SmbiosSystemUuid.ToString("D").ToUpperInvariant());
        AddRow(IdentityScalars, "baseboard serial", id.BaseboardSerial);
        AddRow(IdentityScalars, "chassis serial", id.ChassisSerial);
        AddRow(IdentityScalars, "bios vendor", id.BiosVendor);
        AddRow(IdentityScalars, "bios version", id.BiosVersion);
        AddRow(IdentityScalars, "machine guid", id.MachineGuid.ToString("D").ToUpperInvariant());
        AddRow(IdentityScalars, "install date",
            DateTime.FromFileTimeUtc(id.InstallDateFiletime).ToString("yyyy-MM-dd HH:mm 'UTC'"));
        AddRow(IdentityScalars, "product id", id.ProductId);
        AddRow(IdentityScalars, "digital productid",
            Convert.ToHexString(id.DigitalProductId.AsSpan(0, Math.Min(32, id.DigitalProductId.Length))) + "...");
        AddRow(IdentityScalars, "gpu", id.GpuVendorPretty());
        AddRow(IdentityScalars, "edid nonce", Convert.ToHexString(id.EdidNonce));
    }

    private void RenderMacList(DerivedIdentity id)
    {
        var rows = new List<object>();
        for (int i = 0; i < id.MacAddresses.Length; i++)
        {
            var m = id.MacAddresses[i];
            rows.Add(new { Index = i.ToString().PadLeft(2, '0'), Mac = m.Pretty(), Vendor = m.Oui.Vendor });
        }
        MacList.ItemsSource = rows;
    }

    private void RenderDiskList(DerivedIdentity id)
    {
        var rows = new List<object>();
        for (int i = 0; i < id.DiskSerials.Length; i++)
        {
            rows.Add(new { Index = i.ToString().PadLeft(2, '0'), Serial = id.DiskSerials[i] });
        }
        DiskList.ItemsSource = rows;
    }

    private void RenderVolumeList(DerivedIdentity id)
    {
        var letters = new[] { "C:", "D:", "E:", "F:" };
        var rows = new List<object>();
        for (int i = 0; i < id.VolumeSerials.Length && i < letters.Length; i++)
        {
            rows.Add(new { Letter = letters[i], Serial = $"0x{id.VolumeSerials[i]:X8}" });
        }
        VolumeList.ItemsSource = rows;
    }

    private void RenderHvScalars(DerivedIdentity id)
    {
        HvScalars.Children.Clear();
        AddRow(HvScalars, "service name", id.ServiceName);
        AddRow(HvScalars, "device suffix", $@"\Device\{id.DeviceSuffix}");

        var poolNames = new[] { "svm", "npt", "vmexit", "dump", "integrity", "dispatch" };
        for (int i = 0; i < 6; i++)
        {
            var tag = id.PoolTags[i];
            var letters = new string(new[]
            {
                (char)(byte)(tag & 0xFF),
                (char)(byte)((tag >> 8) & 0xFF),
                (char)(byte)((tag >> 16) & 0xFF),
                (char)(byte)((tag >> 24) & 0xFF),
            });
            AddRow(HvScalars, $"pool tag [{poolNames[i]}]", $"{letters}  0x{tag:X8}");
        }

        AddRow(HvScalars, "cfg magic override", $"0x{id.CfgMagicOverride:X16}");
        AddRow(HvScalars, "vmmcall magic", $"0x{id.VmmcallMagic:X16}");
        AddRow(HvScalars, "rename donor",
            $"{SeedService.DonorPool[id.RenameDonorIndex]}  (idx {id.RenameDonorIndex})");
        AddRow(HvScalars, "guest asid", $"0x{id.GuestAsid:X4}");
        AddRow(HvScalars, "section scramble", $"0x{id.SectionScrambleSeed:X8}");
        AddRow(HvScalars, "driver nonce", $"0x{id.DriverNonce:X16}");
    }

    private void RenderToggles()
    {
        TogglePanel.Children.Clear();

        var defs = new (string Label, int Bit, string Tooltip)[]
        {
            ("per-process CI state spoofing", 0, "surfaces 35-37 return CI-off"),
            ("machine identity spoofing",     1, "master gate for machine-identity tab"),
            ("HV introspection resistance",   2, "CHAMBER_HV_INTROSPECTION_RESIST"),
            ("pool tag randomize: svm",       3, ""),
            ("pool tag randomize: npt",       4, ""),
            ("pool tag randomize: vmexit",    5, ""),
            ("pool tag randomize: dump",      6, ""),
            ("pool tag randomize: integrity", 7, ""),
            ("pool tag randomize: dispatch",  8, ""),
            ("TPM-absent spoof",              9, "surfaces 59-60 mitigation"),
        };

        foreach (var def in defs)
        {
            var cb = new CheckBox
            {
                Content = def.Label,
                IsChecked = (_seed.Toggles & (1u << def.Bit)) != 0,
                Margin = new Thickness(0, 3, 0, 3),
                ToolTip = def.Tooltip,
                Tag = def.Bit,
            };
            cb.Checked += OnToggleChanged;
            cb.Unchecked += OnToggleChanged;
            TogglePanel.Children.Add(cb);
        }
    }

    private void OnToggleChanged(object sender, RoutedEventArgs e)
    {
        var cb = (CheckBox)sender;
        var bit = (int)cb.Tag!;
        var mask = 1u << bit;
        if (cb.IsChecked == true) _seed.Toggles |= mask;
        else _seed.Toggles &= ~mask;
    }

    private static void AddRow(Panel host, string label, string value)
    {
        var g = new Grid { Margin = new Thickness(0, 3, 0, 3) };
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(220) });
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
            TextWrapping = TextWrapping.Wrap,
        };

        Grid.SetColumn(l, 0);
        Grid.SetColumn(v, 1);
        g.Children.Add(l);
        g.Children.Add(v);
        host.Children.Add(g);

        var rule = new Border
        {
            Height = 1,
            Background = (Brush)Application.Current.FindResource("ChamberLine"),
            Margin = new Thickness(0, 2, 0, 0),
            Opacity = 0.35,
        };
        host.Children.Add(rule);
    }

    private void OnRandomizeAll(object sender, RoutedEventArgs e)
    {
        _seed.Randomize();
        Refresh();
    }

    private void OnRandomizeIdentity(object sender, RoutedEventArgs e)
    {
        _seed.BumpIdentitySalt();
        Refresh();
    }

    private void OnRandomizeHv(object sender, RoutedEventArgs e)
    {
        _seed.BumpHvSalt();
        Refresh();
    }

    private async void OnCopySeed(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(_seed.SeedHex);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Copy failed: {ex.Message}", "The Chamber");
        }
        await System.Threading.Tasks.Task.CompletedTask;
    }

    private void OnPasteSeed(object sender, RoutedEventArgs e)
    {
        try
        {
            var txt = Clipboard.GetText()?.Trim() ?? "";
            if (!_seed.SetSeedHex(txt))
            {
                MessageBox.Show(this,
                    "Clipboard content must be exactly 64 hex characters (32-byte seed).",
                    "The Chamber: paste seed");
                return;
            }
            Refresh();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Paste failed: {ex.Message}", "The Chamber");
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnProceed(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }
}
