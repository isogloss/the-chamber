using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TheChamber.Services;

/// <summary>
/// Thin wrapper around bcdedit for the two boot flags the driver load
/// path cares about: <c>testsigning</c> (must be ON for self-signed
/// drivers) and <c>hypervisorlaunchtype</c>/HVCI (must be OFF so AMD-SVM
/// is available to the host). Writes a snapshot of pre-change state to
/// <c>%AppData%\TheChamber\bcd_snapshot.txt</c> so UNINSTALL.ps1 can
/// revert.
/// </summary>
public sealed class BcdState
{
    public bool TestSigningOn { get; init; }
    public bool HvciOn { get; init; }
    public bool HypervisorOn { get; init; }
    public string RawEnum { get; init; } = "";
}

public sealed class BcdService
{
    public string SnapshotPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "TheChamber",
        "bcd_snapshot.txt");

    public async Task<BcdState> ReadAsync()
    {
        var raw = await RunBcdEditAsync("/enum", "{current}").ConfigureAwait(false);
        var vbs = await RunBcdEditAsync("/enum", "{current}", "/v").ConfigureAwait(false);
        var all = raw + "\n" + vbs;

        return new BcdState
        {
            TestSigningOn = Contains(all, "testsigning", "Yes"),
            HvciOn = Contains(all, "hypervisorlaunchtype", "Auto")
                     || Contains(all, "vsmlaunchtype", "Auto"),
            HypervisorOn = Contains(all, "hypervisorlaunchtype", "Auto"),
            RawEnum = all,
        };
    }

    public async Task SnapshotAsync()
    {
        // Snapshot the full enumeration so the revert path has something
        // deterministic to work from. Overwrites the previous snapshot;
        // keep one layer deep because deeper "snapshot of snapshot"
        // chains are a trap.
        var text = await RunBcdEditAsync("/enum", "all", "/v").ConfigureAwait(false);
        Directory.CreateDirectory(Path.GetDirectoryName(SnapshotPath)!);
        await File.WriteAllTextAsync(SnapshotPath, text, Encoding.UTF8).ConfigureAwait(false);
    }

    public Task SetTestSigningAsync(bool on) =>
        RunBcdEditAsync("/set", "testsigning", on ? "on" : "off");

    public async Task SetHvciAsync(bool on)
    {
        // HVCI is really a combo of hypervisorlaunchtype and vsmlaunchtype;
        // bcdedit also honors the /deletevalue form to force it off.
        if (on)
        {
            await RunBcdEditAsync("/set", "hypervisorlaunchtype", "auto").ConfigureAwait(false);
            await RunBcdEditAsync("/set", "vsmlaunchtype", "auto").ConfigureAwait(false);
        }
        else
        {
            await RunBcdEditAsync("/set", "hypervisorlaunchtype", "off").ConfigureAwait(false);
            await RunBcdEditAsync("/deletevalue", "vsmlaunchtype").ConfigureAwait(false);
        }
    }

    public Task ScheduleRebootAsync(int seconds) =>
        RunProcessAsync("shutdown.exe", "/r", "/t", seconds.ToString(),
            "/c", "The Chamber: rebooting to apply boot flags.");

    private static bool Contains(string hay, string key, string value)
    {
        foreach (var line in hay.Split('\n'))
        {
            var t = line.Trim();
            if (t.StartsWith(key, StringComparison.OrdinalIgnoreCase)
                && t.Contains(value, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static Task<string> RunBcdEditAsync(params string[] args) =>
        RunProcessCaptureAsync("bcdedit.exe", args);

    private static Task RunProcessAsync(string exe, params string[] args) =>
        RunProcessCaptureAsync(exe, args);

    private static async Task<string> RunProcessCaptureAsync(string exe, string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {exe}");

        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync().ConfigureAwait(false);
        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        if (p.ExitCode != 0 && !string.IsNullOrWhiteSpace(stderr))
        {
            // bcdedit is quite happy to write to stderr for informational
            // messages even on exit 0; we only surface true failures.
            throw new InvalidOperationException(
                $"{exe} {string.Join(' ', args)} failed (exit {p.ExitCode}): {stderr.Trim()}");
        }

        return stdout;
    }
}
