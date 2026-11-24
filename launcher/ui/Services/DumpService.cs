using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using TheChamber.Interop;
using TheChamber.Model;

namespace TheChamber.Services;

/// <summary>
/// Launcher-side facade over the Wave 6 dump IOCTLs. Every public
/// method does the P/Invoke marshalling into one of the
/// <see cref="DumpIoctls"/> packets, calls
/// <c>DeviceIoControl</c> on the HV control device, and surfaces a
/// managed result or <see cref="Win32Exception"/> on failure.
///
/// Handle discipline mirrors <see cref="DriverLoader"/>: the service is
/// constructed with a <see cref="DriverLoader"/> reference and opens a
/// fresh control-device handle per call via
/// <see cref="DriverLoader.OpenDevice"/>. We never cache the handle —
/// the operator can shut the driver down from another tab and we want
/// to see <c>device closed</c> on the next IOCTL rather than EBADF.
///
/// Threading: every method is <c>async Task</c> and offloads the actual
/// DeviceIoControl to <c>Task.Run</c>; the dispatcher stays free for
/// the Dump tab's 2 s process-list refresh and for history refreshes
/// after each arm.
///
/// Error handling: a failing IOCTL throws a Win32Exception the caller
/// can surface in a friendly MessageBox. The service never writes to
/// disk on failure; the manual-dump path only writes if the driver
/// returns Status == 0 and BytesWritten > 0.
/// </summary>
public sealed class DumpService
{
    private readonly DriverLoader _loader;

    // Logical name the launcher's .csproj gives the embedded shim DLL
    // (<EmbeddedResource .. LogicalName="TheChamber.Drivers.chamber_shim.dll"/>).
    // Resolving it by LogicalName rather than by relative file path keeps
    // the single-file publish working — the resource travels inside the
    // assembly, not next to it on disk.
    private const string ShimResourceName = "TheChamber.Drivers.chamber_shim.dll";

    // Wave 8.5 fingerprint coordination state. Guards against duplicate
    // pushes of the shim image (several MB per copy — the driver only
    // needs one) and lets Clear undo add_pid for the last-selected
    // target without the caller remembering the PID themselves.
    private readonly SemaphoreSlim _fpStateLock = new(1, 1);
    private bool _shimImagePushed;
    private uint? _currentTargetPid;

    public DumpService(DriverLoader loader)
    {
        _loader = loader ?? throw new ArgumentNullException(nameof(loader));
    }

    /// <summary>
    /// Push the embedded <c>chamber_shim.dll</c> bytes to the
    /// fingerprint driver via IOCTL_CFP_SET_SHIM_IMAGE and remember
    /// that it was pushed. Idempotent: on the second and later calls
    /// the embedded bytes are not reloaded and the IOCTL is skipped.
    /// Call this at service initialization (before the first
    /// Arm/Dump) and again whenever the fingerprint driver reloads;
    /// the latter path resets the "pushed" flag through
    /// <see cref="InvalidateFingerprintStateAsync"/>.
    /// A no-op if either the shim resource or the fingerprint driver
    /// is not loaded — fingerprint integration is optional, and
    /// returning quietly keeps the dump-tab usable on a dev machine
    /// that has only the HV side built.
    /// </summary>
    public async Task<bool> PushShimImageAsync()
    {
        if (_loader.LoadedFingerprintServiceName is null)
        {
            return false;
        }

        await _fpStateLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_shimImagePushed) return true;

            var shimBytes = LoadEmbeddedShimOrNull();
            if (shimBytes is null || shimBytes.Length == 0)
            {
                // Dev build without the shim artifact; mark pushed so
                // we don't keep probing the resource stream on every
                // Arm call.
                _shimImagePushed = true;
                return false;
            }

            var sha = SHA256.HashData(shimBytes);

            await Task.Run(() =>
            {
                using var fp = _loader.OpenFingerprintDeviceAsync().GetAwaiter().GetResult();
                var headerSize = Marshal.SizeOf<CfpIoctls.SetShimImageRequest>();
                var totalSize = headerSize + shimBytes.Length;
                var inBuf = Marshal.AllocHGlobal(totalSize);
                try
                {
                    var hdr = new CfpIoctls.SetShimImageRequest
                    {
                        ImageSize = (uint)shimBytes.Length,
                        Flags = 0,
                        ExpectedSha256 = sha,
                    };
                    Marshal.StructureToPtr(hdr, inBuf, fDeleteOld: false);
                    Marshal.Copy(shimBytes, 0, IntPtr.Add(inBuf, headerSize), shimBytes.Length);

                    if (!NativeMethods.DeviceIoControl(
                            fp,
                            CfpIoctls.IoctlSetShimImage,
                            inBuf, (uint)totalSize,
                            IntPtr.Zero, 0,
                            out _, IntPtr.Zero))
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "IOCTL_CFP_SET_SHIM_IMAGE failed.");
                    }
                }
                finally
                {
                    Marshal.DestroyStructure<CfpIoctls.SetShimImageRequest>(inBuf);
                    Marshal.FreeHGlobal(inBuf);
                }
            }).ConfigureAwait(false);

            _shimImagePushed = true;
            return true;
        }
        finally
        {
            _fpStateLock.Release();
        }
    }

    /// <summary>
    /// Push <paramref name="pid"/> to the fingerprint driver's spoof
    /// list via IOCTL_CFP_ADD_PID. Called in response to an
    /// OperatorWindow process-select event; the driver's registry /
    /// FLT / IC callbacks then gate on membership so unlisted PIDs
    /// pay no rewrite cost. Idempotent on the driver side (see
    /// cfp_target_add in driver/fingerprint/target_pid.c), so a
    /// redundant selection is cheap.
    /// </summary>
    public async Task SetTargetPidAsync(uint pid)
    {
        if (_loader.LoadedFingerprintServiceName is null) return;
        if (pid == 0) throw new ArgumentOutOfRangeException(nameof(pid));

        // Make sure the shim image is in place before any spoofed PID
        // lands; the driver pairs the two, and a PID added before the
        // shim is staged would spin in the post-create callback.
        await PushShimImageAsync().ConfigureAwait(false);

        var req = new CfpIoctls.CfpPidRequest { Pid = pid, Reserved = 0 };
        await RunFingerprintVoidAsync(CfpIoctls.IoctlAddPid, req, "IOCTL_CFP_ADD_PID")
            .ConfigureAwait(false);

        await _fpStateLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _currentTargetPid = pid;
        }
        finally
        {
            _fpStateLock.Release();
        }
    }

    /// <summary>
    /// Drop <paramref name="pid"/> from the fingerprint driver's spoof
    /// list via IOCTL_CFP_REMOVE_PID. Safe to call for a PID that is
    /// not currently listed; the driver returns STATUS_NOT_FOUND which
    /// is surfaced as a Win32Exception the caller can swallow.
    /// </summary>
    public async Task RemoveTargetPidAsync(uint pid)
    {
        if (_loader.LoadedFingerprintServiceName is null) return;
        if (pid == 0) throw new ArgumentOutOfRangeException(nameof(pid));

        var req = new CfpIoctls.CfpPidRequest { Pid = pid, Reserved = 0 };
        try
        {
            await RunFingerprintVoidAsync(CfpIoctls.IoctlRemovePid, req, "IOCTL_CFP_REMOVE_PID")
                .ConfigureAwait(false);
        }
        finally
        {
            await _fpStateLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_currentTargetPid == pid) _currentTargetPid = null;
            }
            finally
            {
                _fpStateLock.Release();
            }
        }
    }

    /// <summary>
    /// Clear every PID in the fingerprint driver's spoof list via
    /// IOCTL_CFP_CLEAR. Called on process-deselect (when the operator
    /// picks "no process") and as part of
    /// <see cref="DisarmAllAsync"/> so a disarmed session does not
    /// leave the driver spoofing stale PIDs.
    /// </summary>
    public async Task ClearTargetsAsync()
    {
        if (_loader.LoadedFingerprintServiceName is null) return;

        await Task.Run(() =>
        {
            using var fp = _loader.OpenFingerprintDeviceAsync().GetAwaiter().GetResult();
            if (!NativeMethods.DeviceIoControl(
                    fp,
                    CfpIoctls.IoctlClear,
                    IntPtr.Zero, 0,
                    IntPtr.Zero, 0,
                    out _, IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "IOCTL_CFP_CLEAR failed.");
            }
        }).ConfigureAwait(false);

        await _fpStateLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _currentTargetPid = null;
        }
        finally
        {
            _fpStateLock.Release();
        }
    }

    /// <summary>
    /// Reset the service's cached fingerprint-driver state, so the
    /// next <see cref="PushShimImageAsync"/> re-pushes the shim and
    /// the next <see cref="SetTargetPidAsync"/> re-asserts its PID.
    /// Call this if the fingerprint driver has been reloaded under
    /// the service — the HV side can stay up while the fingerprint
    /// side is replaced, and the driver-side state table is empty
    /// again after such a reload.
    /// </summary>
    public async Task InvalidateFingerprintStateAsync()
    {
        await _fpStateLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _shimImagePushed = false;
            _currentTargetPid = null;
        }
        finally
        {
            _fpStateLock.Release();
        }
    }

    /// <summary>
    /// Manual "dump now" path. Allocates a large (default 128 MiB) pinned
    /// byte buffer in managed memory, hands its VA to the driver via
    /// IOCTL_THE_CHAMBER_DUMP_NOW, reads back status, then writes
    /// <c>BytesWritten</c> to disk at
    /// <c>outputDir/&lt;pid&gt;-&lt;yyyyMMdd_HHmmss&gt;-manual.bin</c> and
    /// returns a <see cref="DumpRecord"/> the UI can insert into the
    /// history list before the next QueryHistoryAsync refresh lands.
    /// </summary>
    public async Task<DumpRecord> DumpNowAsync(uint pid, string outputDir)
    {
        if (string.IsNullOrWhiteSpace(outputDir))
            throw new ArgumentException("Output directory required.", nameof(outputDir));

        Directory.CreateDirectory(outputDir);

        // Keep the fingerprint driver aware of this PID so any in-flight
        // registry / FLT / IC callback for the dumped process spoofs its
        // fingerprint while the dump is captured. Best effort: a
        // fingerprint-side failure is logged into the Win32Exception
        // message but does not abort the dump, which can still complete
        // on the HV side alone.
        await TryEnsureFingerprintTargetAsync(pid).ConfigureAwait(false);

        // 128 MiB window matches the driver's current ring budget for a
        // single-shot capture; operators can retry with a larger buffer
        // if a packed sample's unpacked image exceeds it.
        const int BufferSize = 128 * 1024 * 1024;
        var payload = GC.AllocateUninitializedArray<byte>(BufferSize, pinned: true);

        var status = await Task.Run(() =>
        {
            using var h = _loader.OpenDevice();
            var req = new DumpIoctls.DumpNowRequest
            {
                Pid = pid,
                OutputBufferVa = (ulong)(long)Marshal.UnsafeAddrOfPinnedArrayElement(payload, 0),
                OutputBufferSize = (ulong)BufferSize,
            };
            return Ioctl<DumpIoctls.DumpNowRequest, DumpIoctls.DumpNowStatus>(
                h, DumpIoctls.IoctlDumpNow, ref req);
        }).ConfigureAwait(false);

        if (status.Status != 0)
        {
            throw new Win32Exception(
                unchecked((int)status.Status),
                $"IOCTL_DUMP_NOW returned NTSTATUS 0x{status.Status:X8}");
        }

        var bytes = (long)status.BytesWritten;
        var timestamp = DateTime.Now;
        var fileName = $"{pid}-{timestamp:yyyyMMdd_HHmmss}-manual.bin";
        var path = Path.Combine(outputDir, fileName);

        if (bytes > 0)
        {
            // The driver writes directly into the pinned VA; we just
            // flush the live window to disk.
            await using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
            await fs.WriteAsync(payload.AsMemory(0, (int)Math.Min(bytes, int.MaxValue))).ConfigureAwait(false);
        }

        return new DumpRecord
        {
            Timestamp = timestamp,
            Target = pid.ToString(),
            Trigger = "manual",
            Bytes = bytes,
            Path = path,
        };
    }

    /// <summary>Arm the write-to-execute trigger for the target.</summary>
    public async Task ArmWxAsync(uint pid)
    {
        await TryEnsureFingerprintTargetAsync(pid).ConfigureAwait(false);
        var req = new DumpIoctls.ArmPidRequest { Pid = pid };
        await RunVoidAsync(DumpIoctls.IoctlArmWx, req, "IOCTL_ARM_WX").ConfigureAwait(false);
    }

    /// <summary>Arm the "execute at suspected OEP" trigger.</summary>
    public async Task ArmOepAsync(uint pid, ulong oep)
    {
        await TryEnsureFingerprintTargetAsync(pid).ConfigureAwait(false);
        var req = new DumpIoctls.ArmOepRequest { Pid = pid, Oep = oep };
        await RunVoidAsync(DumpIoctls.IoctlArmOep, req, "IOCTL_ARM_OEP").ConfigureAwait(false);
    }

    /// <summary>Arm the "N bytes written to watched page range" trigger.</summary>
    public async Task ArmWriteThresholdAsync(uint pid, uint bytes)
    {
        await TryEnsureFingerprintTargetAsync(pid).ConfigureAwait(false);
        var req = new DumpIoctls.ArmWriteThresholdRequest
        {
            Pid = pid,
            ThresholdBytes = bytes,
        };
        await RunVoidAsync(DumpIoctls.IoctlArmWriteThreshold, req, "IOCTL_ARM_WRITE_THRESHOLD")
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Arm the "WFP payload observed" trigger. Documented as a stub: the
    /// driver side accepts the IOCTL and records the arm, but the WFP
    /// callout the arm subscribes to is only wired up once the Wave 6
    /// WFP shim ships — until then no trigger fires. The UI still shows
    /// the arm in the history list once <see cref="DisarmAllAsync"/> or
    /// a driver-side cancel clears it.
    /// </summary>
    public async Task ArmPayloadAsync(uint pid)
    {
        await TryEnsureFingerprintTargetAsync(pid).ConfigureAwait(false);
        var req = new DumpIoctls.ArmPidRequest { Pid = pid };
        await RunVoidAsync(DumpIoctls.IoctlArmPayload, req, "IOCTL_ARM_PAYLOAD").ConfigureAwait(false);
    }

    /// <summary>
    /// Drops every arm this session issued. Safe to call with no arms
    /// pending; the driver returns success either way. The fingerprint
    /// driver's spoof list is cleared last so a disarmed session
    /// stops spoofing whatever PIDs were in flight; a fingerprint-side
    /// failure is swallowed because the HV disarm has already
    /// succeeded by that point and is the user-visible outcome.
    /// </summary>
    public async Task DisarmAllAsync()
    {
        await Task.Run(() =>
        {
            using var h = _loader.OpenDevice();
            if (!NativeMethods.DeviceIoControl(
                    h,
                    DumpIoctls.IoctlDisarmTriggers,
                    IntPtr.Zero, 0,
                    IntPtr.Zero, 0,
                    out _, IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "IOCTL_DISARM_TRIGGERS failed.");
            }
        }).ConfigureAwait(false);

        try
        {
            await ClearTargetsAsync().ConfigureAwait(false);
        }
        catch
        {
            // HV disarm already succeeded; swallowing keeps the
            // caller's view of "disarm succeeded" accurate.
        }
    }

    /// <summary>
    /// Pulls the driver's bounded history ring. The output buffer is
    /// sized for the ring's documented capacity (64 entries) which fits
    /// in a single IOCTL round-trip and in METHOD_BUFFERED's SystemBuffer
    /// budget (one entry is ~800 bytes; 64 * ~800 ~= 50 KiB).
    /// </summary>
    public async Task<IReadOnlyList<DumpRecord>> QueryHistoryAsync()
    {
        return await Task.Run(() =>
        {
            using var h = _loader.OpenDevice();

            var headerSize = Marshal.SizeOf<DumpIoctls.DumpHistoryHeader>();
            var entrySize = Marshal.SizeOf<DumpIoctls.DumpHistoryEntry>();
            const int MaxEntries = 64;
            var outSize = headerSize + entrySize * MaxEntries;
            var outBuf = Marshal.AllocHGlobal(outSize);
            try
            {
                if (!NativeMethods.DeviceIoControl(
                        h,
                        DumpIoctls.IoctlQueryDumpHistory,
                        IntPtr.Zero, 0,
                        outBuf, (uint)outSize,
                        out var returned, IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        "IOCTL_QUERY_DUMP_HISTORY failed.");
                }

                var hdr = Marshal.PtrToStructure<DumpIoctls.DumpHistoryHeader>(outBuf);
                var count = (int)Math.Min(hdr.Count, (uint)MaxEntries);

                // Belt and braces: never read past what the driver actually wrote.
                var maxByReturned = (int)((returned - headerSize) / entrySize);
                if (maxByReturned < 0) maxByReturned = 0;
                if (count > maxByReturned) count = maxByReturned;

                var records = new List<DumpRecord>(count);
                var entryPtr = IntPtr.Add(outBuf, headerSize);
                for (var i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<DumpIoctls.DumpHistoryEntry>(entryPtr);
                    records.Add(ToRecord(entry));
                    entryPtr = IntPtr.Add(entryPtr, entrySize);
                }
                return (IReadOnlyList<DumpRecord>)records;
            }
            finally
            {
                Marshal.FreeHGlobal(outBuf);
            }
        }).ConfigureAwait(false);
    }

    // --- internal helpers ---

    private static DumpRecord ToRecord(DumpIoctls.DumpHistoryEntry e)
    {
        DateTime ts;
        try
        {
            ts = DateTime.FromFileTime(e.FileTimeUtc);
        }
        catch (ArgumentOutOfRangeException)
        {
            ts = DateTime.MinValue;
        }

        var trigger = ((DumpIoctls.TriggerKindCode)e.TriggerKind) switch
        {
            DumpIoctls.TriggerKindCode.Manual => "manual",
            DumpIoctls.TriggerKindCode.WriteToExecute => "wx",
            DumpIoctls.TriggerKindCode.Oep => "oep",
            DumpIoctls.TriggerKindCode.WriteThreshold => "threshold",
            DumpIoctls.TriggerKindCode.PayloadReceived => "payload",
            _ => $"?({e.TriggerKind})",
        };

        var target = string.IsNullOrEmpty(e.TargetName)
            ? e.Pid.ToString()
            : $"{e.TargetName} ({e.Pid})";

        return new DumpRecord
        {
            Timestamp = ts,
            Target = target,
            Trigger = trigger,
            Bytes = (long)e.Bytes,
            Path = e.PathOnDisk ?? string.Empty,
        };
    }

    private Task RunVoidAsync<TIn>(uint code, TIn req, string ioctlName)
        where TIn : struct
    {
        return Task.Run(() =>
        {
            using var h = _loader.OpenDevice();
            var inSize = Marshal.SizeOf<TIn>();
            var inBuf = Marshal.AllocHGlobal(inSize);
            try
            {
                Marshal.StructureToPtr(req, inBuf, fDeleteOld: false);
                if (!NativeMethods.DeviceIoControl(
                        h, code,
                        inBuf, (uint)inSize,
                        IntPtr.Zero, 0,
                        out _, IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        $"{ioctlName} failed.");
                }
            }
            finally
            {
                Marshal.DestroyStructure<TIn>(inBuf);
                Marshal.FreeHGlobal(inBuf);
            }
        });
    }

    private static TOut Ioctl<TIn, TOut>(SafeFileHandle h, uint code, ref TIn req)
        where TIn : struct
        where TOut : struct
    {
        var inSize = Marshal.SizeOf<TIn>();
        var outSize = Marshal.SizeOf<TOut>();
        var inBuf = Marshal.AllocHGlobal(inSize);
        var outBuf = Marshal.AllocHGlobal(outSize);
        try
        {
            Marshal.StructureToPtr(req, inBuf, fDeleteOld: false);
            if (!NativeMethods.DeviceIoControl(
                    h, code,
                    inBuf, (uint)inSize,
                    outBuf, (uint)outSize,
                    out _, IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    $"DeviceIoControl(0x{code:X8}) failed.");
            }
            return Marshal.PtrToStructure<TOut>(outBuf);
        }
        finally
        {
            Marshal.DestroyStructure<TIn>(inBuf);
            Marshal.FreeHGlobal(inBuf);
            Marshal.FreeHGlobal(outBuf);
        }
    }

    // --- Wave 8.5 fingerprint-driver helpers ---

    /// <summary>
    /// Best-effort ensure that the shim is staged and <paramref name="pid"/>
    /// is on the fingerprint driver's spoof list. If the fingerprint
    /// driver is not loaded, this is a no-op. If it is loaded but the
    /// push fails, the exception is swallowed: the HV-side Arm/Dump
    /// that follows is the user-visible operation, and a fingerprint
    /// failure must not abort it. Use <see cref="SetTargetPidAsync"/>
    /// directly when the caller wants the failure propagated.
    /// </summary>
    private async Task TryEnsureFingerprintTargetAsync(uint pid)
    {
        if (_loader.LoadedFingerprintServiceName is null) return;
        try
        {
            await SetTargetPidAsync(pid).ConfigureAwait(false);
        }
        catch
        {
            // Fingerprint-side failure must not abort the HV arm/dump.
            // The caller surfaces the HV result; fingerprint integration
            // is an auxiliary surface.
        }
    }

    /// <summary>
    /// Fingerprint-device equivalent of <see cref="RunVoidAsync"/>:
    /// opens a fresh control-device handle on the fingerprint driver,
    /// marshals <paramref name="req"/>, and surfaces a Win32Exception
    /// on failure. Serialised through <see cref="_fpStateLock"/> is
    /// unnecessary here — DeviceIoControl is thread-safe.
    /// </summary>
    private Task RunFingerprintVoidAsync<TIn>(uint code, TIn req, string ioctlName)
        where TIn : struct
    {
        return Task.Run(() =>
        {
            using var fp = _loader.OpenFingerprintDeviceAsync().GetAwaiter().GetResult();
            var inSize = Marshal.SizeOf<TIn>();
            var inBuf = Marshal.AllocHGlobal(inSize);
            try
            {
                Marshal.StructureToPtr(req, inBuf, fDeleteOld: false);
                if (!NativeMethods.DeviceIoControl(
                        fp, code,
                        inBuf, (uint)inSize,
                        IntPtr.Zero, 0,
                        out _, IntPtr.Zero))
                {
                    throw new Win32Exception(
                        Marshal.GetLastWin32Error(),
                        $"{ioctlName} failed.");
                }
            }
            finally
            {
                Marshal.DestroyStructure<TIn>(inBuf);
                Marshal.FreeHGlobal(inBuf);
            }
        });
    }

    /// <summary>
    /// Read the embedded <c>chamber_shim.dll</c> bytes out of this
    /// assembly's manifest resources. Returns null on a dev build that
    /// published without the shim DLL (Condition="Exists(...)" in the
    /// csproj skips the EmbeddedResource in that case).
    /// </summary>
    private static byte[]? LoadEmbeddedShimOrNull()
    {
        var asm = Assembly.GetExecutingAssembly();
        using var s = asm.GetManifestResourceStream(ShimResourceName);
        if (s is null) return null;
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }
}
