using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
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

    public DumpService(DriverLoader loader)
    {
        _loader = loader ?? throw new ArgumentNullException(nameof(loader));
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
    public Task ArmWxAsync(uint pid)
    {
        var req = new DumpIoctls.ArmPidRequest { Pid = pid };
        return RunVoidAsync(DumpIoctls.IoctlArmWx, req, "IOCTL_ARM_WX");
    }

    /// <summary>Arm the "execute at suspected OEP" trigger.</summary>
    public Task ArmOepAsync(uint pid, ulong oep)
    {
        var req = new DumpIoctls.ArmOepRequest { Pid = pid, Oep = oep };
        return RunVoidAsync(DumpIoctls.IoctlArmOep, req, "IOCTL_ARM_OEP");
    }

    /// <summary>Arm the "N bytes written to watched page range" trigger.</summary>
    public Task ArmWriteThresholdAsync(uint pid, uint bytes)
    {
        var req = new DumpIoctls.ArmWriteThresholdRequest
        {
            Pid = pid,
            ThresholdBytes = bytes,
        };
        return RunVoidAsync(DumpIoctls.IoctlArmWriteThreshold, req, "IOCTL_ARM_WRITE_THRESHOLD");
    }

    /// <summary>
    /// Arm the "WFP payload observed" trigger. Documented as a stub: the
    /// driver side accepts the IOCTL and records the arm, but the WFP
    /// callout the arm subscribes to is only wired up once the Wave 6
    /// WFP shim ships — until then no trigger fires. The UI still shows
    /// the arm in the history list once <see cref="DisarmAllAsync"/> or
    /// a driver-side cancel clears it.
    /// </summary>
    public Task ArmPayloadAsync(uint pid)
    {
        var req = new DumpIoctls.ArmPidRequest { Pid = pid };
        return RunVoidAsync(DumpIoctls.IoctlArmPayload, req, "IOCTL_ARM_PAYLOAD");
    }

    /// <summary>
    /// Drops every arm this session issued. Safe to call with no arms
    /// pending; the driver returns success either way.
    /// </summary>
    public Task DisarmAllAsync()
    {
        return Task.Run(() =>
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
        });
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
}
