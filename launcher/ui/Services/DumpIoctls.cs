using System;
using System.Runtime.InteropServices;

namespace TheChamber.Services;

/// <summary>
/// IOCTL function codes exposed by the_chamber.sys for the Wave 6 dump
/// surface. Function codes 0x820..0x826 cohabit the HV control device
/// with the earlier STATUS/KICK/SHUTDOWN block (0x801..0x803, defined in
/// <see cref="TheChamber.Interop.DeviceIoControl"/>).
///
/// Each IOCTL is METHOD_BUFFERED — the IO manager copies the input
/// buffer into the system-managed SystemBuffer for the driver and copies
/// the output back on completion. That contract fits every Wave 6 code
/// here, including DUMP_NOW: the operator passes a target PID plus the
/// VA of a user-mode buffer it owns (pinned on the managed heap) and the
/// driver's host-context walker writes TLV records into that VA directly
/// after KeStackAttachProcess. The METHOD_BUFFERED SystemBuffer carries
/// only the small request / status struct; the large capture payload
/// never travels through it.
///
/// Access bits:
///   FILE_READ_ACCESS (0x1)       — QUERY_DUMP_HISTORY reads driver state
///   FILE_WRITE_ACCESS (0x2)      — every ARM_* mutates driver state
///   READ|WRITE (0x3)             — DUMP_NOW both reads status out and
///                                  mutates (the dump itself is a state
///                                  transition, even though the payload
///                                  path is out-of-band through the
///                                  operator's own VA)
/// </summary>
internal static class DumpIoctls
{
    // CTL_CODE(DeviceType, Function, Method, Access)
    //   = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
    //
    // DeviceType 0x8000 matches the_chamber.sys's registration in
    // driver/the_chamber.c and the existing 0x801..0x803 block; keeping
    // the same device type is what lets both blocks arrive on the same
    // handle.
    private const uint FileDeviceChamber = 0x8000;
    private const uint FileReadAccess = 0x1;
    private const uint FileWriteAccess = 0x2;
    private const uint FileReadWriteAccess = FileReadAccess | FileWriteAccess;
    private const uint MethodBuffered = 0;

    /// <summary>
    /// Recomputes CTL_CODE from the formula. Kept <c>internal static</c>
    /// so the driver-side test fixture can call it and confirm the
    /// launcher and driver agree on each 32-bit code bit-for-bit.
    /// </summary>
    internal static uint CtlCode(uint function, uint access) =>
        (FileDeviceChamber << 16) | (access << 14) | (function << 2) | MethodBuffered;

    // Wave 6 function codes. Driver side mints these in the same header
    // the_chamber.h; keep them synchronised with driver/the_chamber.h.
    public const uint FnDumpNow = 0x820;
    public const uint FnArmWx = 0x821;
    public const uint FnArmOep = 0x822;
    public const uint FnArmWriteThreshold = 0x823;
    public const uint FnArmPayload = 0x824;
    public const uint FnDisarmTriggers = 0x825;
    public const uint FnQueryDumpHistory = 0x826;

    /// <summary>
    /// IOCTL_THE_CHAMBER_DUMP_NOW — manual trigger. Input:
    /// <see cref="DumpNowRequest"/>; output: <see cref="DumpNowStatus"/>.
    /// The output buffer referenced by the request is the operator's
    /// own pinned heap allocation; the driver writes TLV records there
    /// out-of-band.
    /// </summary>
    public static readonly uint IoctlDumpNow = CtlCode(FnDumpNow, FileReadWriteAccess);

    /// <summary>
    /// IOCTL_THE_CHAMBER_ARM_WX — arm the write-to-execute trigger for
    /// the target CR3. Input: <see cref="ArmPidRequest"/>; no output.
    /// Driver fires a dump when any user-space page in the target CR3
    /// transitions from write-watched to executable.
    /// </summary>
    public static readonly uint IoctlArmWx = CtlCode(FnArmWx, FileWriteAccess);

    /// <summary>
    /// IOCTL_THE_CHAMBER_ARM_OEP — arm the "execute at suspected OEP"
    /// trigger. Input: <see cref="ArmOepRequest"/>; no output.
    /// </summary>
    public static readonly uint IoctlArmOep = CtlCode(FnArmOep, FileWriteAccess);

    /// <summary>
    /// IOCTL_THE_CHAMBER_ARM_WRITE_THRESHOLD — arm a "N bytes written to
    /// a single page range" trigger. Input:
    /// <see cref="ArmWriteThresholdRequest"/>; no output.
    /// </summary>
    public static readonly uint IoctlArmWriteThreshold =
        CtlCode(FnArmWriteThreshold, FileWriteAccess);

    /// <summary>
    /// IOCTL_THE_CHAMBER_ARM_PAYLOAD — arm the "WFP payload observed"
    /// trigger. Input: <see cref="ArmPidRequest"/>; no output. Until
    /// the WFP shim ships the driver returns success and arms a no-op
    /// subscription (see DumpService docs).
    /// </summary>
    public static readonly uint IoctlArmPayload = CtlCode(FnArmPayload, FileWriteAccess);

    /// <summary>
    /// IOCTL_THE_CHAMBER_DISARM_TRIGGERS — drops every arm set by the
    /// current session, whatever trigger kind. No input, no output.
    /// </summary>
    public static readonly uint IoctlDisarmTriggers =
        CtlCode(FnDisarmTriggers, FileWriteAccess);

    /// <summary>
    /// IOCTL_THE_CHAMBER_QUERY_DUMP_HISTORY — reads back the bounded
    /// ring of past dumps the driver has written. No input; output is
    /// a <see cref="DumpHistoryHeader"/> immediately followed by
    /// <see cref="DumpHistoryEntry"/>[Count]. Driver clamps Count to
    /// whatever fits in the OutputBufferLength passed by the caller.
    /// </summary>
    public static readonly uint IoctlQueryDumpHistory =
        CtlCode(FnQueryDumpHistory, FileReadAccess);

    // --- Marshalling layouts ---
    //
    // Every struct here is packed LayoutKind.Sequential with explicit
    // Pack=8 to match the driver's natural 8-byte alignment on x64 and
    // to keep the ULONGLONG fields aligned without hidden pad. The
    // driver side mirrors these layouts in driver/the_chamber.h.

    /// <summary>
    /// Input to IOCTL_THE_CHAMBER_DUMP_NOW.
    ///   - <c>Pid</c>            — target process to snapshot
    ///   - <c>OutputBufferVa</c> — VA of a pinned, writable buffer in
    ///                             the caller's user-mode VA space
    ///   - <c>OutputBufferSize</c> — byte capacity of that buffer
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct DumpNowRequest
    {
        public ulong Pid;
        public ulong OutputBufferVa;
        public ulong OutputBufferSize;
    }

    /// <summary>
    /// Output from IOCTL_THE_CHAMBER_DUMP_NOW.
    ///   - <c>Status</c>      — 0 on success, non-zero NTSTATUS on error
    ///   - <c>BytesWritten</c> — TLV byte count the driver produced into
    ///                           the caller's output VA
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct DumpNowStatus
    {
        public uint Status;
        public uint Reserved;
        public ulong BytesWritten;
    }

    /// <summary>
    /// Input to every ARM_* IOCTL that takes only a PID.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct ArmPidRequest
    {
        public ulong Pid;
    }

    /// <summary>
    /// Input to IOCTL_THE_CHAMBER_ARM_OEP.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct ArmOepRequest
    {
        public ulong Pid;
        public ulong Oep;
    }

    /// <summary>
    /// Input to IOCTL_THE_CHAMBER_ARM_WRITE_THRESHOLD.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct ArmWriteThresholdRequest
    {
        public ulong Pid;
        public uint ThresholdBytes;
        public uint Reserved;
    }

    /// <summary>
    /// Header of the IOCTL_THE_CHAMBER_QUERY_DUMP_HISTORY output.
    ///   - <c>Count</c>  — number of valid DumpHistoryEntry records that
    ///                     follow this header in the SystemBuffer
    ///   - <c>Capacity</c> — max entries the driver's ring can hold
    ///                     (useful for sizing the next call)
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct DumpHistoryHeader
    {
        public uint Count;
        public uint Capacity;
    }

    /// <summary>
    /// One history record. Strings are fixed 128 UTF-16 chars inline so
    /// the whole packet is METHOD_BUFFERED-safe. Driver side zero-fills
    /// unused tail bytes; both "Target" and "TriggerKind" are user-facing
    /// strings mirrored from the arming IOCTL that produced this dump.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
    public struct DumpHistoryEntry
    {
        /// <summary>FILETIME-style (100ns intervals since 1601-01-01 UTC).</summary>
        public long FileTimeUtc;
        public uint Pid;
        public uint TriggerKind;
        public ulong Bytes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string TargetName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string PathOnDisk;
    }

    /// <summary>
    /// Enumeration of trigger kinds, shared with the driver.
    /// </summary>
    public enum TriggerKindCode : uint
    {
        Manual = 0,
        WriteToExecute = 1,
        Oep = 2,
        WriteThreshold = 3,
        PayloadReceived = 4,
    }
}
