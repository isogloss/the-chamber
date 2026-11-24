using System;
using System.Runtime.InteropServices;

namespace TheChamber.Services;

/// <summary>
/// IOCTL function codes exposed by the_chamber.sys for the Wave 6 dump
/// surface. Function codes 0x820..0x826 cohabit the HV control device
/// with the earlier STATUS/KICK/SHUTDOWN block (0x801..0x803, defined in
/// <see cref="TheChamber.Interop.DeviceIoControl"/>) and the Wave 8.5
/// fingerprint-coordination code 0x830
/// (<see cref="IoctlGetFingerprintDeviceName"/>).
///
/// The fingerprint driver (chamber_fingerprint.sys) publishes its own
/// control device under a per-boot random suffix and carries a disjoint
/// IOCTL space rooted in FILE_DEVICE_UNKNOWN; its codes are bundled
/// below as <see cref="CfpIoctls"/> so one call site covers both
/// driver surfaces without accidentally tying their device types
/// together (the whole point of the fingerprint driver using
/// FILE_DEVICE_UNKNOWN is to keep a cross-driver correlator from
/// pairing the two images on IOCTL space alone — see
/// driver/fingerprint/target_pid.c for the full rationale).
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

    // Wave 8.5 fingerprint-coordination function code on the HV control
    // device. The HV driver and the fingerprint driver share one CFG v2
    // blob (see driver/fingerprint/cfg_shared.c:cfp_read_cfgblob), so
    // the HV side is authoritative for the fingerprint driver's current
    // per-boot random device suffix and the launcher can learn it off
    // the HV handle it already holds. This keeps the launcher from
    // having to guess, enumerate, or bake the suffix into the operator-
    // facing settings file — the whole suffix-randomization scheme in
    // driver/fingerprint/entry.c is undone the moment a cleartext copy
    // of the suffix lives anywhere discoverable.
    public const uint FnGetFingerprintDeviceName = 0x830;

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

    /// <summary>
    /// IOCTL_CFP_GET_DEVICE_NAME — asks the HV driver for the current
    /// per-boot random DOS-namespace suffix of the fingerprint driver's
    /// control device. No input; output is a
    /// <see cref="FingerprintDeviceNameResponse"/> whose
    /// <c>SuffixLengthChars</c> names how many UTF-16 characters of
    /// <c>Suffix</c> are valid (never null-terminated by the driver,
    /// so the launcher trims on <c>SuffixLengthChars</c> not on
    /// <c>wcslen</c>). FILE_READ_ACCESS matches the read-only nature
    /// of the query; a sample with only a read handle to the HV device
    /// can still ask, and the driver side gates on handle-origin SID
    /// rather than on IOCTL access bits.
    /// </summary>
    public static readonly uint IoctlGetFingerprintDeviceName =
        CtlCode(FnGetFingerprintDeviceName, FileReadAccess);

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

    /// <summary>
    /// Output of IOCTL_CFP_GET_DEVICE_NAME. The driver writes
    /// <c>SuffixLengthChars</c> UTF-16 code units of the suffix (no
    /// terminating NUL — the field is a count, not a C-string length)
    /// into <c>Suffix</c>. The suffix is the DOS-namespace basename
    /// only, e.g. <c>cfp7a9b1e2c3d4e5f6a</c>; the launcher constructs
    /// the full device path by prepending <c>\\.\</c>. 128 code units
    /// of capacity comfortably contains the entry.c name scheme (16
    /// hex chars of randomness after any base prefix) and keeps the
    /// whole output inside METHOD_BUFFERED's SystemBuffer budget.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
    public struct FingerprintDeviceNameResponse
    {
        /// <summary>Count of UTF-16 code units in <c>Suffix</c> that are valid.</summary>
        public uint SuffixLengthChars;
        public uint Reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string Suffix;
    }
}

/// <summary>
/// IOCTL function codes exposed by chamber_fingerprint.sys. These sit
/// in a disjoint device-type space from the HV driver's codes
/// (FILE_DEVICE_UNKNOWN vs FILE_DEVICE_CHAMBER=0x8000); a cross-driver
/// correlator cannot pair the two images on IOCTL device type alone.
/// Codes 0x801..0x805 are already live on the driver side (see
/// driver/fingerprint/target_pid.c + driver/fingerprint/entry.c);
/// 0x806 (SET_SHIM_IMAGE) is reserved for the launcher-side push of
/// the user-mode chamber_shim.dll bytes that the fingerprint driver
/// maps into each spoofed process at PsSetCreateProcessNotifyRoutineEx
/// post-create.
/// </summary>
internal static class CfpIoctls
{
    // FILE_DEVICE_UNKNOWN matches driver/fingerprint/target_pid.c's
    // CFP_IOCTL_DEVICE_TYPE. Changing it would silently break every
    // IOCTL on this device; the driver computes the same CTL_CODE and
    // compares bit-for-bit.
    private const uint FileDeviceUnknown = 0x00000022;
    private const uint FileReadAccess = 0x1;
    private const uint FileWriteAccess = 0x2;
    private const uint MethodBuffered = 0;

    internal static uint CtlCode(uint function, uint access) =>
        (FileDeviceUnknown << 16) | (access << 14) | (function << 2) | MethodBuffered;

    // Live driver-side codes. Keep in lockstep with
    // driver/fingerprint/target_pid.c (0x801/0x802/0x804) and
    // driver/fingerprint/entry.c (0x805).
    public const uint FnAddPid = 0x801;
    public const uint FnRemovePid = 0x802;
    public const uint FnClear = 0x804;
    public const uint FnArmPid = 0x805;

    // Wave 8.5 reservation. Driver side will dispatch 0x806 against
    // the shim-image staging buffer once the user-mode ntdll shim is
    // production-ready (today's ic_trampoline.asm is the handshake
    // skeleton). The launcher code path is live and idempotent so a
    // driver that already carries the dispatch sees a matching push
    // the first time the operator arms a trigger.
    public const uint FnSetShimImage = 0x806;

    public static readonly uint IoctlAddPid = CtlCode(FnAddPid, FileWriteAccess);
    public static readonly uint IoctlRemovePid = CtlCode(FnRemovePid, FileWriteAccess);
    public static readonly uint IoctlClear = CtlCode(FnClear, FileWriteAccess);
    public static readonly uint IoctlArmPid = CtlCode(FnArmPid, FileWriteAccess);
    public static readonly uint IoctlSetShimImage = CtlCode(FnSetShimImage, FileWriteAccess);

    /// <summary>
    /// Input to IOCTL_CFP_ADD_PID and IOCTL_CFP_REMOVE_PID. Matches
    /// driver/fingerprint/target_pid.c:CFP_IOCTL_PID exactly (ULONG pid
    /// plus a ULONG reserved slot keeping the struct 8-byte aligned).
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct CfpPidRequest
    {
        public uint Pid;
        public uint Reserved;
    }

    /// <summary>
    /// Input to IOCTL_CFP_SET_SHIM_IMAGE. The shim bytes travel inline
    /// in the METHOD_BUFFERED SystemBuffer after the fixed header; the
    /// driver reads <c>ImageSize</c> bytes starting at
    /// <c>sizeof(SetShimImageRequest)</c>. <c>ExpectedSha256</c> gives
    /// the driver a cheap integrity gate before it stages the image,
    /// so a torn push cannot leave a half-copied buffer live.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct SetShimImageRequest
    {
        /// <summary>Byte count of the shim image that follows this header.</summary>
        public uint ImageSize;
        /// <summary>Reserved for future flags (e.g. staging-lane selector).</summary>
        public uint Flags;
        /// <summary>SHA-256 of the image bytes; the driver verifies before staging.</summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ExpectedSha256;
    }
}
