using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TheChamber.Interop;

/// <summary>
/// P/Invoke surface. Kept narrow; everything here is called by exactly
/// one service, and the signatures track the documented ntdll / kernel32
/// / imagehlp prototypes.
/// </summary>
internal static class NativeMethods
{
    public const uint STATUS_IMAGE_ALREADY_LOADED = 0xC000010E;

    public const uint SeLoadDriverPrivilege = 10;

    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
    public const int ERROR_FILE_NOT_FOUND = 2;

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern void RtlInitUnicodeString(
        ref UNICODE_STRING dst,
        [MarshalAs(UnmanagedType.LPWStr)] string src);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern uint NtLoadDriver(ref UNICODE_STRING driverServiceName);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern uint NtUnloadDriver(ref UNICODE_STRING driverServiceName);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern uint RtlAdjustPrivilege(
        uint privilege,
        [MarshalAs(UnmanagedType.U1)] bool enable,
        [MarshalAs(UnmanagedType.U1)] bool currentThread,
        [MarshalAs(UnmanagedType.U1)] out bool previousValue);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern uint RtlNtStatusToDosError(uint ntStatus);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    public static extern SafeFileHandle CreateFileW(
        string name,
        uint access,
        uint share,
        IntPtr sa,
        uint creation,
        uint flags,
        IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint ioControlCode,
        IntPtr inBuffer,
        uint inBufferSize,
        IntPtr outBuffer,
        uint outBufferSize,
        out uint bytesReturned,
        IntPtr overlapped);
}
