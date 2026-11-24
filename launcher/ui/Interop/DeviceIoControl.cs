using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TheChamber.Interop;

/// <summary>
/// Thin wrappers over the three IOCTLs exposed by the_chamber.sys
/// (STATUS / KICK / SHUTDOWN). CTL_CODE matches driver/the_chamber.h.
/// </summary>
internal static class DeviceIoControl
{
    // CTL_CODE(0x8000, func, METHOD_BUFFERED=0, access)
    //   = (0x8000 << 16) | (access << 14) | (func << 2) | 0
    private const uint FileDeviceChamber = 0x8000;
    private const uint FileReadAccess = 1;
    private const uint FileWriteAccess = 2;
    private const uint MethodBuffered = 0;

    private static uint CtlCode(uint func, uint access) =>
        (FileDeviceChamber << 16) | (access << 14) | (func << 2) | MethodBuffered;

    public static readonly uint IoctlStatus = CtlCode(0x801, FileReadAccess);
    public static readonly uint IoctlKick = CtlCode(0x802, FileWriteAccess);
    public static readonly uint IoctlShutdown = CtlCode(0x803, FileWriteAccess);

    [StructLayout(LayoutKind.Sequential)]
    public struct ChamberStatus
    {
        public uint Version;
        public uint CpuCount;
        public uint ActiveCpus;
        public uint Reserved;
        public ulong VmexitCount;
    }

    public static ChamberStatus Status(SafeFileHandle device)
    {
        var size = (uint)Marshal.SizeOf<ChamberStatus>();
        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (!NativeMethods.DeviceIoControl(
                    device, IoctlStatus,
                    IntPtr.Zero, 0,
                    buf, size,
                    out _, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "IOCTL_STATUS failed.");
            }
            return Marshal.PtrToStructure<ChamberStatus>(buf);
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    public static void Kick(SafeFileHandle device)
    {
        if (!NativeMethods.DeviceIoControl(
                device, IoctlKick,
                IntPtr.Zero, 0,
                IntPtr.Zero, 0,
                out _, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "IOCTL_KICK failed.");
        }
    }

    public static bool Shutdown(SafeFileHandle device)
    {
        return NativeMethods.DeviceIoControl(
            device, IoctlShutdown,
            IntPtr.Zero, 0,
            IntPtr.Zero, 0,
            out _, IntPtr.Zero);
    }
}
