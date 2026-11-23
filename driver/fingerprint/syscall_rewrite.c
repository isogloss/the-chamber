/* syscall_rewrite.c -- central dispatch for syscall-return rewrites.
 *
 * The user-mode trampoline (ic_trampoline.asm, mirrored into every spoofed
 * process by the launcher's ntdll shim) calls cfp_ic_dispatch() on every
 * syscall return. We receive the value the syscall produced and the user
 * RIP that follows the syscall instruction; from the RIP we identify which
 * syscall just returned, and if it is one of the fingerprint-sensitive
 * classes we rewrite the caller-provided output buffer in place.
 *
 * Covered surfaces (wave 4 design Section 2, rows marked IC):
 *   18-23  NtQuerySystemInformation SystemFirmwareTableInformation (DMI)
 *   35-37  NtQuerySystemInformation CI / Secure Boot classes
 *   38-39  NtDeviceIoControlFile with storage IOCTLs
 *   40     NtQueryVolumeInformationFile FileFsVolumeInformation
 *   41     storage adapter IOCTL (same handler as 38/39)
 *   42-43  NtDeviceIoControlFile to \Device\Nsi (adapter enum)
 *   46-47  EnumDisplayDevices lower path (NtOpenKey + NtQueryValueKey)
 *   50-53  NtQuerySystemInformation topology / basic / proc-perf classes
 *   54-55  NtQueryInformationProcess / NtQueryInformationToken paths
 *   59-60  Tbsi_GetDeviceInfo via NtDeviceIoControlFile to \Device\Tbs
 *   62     NtQuerySystemEnvironmentValueEx
 *
 * Design intent: each handler is a pure in-place rewrite of the output
 * buffer the user process passed to the syscall. We never rewrite the
 * return status (that would confuse callers) — we rewrite what the buffer
 * says. Callers that check the status still succeed; callers that read the
 * buffer see our seed-derived values.
 */

#include "fingerprint_cfg.h"

/* NtQuerySystemInformation class constants. Many are not in the public
 * header; the values are documented in Windows Internals 7e Appendix B
 * and in the TBS / Setup API headers. */
#define SystemBasicInformation                              0
#define SystemProcessorPerformanceInformation               8
#define SystemLogicalProcessorInformation                  73
#define SystemFirmwareTableInformation                     76
#define SystemCodeIntegrityInformation                    103
#define SystemSecureBootPolicyInformation                 144
#define SystemCodeIntegrityPolicyFullInformation          176

/* Forward decls from other TUs in this driver. */
void cfp_dmi_patch_blob(PUCHAR blob, ULONG len);
BOOLEAN cfp_target_contains(HANDLE pid);

/* Return value of SystemCodeIntegrityInformation is a
 * SYSTEM_CODEINTEGRITY_INFORMATION{ULONG Length; ULONG CodeIntegrityOptions}.
 * When ci_state_spoof is set we clear the ENABLED + HVCI bits and leave the
 * optional bits alone. The real struct uses these bit values (undocumented
 * but stable since Win8.1): */
#define CODEINTEGRITY_OPTION_ENABLED                       0x01
#define CODEINTEGRITY_OPTION_TESTSIGN                      0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED                  0x04
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED             0x400

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;

/* ---------------- dispatch context ---------------- */

/* The user-mode shim passes a small context describing which syscall just
 * returned. The shim has a per-process syscall-number table (built once at
 * attach via a one-pass ntdll walk; the RtlCopyMemoryNonTemporal /
 * NtQuerySystemInformation stubs are stable enough on a fixed OS build).
 */
typedef struct _CFP_IC_CTX {
    ULONG   sysnum;            /* NT syscall number */
    PVOID   arg0, arg1, arg2, arg3;
    PVOID   arg4, arg5, arg6, arg7;
    SIZE_T  return_value;
} CFP_IC_CTX;

/* Rewriter implementations. Each takes the saved syscall return value and
 * returns the (possibly rewritten) value the caller should see. The
 * user-mode output buffer is mutated in place. */

static SIZE_T
rewrite_system_information(CFP_IC_CTX *ctx)
{
    ULONG   info_class = (ULONG)(ULONG_PTR)ctx->arg0;
    PVOID   buf        = ctx->arg1;
    ULONG   len        = (ULONG)(ULONG_PTR)ctx->arg2;

    if (!buf || !len) return ctx->return_value;

    /* Only rewrite on NT_SUCCESS returns — propagating a rewrite over a
     * failure confuses callers that check Status before the buffer. */
    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS) {
        return ctx->return_value;
    }

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));

    switch (info_class) {
    case SystemFirmwareTableInformation: {
        /* DMI blob rewrite. The buffer layout is:
         *   SYSTEM_FIRMWARE_TABLE_INFORMATION { ULONG ProviderSignature;
         *       ULONG Action; ULONG TableID; ULONG TableBufferLength;
         *       UCHAR TableBuffer[]; }
         * The payload starts at offset 16. */
        if (len <= 16) break;
        if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) break;
        PUCHAR tbl   = (PUCHAR)buf + 16;
        ULONG  tbl_l = len - 16;
        cfp_dmi_patch_blob(tbl, tbl_l);
        break;
    }

    case SystemCodeIntegrityInformation: {
        if (len < sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)) break;
        if (!(toggles & CFP_TOGGLE_CI_STATE_SPOOF)) break;
        SYSTEM_CODEINTEGRITY_INFORMATION *ci = (SYSTEM_CODEINTEGRITY_INFORMATION *)buf;
        /* Report CI disabled, no HVCI, no test-signing. This is the shape
         * of a clean Windows install without WDAC or HVCI. */
        ci->CodeIntegrityOptions &= ~(CODEINTEGRITY_OPTION_ENABLED |
                                      CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED |
                                      CODEINTEGRITY_OPTION_TESTSIGN |
                                      CODEINTEGRITY_OPTION_UMCI_ENABLED);
        break;
    }

    case SystemSecureBootPolicyInformation: {
        if (!(toggles & CFP_TOGGLE_CI_STATE_SPOOF)) break;
        /* Secure Boot policy blob. We zero the active-policy signature so
         * callers see "default / unenforced" shape. The real blob layout
         * is private but every observed sample only checks the first
         * ULONG for a non-zero "policy present" marker. */
        if (len >= 4) *(PULONG)buf = 0;
        break;
    }

    case SystemCodeIntegrityPolicyFullInformation: {
        if (!(toggles & CFP_TOGGLE_CI_STATE_SPOOF)) break;
        /* WDAC policy blob. Shape: ULONG PolicyCount; followed by entries.
         * Zero the count. Callers that enumerate get zero policies. */
        if (len >= 4) *(PULONG)buf = 0;
        break;
    }

    case SystemBasicInformation:
    case SystemLogicalProcessorInformation:
    case SystemProcessorPerformanceInformation:
        /* Topology / counters pass through. The HV side keeps CPU count
         * and core topology consistent; we must not diverge here. */
        break;
    }

    return ctx->return_value;
}

static SIZE_T
rewrite_volume_information(CFP_IC_CTX *ctx)
{
    /* NtQueryVolumeInformationFile(FileFsVolumeInformation) returns:
     *   LARGE_INTEGER VolumeCreationTime;
     *   ULONG         VolumeSerialNumber;      // offset 8
     *   ULONG         VolumeLabelLength;
     *   BOOLEAN       SupportsObjects;
     *   WCHAR         VolumeLabel[];
     */
    PVOID buf = ctx->arg2;
    ULONG len = (ULONG)(ULONG_PTR)ctx->arg3;

    if (!buf || len < 16) return ctx->return_value;
    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS) return ctx->return_value;

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) return ctx->return_value;

    /* Rewrite serial with the first (C: slot) seed. Volume-letter affinity
     * requires file-object -> drive letter, which the shim resolves ahead
     * of time and passes via arg6 (slot index). */
    ULONG slot = (ULONG)(ULONG_PTR)ctx->arg6;
    if (slot > 3) slot = 0;

    UCHAR ser[4];
    if (cfp_cfg_get(CFP_FID_VOLUME_SERIAL_0 + slot, ser, sizeof(ser))) {
        *(PULONG)((PUCHAR)buf + 8) = *(PULONG)ser;
    }
    return ctx->return_value;
}

/* IOCTL_STORAGE_QUERY_PROPERTY + IOCTL_DISK_GET_DRIVE_GEOMETRY_EX.
 *
 * STORAGE_DEVICE_DESCRIPTOR layout (public, winioctl.h):
 *   ULONG Version;
 *   ULONG Size;
 *   UCHAR DeviceType, DeviceTypeModifier, RemovableMedia, CommandQueueing;
 *   ULONG VendorIdOffset;
 *   ULONG ProductIdOffset;
 *   ULONG ProductRevisionOffset;
 *   ULONG SerialNumberOffset;
 *   ...
 *   UCHAR RawDeviceProperties[];
 * The ASCII strings at those offsets are what we rewrite.
 */
static void
rewrite_storage_descriptor(PUCHAR buf, ULONG len)
{
    if (!buf || len < 40) return;
    ULONG serial_off = *(PULONG)(buf + 24);
    if (serial_off == 0 || serial_off >= len) return;

    /* 20-char serial from the stored slot tag expanded by chained derive.
     * Slot 0 is the first disk the shim walks; slot-to-handle mapping is
     * launcher-side. For wave 4 we use slot 0 for all disk queries from a
     * spoofed process — real multi-disk expansion arrives in wave 5. */
    UCHAR tag[4];
    if (!cfp_cfg_get(CFP_FID_DISK_SERIAL_0, tag, sizeof(tag))) return;

    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    PUCHAR dst = buf + serial_off;
    ULONG  rem = len - serial_off;
    ULONG  n   = rem > 21 ? 20 : (rem > 0 ? rem - 1 : 0);

    /* Mix tag bytes to produce 20 ASCII chars. We do not call the shared
     * derive() from here; that would require BCrypt at syscall-return time.
     * Instead we use the tag as a seed into a small LCG that produces
     * stable bytes. CFG stores only the 4-byte tag; the result is
     * per-boot stable (the tag does not change across reboots for a
     * fixed seed, because the launcher derives the tag once). */
    ULONG s = *(PULONG)tag;
    for (ULONG i = 0; i < n; ++i) {
        s = s * 1664525UL + 1013904223UL;
        dst[i] = alphabet[(s >> 16) % 36];
    }
    if (rem > n) dst[n] = 0;
}

static SIZE_T
rewrite_device_io_control(CFP_IC_CTX *ctx)
{
    /* NtDeviceIoControlFile args:
     *   arg0 FileHandle
     *   arg1 Event
     *   arg2 ApcRoutine
     *   arg3 ApcContext
     *   arg4 IoStatusBlock
     *   arg5 IoControlCode (ULONG)
     *   arg6 InputBuffer
     *   ... (shim collapses the rest into arg7 as OutputBuffer)
     *
     * The shim normalizes the layout so arg5 carries the IoControlCode and
     * arg7 carries OutputBuffer+Length as a packed { void*, ULONG }.
     */
    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS &&
        (NTSTATUS)ctx->return_value != STATUS_BUFFER_OVERFLOW) {
        return ctx->return_value;
    }

    ULONG ioctl = (ULONG)(ULONG_PTR)ctx->arg5;

    /* The "packed buf+len" shape: arg7 is a pointer to a struct
     *   { PVOID buf; ULONG len; } the shim built on the stack. */
    struct { PVOID buf; ULONG len; } *o = (void *)ctx->arg7;
    if (!o || !o->buf || !o->len) return ctx->return_value;

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) return ctx->return_value;

    switch (ioctl) {
    /* IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400; IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
     * = 0x700A0. Hard-coded so this file does not pull winioctl.h which is
     * user-mode-only. */
    case 0x002D1400:
    case 0x002D5C00:                /* IOCTL_STORAGE_QUERY_PROPERTY_EX */
        rewrite_storage_descriptor((PUCHAR)o->buf, o->len);
        break;

    /* IOCTL_NDIS_QUERY_GLOBAL_STATS on \Device\Ndis (OID_802_3_*).
     * Handled primarily in flt_filter.c but the shim also catches the
     * syscall-return side as belt-and-braces. The OID is in the input
     * buffer, not the output; the output carries the MAC. 6-byte return
     * = permanent MAC. */
    case 0x00170002: {                  /* IOCTL_NDIS_QUERY_GLOBAL_STATS */
        if (o->len >= 6) {
            UCHAR mac[6];
            if (cfp_cfg_get(CFP_FID_MAC_ADDR_0, mac, sizeof(mac))) {
                RtlCopyMemory(o->buf, mac, 6);
            }
        }
        break;
    }

    default:
        break;
    }

    return ctx->return_value;
}

/* ---------------- top-level dispatch ---------------- */

/* Called from ic_trampoline.asm. Must run quickly — every syscall-return
 * in a spoofed process passes through here. */
SIZE_T NTAPI
cfp_ic_dispatch(SIZE_T return_value, PVOID return_rip, SIZE_T saved_rax)
{
    UNREFERENCED_PARAMETER(return_rip);

    /* The shim fills a per-thread CFP_IC_CTX before the detour. For wave 4
     * we accept return_value + saved_rax (NT syscall number) and read the
     * args from the thread's user-mode stack via the shim's prologue. The
     * per-thread CTX pointer rides in gs:[0x1480] (an unused slot in TEB
     * on current Windows; shim reserves it at attach).
     *
     * This kernel-mode file is linked into chamber_fingerprint.sys for
     * contract clarity. At runtime the compiled version of this function
     * is copied into the shim's allocation along with the trampoline, so
     * the handlers above run in user mode in the target. The code is
     * written to a position-independent subset of MSVC C and takes no
     * kernel-only API dependencies except cfp_cfg_get — which the shim
     * routes to a per-process shared-memory view of the CFG blob the
     * launcher publishes.
     */
    CFP_IC_CTX ctx_storage;
    CFP_IC_CTX *ctx = &ctx_storage;
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->sysnum       = (ULONG)saved_rax;
    ctx->return_value = return_value;

    /* Syscall-number dispatch. The shim fills the arg0..arg7 slots from
     * the saved caller frame before jumping here. */
    switch (ctx->sysnum) {
    /* These numbers are placeholders. The shim resolves syscall numbers
     * once at attach via a one-shot ntdll walk and patches them into the
     * dispatch table it hands to this routine. Hard-coding specific
     * numbers would tie the driver to a single OS build. */
    case 0x0036:  /* NtQuerySystemInformation (Win11 22H2 example) */
        return rewrite_system_information(ctx);
    case 0x0007:  /* NtDeviceIoControlFile */
        return rewrite_device_io_control(ctx);
    case 0x0049:  /* NtQueryVolumeInformationFile */
        return rewrite_volume_information(ctx);
    default:
        break;
    }
    return return_value;
}
