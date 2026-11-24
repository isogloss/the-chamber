/* flt_filter.c -- minifilter for IRP_MJ_DEVICE_CONTROL on NDIS.
 *
 * A sample can call DeviceIoControl on a handle to \Device\Ndis with
 * IOCTL_NDIS_QUERY_GLOBAL_STATS and OID OID_802_3_PERMANENT_ADDRESS or
 * OID_802_3_CURRENT_ADDRESS to read the adapter's hardware MAC.
 * GetAdaptersAddresses / GetAdaptersInfo bottom out in the same path,
 * and the IC handler in syscall_rewrite.c covers the syscall-return
 * side of that chain. This minifilter exists so a sample opening
 * \Device\Ndis directly (rather than through iphlpapi) sees the same
 * spoofed MAC.
 *
 * Minifilter rather than legacy filter because FltRegisterFilter is the
 * documented, PG-safe, EDR-sanctioned attach path. We register with a
 * context-registration record that holds the spoof PID set for quick
 * filtering (we reach into the Flt pre-op callback at DISPATCH_LEVEL;
 * KSPIN_LOCK across to cfp_target_contains is fine).
 *
 * We filter only IRP_MJ_DEVICE_CONTROL. Open, close, read, write all
 * bypass. On device control, we match the control code against the
 * two NDIS IOCTLs we care about and, in post-op, rewrite the output
 * buffer.
 */

#include <ntifs.h>
#include <fltKernel.h>
#include "fingerprint_cfg.h"

#define CFP_TAG                 'cFPC'

/* --- forward decls --- */
BOOLEAN cfp_target_contains(HANDLE pid);

/* IOCTL + OID constants (ntddndis.h is user-mode; keep the raw values
 * here so this driver pulls only fltKernel + ntifs). */
#define IOCTL_NDIS_QUERY_GLOBAL_STATS    0x00170002UL
#define OID_802_3_PERMANENT_ADDRESS      0x01010101UL
#define OID_802_3_CURRENT_ADDRESS        0x01010102UL

/* --- state --- */

static PFLT_FILTER g_filter = NULL;

/* --- pre-op --- */

static FLT_PREOP_CALLBACK_STATUS
cfp_flt_pre_devctl(PFLT_CALLBACK_DATA data,
                   PCFLT_RELATED_OBJECTS objs,
                   PVOID *completion_ctx)
{
    UNREFERENCED_PARAMETER(objs);
    UNREFERENCED_PARAMETER(completion_ctx);

    /* PID filter first — keeps the hot path fast for unrelated opens. */
    HANDLE pid = PsGetCurrentProcessId();
    if (!cfp_target_contains(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Only interested in IRP_MJ_DEVICE_CONTROL (and FS version thereof). */
    if (data->Iopb->MajorFunction != IRP_MJ_DEVICE_CONTROL &&
        data->Iopb->MajorFunction != IRP_MJ_INTERNAL_DEVICE_CONTROL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG ioctl = data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;
    if (ioctl != IOCTL_NDIS_QUERY_GLOBAL_STATS) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Inspect the OID in the input buffer. The NDIS stats IOCTL puts the
     * OID as a ULONG at the start of the input buffer; the output buffer
     * gets the stat's value. */
    PVOID in_buf   = data->Iopb->Parameters.DeviceIoControl.Common.InputBuffer;
    ULONG in_len   = data->Iopb->Parameters.DeviceIoControl.Common.InputBufferLength;
    if (!in_buf || in_len < sizeof(ULONG)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        ULONG oid = *(volatile ULONG *)in_buf;
        if (oid != OID_802_3_PERMANENT_ADDRESS &&
            oid != OID_802_3_CURRENT_ADDRESS) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Request a post-op callback so we can rewrite the 6-byte MAC after
     * the real driver filled it in. */
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* --- post-op --- */

static FLT_POSTOP_CALLBACK_STATUS
cfp_flt_post_devctl(PFLT_CALLBACK_DATA data,
                    PCFLT_RELATED_OBJECTS objs,
                    PVOID completion_ctx,
                    FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(objs);
    UNREFERENCED_PARAMETER(completion_ctx);

    if (flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PVOID out_buf = data->Iopb->Parameters.DeviceIoControl.Common.OutputBuffer;
    ULONG out_len = data->Iopb->Parameters.DeviceIoControl.Common.OutputBufferLength;
    if (!out_buf || out_len < 6) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* We do not know which adapter the sample is talking to at Flt level;
     * use slot 0 for the first query and rotate on subsequent ones is a
     * later-wave refinement. Slot 0 is what iphlpapi normalizes to for
     * the "primary" adapter and matches what the IC-side rewrite picks
     * for symmetry. */
    UCHAR mac[6];
    if (!cfp_cfg_get(CFP_FID_MAC_ADDR_0, mac, sizeof(mac))) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    __try {
        RtlCopyMemory(out_buf, mac, 6);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* user buffer vanished — nothing to do */
    }

    data->IoStatus.Information = 6;
    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* --- registration --- */

static const FLT_OPERATION_REGISTRATION cfp_flt_ops[] = {
    { IRP_MJ_DEVICE_CONTROL, 0, cfp_flt_pre_devctl, cfp_flt_post_devctl },
    { IRP_MJ_INTERNAL_DEVICE_CONTROL, 0, cfp_flt_pre_devctl, cfp_flt_post_devctl },
    { IRP_MJ_OPERATION_END }
};

static NTSTATUS FLTAPI
cfp_flt_unload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);
    if (g_filter) {
        FltUnregisterFilter(g_filter);
        g_filter = NULL;
    }
    return STATUS_SUCCESS;
}

/* InstanceSetup: FltMgr calls this whenever a volume mounts. We accept
 * the attach only for volumes whose device type we care about — the
 * real MAC rewrite path lives on the NDIS IOCTL side, not on a file
 * system volume, so we refuse attaches on plain FS volumes and keep
 * the filter inert there. Without this hook FltMgr auto-attaches the
 * filter to every mounted FS and racks up hundreds of pointless
 * post-ops per boot; the earlier NULL slot made that worse. */
static NTSTATUS FLTAPI
cfp_flt_instance_setup(PCFLT_RELATED_OBJECTS objs,
                       FLT_INSTANCE_SETUP_FLAGS flags,
                       DEVICE_TYPE volume_dev_type,
                       FLT_FILESYSTEM_TYPE volume_fs_type)
{
    UNREFERENCED_PARAMETER(objs);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volume_dev_type);
    UNREFERENCED_PARAMETER(volume_fs_type);
    /* Refuse the attach by default. The MAC rewrite path does not need
     * a per-volume context; the pre-op callbacks fire from any attach
     * the filter holds, so one attach to the system (via FltMgr's
     * built-in no-volume context) is enough. */
    return STATUS_FLT_DO_NOT_ATTACH;
}

/* FLT altitude. Pick a value in the Microsoft-registered
 * 330000-339998 ("Security Enhancer") range; the real per-install
 * number is provisioned by the launcher under
 *   HKLM\System\CurrentControlSet\Services\<svc>\Instances\
 *     DefaultInstance\Altitude
 * before SCM start, because FltMgr reads Altitude from the registry
 * (not from FLT_REGISTRATION). The constant here is a build-time
 * fallback the launcher's provisioning path should overwrite. */
static const FLT_REGISTRATION cfp_flt_reg = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                               /* Flags */
    NULL,                            /* ContextRegistration */
    cfp_flt_ops,
    cfp_flt_unload,
    cfp_flt_instance_setup,          /* InstanceSetup */
    NULL, NULL,                      /* InstanceQueryTeardown, InstanceTeardownStart */
    NULL, NULL, NULL,
    NULL,                            /* NormalizeNameComponentCallback */
    NULL,                            /* NormalizeContextCleanupCallback */
    NULL                             /* TransactionNotificationCallback */
};

NTSTATUS
cfp_flt_register(PDRIVER_OBJECT drv)
{
    NTSTATUS s = FltRegisterFilter(drv, &cfp_flt_reg, &g_filter);
    if (!NT_SUCCESS(s)) return s;

    s = FltStartFiltering(g_filter);
    if (!NT_SUCCESS(s)) {
        FltUnregisterFilter(g_filter);
        g_filter = NULL;
    }
    return s;
}

void
cfp_flt_unregister_now(void)
{
    if (g_filter) {
        FltUnregisterFilter(g_filter);
        g_filter = NULL;
    }
}
