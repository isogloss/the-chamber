/* entry.c -- DriverEntry for chamber_fingerprint.sys.
 *
 * Orchestration only. Each subsystem lives in its own translation unit;
 * this file wires them together in the required order and provides the
 * control device + dispatch table.
 *
 * Boot sequence:
 *   1. cfp_cfg_load   : pull CHAMBER_CFG_V2 from Services\<svc>\Parameters\CfgBlob
 *   2. cfp_target_init: spoof-list spin lock
 *   3. cfp_instr_init : IC arm table
 *   4. Create control device + symlink (launcher opens this for IOCTLs)
 *   5. cfp_cm_register: CmRegisterCallbackEx for registry surfaces
 *   6. cfp_flt_register: FltRegisterFilter for NDIS IOCTLs
 *   7. cfp_instr_register: PsSetCreateProcessNotifyRoutineEx for per-PID arming
 *
 * Any step failing tears down the earlier ones in reverse order and
 * returns the failure. A partial teardown never leaks a registered
 * callback.
 *
 * Device and symlink names are static in this revision — per-install
 * randomization of these names is a planned extension of the same
 * CFG-driven rename scheme the HV driver already has. The launcher
 * opens \\.\CFPControl to send IOCTLs.
 */

#include "fingerprint_cfg.h"
#include <wdmsec.h>     /* IoCreateDeviceSecure + SDDL_* constants */

#define CFP_TAG         'cFPC'

/* --- forwarded from other TUs --- */
NTSTATUS cfp_cfg_load(PUNICODE_STRING registry_path);
void     cfp_cfg_unload(void);

void     cfp_target_init(void);
void     cfp_target_cleanup(void);
NTSTATUS cfp_target_handle_ioctl(PIRP irp, PIO_STACK_LOCATION iosp, PULONG_PTR info);

void     cfp_instr_init(void);
NTSTATUS cfp_instr_register(PDEVICE_OBJECT control_device);
void     cfp_instr_unregister(void);
NTSTATUS cfp_instr_pend(HANDLE pid, PVOID user_trampoline);

NTSTATUS cfp_cm_register(void);
void     cfp_cm_unregister(void);

NTSTATUS cfp_flt_register(PDRIVER_OBJECT drv);
void     cfp_flt_unregister_now(void);

/* --- state --- */

static PDEVICE_OBJECT g_device        = NULL;
static UNICODE_STRING g_symlink_name  = {0};
static BOOLEAN        g_symlink_made  = FALSE;

/* Extended arm IOCTL carries both PID and user-mode trampoline VA. */
#define IOCTL_CFP_ARM_PID    CTL_CODE(0x8001, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _CFP_ARM_REQUEST {
    ULONG pid;
    ULONG reserved;
    ULONGLONG user_trampoline;
} CFP_ARM_REQUEST;

/* --- dispatch --- */

static NTSTATUS
cfp_create_close(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
cfp_devctl(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION iosp = IoGetCurrentIrpStackLocation(irp);
    ULONG     code = iosp->Parameters.DeviceIoControl.IoControlCode;
    ULONG_PTR info = 0;
    NTSTATUS  status;

    if (code == IOCTL_CFP_ARM_PID) {
        ULONG in_len = iosp->Parameters.DeviceIoControl.InputBufferLength;
        if (in_len < sizeof(CFP_ARM_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            CFP_ARM_REQUEST *req = (CFP_ARM_REQUEST *)irp->AssociatedIrp.SystemBuffer;
            status = cfp_instr_pend((HANDLE)(ULONG_PTR)req->pid,
                                    (PVOID)(ULONG_PTR)req->user_trampoline);
        }
    } else {
        status = cfp_target_handle_ioctl(irp, iosp, &info);
    }

    irp->IoStatus.Status      = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* --- unload --- */

static VOID
cfp_unload(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);

    /* Deregister in reverse order of registration. Pending callbacks
     * drain before each API returns. */
    cfp_instr_unregister();
    cfp_flt_unregister_now();
    cfp_cm_unregister();

    if (g_symlink_made) {
        IoDeleteSymbolicLink(&g_symlink_name);
        g_symlink_made = FALSE;
    }
    if (g_device) {
        IoDeleteDevice(g_device);
        g_device = NULL;
    }

    cfp_target_cleanup();
    cfp_cfg_unload();
}

/* --- DriverEntry --- */

NTSTATUS
DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path)
{
    NTSTATUS status;

    /* 1. Load CFG v2. Without a valid blob we cannot spoof consistently
     *    with the HV side, so a failure here must stop the load. */
    status = cfp_cfg_load(reg_path);
    if (!NT_SUCCESS(status)) {
        CHAMBER_LOG_ERR("cfp: cfg load failed 0x%08x\n", status);
        return status;
    }

    /* 2 + 3. Per-subsystem init that cannot fail. */
    cfp_target_init();
    cfp_instr_init();

    /* 4. Control device. SDDL_DEVOBJ_SYS_ALL_ADM_ALL: SYSTEM + admins only.
     *    The launcher runs elevated; no non-admin process should be able
     *    to open \\.\CFPControl and arm spoofing. */
    UNICODE_STRING dev_name;
    RtlInitUnicodeString(&dev_name, L"\\Device\\CFPControl");
    status = IoCreateDeviceSecure(
        drv, 0, &dev_name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        NULL, &g_device);
    if (!NT_SUCCESS(status)) {
        cfp_cfg_unload();
        return status;
    }
    g_device->Flags |= DO_BUFFERED_IO;
    g_device->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&g_symlink_name, L"\\DosDevices\\CFPControl");
    status = IoCreateSymbolicLink(&g_symlink_name, &dev_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device);
        g_device = NULL;
        cfp_cfg_unload();
        return status;
    }
    g_symlink_made = TRUE;

    drv->MajorFunction[IRP_MJ_CREATE]         = cfp_create_close;
    drv->MajorFunction[IRP_MJ_CLOSE]          = cfp_create_close;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = cfp_devctl;
    drv->DriverUnload                          = cfp_unload;

    /* 5. Registry callback. */
    status = cfp_cm_register();
    if (!NT_SUCCESS(status)) {
        CHAMBER_LOG_ERR("cfp: cm register failed 0x%08x\n", status);
        goto bail_after_device;
    }

    /* 6. Minifilter. Not fatal if Fltmgr is unavailable in the pre-boot
     *    phase this driver happened to be loaded during — cm + IC cover
     *    the primary adapter path. */
    NTSTATUS flt_s = cfp_flt_register(drv);
    if (!NT_SUCCESS(flt_s)) {
        CHAMBER_LOG_WARN("cfp: flt register failed 0x%08x; continuing\n", flt_s);
    }

    /* 7. Process-create notify (installs IC per-PID). */
    status = cfp_instr_register(g_device);
    if (!NT_SUCCESS(status)) {
        CHAMBER_LOG_ERR("cfp: instr register failed 0x%08x\n", status);
        goto bail_after_flt;
    }

    return STATUS_SUCCESS;

bail_after_flt:
    cfp_flt_unregister_now();
    cfp_cm_unregister();
bail_after_device:
    IoDeleteSymbolicLink(&g_symlink_name);
    g_symlink_made = FALSE;
    IoDeleteDevice(g_device);
    g_device = NULL;
    cfp_target_cleanup();
    cfp_cfg_unload();
    return status;
}
