/* target_pid.c -- spoof-list management.
 *
 * The operator (the launcher process, or a sample runner the operator
 * attaches) opens the control device and calls IOCTL_CFP_ADD_PID with its
 * own PID plus every sample PID it wants spoofed. The CM / FLT / IC
 * callbacks all gate on membership here: an unlisted PID sees the real
 * system, so the rewrite cost is paid only for the operator's own
 * processes.
 *
 * Design intent: the list is small (operator + 1-8 samples typical). A
 * fixed-size table with a KSPIN_LOCK is cheaper than a search tree and
 * runs at DISPATCH_LEVEL from the registry callback's post-op context.
 */

#include "fingerprint_cfg.h"

#define CFP_TAG                      'cFPC'
#define CFP_MAX_PIDS                 32

/* IOCTL control codes. Use FILE_DEVICE_UNKNOWN (0x22), the standard for
 * a custom control device — the previous 0x8001 was one nibble away
 * from the HV driver's 0x8000 and a cross-driver correlator could pair
 * them on that distance alone. FILE_DEVICE_UNKNOWN is also what
 * IoCreateDeviceSecure in entry.c uses, so the control-code header
 * check (IoValidateDeviceIoControlAccess for buffered-IO IOCTLs) now
 * passes verbatim rather than only by accident. */
#define CFP_IOCTL_DEVICE_TYPE        FILE_DEVICE_UNKNOWN

#define IOCTL_CFP_ADD_PID       CTL_CODE(CFP_IOCTL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_CFP_REMOVE_PID    CTL_CODE(CFP_IOCTL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* QUERY_LIST removed: it was readable by any admin/SYSTEM sample and
 * leaked the spoof-PID set verbatim. The launcher does not need to read
 * its own PIDs back from the driver — it holds them locally. See
 * target_pid.c history for the removed dispatch case. */
#define IOCTL_CFP_CLEAR         CTL_CODE(CFP_IOCTL_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _CFP_IOCTL_PID {
    ULONG pid;              /* 32-bit; HANDLE values on x64 are always
                               page-aligned PIDs that fit in 32 bits */
    ULONG reserved;
} CFP_IOCTL_PID;

typedef struct _CFP_IOCTL_LIST {
    ULONG count;
    ULONG pids[CFP_MAX_PIDS];
} CFP_IOCTL_LIST;

/* -------- state -------- */

static KSPIN_LOCK  g_pid_lock;
static HANDLE      g_pids[CFP_MAX_PIDS];
static ULONG       g_pid_count = 0;

void
cfp_target_init(void)
{
    KeInitializeSpinLock(&g_pid_lock);
    RtlZeroMemory(g_pids, sizeof(g_pids));
    g_pid_count = 0;
}

void
cfp_target_cleanup(void)
{
    KIRQL old;
    KeAcquireSpinLock(&g_pid_lock, &old);
    RtlZeroMemory(g_pids, sizeof(g_pids));
    g_pid_count = 0;
    KeReleaseSpinLock(&g_pid_lock, old);
}

/* Hot-path test. Called from Cm post-op at DISPATCH_LEVEL and from Flt and
 * IC entry points at PASSIVE / APC_LEVEL — must be callable at any IRQL up
 * to DISPATCH_LEVEL. KSPIN_LOCK is DISPATCH_LEVEL-safe. */
BOOLEAN
cfp_target_contains(HANDLE pid)
{
    KIRQL old;
    BOOLEAN hit = FALSE;
    KeAcquireSpinLock(&g_pid_lock, &old);
    for (ULONG i = 0; i < g_pid_count; ++i) {
        if (g_pids[i] == pid) {
            hit = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_pid_lock, old);
    return hit;
}

/* Add. Idempotent; returns STATUS_SUCCESS whether the pid was new or
 * already present. STATUS_INSUFFICIENT_RESOURCES if the table is full. */
NTSTATUS
cfp_target_add(HANDLE pid)
{
    KIRQL old;
    NTSTATUS status = STATUS_SUCCESS;

    if (pid == 0) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_pid_lock, &old);
    for (ULONG i = 0; i < g_pid_count; ++i) {
        if (g_pids[i] == pid) goto out;
    }
    if (g_pid_count >= CFP_MAX_PIDS) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    g_pids[g_pid_count++] = pid;
out:
    KeReleaseSpinLock(&g_pid_lock, old);
    return status;
}

NTSTATUS
cfp_target_remove(HANDLE pid)
{
    KIRQL old;
    NTSTATUS status = STATUS_NOT_FOUND;

    KeAcquireSpinLock(&g_pid_lock, &old);
    for (ULONG i = 0; i < g_pid_count; ++i) {
        if (g_pids[i] == pid) {
            /* compact */
            for (ULONG j = i + 1; j < g_pid_count; ++j) {
                g_pids[j - 1] = g_pids[j];
            }
            g_pids[--g_pid_count] = NULL;
            status = STATUS_SUCCESS;
            break;
        }
    }
    KeReleaseSpinLock(&g_pid_lock, old);
    return status;
}

ULONG
cfp_target_snapshot(_Out_writes_(cap) HANDLE *out, _In_ ULONG cap)
{
    KIRQL old;
    ULONG n;
    KeAcquireSpinLock(&g_pid_lock, &old);
    n = g_pid_count < cap ? g_pid_count : cap;
    for (ULONG i = 0; i < n; ++i) {
        out[i] = g_pids[i];
    }
    KeReleaseSpinLock(&g_pid_lock, old);
    return n;
}

/* ---------------- IOCTL dispatch ---------------- */

NTSTATUS
cfp_target_handle_ioctl(_In_ PIRP irp,
                        _In_ PIO_STACK_LOCATION iosp,
                        _Out_ PULONG_PTR info)
{
    ULONG   code     = iosp->Parameters.DeviceIoControl.IoControlCode;
    PVOID   buf      = irp->AssociatedIrp.SystemBuffer;
    ULONG   in_len   = iosp->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status  = STATUS_INVALID_DEVICE_REQUEST;

    *info = 0;

    switch (code) {
    case IOCTL_CFP_ADD_PID: {
        if (in_len < sizeof(CFP_IOCTL_PID)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        CFP_IOCTL_PID *p = (CFP_IOCTL_PID *)buf;
        status = cfp_target_add((HANDLE)(ULONG_PTR)p->pid);
        break;
    }

    case IOCTL_CFP_REMOVE_PID: {
        if (in_len < sizeof(CFP_IOCTL_PID)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        CFP_IOCTL_PID *p = (CFP_IOCTL_PID *)buf;
        status = cfp_target_remove((HANDLE)(ULONG_PTR)p->pid);
        break;
    }

    /* IOCTL_CFP_QUERY_LIST deliberately removed: a readable spoof list
     * is a correlator any admin/SYSTEM process (including an arbitrary
     * sample launched outside the launcher) could query to enumerate
     * every PID the chamber is spoofing. The launcher holds the PID
     * set in its own memory; it does not need to read it back from the
     * driver. If a future diagnostic needs the list, gate the dispatch
     * on a CFG_V2 shared-secret handshake (nonce derived from
     * CHAMBER_CFG_V2.seed, exchanged over a METHOD_IN_DIRECT buffer),
     * not on admin/SYSTEM access. */

    case IOCTL_CFP_CLEAR:
        cfp_target_cleanup();
        status = STATUS_SUCCESS;
        break;
    }

    return status;
}
