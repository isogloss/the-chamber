/* instrumentation.c -- per-process arming of the syscall-return trampoline.
 *
 * NtSetInformationProcess(ProcessInstrumentationCallback) sets
 * KPROCESS.InstrumentationCallback to a user-mode address the kernel
 * dispatches to at every syscall return before RIP resumes. This is
 * documented, EDR-sanctioned, and PG does not hash it.
 *
 * Flow:
 *   1. PsSetCreateProcessNotifyRoutineEx catches process create.
 *   2. If the new PID is on the spoof list (because the launcher already
 *      added it via IOCTL_CFP_ADD_PID, e.g. for samples it just spawned),
 *      queue a work item: at PASSIVE_LEVEL, attach to the target process,
 *      resolve NtSetInformationProcess, and arm the callback with a
 *      user-mode trampoline address the operator passed in at IOCTL time.
 *   3. On process exit, drop the PID from the spoof list.
 *
 * The user-mode trampoline body is a follow-up (operator-side ntdll shim).
 * This file implements the kernel-side registration path with a validated
 * callback pointer stored in a per-process entry.
 *
 * The one special-case: the callback pointer is set per-process, so we
 * must stash it until the moment we attach. The arm-callback payload
 * travels alongside the PID on an extended IOCTL (handled in target_pid.c
 * via a parallel IOCTL added below).
 */

#include "fingerprint_cfg.h"

#define CFP_TAG                     'cFPC'
#define CFP_INSTR_ARM_MAX           32

/* ProcessInstrumentationCallback information class.
 *
 * Not in the public ntddk.h. The documented information-class constant is
 * 40 (0x28). The structure consumed by NtSetInformationProcess is:
 *
 *   typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
 *       ULONG Version;        // must be 0 on 64-bit
 *       ULONG Reserved;       // must be 0
 *       PVOID Callback;       // user-mode VA
 *   } PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;
 *
 * ZwSetInformationProcess refuses the class from kernel mode on some
 * builds; the correct path is to attach to the target process and issue
 * the call via a PreviousMode = UserMode stub. We stage this through
 * KeStackAttachProcess + ZwSetInformationProcess with the target as
 * ProcessHandle = NtCurrentProcess().
 */

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

#ifndef ProcessInstrumentationCallback
#define ProcessInstrumentationCallback  ((PROCESSINFOCLASS)40)
#endif

/* -------- per-pid pending arm table -------- */

typedef struct _CFP_INSTR_ARM {
    HANDLE   pid;
    PVOID    user_trampoline;      /* user-mode VA the shim installed */
    PVOID    shadow_cookie;        /* last value the target itself set
                                    * via NtSetInformationProcess(class 40)
                                    * — returned verbatim to that same
                                    * target on a class-40 query so a
                                    * packer that round-trips its own
                                    * cookie reads its own bytes back */
    BOOLEAN  armed;
} CFP_INSTR_ARM;

static KSPIN_LOCK      g_arm_lock;
static CFP_INSTR_ARM   g_arms[CFP_INSTR_ARM_MAX];
static ULONG           g_arm_count = 0;
static BOOLEAN         g_notify_registered = FALSE;

void
cfp_instr_init(void)
{
    KeInitializeSpinLock(&g_arm_lock);
    RtlZeroMemory(g_arms, sizeof(g_arms));
    g_arm_count = 0;
}

/* Record a pending arm. Called from the IOCTL path when the operator
 * supplies a user-mode trampoline address along with the PID. The actual
 * NtSetInformationProcess call fires when PsSetCreateProcessNotifyRoutineEx
 * tells us the process exists (and KeStackAttachProcess has a valid
 * EPROCESS to attach to). */
NTSTATUS
cfp_instr_pend(HANDLE pid, PVOID user_trampoline)
{
    KIRQL old;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid) {
            g_arms[i].user_trampoline = user_trampoline;
            g_arms[i].armed = FALSE;
            goto out;
        }
    }
    if (g_arm_count >= CFP_INSTR_ARM_MAX) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    g_arms[g_arm_count].pid             = pid;
    g_arms[g_arm_count].user_trampoline = user_trampoline;
    g_arms[g_arm_count].shadow_cookie   = NULL;
    g_arms[g_arm_count].armed           = FALSE;
    ++g_arm_count;
out:
    KeReleaseSpinLock(&g_arm_lock, old);
    return status;
}

static PVOID
cfp_instr_take_pending(HANDLE pid)
{
    KIRQL old;
    PVOID tr = NULL;
    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid && !g_arms[i].armed) {
            tr = g_arms[i].user_trampoline;
            g_arms[i].armed = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_arm_lock, old);
    return tr;
}

/* Remember the user-mode VA a target's own NtSetInformationProcess call
 * passed. The IC dispatcher filters the paired NtQueryInformationProcess
 * (class 40) return and substitutes this value so a packer that round-
 * trips its IC cookie reads its own bytes, not our shim's trampoline VA.
 *
 * Called from the IC return path for every set-op the target itself
 * issued against class 40; takes the new cookie value from the syscall
 * arg buffer. Safe to call at any IRQL up to DISPATCH_LEVEL. */
void
cfp_instr_shadow_set(HANDLE pid, PVOID cookie)
{
    KIRQL old;
    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid) {
            g_arms[i].shadow_cookie = cookie;
            break;
        }
    }
    KeReleaseSpinLock(&g_arm_lock, old);
}

/* Return the shadow cookie this PID last set (or NULL if the PID never
 * issued a class-40 set, which matches the "no instrumentation callback"
 * contract real Windows returns). Pairs with cfp_instr_shadow_set. */
PVOID
cfp_instr_shadow_get(HANDLE pid)
{
    KIRQL old;
    PVOID c = NULL;
    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid) {
            c = g_arms[i].shadow_cookie;
            break;
        }
    }
    KeReleaseSpinLock(&g_arm_lock, old);
    return c;
}

static void
cfp_instr_drop(HANDLE pid)
{
    KIRQL old;
    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid) {
            for (ULONG j = i + 1; j < g_arm_count; ++j) {
                g_arms[j - 1] = g_arms[j];
            }
            RtlZeroMemory(&g_arms[--g_arm_count], sizeof(g_arms[0]));
            break;
        }
    }
    KeReleaseSpinLock(&g_arm_lock, old);
}

/* -------- arm on first-reach -------- */

/* Attach to the target, call ZwSetInformationProcess. PreviousMode is
 * kernel in this context so the call is validated as a kernel-originated
 * request; the trampoline VA the launcher passes must be a VA that is
 * already mapped into the target's user space (the ntdll shim the
 * launcher injects before adding the PID). */
static NTSTATUS
cfp_instr_apply(HANDLE pid, PVOID user_trampoline)
{
    PAGED_CODE();

    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &target);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(target, &apc);

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
    info.Version  = 0;
    info.Reserved = 0;
    info.Callback = user_trampoline;

    /* ZwSetInformationProcess on the current (attached) process. */
    status = ZwSetInformationProcess(ZwCurrentProcess(),
                                     ProcessInstrumentationCallback,
                                     &info,
                                     sizeof(info));

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(target);
    return status;
}

/* Work item: fires at PASSIVE_LEVEL from the process-create notify path.
 * We cannot call ZwSetInformationProcess directly from the notify callback
 * because that callback can run at APC_LEVEL (ZwSet* requires PASSIVE).
 */
typedef struct _CFP_INSTR_WORK {
    PIO_WORKITEM  work;
    HANDLE        pid;
    PVOID         trampoline;
} CFP_INSTR_WORK;

IO_WORKITEM_ROUTINE cfp_instr_work_routine;
VOID
cfp_instr_work_routine(PDEVICE_OBJECT dev, PVOID ctx)
{
    UNREFERENCED_PARAMETER(dev);
    CFP_INSTR_WORK *w = (CFP_INSTR_WORK *)ctx;

    NTSTATUS status = cfp_instr_apply(w->pid, w->trampoline);
    if (!NT_SUCCESS(status)) {
        CHAMBER_LOG_ERR("cfp: IC arm failed pid=%lu status=0x%08x\n",
                        (ULONG)(ULONG_PTR)w->pid, status);
    }

    IoFreeWorkItem(w->work);
    ExFreePoolWithTag(w, CFP_TAG);
}

/* -------- PsSetCreateProcessNotifyRoutineEx -------- */

/* Forward decl to target_pid.c. */
BOOLEAN cfp_target_contains(HANDLE pid);
NTSTATUS cfp_target_remove(HANDLE pid);

static PDEVICE_OBJECT g_notify_device = NULL;

static void
cfp_create_notify(PEPROCESS proc, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{
    UNREFERENCED_PARAMETER(proc);

    if (info) {
        /* Process create. If the PID is already on the spoof list and has
         * a pending arm, queue the IC install. The launcher adds the PID
         * before spawning the sample (CREATE_SUSPENDED), so by the time
         * this notify fires the arm entry is in place. */
        if (!cfp_target_contains(pid)) {
            return;
        }
        PVOID tr = cfp_instr_take_pending(pid);
        if (!tr || !g_notify_device) {
            return;
        }

        CFP_INSTR_WORK *w = (CFP_INSTR_WORK *)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(*w), CFP_TAG);
        if (!w) return;

        w->work = IoAllocateWorkItem(g_notify_device);
        if (!w->work) {
            ExFreePoolWithTag(w, CFP_TAG);
            return;
        }
        w->pid        = pid;
        w->trampoline = tr;
        IoQueueWorkItem(w->work, cfp_instr_work_routine, DelayedWorkQueue, w);
    } else {
        /* Process exit. Scrub both tables so a new process reusing this
         * PID does not inherit stale spoof state. */
        cfp_instr_drop(pid);
        cfp_target_remove(pid);
    }
}

NTSTATUS
cfp_instr_register(PDEVICE_OBJECT control_device)
{
    PAGED_CODE();

    if (g_notify_registered) return STATUS_SUCCESS;

    g_notify_device = control_device;
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(cfp_create_notify, FALSE);
    if (!NT_SUCCESS(status)) {
        g_notify_device = NULL;
        return status;
    }
    g_notify_registered = TRUE;
    return STATUS_SUCCESS;
}

void
cfp_instr_unregister(void)
{
    if (g_notify_registered) {
        PsSetCreateProcessNotifyRoutineEx(cfp_create_notify, TRUE);
        g_notify_registered = FALSE;
    }
    g_notify_device = NULL;
}
