/* instrumentation.c -- per-process arming of the syscall-return trampoline.
 *
 * NtSetInformationProcess(ProcessInstrumentationCallback) sets
 * KPROCESS.InstrumentationCallback to a user-mode address the kernel
 * dispatches to at every syscall return before RIP resumes. This is
 * documented, EDR-sanctioned, and PG does not hash it.
 *
 * Flow (post-Wave-8.5):
 *   1. Launcher pushes shim bytes via IOCTL_CFP_SET_SHIM_IMAGE — the
 *      driver keeps one shared paged-pool copy of chamber_shim.dll
 *      bytes until unload.
 *   2. Launcher calls IOCTL_CFP_ADD_PID + IOCTL_CFP_ARM_PID. The arm
 *      request carries the RVA of the trampoline entry inside the
 *      shim bytes (NOT an absolute user VA — the user VA is only
 *      known after the per-process mapping in step 4).
 *   3. PsSetCreateProcessNotifyRoutineEx catches process create and
 *      cfp_create_notify records readiness; the actual IC-arm
 *      deferred until the shim is mapped (step 4), otherwise the IC
 *      VA would point into kernel-mode or unmapped user memory and
 *      the first syscall return would AV the target.
 *   4. PsSetLoadImageNotifyRoutine fires on every image load. On the
 *      FIRST image load for a target PID with armed intent:
 *        - PsLookupProcessByProcessId + KeStackAttachProcess
 *        - ZwAllocateVirtualMemory(ZwCurrentProcess(), ...) for a
 *          page-aligned PAGE_EXECUTE_READWRITE region sized to the
 *          shim bytes (ZwProtectVirtualMemory is skipped — see the
 *          inject routine for why a split code/data page dance is a
 *          later hardening pass)
 *        - RtlCopyMemory the shim bytes in under __try so a race
 *          with a dying target cannot bugcheck the driver
 *        - The real user-mode trampoline VA becomes
 *              <alloc_base> + <launcher-supplied RVA>
 *          and NtSetInformationProcess(ProcessInstrumentationCallback)
 *          is issued with that VA.
 *   5. On process exit, drop the PID from the spoof list and release
 *      the per-process entry; the user-mode mapping goes away with
 *      the dying address space, so no ZwFreeVirtualMemory is needed.
 *
 * The user-mode trampoline body lives in chamber_shim.dll (the
 * launcher embeds it and pushes it via IOCTL); ic_trampoline.asm in
 * this directory remains the kernel-signed reference copy against
 * which cfp_ic_dispatch is validated.
 */

/* ntifs.h brings KAPC_STATE / KeStackAttachProcess / KeUnstackDetachProcess
 * / PsLookupProcessByProcessId / ZwAllocateVirtualMemory / ZwFreeVirtualMemory
 * / ZwSetInformationProcess — none of which live in ntddk.h or wdm.h on the
 * WDK 19041 layout. ntifs.h #includes ntddk.h itself so order is safe. */
#include <ntifs.h>
#include "fingerprint_cfg.h"

/* Pool tag resolves through the shared symbol in cfg_shared.c: every
 * fp allocation wears the per-install tag the CFG swap assigned
 * rather than wearing the hard-coded 'cFPC' giveaway. */
#define CFP_TAG                     (g_cfp_pool_tag)
#define CFP_INSTR_ARM_MAX           32
#define CFP_SHIM_MAX_BYTES          (1u * 1024u * 1024u)   /* 1 MiB cap */

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
    HANDLE    pid;
    /* The field the launcher passes in IOCTL_CFP_ARM_PID. Its mode is
     * captured at cfp_instr_pend time via `uses_shim` below:
     *   uses_shim == TRUE  → RVA inside the stored shim bytes; real
     *                        VA is shim_user_base + user_trampoline
     *                        once the image-load notify has mapped
     *                        the shim.
     *   uses_shim == FALSE → absolute user VA the launcher pre-mapped
     *                        by some other means (legacy / testing).
     * PVOID so sign-extension behaves on x64. */
    PVOID     user_trampoline;
    /* Base of the per-process shim mapping cfp_instr_on_image_load
     * installed, or NULL when the shim has not yet been mapped into
     * this PID. The real user VA handed to NtSetInformationProcess
     * is shim_user_base + (ULONG_PTR)user_trampoline. */
    PVOID     shim_user_base;
    PVOID     shadow_cookie;       /* last value the target itself set
                                    * via NtSetInformationProcess(class 40)
                                    * — returned verbatim to that same
                                    * target on a class-40 query so a
                                    * packer that round-trips its own
                                    * cookie reads its own bytes back */
    BOOLEAN   armed;               /* IC install already issued */
    BOOLEAN   shim_mapped;         /* TRUE once shim copy landed in target */
    BOOLEAN   uses_shim;           /* mode latched at pend time */
} CFP_INSTR_ARM;

static KSPIN_LOCK      g_arm_lock;
static CFP_INSTR_ARM   g_arms[CFP_INSTR_ARM_MAX];
static ULONG           g_arm_count = 0;
static BOOLEAN         g_notify_registered = FALSE;
static BOOLEAN         g_load_image_notify_registered = FALSE;

/* Shim-image shared storage.
 *
 * The launcher pushes bytes via IOCTL_CFP_SET_SHIM_IMAGE; we duplicate
 * into our own paged pool so the launcher's SystemBuffer is reusable
 * and the driver's image-load notify (PASSIVE_LEVEL) has a stable
 * source to RtlCopyMemory from.
 *
 * Reads of the shared buffer take g_shim_lock; writes replace the
 * pointer and length under the same lock. Image-load notifies take a
 * snapshot pointer under the lock, release the lock, then operate on
 * the snapshot — this is safe because the only replacement path is
 * cfp_instr_set_shim_image, which frees the old pointer AFTER taking
 * the lock to publish the new one, and the old buffer stays live for
 * exactly the length of one critical section. (A reader that
 * snapshotted before the swap continues to see the old bytes, which
 * is harmless — the target it is about to inject is from the
 * pre-swap generation.) */
static KSPIN_LOCK  g_shim_lock;
static PVOID       g_shim_bytes = NULL;
static ULONG       g_shim_len   = 0;
static ULONG       g_shim_tag   = 0;

void
cfp_instr_init(void)
{
    KeInitializeSpinLock(&g_arm_lock);
    KeInitializeSpinLock(&g_shim_lock);
    RtlZeroMemory(g_arms, sizeof(g_arms));
    g_arm_count = 0;
    g_shim_bytes = NULL;
    g_shim_len   = 0;
    g_shim_tag   = 0;
}

/* Record a pending arm. Called from the IOCTL path when the operator
 * supplies a user-mode trampoline (an RVA inside the shim payload,
 * when a shim has been pushed) along with the PID. The actual
 * NtSetInformationProcess call fires AFTER the shim has been mapped
 * into the target's user AS by cfp_instr_on_image_load; until then
 * the real user VA is not known, so the record stays pending. */
NTSTATUS
cfp_instr_pend(HANDLE pid, PVOID user_trampoline)
{
    KIRQL old;
    NTSTATUS status = STATUS_SUCCESS;

    /* Latch RVA vs absolute-VA interpretation from the GLOBAL shim
     * state at pend time. The operator must call
     * IOCTL_CFP_SET_SHIM_IMAGE before ARM_PID for the RVA path; a
     * later push does not retroactively change already-pended
     * entries. A plain pointer read is atomic on x64 — no lock
     * needed just to decide the mode flag. */
    BOOLEAN uses_shim = (g_shim_bytes != NULL);

    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid) {
            g_arms[i].user_trampoline = user_trampoline;
            g_arms[i].armed           = FALSE;
            g_arms[i].uses_shim       = uses_shim;
            /* Keep shim_mapped / shim_user_base from any earlier
             * mapping: an operator re-arm against the same PID
             * should not force a second shim install. If the target
             * is a new process reusing the PID, cfp_create_notify's
             * exit handler zeroed the entry on process-exit, so
             * shim_user_base is NULL here anyway. */
            goto out;
        }
    }
    if (g_arm_count >= CFP_INSTR_ARM_MAX) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    g_arms[g_arm_count].pid             = pid;
    g_arms[g_arm_count].user_trampoline = user_trampoline;
    g_arms[g_arm_count].shim_user_base  = NULL;
    g_arms[g_arm_count].shadow_cookie   = NULL;
    g_arms[g_arm_count].armed           = FALSE;
    g_arms[g_arm_count].shim_mapped     = FALSE;
    g_arms[g_arm_count].uses_shim       = uses_shim;
    ++g_arm_count;
out:
    KeReleaseSpinLock(&g_arm_lock, old);
    return status;
}

/* Return the resolved user-mode trampoline VA for `pid`, or NULL if
 * the shim has not yet been mapped into that target (in which case
 * the image-load notify will arm later) OR if the arm is already
 * recorded. Mode is determined by the per-entry `uses_shim` flag
 * latched at pend time:
 *   uses_shim == TRUE  → wait for shim_user_base, then return
 *                        shim_user_base + user_trampoline (RVA path).
 *   uses_shim == FALSE → return user_trampoline verbatim (legacy /
 *                        operator pre-mapped the trampoline itself).
 * Marks the entry armed once it hands out a non-NULL VA so a
 * subsequent image-load notify does not queue a duplicate IC install.
 */
static PVOID
cfp_instr_take_pending(HANDLE pid)
{
    KIRQL old;
    PVOID tr = NULL;
    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid && !g_arms[i].armed) {
            if (g_arms[i].uses_shim) {
                if (g_arms[i].shim_user_base != NULL) {
                    tr = (PVOID)((ULONG_PTR)g_arms[i].shim_user_base +
                                 (ULONG_PTR)g_arms[i].user_trampoline);
                }
                /* else: shim not mapped yet — leave armed FALSE so
                 * cfp_instr_on_image_load's follow-up take_pending
                 * retries with a resolved base. */
            } else {
                tr = g_arms[i].user_trampoline;
            }
            if (tr != NULL) g_arms[i].armed = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_arm_lock, old);
    return tr;
}

/* Called from cfp_instr_on_image_load after the shim has been
 * successfully copied into `pid`'s user AS at `user_base`. Returns
 * TRUE if a pending arm existed for that PID so the caller can
 * queue the IC-install work item next. */
static BOOLEAN
cfp_instr_record_shim_base(HANDLE pid, PVOID user_base)
{
    KIRQL old;
    BOOLEAN pending = FALSE;
    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid) {
            g_arms[i].shim_user_base = user_base;
            g_arms[i].shim_mapped    = TRUE;
            pending = !g_arms[i].armed;
            break;
        }
    }
    KeReleaseSpinLock(&g_arm_lock, old);
    return pending;
}

/* TRUE once cfp_instr_record_shim_base has already fired for this
 * PID, so the image-load notify can skip a redundant inject on
 * subsequent image loads. */
static BOOLEAN
cfp_instr_shim_mapped(HANDLE pid)
{
    KIRQL old;
    BOOLEAN mapped = FALSE;
    KeAcquireSpinLock(&g_arm_lock, &old);
    for (ULONG i = 0; i < g_arm_count; ++i) {
        if (g_arms[i].pid == pid) {
            mapped = g_arms[i].shim_mapped;
            break;
        }
    }
    KeReleaseSpinLock(&g_arm_lock, old);
    return mapped;
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

/* -------- shim-image store (launcher → driver) -------- */

/* Duplicate `bytes` into our own paged pool and publish atomically.
 * Any previous image is freed under the lock so a reader that
 * snapshotted the old pointer continues to see the old bytes only
 * for the length of its own critical section. Bounded to
 * CFP_SHIM_MAX_BYTES by the IOCTL dispatcher. */
NTSTATUS
cfp_instr_set_shim_image(PVOID bytes, ULONG len)
{
    PAGED_CODE();

    if (!bytes || len == 0 || len > CFP_SHIM_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Allocate OUTSIDE the lock — pool allocs at PASSIVE_LEVEL cannot
     * run while holding a spin lock. The lock covers only the
     * publish-and-free step. */
    ULONG tag_at_alloc = CFP_TAG;
    PVOID copy = ExAllocatePool2(POOL_FLAG_PAGED, len, tag_at_alloc);
    if (!copy) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(copy, bytes, len);

    KIRQL old;
    KeAcquireSpinLock(&g_shim_lock, &old);
    PVOID prev_bytes = g_shim_bytes;
    ULONG prev_len   = g_shim_len;
    ULONG prev_tag   = g_shim_tag;
    g_shim_bytes = copy;
    g_shim_len   = len;
    g_shim_tag   = tag_at_alloc;
    KeReleaseSpinLock(&g_shim_lock, old);

    if (prev_bytes) {
        RtlSecureZeroMemory(prev_bytes, prev_len);
        ExFreePoolWithTag(prev_bytes,
                          prev_tag ? prev_tag : tag_at_alloc);
    }
    return STATUS_SUCCESS;
}

void
cfp_instr_clear_shim_image(void)
{
    PAGED_CODE();

    KIRQL old;
    KeAcquireSpinLock(&g_shim_lock, &old);
    PVOID prev_bytes = g_shim_bytes;
    ULONG prev_len   = g_shim_len;
    ULONG prev_tag   = g_shim_tag;
    g_shim_bytes = NULL;
    g_shim_len   = 0;
    g_shim_tag   = 0;
    KeReleaseSpinLock(&g_shim_lock, old);

    if (prev_bytes) {
        RtlSecureZeroMemory(prev_bytes, prev_len);
        ExFreePoolWithTag(prev_bytes,
                          prev_tag ? prev_tag : g_cfp_pool_tag);
    }
}

/* Snapshot the current shim buffer under the lock. The caller owns
 * nothing — the buffer stays live as long as no concurrent
 * cfp_instr_set_shim_image / clear runs. On the image-load notify
 * path this is safe because the shim-store writer runs only from
 * IOCTL dispatch, and IOCTL paths never re-enter the image-load
 * notify path. Returns FALSE when no shim has been pushed. */
static BOOLEAN
cfp_instr_shim_snapshot(PVOID *out_bytes, PULONG out_len)
{
    KIRQL old;
    BOOLEAN have = FALSE;
    KeAcquireSpinLock(&g_shim_lock, &old);
    if (g_shim_bytes && g_shim_len > 0) {
        *out_bytes = g_shim_bytes;
        *out_len   = g_shim_len;
        have = TRUE;
    }
    KeReleaseSpinLock(&g_shim_lock, old);
    return have;
}

/* -------- image-load notify + shim injection -------- */

/* Inject the stored shim bytes into `target`'s user AS. On success
 * returns STATUS_SUCCESS and writes the per-process base VA into
 * `*out_base`. The caller then stores that base via
 * cfp_instr_record_shim_base so cfp_instr_take_pending's RVA
 * resolution works. Must be called at PASSIVE_LEVEL (the image-load
 * notify always fires there). */
static NTSTATUS
cfp_instr_inject_shim(PEPROCESS target, PVOID *out_base)
{
    PAGED_CODE();

    *out_base = NULL;

    PVOID src = NULL;
    ULONG src_len = 0;
    if (!cfp_instr_shim_snapshot(&src, &src_len)) {
        return STATUS_NOT_FOUND;
    }

    KAPC_STATE apc;
    KeStackAttachProcess(target, &apc);

    /* Reserve + commit a page-aligned region sized to the shim. The
     * allocator rounds up to PAGE_SIZE; the resulting base is a
     * stable user VA for the attached process. The region is
     * created PAGE_EXECUTE_READWRITE so the copy succeeds and the IC
     * trampoline is executable on syscall return without a separate
     * protect step (ZwProtectVirtualMemory is not reliably exported
     * across every WDK the fp driver has to build against). A later
     * hardening pass can split code and data pages and demote the
     * data page to PAGE_READWRITE once the shim's user-mode loader
     * owns its own protect dance. */
    PVOID base = NULL;
    SIZE_T region = src_len;
    NTSTATUS status = ZwAllocateVirtualMemory(ZwCurrentProcess(),
                                              &base, 0, &region,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apc);
        return status;
    }

    /* Copy inside a __try so a race with the process tearing down
     * cannot bugcheck the driver. */
    __try {
        RtlCopyMemory(base, src, src_len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SIZE_T zero = 0;
        (void)ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &zero,
                                  MEM_RELEASE);
        KeUnstackDetachProcess(&apc);
        return STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&apc);

    *out_base = base;
    return STATUS_SUCCESS;
}

/* PsSetLoadImageNotifyRoutine callback. Fires at PASSIVE_LEVEL on
 * every image load system-wide, so the hot path has to short-circuit
 * fast for non-targets. Flow for a target PID:
 *   1. Skip if PID is not on the spoof list.
 *   2. Skip if the shim has already been mapped into this PID (we
 *      only need the FIRST qualifying image load).
 *   3. PsLookupProcessByProcessId + cfp_instr_inject_shim.
 *   4. Record the new base via cfp_instr_record_shim_base.
 *   5. Queue the IC-install work item so NtSetInformationProcess
 *      runs at PASSIVE_LEVEL (we are already PASSIVE here but the
 *      work-item path matches the create-notify queueing style and
 *      avoids any PASSIVE-vs-APC re-entry concerns from paired
 *      image-load notifies for the same PID).
 */
static VOID
cfp_instr_on_image_load(PUNICODE_STRING full_image_name,
                        HANDLE pid,
                        PIMAGE_INFO image_info)
{
    UNREFERENCED_PARAMETER(full_image_name);
    UNREFERENCED_PARAMETER(image_info);

    PAGED_CODE();

    if (!pid) return;
    /* Kernel-mode image loads carry SystemModeImage=0 but pid=0
     * (SYSTEM) so the pid guard above also filters most of them. */
    if (!cfp_target_contains(pid)) return;
    if (cfp_instr_shim_mapped(pid)) return;

    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &target);
    if (!NT_SUCCESS(status)) return;

    PVOID user_base = NULL;
    status = cfp_instr_inject_shim(target, &user_base);
    ObDereferenceObject(target);
    if (!NT_SUCCESS(status) || !user_base) return;

    BOOLEAN pending = cfp_instr_record_shim_base(pid, user_base);
    if (!pending || !g_notify_device) return;

    /* Queue the IC-install work item with the resolved VA. */
    PVOID tr = cfp_instr_take_pending(pid);
    if (!tr) return;

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
    IoQueueWorkItem(w->work, cfp_instr_work_routine,
                    DelayedWorkQueue, w);
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

    /* Register the image-load notify: without it, a shim-based arm
     * stays pending forever because the per-process mapping never
     * runs. A failure here is non-fatal (the create-notify still
     * covers the legacy absolute-VA path) but the RVA path will not
     * fire — log at _WARN. */
    status = PsSetLoadImageNotifyRoutine(cfp_instr_on_image_load);
    if (NT_SUCCESS(status)) {
        g_load_image_notify_registered = TRUE;
    } else {
        CHAMBER_LOG_WARN("cfp: PsSetLoadImageNotifyRoutine failed 0x%08x; "
                         "shim-based IC arming will not fire\n", status);
    }
    return STATUS_SUCCESS;
}

void
cfp_instr_unregister(void)
{
    /* Deregister in reverse order of registration. PsRemove*
     * synchronizes with any in-flight callback so no callback will
     * observe freed state after return. */
    if (g_load_image_notify_registered) {
        (void)PsRemoveLoadImageNotifyRoutine(cfp_instr_on_image_load);
        g_load_image_notify_registered = FALSE;
    }
    if (g_notify_registered) {
        PsSetCreateProcessNotifyRoutineEx(cfp_create_notify, TRUE);
        g_notify_registered = FALSE;
    }
    g_notify_device = NULL;

    /* Release the stored shim bytes. Unlike the per-process mapping
     * (which the dying target's AS teardown reclaims automatically),
     * the shared paged-pool copy is driver-owned and has to be
     * freed on driver unload. */
    cfp_instr_clear_shim_image();
}
