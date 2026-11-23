/* dump_trigger.c -- passive triggers for operator-driven dumps.
 *
 * Trigger kinds (all NPT-only or operator-initiated; no breakpoint,
 * page-guard, DR write, inline hook or SSDT touch):
 *
 *   MANUAL           Immediate dump via IOCTL.
 *   PAYLOAD          Same as MANUAL; distinct kind so the history ring
 *                    records what tripped the capture.
 *   WX               NPT-unmap each page covering the target's user
 *                    address space. First execute on the page faults;
 *                    the handler re-maps and fires a dump.
 *   OEP              NPT-unmap the one PDE covering a suspected OEP
 *                    GVA. First access there fires a dump.
 *   WRITE_THRESHOLD  NPT-unmap writable user pages; each write adds
 *                    to a per-target counter and crossing the
 *                    operator-supplied threshold fires a dump.
 *
 * Fault classification uses AMD APM Vol 2 Table 15-8 (NPF exit_info_1):
 *
 *   bit 0  P      present violation (always 1 for a cleared PDE)
 *   bit 1  W/R    1 = write, 0 = read
 *   bit 2  U/S    1 = user, 0 = supervisor
 *   bit 3  RSV    reserved bit set in the page tables
 *   bit 4  ID     1 = instruction fetch
 *   bit 32 GPA    set by the HV for nested faults vs guest faults
 *
 * NPT edits in this module use npt_map_page from npt.h (unchanged
 * for Wave 6). npt_map_page writes a fresh 2 MB leaf with the
 * supplied low-12-bit flags; passing flags=0 leaves the PDE marked
 * not-present (bit 0 clear) so the next access NPFs. Deliberately
 * NOT npt_hide_range, which stores the GPA in the HV-introspection
 * hide side table and would cause handle_npf to inject #PF.
 *
 * A follow-up pass in npt.c that exposed per-permission edits (just
 * W, just X) would let WX and WRITE_THRESHOLD trap only the
 * intended access class; today they consult exit_info_1 to decide
 * whether the fault is the one the trigger cared about and
 * transparently re-map and retry otherwise.
 */

/* dump_trigger.c is textually included from the tail of dump.c (see
 * the composition note in dump.c). The kernel API prototypes and
 * MemoryBasicInformation enum are declared once in dump.c's prologue
 * and inherit into this file; redeclaring them here would create
 * duplicate-signature conflicts in the composed translation unit. */
#include "npt.h"
#include "dump_trigger.h"

/* --- Trigger state ------------------------------------------------- */

/* Each armed trigger owns a 2 MB-aligned GPA set (the host-physical
 * frames covering the target's user pages at arm time). The set is
 * scanned on every NPF; small-N linear scan is fine for the common
 * case of a single-digit number of armed triggers each covering a
 * few hundred 2 MB regions. */
#define TRIGGER_MAX_GPAS   2048
#define TRIGGER_MAX_ARMED  16

typedef struct _TRIGGER_STATE {
    BOOLEAN       in_use;
    ULONG         kind;             /* CHAMBER_TRIGGER_* */
    ULONGLONG     target_pid;
    ULONGLONG     target_cr3;       /* captured at arm time */
    PEPROCESS     target_eprocess;  /* referenced; released on disarm */
    PEPROCESS     operator_eprocess;/* who owns output_va; referenced */

    /* Operator output sink. The kernel keeps the VA and probes it
     * only inside the dump path. */
    ULONGLONG     output_va;
    ULONGLONG     output_size;

    /* WX / OEP / WRITE_THRESHOLD extras. */
    ULONGLONG     oep_gva;          /* OEP only */
    ULONGLONG     threshold_bytes;  /* WRITE_THRESHOLD only */
    volatile LONG64 write_counter;  /* WRITE_THRESHOLD only */

    BOOLEAN       rearm;

    /* 2 MB GPA set. Each entry carries the hidden flag so a later
     * disarm can skip already-restored regions. */
    struct {
        ULONGLONG gpa_2mb;
        ULONGLONG original_hpa;  /* for npt_map_page restore */
        volatile LONG consumed;  /* trigger already fired on this GPA */
    } gpas[TRIGGER_MAX_GPAS];
    ULONG         gpa_count;

    /* Deferred fire plumbing. The NPF handler runs at DISPATCH_LEVEL
     * and cannot KeStackAttachProcess; it stashes the fault GPA on
     * the slot and queues the slot's WORK_QUEUE_ITEM, which runs the
     * dump at PASSIVE_LEVEL. fire_in_progress is a 0/1 cmpxchg gate
     * so a burst of NPFs on the same slot queues at most one work
     * item. The work item lives inline in the slot; the backing
     * pool is freed by dump_trigger_shutdown. */
    WORK_QUEUE_ITEM fire_work_item;
    volatile LONG fire_in_progress;
    volatile LONGLONG fire_gpa;
    volatile LONG fire_disarm_after;
    volatile LONG fire_rearm_after;
    ULONG         fire_kind_snapshot;
} TRIGGER_STATE;

static TRIGGER_STATE *g_triggers = NULL;
static KSPIN_LOCK     g_trigger_lock;
static BOOLEAN        g_trigger_init = FALSE;

/* Outstanding work-item counter; incremented when a WORK_QUEUE_ITEM
 * is queued and decremented when the worker returns. dump_trigger_shutdown
 * uses it to wait for stragglers before freeing the trigger pool. */
static volatile LONG g_trigger_outstanding = 0;

/* --- Lifecycle ----------------------------------------------------- */

static WORKER_THREAD_ROUTINE trigger_fire_worker;

NTSTATUS dump_trigger_init(void)
{
    if (g_trigger_init) return STATUS_SUCCESS;

    g_triggers = (TRIGGER_STATE *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(TRIGGER_STATE) * TRIGGER_MAX_ARMED,
        POOLTAG("dump_trig"));
    if (!g_triggers) return STATUS_INSUFFICIENT_RESOURCES;

    KeInitializeSpinLock(&g_trigger_lock);
    g_trigger_outstanding = 0;
    g_trigger_init = TRUE;
    return STATUS_SUCCESS;
}

static void trigger_reset_slot_locked(TRIGGER_STATE *t);

void dump_trigger_shutdown(void)
{
    ULONG i;
    KIRQL irql;
    ULONG waits = 0;

    if (!g_trigger_init) return;

    KeAcquireSpinLock(&g_trigger_lock, &irql);
    for (i = 0; i < TRIGGER_MAX_ARMED; i++) {
        if (g_triggers[i].in_use) {
            trigger_reset_slot_locked(&g_triggers[i]);
        }
    }
    KeReleaseSpinLock(&g_trigger_lock, irql);

    /* Wait for any in-flight workers to return before freeing the
     * trigger pool. Cap the wait at ~5 s so a wedged worker can't
     * block unload indefinitely. */
    while (InterlockedCompareExchange(&g_trigger_outstanding, 0, 0) > 0
           && waits < 5000) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000LL; /* 1 ms */
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        waits++;
    }

    ExFreePoolWithTag(g_triggers, POOLTAG("dump_trig"));
    g_triggers = NULL;
    g_trigger_init = FALSE;
}

/* --- Slot management ---------------------------------------------- */

/* Find an in-use slot by PID + kind. Returns NULL if none; the caller
 * must hold g_trigger_lock. */
static TRIGGER_STATE *trigger_find_locked(ULONGLONG pid, ULONG kind)
{
    ULONG i;
    for (i = 0; i < TRIGGER_MAX_ARMED; i++) {
        if (g_triggers[i].in_use &&
            g_triggers[i].target_pid == pid &&
            g_triggers[i].kind == kind) {
            return &g_triggers[i];
        }
    }
    return NULL;
}

static TRIGGER_STATE *trigger_find_by_gpa_locked(ULONGLONG gpa_2mb,
                                                  ULONG     *gpa_idx_out)
{
    ULONG i, j;
    for (i = 0; i < TRIGGER_MAX_ARMED; i++) {
        if (!g_triggers[i].in_use) continue;
        for (j = 0; j < g_triggers[i].gpa_count; j++) {
            if (g_triggers[i].gpas[j].gpa_2mb == gpa_2mb) {
                if (gpa_idx_out) *gpa_idx_out = j;
                return &g_triggers[i];
            }
        }
    }
    return NULL;
}

static TRIGGER_STATE *trigger_alloc_slot_locked(void)
{
    ULONG i;
    for (i = 0; i < TRIGGER_MAX_ARMED; i++) {
        if (!g_triggers[i].in_use) {
            RtlZeroMemory(&g_triggers[i], sizeof(TRIGGER_STATE));
            g_triggers[i].in_use = TRUE;
            return &g_triggers[i];
        }
    }
    return NULL;
}

/* Restore every GPA this trigger hid and release its EPROCESS refs. */
static void trigger_reset_slot_locked(TRIGGER_STATE *t)
{
    ULONG i;
    if (!t) return;

    for (i = 0; i < t->gpa_count; i++) {
        /* Restore the identity leaf. The prior hpa is just the gpa
         * since the NPT is an identity map (see npt_init). */
        (void)npt_map_page(t->gpas[i].gpa_2mb,
                           t->gpas[i].gpa_2mb,
                           NPT_PRESENT | NPT_WRITABLE | NPT_USER);
    }

    if (t->target_eprocess) {
        ObDereferenceObject(t->target_eprocess);
        t->target_eprocess = NULL;
    }
    if (t->operator_eprocess) {
        ObDereferenceObject(t->operator_eprocess);
        t->operator_eprocess = NULL;
    }

    RtlZeroMemory(t, sizeof(*t));
}

/* --- NPT marking helpers ------------------------------------------ */

/* Collect every 2 MB GPA that currently backs a committed user page in
 * the target's AS. Attaches to the target for ZwQueryVirtualMemory
 * and MmGetPhysicalAddress. Bounded by TRIGGER_MAX_GPAS; returns the
 * count stored into t->gpas[]. */
static NTSTATUS trigger_collect_gpas(TRIGGER_STATE *t,
                                      PEPROCESS      target,
                                      BOOLEAN        writable_only,
                                      ULONGLONG      only_gva /* 0 = all */)
{
    KAPC_STATE apc;
    ULONG_PTR va = 0;
    const ULONG_PTR user_limit = 0x00007FFFFFFEFFFFULL;
    struct _MBI {
        PVOID     BaseAddress;
        PVOID     AllocationBase;
        ULONG     AllocationProtect;
        ULONG     __pad0;
        SIZE_T    RegionSize;
        ULONG     State;
        ULONG     Protect;
        ULONG     Type;
        ULONG     __pad1;
    } mbi;
    SIZE_T   ret_len;
    NTSTATUS st;
    ULONGLONG last_recorded_pde = (ULONGLONG)-1;

    t->gpa_count = 0;

    while (va < user_limit && t->gpa_count < TRIGGER_MAX_GPAS) {
        KeStackAttachProcess(target, &apc);
        RtlZeroMemory(&mbi, sizeof(mbi));
        st = ZwQueryVirtualMemory((HANDLE)(LONG_PTR)-1,
                                   (PVOID)va,
                                   MemoryBasicInformation,
                                   &mbi,
                                   sizeof(mbi),
                                   &ret_len);
        KeUnstackDetachProcess(&apc);

        if (!NT_SUCCESS(st)) break;
        if (mbi.RegionSize == 0) break;

        if (mbi.State == 0x1000 /* MEM_COMMIT */) {
            BOOLEAN keep = TRUE;
            if (writable_only) {
                /* Protection bits (winnt): PAGE_READWRITE 0x04,
                 * PAGE_WRITECOPY 0x08, PAGE_EXECUTE_READWRITE 0x40,
                 * PAGE_EXECUTE_WRITECOPY 0x80. */
                ULONG w = mbi.Protect & 0xCC;
                if (w == 0) keep = FALSE;
            }
            if (only_gva) {
                ULONGLONG rb = (ULONGLONG)(ULONG_PTR)mbi.BaseAddress;
                ULONGLONG re = rb + (ULONGLONG)mbi.RegionSize;
                if (only_gva < rb || only_gva >= re) keep = FALSE;
            }
            if (keep) {
                ULONG_PTR p;
                ULONG_PTR start = (ULONG_PTR)mbi.BaseAddress;
                ULONG_PTR end   = start + mbi.RegionSize;
                if (only_gva) {
                    /* Collapse to a single page covering the OEP. */
                    start = (ULONG_PTR)only_gva;
                    end   = start + PAGE_SIZE;
                }
                for (p = start; p < end; p += PAGE_SIZE) {
                    PHYSICAL_ADDRESS pa;
                    ULONGLONG pde_base;

                    KeStackAttachProcess(target, &apc);
                    pa = MmGetPhysicalAddress((PVOID)p);
                    KeUnstackDetachProcess(&apc);

                    if (pa.QuadPart == 0) continue;

                    pde_base = (ULONGLONG)pa.QuadPart & ~(NPT_PAGE_SIZE_2MB - 1);
                    if (pde_base == last_recorded_pde) continue;
                    last_recorded_pde = pde_base;

                    if (t->gpa_count >= TRIGGER_MAX_GPAS) break;
                    t->gpas[t->gpa_count].gpa_2mb      = pde_base;
                    t->gpas[t->gpa_count].original_hpa = pde_base;
                    t->gpas[t->gpa_count].consumed     = 0;
                    t->gpa_count++;
                }
            }
        }

        if ((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize <= va) break;
        va = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    }

    return (t->gpa_count > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* Flip every per-CPU VMCB's TLB_CONTROL_FLUSH_GUEST so the hide pass
 * takes effect without waiting for natural TLB eviction. Nothing in
 * this call races the running guest in a harmful way: tlb_control is
 * a single-byte field (see npt.c comment) and a doubled flush on one
 * CPU is a no-op. */
static void trigger_broadcast_tlb_flush(void)
{
    ULONG i;
    if (!g_cpu_ctx) return;
    for (i = 0; i < g_cpu_count; i++) {
        VMCB *v = (VMCB *)g_cpu_ctx[i].vmcb_va;
        if (v) npt_tlb_flush(v);
    }
}

/* Clear every GPA collected into t->gpas by rewriting its PDE with no
 * permission bits. The next access NPFs and our dump_trigger_on_npf
 * handler finds the slot and classifies the fault. We don't call
 * npt_hide_range here because that would stash the GPA in npt.c's
 * introspection-hide side table -- handle_npf would then take the
 * HV-image path (inject #PF) instead of handing the fault to us. */
static void trigger_install_npt_hides(TRIGGER_STATE *t)
{
    ULONG i;
    for (i = 0; i < t->gpa_count; i++) {
        /* flags=0 => PDE carries PS (set unconditionally by npt_map_page)
         * but no P/W/U, so the next access takes an NPF. */
        (void)npt_map_page(t->gpas[i].gpa_2mb,
                           t->gpas[i].gpa_2mb,
                           0);
    }
    trigger_broadcast_tlb_flush();
}

/* --- Arm paths ----------------------------------------------------- */

static NTSTATUS trigger_arm_common(ULONG kind,
                                    ULONGLONG target_pid,
                                    ULONGLONG oep_gva,
                                    ULONGLONG threshold,
                                    PVOID     out_va,
                                    ULONGLONG out_size,
                                    BOOLEAN   rearm)
{
    PEPROCESS target = NULL;
    PEPROCESS oper = NULL;
    NTSTATUS  st;
    TRIGGER_STATE *t;
    KIRQL irql;
    BOOLEAN writable_only = (kind == CHAMBER_TRIGGER_WRITE_THRESHOLD);
    ULONGLONG only_gva = (kind == CHAMBER_TRIGGER_OEP) ? oep_gva : 0;
    ULONGLONG target_cr3;
    KAPC_STATE apc;

    if (!g_trigger_init) return STATUS_INVALID_DEVICE_STATE;
    if (target_pid == 0) return STATUS_INVALID_PARAMETER;
    if (!out_va || out_size == 0) return STATUS_INVALID_PARAMETER;

    st = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)target_pid, &target);
    if (!NT_SUCCESS(st) || !target) return STATUS_INVALID_CID;

    /* Capture the operator process. Arm IOCTLs always come in through
     * the IRP dispatcher at IRP_MJ_DEVICE_CONTROL which runs in the
     * calling thread's context, so PsGetCurrentProcess is the
     * operator. A reference holds the EPROCESS alive until disarm so
     * a delayed trigger fire can still attach for the write. */
    oper = PsGetCurrentProcess();
    if (oper) ObReferenceObject(oper);

    KeStackAttachProcess(target, &apc);
    target_cr3 = __readcr3() & ~0xFFFULL;
    KeUnstackDetachProcess(&apc);

    KeAcquireSpinLock(&g_trigger_lock, &irql);
    {
        TRIGGER_STATE *existing = trigger_find_locked(target_pid, kind);
        if (existing) {
            trigger_reset_slot_locked(existing);
        }
        t = trigger_alloc_slot_locked();
    }
    KeReleaseSpinLock(&g_trigger_lock, irql);

    if (!t) {
        ObDereferenceObject(target);
        if (oper) ObDereferenceObject(oper);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    t->kind              = kind;
    t->target_pid        = target_pid;
    t->target_cr3        = target_cr3;
    t->target_eprocess   = target;  /* ownership transferred */
    t->operator_eprocess = oper;    /* ownership transferred */
    t->output_va         = (ULONGLONG)(ULONG_PTR)out_va;
    t->output_size       = out_size;
    t->oep_gva           = oep_gva;
    t->threshold_bytes   = threshold;
    t->write_counter     = 0;
    t->rearm             = rearm;

    st = trigger_collect_gpas(t, target, writable_only, only_gva);
    if (!NT_SUCCESS(st)) {
        KeAcquireSpinLock(&g_trigger_lock, &irql);
        trigger_reset_slot_locked(t);
        KeReleaseSpinLock(&g_trigger_lock, irql);
        return st;
    }

    trigger_install_npt_hides(t);
    return STATUS_SUCCESS;
}

NTSTATUS dump_trigger_arm_wx(ULONGLONG target_pid,
                              PVOID     output_buffer_va,
                              ULONGLONG output_buffer_size,
                              BOOLEAN   rearm)
{
    return trigger_arm_common(CHAMBER_TRIGGER_WX,
                              target_pid,
                              0,
                              0,
                              output_buffer_va,
                              output_buffer_size,
                              rearm);
}

NTSTATUS dump_trigger_arm_oep(ULONGLONG target_pid,
                               ULONGLONG suspected_oep_gva,
                               PVOID     output_buffer_va,
                               ULONGLONG output_buffer_size,
                               BOOLEAN   rearm)
{
    if (suspected_oep_gva == 0) return STATUS_INVALID_PARAMETER;
    return trigger_arm_common(CHAMBER_TRIGGER_OEP,
                              target_pid,
                              suspected_oep_gva,
                              0,
                              output_buffer_va,
                              output_buffer_size,
                              rearm);
}

NTSTATUS dump_trigger_arm_write_threshold(ULONGLONG target_pid,
                                           ULONGLONG threshold_bytes,
                                           PVOID     output_buffer_va,
                                           ULONGLONG output_buffer_size,
                                           BOOLEAN   rearm)
{
    if (threshold_bytes == 0) return STATUS_INVALID_PARAMETER;
    return trigger_arm_common(CHAMBER_TRIGGER_WRITE_THRESHOLD,
                              target_pid,
                              0,
                              threshold_bytes,
                              output_buffer_va,
                              output_buffer_size,
                              rearm);
}

/* --- Manual / payload --------------------------------------------- */

static ULONGLONG trigger_manual_like(ULONGLONG kind,
                                      ULONGLONG target_pid,
                                      PVOID     kernel_buf,
                                      ULONGLONG cap)
{
    return dump_run_targeted(target_pid,
                              kernel_buf,
                              cap,
                              (ULONG)kind,
                              0,
                              NULL,
                              NULL);
}

ULONGLONG dump_trigger_manual(ULONGLONG target_pid,
                               PVOID     kernel_output_buf,
                               ULONGLONG output_capacity)
{
    return trigger_manual_like(CHAMBER_TRIGGER_MANUAL,
                               target_pid, kernel_output_buf, output_capacity);
}

ULONGLONG dump_trigger_payload(ULONGLONG target_pid,
                                PVOID     kernel_output_buf,
                                ULONGLONG output_capacity)
{
    return trigger_manual_like(CHAMBER_TRIGGER_PAYLOAD,
                               target_pid, kernel_output_buf, output_capacity);
}

/* --- Disarm -------------------------------------------------------- */

NTSTATUS dump_trigger_disarm(ULONGLONG target_pid, ULONG trigger_mask)
{
    ULONG i;
    KIRQL irql;
    BOOLEAN any = FALSE;
    ULONG mask = trigger_mask ? trigger_mask : CHAMBER_TRIGGER_ANY;

    if (!g_trigger_init) return STATUS_INVALID_DEVICE_STATE;

    KeAcquireSpinLock(&g_trigger_lock, &irql);
    for (i = 0; i < TRIGGER_MAX_ARMED; i++) {
        if (!g_triggers[i].in_use) continue;
        if (target_pid != 0 && g_triggers[i].target_pid != target_pid)
            continue;
        if ((g_triggers[i].kind & mask) == 0) continue;
        trigger_reset_slot_locked(&g_triggers[i]);
        any = TRUE;
    }
    KeReleaseSpinLock(&g_trigger_lock, irql);

    trigger_broadcast_tlb_flush();
    return any ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* --- NPF handling ------------------------------------------------- */

/* PASSIVE_LEVEL worker that services one pending fire. The NPF handler
 * raised the fire_in_progress flag and queued this routine; we clear
 * fire_in_progress on exit. The trigger slot may already be
 * disarm_after'd under the spin lock; in that case we still do the
 * dump (the operator asked for it) and then free the slot. */
static VOID trigger_fire_worker(PVOID Context)
{
    TRIGGER_STATE *t = (TRIGGER_STATE *)Context;
    ULONGLONG     cr3 = 0;
    ULONG         parked = 0;
    ULONGLONG     bytes = 0;
    ULONGLONG     fault_gpa;
    ULONG         kind_at_fire;
    ULONGLONG     target_pid;
    ULONGLONG     output_va;
    ULONGLONG     output_size;
    BOOLEAN       disarm_after;
    BOOLEAN       rearm_after;
    KIRQL         irql;

    if (!t) return;

    /* Snapshot the fire parameters under the lock so a concurrent
     * disarm cannot rug-pull them mid-dump. */
    KeAcquireSpinLock(&g_trigger_lock, &irql);
    if (!t->in_use) {
        KeReleaseSpinLock(&g_trigger_lock, irql);
        InterlockedExchange(&t->fire_in_progress, 0);
        InterlockedDecrement(&g_trigger_outstanding);
        return;
    }
    fault_gpa    = (ULONGLONG)InterlockedCompareExchange64(
                        (volatile LONG64 *)&t->fire_gpa, 0, 0);
    kind_at_fire = t->fire_kind_snapshot;
    target_pid   = t->target_pid;
    output_va    = t->output_va;
    output_size  = t->output_size;
    disarm_after = (BOOLEAN)InterlockedCompareExchange(
                        &t->fire_disarm_after, 0, 0);
    rearm_after  = (BOOLEAN)InterlockedCompareExchange(
                        &t->fire_rearm_after, 0, 0);

    /* Operator EPROCESS is held referenced across the slot's lifetime;
     * the worker reads it under the lock so a concurrent disarm
     * cannot dereference it mid-write. */
    {
        PEPROCESS oper = t->operator_eprocess;
        KeReleaseSpinLock(&g_trigger_lock, irql);

        bytes = dump_run_targeted_ex(target_pid,
                                      oper,
                                      (PVOID)(ULONG_PTR)output_va,
                                      output_size,
                                      kind_at_fire,
                                      fault_gpa,
                                      TRUE,     /* output_is_user */
                                      &cr3,
                                      &parked);
        (void)bytes;
    }

    /* Post-fire bookkeeping. */
    KeAcquireSpinLock(&g_trigger_lock, &irql);
    if (t->in_use && t->kind == kind_at_fire) {
        if (disarm_after) {
            trigger_reset_slot_locked(t);
        } else if (rearm_after) {
            ULONG i;
            for (i = 0; i < t->gpa_count; i++) {
                if (t->kind == CHAMBER_TRIGGER_WX &&
                    InterlockedCompareExchange(
                        &t->gpas[i].consumed, 0, 0)) {
                    continue;
                }
                (void)npt_map_page(t->gpas[i].gpa_2mb,
                                   t->gpas[i].gpa_2mb,
                                   0);
            }
        }
    }
    KeReleaseSpinLock(&g_trigger_lock, irql);

    trigger_broadcast_tlb_flush();

    InterlockedExchange(&t->fire_in_progress, 0);
    InterlockedDecrement(&g_trigger_outstanding);
}

/* Called from vmexit.c handle_npf at the caller's current IRQL (as
 * high as DISPATCH_LEVEL on the VMEXIT path). Returns TRUE if the
 * GPA belonged to a trigger (fault handled by remapping; the caller
 * must NOT advance RIP). Returns FALSE if the fault is not ours.
 *
 * On a matching fault:
 *   1. Re-map the PDE with full P|W|U via npt_map_page so the
 *      instruction retry completes.
 *   2. Classify the access via fault_info bits.
 *   3. If the classification matches the trigger kind, stash the
 *      fire context on the slot and queue the slot's work item.
 *      The dump itself runs at PASSIVE_LEVEL via the worker.
 */
BOOLEAN dump_trigger_on_npf(VMCB *vmcb, ULONGLONG fault_gpa,
                             ULONGLONG fault_info)
{
    ULONGLONG gpa_2mb;
    TRIGGER_STATE *t;
    ULONG gpa_idx = 0;
    KIRQL irql;
    BOOLEAN is_write;
    BOOLEAN is_exec;
    ULONG kind;
    BOOLEAN fire_this_access = FALSE;
    ULONGLONG threshold = 0;
    LONG64 counter_after = 0;
    ULONGLONG write_add = 0;
    BOOLEAN queued = FALSE;

    UNREFERENCED_PARAMETER(vmcb);

    if (!g_trigger_init) return FALSE;

    gpa_2mb = fault_gpa & ~(NPT_PAGE_SIZE_2MB - 1);

    KeAcquireSpinLock(&g_trigger_lock, &irql);
    t = trigger_find_by_gpa_locked(gpa_2mb, &gpa_idx);
    if (!t) {
        KeReleaseSpinLock(&g_trigger_lock, irql);
        return FALSE;
    }
    kind = t->kind;

    /* Always restore the PDE first so the instruction retry can
     * complete without the guest seeing an unhandled NPF. */
    (void)npt_map_page(gpa_2mb, gpa_2mb,
                       NPT_PRESENT | NPT_WRITABLE | NPT_USER);
    InterlockedExchange(&t->gpas[gpa_idx].consumed, 1);

    is_write = (fault_info & (1ULL << 1)) != 0;
    is_exec  = (fault_info & (1ULL << 4)) != 0;

    switch (kind) {
    case CHAMBER_TRIGGER_WX:
        /* The task's intent is to trap on the W->X transition: after
         * a page has been written to, the next execute on it fires
         * the dump. We approximate: an instruction-fetch fault on
         * an armed page fires; a write-only fault is treated as
         * the write leg (just remap, no fire); a read-only fault
         * also remaps silently. */
        if (is_exec) fire_this_access = TRUE;
        break;

    case CHAMBER_TRIGGER_OEP:
        /* OEP trigger fires on any access to the covering PDE; the
         * GVA-level precision is enforced by trigger_collect_gpas
         * narrowing the set to the one covering oep_gva. */
        fire_this_access = TRUE;
        break;

    case CHAMBER_TRIGGER_WRITE_THRESHOLD:
        /* Count writes, not reads. Bump the counter by one page per
         * fault -- byte-accurate counting requires per-byte NPT
         * which is out of scope for the initial landing; comment in
         * dump_trigger.h names the granularity limitation. */
        if (is_write) {
            write_add = PAGE_SIZE;
            counter_after = InterlockedExchangeAdd64(&t->write_counter,
                                                     (LONG64)write_add)
                            + (LONG64)write_add;
            threshold = t->threshold_bytes;
            if ((ULONGLONG)counter_after >= threshold) {
                fire_this_access = TRUE;
            }
        }
        break;

    default:
        break;
    }

    if (fire_this_access) {
        /* One in-flight fire per slot. A second NPF before the
         * worker drains is dropped (the operator sees the first
         * fire's dump; the trigger either disarms or re-hides for
         * the next). */
        if (InterlockedCompareExchange(&t->fire_in_progress, 1, 0) == 0) {
            t->fire_kind_snapshot = kind;
            InterlockedExchange64(
                (volatile LONG64 *)&t->fire_gpa, (LONG64)fault_gpa);
            InterlockedExchange(&t->fire_disarm_after, t->rearm ? 0 : 1);
            InterlockedExchange(&t->fire_rearm_after, t->rearm ? 1 : 0);

            ExInitializeWorkItem(&t->fire_work_item,
                                 trigger_fire_worker, t);
            InterlockedIncrement(&g_trigger_outstanding);
            ExQueueWorkItem(&t->fire_work_item, DelayedWorkQueue);
            queued = TRUE;
        }
    }
    KeReleaseSpinLock(&g_trigger_lock, irql);

    (void)queued;
    return TRUE;
}
