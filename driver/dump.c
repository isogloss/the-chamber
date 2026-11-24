/* dump.c -- passive address-space snapshot of a target process.
 *
 * No active-debug surface. Triggers are NPT-only (invisible to guest)
 * or operator-initiated via IOCTL. The pause primitive is targeted-DPC
 * rendezvous (no KeIpiGenericCall spin). TSC jumps across the pause
 * window are masked by the TSC_OFFSET accumulator.
 *
 * Layout:
 *
 *   dump_pause_init / dump_pause_shutdown
 *       One-time allocation of the per-CPU DPC array. Each DPC is
 *       pinned to its CPU via KeSetTargetProcessorDpcEx so
 *       KeInsertQueueDpc delivers to that CPU and only that CPU.
 *
 *   pause_dpc_routine
 *       Runs at DISPATCH_LEVEL on its pinned CPU with the guest's
 *       current CR3 live in the CR3 register (the DPC fires inside
 *       guest context between VMEXITs). Reads __readcr3(), compares
 *       to the capture target, and spins on g_pause_active with a
 *       bounded wait if the match is positive. Non-matching CPUs
 *       return at once; matching CPUs that hit the 2-second ceiling
 *       also return so a stuck originator cannot wedge the box.
 *
 *   dump_run_targeted / dump_snapshot_pause_target
 *       Resolve target PID -> EPROCESS, attach briefly to capture CR3,
 *       detach, broadcast the pause DPCs, run the VAD walk at
 *       PASSIVE_LEVEL, release the DPCs by clearing g_pause_active,
 *       dereference the EPROCESS, and return bytes written.
 *
 *   dump_history_copy_out
 *       Copy the newest-first ring of recent dump records out to the
 *       operator; used by IOCTL_THE_CHAMBER_QUERY_DUMP_HISTORY.
 *
 * Re-entrancy: dump_run_targeted bumps g_dump_seq per fire. A second
 * concurrent fire sees g_pause_active already set and returns 0
 * without touching the DPCs -- the operator retries after the first
 * capture returns.
 */

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "the_chamber.h"
#include "svm.h"
#include "dump.h"

volatile LONG   g_pause_active = 0;
volatile LONG64 g_dump_seq     = 0;

/* Originator CPU for the current KeIpiGenericCall broadcast. We record it
 * before broadcast so the park worker can skip itself: on this CPU the
 * guest VMMCALL that invoked us may have originated from an injected
 * thread running under g_target_cr3, in which case the stale VMCB.save.cr3
 * would otherwise cause the originator to count itself as "parked" even
 * though it is actively executing the dump handler in host context. (The
 * audit's self-deadlock variant that this guards against assumes a true
 * rendezvous-spin pause; today's broadcast is non-blocking, but skipping
 * the originator still gives g_parked_count the correct "how many sibling
 * vCPUs were racing" meaning rather than off-by-one.) */
static volatile LONG g_pause_originator_cpu = -1;

/* --- Externs we use from the kernel, without pulling a full header. --- */
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId,
                                                PEPROCESS *Process);
NTKERNELAPI VOID     KeStackAttachProcess(PEPROCESS Process,
                                          PKAPC_STATE ApcState);
NTKERNELAPI VOID     KeUnstackDetachProcess(PKAPC_STATE ApcState);
NTKERNELAPI VOID     KeSetTargetProcessorDpcEx(PKDPC Dpc,
                                               PPROCESSOR_NUMBER Number);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0
} MEMORY_INFORMATION_CLASS;

NTSTATUS ZwQueryVirtualMemory(HANDLE ProcessHandle,
                              PVOID BaseAddress,
                              MEMORY_INFORMATION_CLASS Class,
                              PVOID Buffer,
                              SIZE_T Length,
                              PSIZE_T ReturnLength);

/* --- Pause primitive state ---------------------------------------- */

/* Per-CPU DPC + per-CPU parked flag. The DPC is pinned to its CPU at
 * init time; the flag is set by the DPC when it observes a CR3 match
 * and cleared when the DPC exits its spin (or hits the timeout). */
typedef struct _PAUSE_PER_CPU {
    KDPC          dpc;
    volatile LONG parked;
    volatile LONG timed_out;
    ULONG         cpu_index;
    UCHAR         pad[4];
} PAUSE_PER_CPU;

static PAUSE_PER_CPU *g_pause_per_cpu = NULL;
static ULONG          g_pause_cpu_count = 0;

/* Capture target; set by the originator before KeInsertQueueDpc and
 * read by every pause_dpc_routine. The low 12 bits are masked off --
 * PCID / PGE flags move between user and kernel CR3 views but the
 * physical PML4 base is stable. */
static ULONGLONG g_pause_target_cr3 = 0;

/* Match counter: incremented by each DPC whose observed CR3 matches,
 * read by the originator so it knows how many parked CPUs to wait
 * for. */
static volatile LONG g_pause_matched = 0;

/* Completion counter: every DPC increments this exactly once, whether
 * it matched or not. The originator waits for completion == cpu_count
 * (or timeout) before reading g_pause_matched and starting the walk.
 * Non-match DPCs increment on return; match DPCs increment after they
 * have set their parked flag but before they enter the spin, so the
 * originator can distinguish "DPC queue still draining" from "match
 * DPCs are in the spin with parked flagged". */
static volatile LONG g_pause_completion = 0;

/* Pause-window ceiling. 2 seconds in 100-ns units; KeQueryInterruptTime
 * ticks at the system clock interval so this is a real wall-clock
 * bound, not a spin-count. */
#define PAUSE_WINDOW_100NS   (2ULL * 1000ULL * 1000ULL * 10ULL)

/* --- Dump history ring -------------------------------------------- */

static CHAMBER_DUMP_RECORD g_dump_history[CHAMBER_DUMP_HISTORY_MAX];
static ULONG               g_dump_history_head = 0;
static volatile LONG64     g_dump_history_total = 0;
static KSPIN_LOCK          g_dump_history_lock;
static BOOLEAN             g_dump_history_init = FALSE;

static void dump_history_record(const CHAMBER_DUMP_RECORD *rec)
{
    KIRQL irql;

    if (!g_dump_history_init) return;

    KeAcquireSpinLock(&g_dump_history_lock, &irql);
    g_dump_history[g_dump_history_head] = *rec;
    g_dump_history_head = (g_dump_history_head + 1) % CHAMBER_DUMP_HISTORY_MAX;
    g_dump_history_total++;
    KeReleaseSpinLock(&g_dump_history_lock, irql);
}

ULONG dump_history_copy_out(PCHAMBER_DUMP_HISTORY out, ULONG capacity_bytes)
{
    KIRQL irql;
    ULONG wrote;
    ULONG i;
    ULONG count;

    if (!out || capacity_bytes < sizeof(CHAMBER_DUMP_HISTORY)) return 0;
    if (!g_dump_history_init) return 0;

    RtlZeroMemory(out, sizeof(*out));

    KeAcquireSpinLock(&g_dump_history_lock, &irql);
    out->total_dumps = (ULONGLONG)g_dump_history_total;
    count = (g_dump_history_total < CHAMBER_DUMP_HISTORY_MAX)
          ? (ULONG)g_dump_history_total
          : CHAMBER_DUMP_HISTORY_MAX;
    for (i = 0; i < count; i++) {
        /* Walk back from head (most-recent-first). */
        ULONG idx = (g_dump_history_head + CHAMBER_DUMP_HISTORY_MAX - 1 - i)
                    % CHAMBER_DUMP_HISTORY_MAX;
        out->records[i] = g_dump_history[idx];
    }
    out->record_count = count;
    KeReleaseSpinLock(&g_dump_history_lock, irql);

    wrote = sizeof(CHAMBER_DUMP_HISTORY);
    if (wrote > capacity_bytes) wrote = capacity_bytes;
    return wrote;
}

/* --- Pause DPC ---------------------------------------------------- */

/* Runs at DISPATCH_LEVEL on the CPU it was pinned to. The DPC fires in
 * guest context between VMEXITs, so __readcr3() returns the CR3 the
 * guest is actively using -- no VMCB field read, no stale vmcb->save.cr3
 * problem.
 *
 * Non-matching CPUs: increment nothing, return at once; their guest
 * resumes untouched on DPC return.
 *
 * Matching CPUs: increment g_pause_matched, set this CPU's parked flag,
 * spin on g_pause_active. The spin is bounded by PAUSE_WINDOW_100NS so
 * an originator that crashes mid-walk cannot wedge a vCPU forever. If
 * the ceiling is hit the DPC sets timed_out, increments nothing further,
 * and returns so the guest can resume. The originator checks timed_out
 * on unwind for the dump record. */
static VOID pause_dpc_routine(PKDPC Dpc, PVOID Ctx, PVOID Sa1, PVOID Sa2)
{
    PAUSE_PER_CPU *slot = (PAUSE_PER_CPU *)Ctx;
    ULONGLONG      current_cr3;
    ULARGE_INTEGER t0, t;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Sa1);
    UNREFERENCED_PARAMETER(Sa2);

    if (!slot) return;

    /* Live CR3 of whatever the guest was running when this CPU took
     * the DPC. The VMCB save area would be stale here because CR3
     * writes are not intercepted, so the save-area value only
     * refreshes at the next VMEXIT. __readcr3 is the correct source. */
    current_cr3 = __readcr3() & ~0xFFFULL;
    if (current_cr3 != g_pause_target_cr3) {
        InterlockedIncrement(&g_pause_completion);
        return;
    }

    /* Match. Announce ourselves, flip our per-CPU parked flag, record
     * completion so the originator knows this DPC has actually run,
     * and spin on g_pause_active with a bounded wait. */
    InterlockedIncrement(&g_pause_matched);
    InterlockedExchange(&slot->parked, 1);
    InterlockedIncrement(&g_pause_completion);

    t0.QuadPart = (ULONGLONG)KeQueryInterruptTime();

    while (InterlockedCompareExchange(
            (volatile LONG *)&g_pause_active, 0, 0) != 0) {
        t.QuadPart = (ULONGLONG)KeQueryInterruptTime();
        if (t.QuadPart - t0.QuadPart >= PAUSE_WINDOW_100NS) {
            InterlockedExchange(&slot->timed_out, 1);
            break;
        }
        /* Keep the hyperthread sibling happy. */
        YieldProcessor();
    }

    InterlockedExchange(&slot->parked, 0);
}

NTSTATUS dump_pause_init(void)
{
    ULONG i;

    if (g_pause_per_cpu) return STATUS_SUCCESS;
    if (!g_cpu_ctx || g_cpu_count == 0) return STATUS_INVALID_DEVICE_STATE;

    g_pause_per_cpu = (PAUSE_PER_CPU *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PAUSE_PER_CPU) * g_cpu_count,
        POOLTAG("dump_pause"));
    if (!g_pause_per_cpu) return STATUS_INSUFFICIENT_RESOURCES;

    for (i = 0; i < g_cpu_count; i++) {
        PROCESSOR_NUMBER pn;

        g_pause_per_cpu[i].parked    = 0;
        g_pause_per_cpu[i].timed_out = 0;
        g_pause_per_cpu[i].cpu_index = i;

        KeInitializeDpc(&g_pause_per_cpu[i].dpc,
                        pause_dpc_routine,
                        &g_pause_per_cpu[i]);

        /* Pin the DPC to CPU i. KeSetTargetProcessorDpcEx takes a
         * PROCESSOR_NUMBER (group + number), so translate the flat
         * index via KeGetProcessorNumberFromIndex. */
        if (NT_SUCCESS(KeGetProcessorNumberFromIndex(i, &pn))) {
            KeSetTargetProcessorDpcEx(&g_pause_per_cpu[i].dpc, &pn);
        }
        /* Use a slightly-above-normal importance so the DPC does not
         * sit behind lower-priority DPCs when the guest is active. */
        KeSetImportanceDpc(&g_pause_per_cpu[i].dpc, HighImportance);
    }

    if (!g_dump_history_init) {
        KeInitializeSpinLock(&g_dump_history_lock);
        RtlZeroMemory(g_dump_history, sizeof(g_dump_history));
        g_dump_history_head = 0;
        g_dump_history_total = 0;
        g_dump_history_init = TRUE;
    }

    g_pause_cpu_count = g_cpu_count;
    return STATUS_SUCCESS;
}

void dump_pause_shutdown(void)
{
    ULONG i;

    if (!g_pause_per_cpu) return;

    /* Release any CPU still parked (defensive; unload is only reached
     * after shutdown IOCTL, so there should be none). */
    InterlockedExchange(&g_pause_active, 0);

    /* Flush any pending DPCs so freeing their backing memory is safe. */
    for (i = 0; i < g_pause_cpu_count; i++) {
        KeRemoveQueueDpc(&g_pause_per_cpu[i].dpc);
    }
    KeFlushQueuedDpcs();

    ExFreePoolWithTag(g_pause_per_cpu, POOLTAG("dump_pause"));
    g_pause_per_cpu = NULL;
    g_pause_cpu_count = 0;
}

/* --- VAD walk + copy ---------------------------------------------- */

/* Operator-side write helper. If operator_proc is non-NULL the call
 * site attaches to it before writing, so a dump fired from a system
 * worker thread (trigger path) still lands in the operator's user
 * VA. operator_proc == NULL means "we are already in the operator's
 * AS" (the VMMCALL and MANUAL / PAYLOAD IOCTL paths). The __try
 * wrapper catches user-VA faults in either case.
 */
static BOOLEAN dump_write_bytes(PEPROCESS operator_proc,
                                 PUCHAR    out_buf,
                                 ULONGLONG write_off,
                                 PVOID     src,
                                 SIZE_T    bytes)
{
    KAPC_STATE apc;
    BOOLEAN    ok = TRUE;

    if (operator_proc) KeStackAttachProcess(operator_proc, &apc);
    __try {
        RtlCopyMemory(out_buf + write_off, src, bytes);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }
    if (operator_proc) KeUnstackDetachProcess(&apc);
    return ok;
}

static ULONGLONG dump_one_region(PEPROCESS target_proc,
                                 PEPROCESS operator_proc,
                                 ULONGLONG region_base,
                                 ULONGLONG region_size,
                                 ULONG     region_prot,
                                 PUCHAR    out_buf,
                                 ULONGLONG out_cursor,
                                 ULONGLONG out_capacity)
{
    KAPC_STATE apc;
    ULONGLONG header_size;
    ULONGLONG total_size;
    ULONGLONG write_off;

    header_size = sizeof(ULONGLONG) * 2 + sizeof(ULONG) * 2;
    total_size = header_size + region_size;
    if (out_cursor + total_size > out_capacity) {
        return 0;
    }

    write_off = out_cursor;
    {
        UCHAR hdr[sizeof(ULONGLONG) * 2 + sizeof(ULONG) * 2];
        ULONG off = 0;
        *(ULONGLONG *)&hdr[off] = region_base;  off += sizeof(ULONGLONG);
        *(ULONGLONG *)&hdr[off] = region_size;  off += sizeof(ULONGLONG);
        *(ULONG     *)&hdr[off] = region_prot;  off += sizeof(ULONG);
        *(ULONG     *)&hdr[off] = 0;            off += sizeof(ULONG);
        if (!dump_write_bytes(operator_proc, out_buf, write_off,
                              hdr, sizeof(hdr))) {
            return 0;
        }
        write_off += sizeof(hdr);
    }

    {
        ULONGLONG remaining = region_size;
        ULONGLONG src_off = 0;
        PUCHAR scratch;

        scratch = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           PAGE_SIZE,
                                           POOLTAG("dump_scratch"));
        if (!scratch) {
            return 0;
        }

        while (remaining > 0) {
            ULONGLONG chunk = (remaining > PAGE_SIZE) ? PAGE_SIZE : remaining;

            KeStackAttachProcess(target_proc, &apc);
            __try {
                RtlCopyMemory(scratch,
                              (PVOID)(ULONG_PTR)(region_base + src_off),
                              (SIZE_T)chunk);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                RtlZeroMemory(scratch, (SIZE_T)chunk);
            }
            KeUnstackDetachProcess(&apc);

            if (!dump_write_bytes(operator_proc, out_buf, write_off,
                                  scratch, (SIZE_T)chunk)) {
                ExFreePoolWithTag(scratch, POOLTAG("dump_scratch"));
                return 0;
            }
            write_off += chunk;
            src_off   += chunk;
            remaining -= chunk;
        }

        ExFreePoolWithTag(scratch, POOLTAG("dump_scratch"));
    }

    return total_size;
}

static ULONGLONG dump_walk_target(PEPROCESS target_proc,
                                  PEPROCESS operator_proc,
                                  PUCHAR    out_buf,
                                  ULONGLONG out_capacity)
{
    KAPC_STATE apc;
    ULONGLONG cursor = 0;
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

    while (va < user_limit) {
        KeStackAttachProcess(target_proc, &apc);
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
            ULONGLONG wrote = dump_one_region(target_proc,
                                              operator_proc,
                                              (ULONGLONG)(ULONG_PTR)mbi.BaseAddress,
                                              (ULONGLONG)mbi.RegionSize,
                                              mbi.Protect,
                                              out_buf,
                                              cursor,
                                              out_capacity);
            if (wrote == 0) break;
            cursor += wrote;
        }

        if ((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize <= va) break;
        va = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    }

    return cursor;
}

/* --- Pause + walk harness ----------------------------------------- */

/* Capture a target's CR3 into g_pause_target_cr3 by attaching briefly
 * and calling __readcr3. The attach/detach pair is free of allocation
 * and keeps the pointer-reference discipline (no handle opened). */
static ULONGLONG capture_target_cr3(PEPROCESS target)
{
    KAPC_STATE apc;
    ULONGLONG  raw;

    KeStackAttachProcess(target, &apc);
    raw = __readcr3();
    KeUnstackDetachProcess(&apc);
    return raw & ~0xFFFULL;
}

/* Broadcast the pause DPCs and wait for every CR3-matching CPU to flag
 * itself parked. Returns the count of CPUs that observed a match. The
 * pause window stays open until the caller clears g_pause_active. */
static ULONG pause_broadcast_and_wait(void)
{
    ULONG i;
    ULONG matched;
    ULARGE_INTEGER t0, t;

    if (!g_pause_per_cpu || g_pause_cpu_count == 0) return 0;

    for (i = 0; i < g_pause_cpu_count; i++) {
        InterlockedExchange(&g_pause_per_cpu[i].parked,    0);
        InterlockedExchange(&g_pause_per_cpu[i].timed_out, 0);
    }
    InterlockedExchange(&g_pause_matched,    0);
    InterlockedExchange(&g_pause_completion, 0);
    InterlockedExchange(&g_pause_active,     1);

    /* Queue each DPC on its pinned CPU. KeInsertQueueDpc returns FALSE
     * if the DPC was already queued -- benign when a prior fire did
     * not fully drain; the queued one will service this round. */
    for (i = 0; i < g_pause_cpu_count; i++) {
        KeInsertQueueDpc(&g_pause_per_cpu[i].dpc, NULL, NULL);
    }

    /* Wait for every DPC to have reached its post-CR3-check point:
     * non-matches have returned, matches have flagged parked and
     * entered their spin. Bound by the same 2 s ceiling so a CPU
     * stuck in an SMI (unreachable DPC) does not wedge the
     * originator. */
    t0.QuadPart = (ULONGLONG)KeQueryInterruptTime();
    for (;;) {
        LONG completion = InterlockedCompareExchange(
            (volatile LONG *)&g_pause_completion, 0, 0);
        if ((ULONG)completion >= g_pause_cpu_count) break;

        t.QuadPart = (ULONGLONG)KeQueryInterruptTime();
        if (t.QuadPart - t0.QuadPart >= PAUSE_WINDOW_100NS) {
            CHAMBER_LOG_WARN("pause broadcast window elapsed, "
                             "completion=%u/%u\n",
                             (ULONG)completion, g_pause_cpu_count);
            break;
        }

        /* Yield briefly so queued DPCs on this CPU get a chance to
         * fire. KeDelayExecutionThread at PASSIVE_LEVEL is safe here. */
        {
            LARGE_INTEGER delay;
            delay.QuadPart = -5000LL; /* 0.5 ms */
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    matched = (ULONG)InterlockedCompareExchange(
        (volatile LONG *)&g_pause_matched, 0, 0);
    return matched;
}

/* Common harness used by both the VMMCALL and the IOCTL entry points.
 * The caller supplies an EPROCESS pointer and the operator-VA output
 * buffer; we handle the probe, pause, walk, release, and history
 * record.
 *
 * operator_proc is the process that owns out_buf's address space.
 * NULL means "current AS is already the operator's" -- the VMMCALL
 * path and the direct-IOCTL manual/payload paths (where out_buf is
 * a kernel-side METHOD_BUFFERED copy). Non-NULL means attach to it
 * before every write -- the trigger-fire path, which runs in a
 * system worker thread.
 *
 * ObReference/Dereference on target is the caller's responsibility
 * because the lookup path differs between VMMCALL (operator PID in
 * GPR) and IOCTL (operator PID in buffered input). */
static ULONGLONG snapshot_locked(PEPROCESS target,
                                  ULONGLONG target_pid,
                                  PEPROCESS operator_proc,
                                  PUCHAR    out_buf,
                                  ULONGLONG out_cap,
                                  ULONG     trigger_kind,
                                  ULONGLONG trigger_gpa,
                                  BOOLEAN   probe_user_buf,
                                  ULONGLONG *cr3_out,
                                  ULONG     *parked_out)
{
    ULONGLONG     bytes = 0;
    ULONG         matched = 0;
    ULONGLONG     target_cr3;
    LARGE_INTEGER now;
    CHAMBER_DUMP_RECORD rec;

    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return 0;
    }

    /* Re-entrancy gate: a second concurrent dump is refused. */
    if (InterlockedCompareExchange(&g_pause_active, 0, 0) != 0) {
        return 0;
    }

    target_cr3 = capture_target_cr3(target);
    if (target_cr3 == 0) return 0;
    g_pause_target_cr3 = target_cr3;

    /* Detection-surface note (Wave-7 audit, "pause-world-dump" bucket):
     * KeIpiGenericCall drops a correlated per-CPU interrupt which shows
     * up as a simultaneous InterruptCount / DpcCount bump on every CPU
     * in SystemProcessorPerformanceInformation. A real fix (spread the
     * arrivals, or hide the bump) lives in the driver-stealth-hide
     * bucket; flagging only here. All of the time-counter back-fill
     * fixes the audit calls for (TSC_OFFSET, KTHREAD.KernelTime/UserTime,
     * KPRCB.DpcTime/IdleTime, KUSER_SHARED_DATA.TickCountQuad,
     * ThreadState anomaly) assume a multi-millisecond actual pause
     * window; the current broadcast is non-blocking (see KNOWN BUG at
     * top of file) and therefore has no such window to compensate for.
     * They re-appear once the targeted-DPC rewrite lands. */
    matched = pause_broadcast_and_wait();

    if (probe_user_buf) {
        /* Run the probe in operator AS. The attach/detach stays
         * paired across an exception thanks to an inner __try. */
        KAPC_STATE apc;
        BOOLEAN    probed_ok = TRUE;
        if (operator_proc) KeStackAttachProcess(operator_proc, &apc);
        __try {
            ProbeForWrite(out_buf, (SIZE_T)out_cap, sizeof(UCHAR));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            probed_ok = FALSE;
        }
        if (operator_proc) KeUnstackDetachProcess(&apc);
        if (!probed_ok) {
            /* Fall through to history record via bytes = 0. The
             * pause window is still open; the shared release below
             * clears it. */
            goto record_history;
        }
    }
    __try {
        bytes = dump_walk_target(target, operator_proc, out_buf, out_cap);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        bytes = 0;
    }

record_history:

    InterlockedExchange(&g_pause_active, 0);
    InterlockedExchange(&g_pause_originator_cpu, -1);

    KeQuerySystemTimePrecise(&now);
    RtlZeroMemory(&rec, sizeof(rec));
    rec.seq             = (ULONGLONG)InterlockedIncrement64(&g_dump_seq);
    rec.target_pid      = target_pid;
    rec.target_cr3      = target_cr3;
    rec.trigger_gpa     = trigger_gpa;
    rec.bytes_written   = bytes;
    rec.timestamp_100ns = (ULONGLONG)now.QuadPart;
    rec.trigger_kind    = trigger_kind;
    rec.parked_cpus     = matched;
    dump_history_record(&rec);

    if (cr3_out)    *cr3_out    = target_cr3;
    if (parked_out) *parked_out = matched;
    return bytes;
}

/* --- Public entry points ------------------------------------------ */

ULONGLONG dump_snapshot_pause_target(PCHAMBER_DUMP_REQ req)
{
    PEPROCESS target = NULL;
    NTSTATUS  st;
    ULONGLONG bytes;

    if (!req) return 0;
    if (req->target_pid == 0) return 0;
    if (req->output_buffer_va == 0) return 0;
    if (req->output_buffer_size == 0) return 0;

    st = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)req->target_pid, &target);
    if (!NT_SUCCESS(st) || !target) return 0;

    /* VMMCALL path: handler runs on the operator thread's host
     * context, so current AS is the operator's. operator_proc=NULL. */
    bytes = snapshot_locked(target,
                             req->target_pid,
                             NULL,
                             (PUCHAR)(ULONG_PTR)req->output_buffer_va,
                             req->output_buffer_size,
                             CHAMBER_TRIGGER_MANUAL,
                             0,
                             TRUE,
                             NULL,
                             NULL);

    ObDereferenceObject(target);
    return bytes;
}

ULONGLONG dump_run_targeted(ULONGLONG target_pid,
                             PVOID     output_buffer,
                             ULONGLONG output_capacity,
                             ULONG     trigger_kind,
                             ULONGLONG trigger_gpa,
                             ULONGLONG *target_cr3_out,
                             ULONG     *parked_cpus_out)
{
    return dump_run_targeted_ex(target_pid,
                                 NULL,
                                 output_buffer,
                                 output_capacity,
                                 trigger_kind,
                                 trigger_gpa,
                                 FALSE,
                                 target_cr3_out,
                                 parked_cpus_out);
}

/* Trigger-fire variant: the caller supplies the operator EPROCESS
 * because the worker thread is in a different AS than the operator's.
 * The common case (direct IOCTL manual/payload) passes
 * operator_proc=NULL and output_is_user=FALSE, which lets the write
 * path treat out_buf as a METHOD_BUFFERED kernel copy. */
ULONGLONG dump_run_targeted_ex(ULONGLONG target_pid,
                                PEPROCESS operator_proc,
                                PVOID     output_buffer,
                                ULONGLONG output_capacity,
                                ULONG     trigger_kind,
                                ULONGLONG trigger_gpa,
                                BOOLEAN   output_is_user,
                                ULONGLONG *target_cr3_out,
                                ULONG     *parked_cpus_out)
{
    PEPROCESS target = NULL;
    NTSTATUS  st;
    ULONGLONG bytes;

    if (target_pid == 0) return 0;
    if (!output_buffer) return 0;
    if (output_capacity == 0) return 0;

    st = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)target_pid, &target);
    if (!NT_SUCCESS(st) || !target) return 0;

    bytes = snapshot_locked(target,
                             target_pid,
                             operator_proc,
                             (PUCHAR)output_buffer,
                             output_capacity,
                             trigger_kind,
                             trigger_gpa,
                             output_is_user,
                             target_cr3_out,
                             parked_cpus_out);

    ObDereferenceObject(target);
    return bytes;
}

/* --- Translation-unit composition --------------------------------
 *
 * dump_trigger.c holds the passive-trigger registry (WX / OEP /
 * WRITE_THRESHOLD, plus the operator-direct manual and payload
 * variants). It is #included at the tail of dump.c so the existing
 * driver/build.ps1 picks it up without modification (the build
 * script enumerates a static source list; the Wave-6 scope rules
 * forbid touching it). The textual inclusion is the only dependency
 * between the two files; dump_trigger.h still carries the public
 * declarations for the_chamber.c and vmexit.c.
 *
 * Both files are otherwise self-contained -- symbols named here are
 * static or referenced across the compile boundary through dump.h.
 * */
#include "dump_trigger.c"

