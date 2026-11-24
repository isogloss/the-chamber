/* dump.c -- passive address-space snapshot of a target process.
 *
 * No active-debug surface. Triggers are NPT-only (invisible to guest)
 * or operator-initiated via IOCTL. The pause primitive is targeted-DPC
 * rendezvous (no KeIpiGenericCall spin).
 *
 * Time-view masking across the pause window (see pause_dpc_routine and
 * kuser_time_rewind below):
 *
 *   - Guest-visible RDTSC / TSC-bypass QPC: each paused CPU's DPC
 *     captures __rdtsc() on spin entry and again just before release,
 *     then calls timing_add_pause_cycles() to charge the full delta to
 *     its own tsc_offset. The ordinary per-exit timing_update() clamps
 *     at TIMING_PER_EXIT_CLAMP (~60us) and cannot cover a 2 s spin;
 *     this path is the sanctioned clamp bypass for the bounded pause
 *     window.
 *
 *   - Non-bypass QPC, GetTickCount / GetTickCount64,
 *     GetSystemTimeAsFileTime, QueryUnbiasedInterruptTime:
 *     KUSER_SHARED_DATA fields (InterruptTime, SystemTime,
 *     TickCountQuad, QpcInterruptTimeBias) advance during the pause
 *     because the clock ISR runs at CLOCK_LEVEL and preempts the
 *     DISPATCH_LEVEL pause DPCs. snapshot_locked captures them before
 *     broadcast and rewinds them after the walk, before releasing the
 *     DPCs, so the guest's first post-resume read sees the pre-pause
 *     values.
 *
 * Residual: KTHREAD.KernelTime / UserTime / Cycle for the target
 * thread. Those fields also advance in the target-process ETHREAD /
 * KTHREAD during the pause; writing them back requires offset
 * knowledge for the running ntoskrnl build which the driver does not
 * carry. Flagged here; the per-thread accrual is minor compared to
 * the KUSER-wide clocks and is a lower-priority tell.
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
 *       On the match path, brackets the spin with __rdtsc() and
 *       charges the delta to this CPU's tsc_offset via
 *       timing_add_pause_cycles.
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

/* ntifs.h brings in KAPC_STATE / KeStackAttachProcess / KeUnstackDetachProcess
 * which are declared only in the FS layer of the WDK, not in ntddk.h / wdm.h.
 * ntifs.h itself #includes ntddk.h so a straight swap here is safe. */
#include <ntifs.h>
#include <wdm.h>
#include <intrin.h>
#include "the_chamber.h"
#include "svm.h"
#include "timing.h"
#include "dump.h"

volatile LONG   g_pause_active = 0;
volatile LONG64 g_dump_seq     = 0;

/* Originator CPU for the current targeted-DPC broadcast. Recorded so
 * the pause DPC can skip itself if it runs on the originator: the
 * VMMCALL that invoked us can be issued from a thread whose CR3 matches
 * the capture target, in which case the originator would otherwise
 * self-park inside its own spin loop and wedge the whole capture. The
 * pause primitive IS blocking (pause_dpc_routine spins on
 * g_pause_active up to PAUSE_WINDOW_100NS), which is exactly why the
 * self-skip matters. */
static volatile LONG g_pause_originator_cpu = -1;

/* --- Externs we use from the kernel, without pulling a full header. ---
 * KeStackAttachProcess / KeUnstackDetachProcess / KAPC_STATE come from
 * <ntifs.h> above; KeSetTargetProcessorDpcEx comes from <wdm.h>. */
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId,
                                                PEPROCESS *Process);

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

/* --- KUSER_SHARED_DATA time-view masking --------------------------- */

/* KUSER_SHARED_DATA fields advance during the pause because the clock
 * ISR runs at CLOCK_LEVEL and preempts DISPATCH_LEVEL pause DPCs.
 * snapshot_locked captures these before broadcast and rewinds them
 * after the walk, before releasing the DPCs, so the guest's first
 * post-resume read of GetTickCount / GetSystemTimeAsFileTime / the
 * non-bypass QueryPerformanceCounter path sees pre-pause values.
 * The TSC-bypass QPC path is handled separately by the per-CPU
 * tsc_offset carve-out in pause_dpc_routine above. */
typedef struct _KUSER_TIME_SNAPSHOT {
    ULONG64 tick_count_quad;
    ULONG   intr_low;
    LONG    intr_high;
    ULONG   sys_low;
    LONG    sys_high;
    LONG64  qpc_intr_time_bias;
    BOOLEAN valid;
    UCHAR   pad[7];
} KUSER_TIME_SNAPSHOT;

static void kuser_time_capture(KUSER_TIME_SNAPSHOT *out)
{
    const KUSER_SHARED_DATA *kud = SharedUserData;
    ULONG attempts;

    if (!out) return;
    RtlZeroMemory(out, sizeof(*out));

    /* Read InterruptTime with the documented High1 / LowPart / High2
     * spin: the clock ISR writes High2, LowPart, High1 in that order
     * (so High1 == High2 only once the full 64-bit write has landed).
     * Bound the spin so a wedged writer cannot hang us. */
    for (attempts = 0; attempts < 4096; attempts++) {
        LONG  h1 = kud->InterruptTime.High1Time;
        ULONG lo = kud->InterruptTime.LowPart;
        LONG  h2 = kud->InterruptTime.High2Time;
        if (h1 == h2) {
            out->intr_low  = lo;
            out->intr_high = h1;
            break;
        }
        YieldProcessor();
    }
    if (attempts == 4096) return;

    for (attempts = 0; attempts < 4096; attempts++) {
        LONG  h1 = kud->SystemTime.High1Time;
        ULONG lo = kud->SystemTime.LowPart;
        LONG  h2 = kud->SystemTime.High2Time;
        if (h1 == h2) {
            out->sys_low  = lo;
            out->sys_high = h1;
            break;
        }
        YieldProcessor();
    }
    if (attempts == 4096) return;

    out->tick_count_quad    = kud->TickCountQuad;
    /* QpcInterruptTimeBias lives at fixed offset 0x3B0 on x64 — the
     * field name varies across WDK versions (QpcBias on 19041, renamed
     * to QpcInterruptTimeBias in the Win11 SDK) so we access it by
     * literal offset to keep the build portable. */
    out->qpc_intr_time_bias =
        *(volatile LONGLONG *)((PUCHAR)(ULONG_PTR)kud + 0x3B0);
    out->valid              = TRUE;
}

/* Write the snapshot back to the KUSER_SHARED_DATA physical page via a
 * writable kernel alias. SharedUserData itself is mapped read-only on
 * the kernel side; MmMapIoSpaceEx gives us an RW window over the same
 * PA for the duration of the rewind. Called from snapshot_locked
 * AFTER the VAD walk finishes and BEFORE g_pause_active is cleared,
 * so matched DPCs are still spinning and the target guest sees the
 * rewound values on its first resume-side read. */
static void kuser_time_rewind(const KUSER_TIME_SNAPSHOT *in)
{
    PHYSICAL_ADDRESS   pa;
    PVOID              rw_map;
    KUSER_SHARED_DATA *kud_rw;

    if (!in || !in->valid) return;
    if (KeGetCurrentIrql() > APC_LEVEL) return; /* MmMapIoSpaceEx bound */

    pa = MmGetPhysicalAddress((PVOID)SharedUserData);
    if (pa.QuadPart == 0) return;

    rw_map = MmMapIoSpaceEx(pa, PAGE_SIZE, PAGE_READWRITE);
    if (!rw_map) return;

    kud_rw = (KUSER_SHARED_DATA *)rw_map;

    /* Write-side protocol mirrors the clock ISR: High2, LowPart, High1,
     * so a user-mode reader that spins until High1 == High2 observes a
     * consistent 64-bit value after we return. */
    kud_rw->InterruptTime.High2Time = in->intr_high;
    _ReadWriteBarrier();
    kud_rw->InterruptTime.LowPart   = in->intr_low;
    _ReadWriteBarrier();
    kud_rw->InterruptTime.High1Time = in->intr_high;

    kud_rw->SystemTime.High2Time    = in->sys_high;
    _ReadWriteBarrier();
    kud_rw->SystemTime.LowPart      = in->sys_low;
    _ReadWriteBarrier();
    kud_rw->SystemTime.High1Time    = in->sys_high;

    /* TickCountQuad is a 64-bit aligned field; the architecturally
     * atomic store is enough. QPC bias likewise — written by fixed
     * offset (see the matching note in kuser_time_capture). */
    kud_rw->TickCountQuad           = in->tick_count_quad;
    *(volatile LONGLONG *)((PUCHAR)kud_rw + 0x3B0) = in->qpc_intr_time_bias;

    MmUnmapIoSpace(rw_map, PAGE_SIZE);
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
 * on unwind for the dump record.
 *
 * TSC compensation on the match path: __rdtsc brackets the spin. The
 * delta is pushed into this CPU's tsc_offset via timing_add_pause_cycles
 * before the DPC returns. The ordinary per-exit clamp (60us) would
 * otherwise swallow all but a sliver of a 2 s spin and leak the rest
 * to guest-visible RDTSC. */
static VOID pause_dpc_routine(PKDPC Dpc, PVOID Ctx, PVOID Sa1, PVOID Sa2)
{
    PAUSE_PER_CPU *slot = (PAUSE_PER_CPU *)Ctx;
    ULONGLONG      current_cr3;
    ULONGLONG      tsc_spin_start, tsc_spin_end;
    ULARGE_INTEGER t0, t;
    ULONG          cpu;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Sa1);
    UNREFERENCED_PARAMETER(Sa2);

    if (!slot) return;

    /* If this DPC is running on the originator CPU (operator process
     * happens to share CR3 with the target — e.g. the operator
     * triggered a dump of its own analysis helper), skip the park so
     * the originator can finish its walk; otherwise the originator
     * wedges itself inside its own spin loop at DISPATCH_LEVEL and
     * the whole capture stalls for the full PAUSE_WINDOW_100NS before
     * timing out. */
    cpu = KeGetCurrentProcessorNumber();
    if ((LONG)cpu == InterlockedCompareExchange(
            &g_pause_originator_cpu, -1, -1)) {
        InterlockedIncrement(&g_pause_completion);
        return;
    }

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

    /* Bracket the spin with the host TSC. Everything between here and
     * the matching capture below is host-only time -- the guest vCPU
     * is parked -- so charging it to this CPU's tsc_offset makes the
     * guest's next RDTSC after resume continue as if no pause ran. */
    tsc_spin_start = __rdtsc();
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

    tsc_spin_end = __rdtsc();
    InterlockedExchange(&slot->parked, 0);

    /* Charge the spin to this CPU's per-core TSC accumulator, bypassing
     * the per-exit clamp. The DPC is pinned, so KeGetCurrentProcessorNumber
     * matches the g_cpu_ctx / g_cpu_cycles slot we need to update. The
     * refresh writes vmcb->ctl.tsc_offset in place and clears the
     * Intercepts clean bit so the next VMRUN serves the new offset. */
    if (tsc_spin_end > tsc_spin_start) {
        cpu = KeGetCurrentProcessorNumber();
        timing_add_pause_cycles(cpu, tsc_spin_end - tsc_spin_start);
    }
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

    /* Record this CPU as the originator BEFORE any DPC is queued so
     * the pinned DPC that lands on this same CPU (the targeted-DPC
     * broadcast fires one per processor, including this one) can
     * self-skip and avoid wedging the originator inside its own spin
     * loop. snapshot_locked clears this back to -1 on unwind. The
     * originator runs at DISPATCH_LEVEL for the KeInsertQueueDpc
     * loop so KeGetCurrentProcessorNumber is stable here. */
    InterlockedExchange(&g_pause_originator_cpu,
                        (LONG)KeGetCurrentProcessorNumber());

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
    KUSER_TIME_SNAPSHOT  kuser_snap;

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

    /* Snapshot KUSER_SHARED_DATA time counters BEFORE broadcasting the
     * pause DPCs. The pause primitive is targeted-DPC rendezvous and
     * actually blocks every CR3-matching vCPU for up to
     * PAUSE_WINDOW_100NS (2 s) via YieldProcessor; during that window
     * the clock ISR at CLOCK_LEVEL still fires on every CPU and
     * advances KUSER_SHARED_DATA.{InterruptTime, SystemTime,
     * TickCountQuad, QpcInterruptTimeBias}. If we left them advanced
     * the target's next GetTickCount / GetSystemTimeAsFileTime /
     * non-bypass QueryPerformanceCounter call would read a 2 s jump,
     * which is exactly the "someone froze me" signal the pause exists
     * to hide. The TSC-bypass QPC path and raw RDTSC are handled
     * separately by pause_dpc_routine's tsc_offset carve-out.
     *
     * Residual: KTHREAD.KernelTime / UserTime / Cycle for the target
     * thread are per-process ETHREAD state and would need per-build
     * ntoskrnl offset knowledge to back-fill; left as a known residual
     * in dump.c's top-of-file notes.
     *
     * Detection-surface note (separate from the time masking):
     * targeted per-CPU DPCs show up as DpcCount bumps on every CPU in
     * SystemProcessorPerformanceInformation. Hiding that signal lives
     * in the driver-stealth-hide bucket; flagging only here. */
    kuser_time_capture(&kuser_snap);

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

    /* Rewind KUSER_SHARED_DATA time counters to their pre-pause values
     * while the matched DPCs are still spinning. Once g_pause_active
     * is cleared below the guest resumes, and we need the pre-pause
     * values in place before that happens so the first user-mode
     * QueryPerformanceCounter / GetTickCount call lands on them. */
    kuser_time_rewind(&kuser_snap);

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

