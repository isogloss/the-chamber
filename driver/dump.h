/* dump.h -- pause-the-world snapshot of a target process's address space.
 *
 * Passive-dump capture. Two entry points reach the capture path:
 *
 *   1. The operator's VMMCALL (CHAMBER_HCALL_DUMP_CR3, dispatched by
 *      vmexit.c), which still works for backward compatibility with the
 *      first-wave operator tool and for code paths that hold a reference
 *      to the target CR3 directly.
 *
 *   2. The IOCTL path, which carries a target PID and an operator-VA
 *      output buffer, resolves the PID to an EPROCESS, and runs the same
 *      capture mechanics the VMMCALL path uses.
 *
 * Capture mechanics:
 *
 *   1. dump_pause_begin() installs a targeted-DPC rendezvous. One KDPC
 *      per active logical CPU, each pinned via KeSetTargetProcessorDpcEx,
 *      is queued with KeInsertQueueDpc. Every DPC runs at DISPATCH_LEVEL
 *      on its own CPU, reads __readcr3() (which runs on the guest, so
 *      CR3 is live), compares against the capture target, and if the
 *      match is positive spins on g_pause_active with a bounded wait
 *      (two seconds via KeQueryInterruptTime). Non-matching CPUs and
 *      timed-out matching CPUs return at once.
 *
 *   2. The originator spins until the per-CPU parked counter reaches
 *      the observed-matching count, then runs the VAD walk at
 *      PASSIVE_LEVEL via KeStackAttachProcess.
 *
 *   3. Before releasing the DPCs, the originator rewinds the
 *      KUSER_SHARED_DATA time counters (InterruptTime, SystemTime,
 *      TickCountQuad, QpcInterruptTimeBias) that the clock ISR
 *      advanced during the pause -- the matched DPCs are still
 *      holding their CPUs, so the rewind lands before any guest
 *      resumes.
 *
 *   4. dump_pause_end() InterlockedExchanges g_pause_active to 0, which
 *      releases the parked DPCs; each returns and its CPU resumes the
 *      guest on its next VMRUN.
 *
 * Re-entrancy: the DPC array is allocated once (at init) and reused
 * across every call; a global g_dump_seq counter is bumped per fire so
 * the pause state can be matched to a dump record. Only one capture
 * runs at a time -- a second concurrent call sees pause_active already
 * set and returns 0 without re-queueing.
 *
 * Handle discipline: snapshot_pause_target MUST NOT call OpenProcess /
 * NtOpenProcess / ZwDuplicateObject on the target -- any handle-opening
 * path trips ObRegisterCallbacks on PsProcessType. PsLookupProcessByProcessId
 * is a pointer-reference, not a handle open, and is safe. Pair it with
 * ObDereferenceObject on unwind.
 *
 * Time-view masking across the pause window:
 *
 *   - Guest RDTSC / TSC-bypass QueryPerformanceCounter: each matched
 *     pause DPC brackets its spin with __rdtsc() and charges the delta
 *     to its own CPU's tsc_offset via timing_add_pause_cycles (timing.h).
 *     The ordinary per-exit timing_update() clamp (~60us) cannot cover
 *     a 2 s spin, so this path is the sanctioned bypass.
 *
 *   - Non-bypass QueryPerformanceCounter / GetTickCount /
 *     GetSystemTimeAsFileTime / QueryUnbiasedInterruptTime: the
 *     KUSER_SHARED_DATA fields these read advance during the pause
 *     because the clock ISR at CLOCK_LEVEL preempts DISPATCH_LEVEL
 *     DPCs. The originator snapshots them pre-broadcast and rewinds
 *     them post-walk through an MmMapIoSpaceEx writable alias of the
 *     shared page, before clearing g_pause_active.
 *
 *   - Residual: KTHREAD.KernelTime / UserTime / Cycle for the target
 *     thread. Those fields live in ETHREAD/KTHREAD at offsets that
 *     vary per ntoskrnl build; the driver carries no offset table for
 *     them, so per-thread accrual drift is a known lower-priority
 *     residual (dump.c top-of-file notes it as well).
 *
 * --- VMMCALL interface (documented here; no userland code in-tree) ---
 *
 *   mov rax, <code>              ; CHAMBER_HCALL_DUMP_CR3 == 3
 *   mov rbx, <magic>             ; THE_CHAMBER_HYPERCALL_MAGIC
 *   mov rcx, <target_pid>        ; process to snapshot (ULONGLONG)
 *   mov rdx, <output_buffer_va>  ; writable buffer in operator VA space
 *   mov rsi, <output_buffer_size>; byte capacity
 *   vmmcall
 *
 * Return (in guest rax): bytes written, or 0 on error.
 *
 * Output TLV stream, one record per VAD region:
 *
 *   ULONGLONG vad_base;
 *   ULONGLONG vad_size;
 *   ULONG     protection;        // VAD protection bits
 *   ULONG     reserved;          // padding to 8-byte alignment
 *   UCHAR     data[vad_size];
 *
 * No compression, no deduplication, no framing magic. Operator
 * post-processes offline. If the buffer fills mid-region the handler
 * stops writing, releases parked CPUs, and returns bytes written up to
 * that point so the operator can retry with a larger buffer.
 */

#ifndef THE_CHAMBER_DUMP_H
#define THE_CHAMBER_DUMP_H

#include "the_chamber.h"
#include "svm.h"

/* VMMCALL sub-code dispatched by handle_vmmcall in vmexit.c. */
#define CHAMBER_HCALL_DUMP_CR3   3

/* Operator-supplied VMMCALL request. Guest passes the fields in GPRs;
 * vmexit.c marshals them into this struct before calling
 * dump_snapshot_pause_target. */
typedef struct _CHAMBER_DUMP_REQ {
    ULONGLONG target_pid;        /* PID to dump; resolved via PsLookup */
    ULONGLONG output_buffer_va;  /* operator VA receiving TLV stream */
    ULONGLONG output_buffer_size;/* byte capacity */
} CHAMBER_DUMP_REQ, *PCHAMBER_DUMP_REQ;

/* VMMCALL entry point. Returns bytes written to the operator buffer
 * (0 on error). Host context, PASSIVE_LEVEL caller. */
ULONGLONG dump_snapshot_pause_target(PCHAMBER_DUMP_REQ req);

/* IOCTL entry point for a direct dump. The output buffer is a kernel
 * copy (METHOD_BUFFERED) so no probe is performed and the current AS
 * is irrelevant to the write path. trigger_kind is forwarded to the
 * history ring. target_cr3_out and parked_cpus_out are optional. */
ULONGLONG dump_run_targeted(ULONGLONG target_pid,
                             PVOID     output_buffer,
                             ULONGLONG output_capacity,
                             ULONG     trigger_kind,
                             ULONGLONG trigger_gpa,
                             ULONGLONG *target_cr3_out,
                             ULONG     *parked_cpus_out);

/* Trigger-fire variant. operator_proc is the process that owns
 * output_buffer's VA. If output_is_user is TRUE, output_buffer is a
 * user VA in operator_proc's AS and every write attaches briefly to
 * operator_proc. If FALSE, output_buffer is a kernel VA valid from
 * any AS and operator_proc is ignored.
 */
ULONGLONG dump_run_targeted_ex(ULONGLONG target_pid,
                                PEPROCESS operator_proc,
                                PVOID     output_buffer,
                                ULONGLONG output_capacity,
                                ULONG     trigger_kind,
                                ULONGLONG trigger_gpa,
                                BOOLEAN   output_is_user,
                                ULONGLONG *target_cr3_out,
                                ULONG     *parked_cpus_out);

/* Pause primitive lifecycle. dump_pause_init allocates the per-CPU
 * DPC array; dump_pause_shutdown releases it. Called from DriverEntry
 * and UnloadRoutine. */
NTSTATUS dump_pause_init(void);
void     dump_pause_shutdown(void);

/* Dump history ring access. Populates `out` with the newest records
 * (most-recent first). Returns bytes written. */
ULONG    dump_history_copy_out(PCHAMBER_DUMP_HISTORY out,
                                ULONG                 capacity_bytes);

/* Pause state, observable by other translation units. Zero = no pause
 * window active; non-zero = parked DPCs are spinning. */
extern volatile LONG g_pause_active;

/* Monotonic dump sequence number. Bumped by dump_run_targeted on each
 * fire so a trigger that re-arms can distinguish adjacent captures. */
extern volatile LONG64 g_dump_seq;

#endif /* THE_CHAMBER_DUMP_H */
