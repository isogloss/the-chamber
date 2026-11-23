/* dump.h -- pause-the-world snapshot of a target process's address space.
 *
 * Phase 6.2 passive-dump capture. The operator issues a VMMCALL with the
 * code CHAMBER_HCALL_DUMP_CR3 (dispatched by vmexit.c) carrying:
 *
 *   - a target PID (the process whose VADs to walk)
 *   - an output buffer VA (in operator process context) and size
 *
 * The HV handler runs in host (root) context at whatever IRQL the guest
 * was at when VMMCALL fired; for a VMMCALL issued from a PASSIVE_LEVEL
 * user-mode thread that IRQL is PASSIVE_LEVEL, which is what every
 * operation below requires.
 *
 * Capture mechanics:
 *
 *   1. KeIpiGenericCall(ipi_park_if_target_cr3) parks every vCPU whose
 *      current guest CR3 matches the target process's PML4 base. The
 *      IPI runs at IPI_LEVEL -- which is why park is the ONLY work it
 *      does; it must not attach, allocate, walk VADs or anything else
 *      that requires PASSIVE. Parked workers spin on g_pause_active.
 *
 *   2. After the broadcast returns, the ORIGINATING CPU (host-context
 *      PASSIVE_LEVEL) does the VAD walk. It attaches to the target with
 *      KeStackAttachProcess (strictly requires IRQL < DISPATCH_LEVEL;
 *      documented bound), walks the VAD tree, and copies each
 *      committed region to the operator's output buffer in TLV form.
 *
 *   3. InterlockedExchange(&g_pause_active, 0) releases the parked
 *      vCPUs. They re-enter the guest on the next VMRUN.
 *
 * KeIpiGenericCall is a standard IPI at IPI_LEVEL; it is NOT NMI-based
 * and is maskable by raising IRQL >= IPI_LEVEL. No NMI delivery is used
 * anywhere in this file.
 *
 * Handle discipline: snapshot_pause_target MUST NOT call OpenProcess /
 * NtOpenProcess / ZwDuplicateObject on the target -- any handle-opening
 * path trips ObRegisterCallbacks on PsProcessType. PsLookupProcessByProcessId
 * is a pointer-reference, not a handle open, and is safe. Pair it with
 * ObDereferenceObject on unwind.
 *
 * --- User-mode interface (documented here; no userland code in-tree) ---
 *
 * Operator issues:
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

/* Operator-supplied request. Guest passes the fields in GPRs; vmexit.c
 * marshals them into this struct before calling snapshot_pause_target. */
typedef struct _CHAMBER_DUMP_REQ {
    ULONGLONG target_pid;        /* PID to dump; resolved via PsLookup */
    ULONGLONG output_buffer_va;  /* operator VA receiving TLV stream */
    ULONGLONG output_buffer_size;/* byte capacity */
} CHAMBER_DUMP_REQ, *PCHAMBER_DUMP_REQ;

/* Entry point called from handle_vmmcall. Returns bytes written to the
 * operator buffer (0 on error). Host context, PASSIVE_LEVEL caller. */
ULONGLONG dump_snapshot_pause_target(PCHAMBER_DUMP_REQ req);

/* Pause state, shared with the IPI worker. Zero = guest running;
 * non-zero = parked vCPUs must spin. Exposed so the IPI worker in
 * dump.c and (future) debugger integrations can observe it. */
extern volatile LONG g_pause_active;

#endif /* THE_CHAMBER_DUMP_H */
