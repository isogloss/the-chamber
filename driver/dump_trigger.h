/* dump_trigger.h -- passive-trigger registry for operator-driven dumps.
 *
 * Triggers are NPT-only (invisible to guest) or operator-initiated via
 * IOCTL. No breakpoints, no page-guards, no DR writes, no inline hooks
 * and no SSDT touching. Four kinds:
 *
 *   MANUAL           Operator issues IOCTL_THE_CHAMBER_DUMP_NOW; the
 *                    dump fires immediately (no NPT state).
 *
 *   PAYLOAD          Operator issues IOCTL_THE_CHAMBER_DUMP_ON_PAYLOAD
 *                    after a userland WFP callback observes the sample
 *                    receive its payload. Same shape as MANUAL.
 *
 *   WX               Walks the target's user address space, marks each
 *                    covering 2 MB NPT page with permissions that will
 *                    NPF the first execute on a page that was
 *                    previously only written. On the fault, the
 *                    trigger re-marks the page as fully accessible and
 *                    fires a dump. A per-trigger GPA set tracks which
 *                    PDEs we have already reported so subsequent
 *                    executes on the same PDE do not re-trigger.
 *
 *   OEP              Records a target PID + a suspected OEP GVA. Marks
 *                    the covering 2 MB PDE as execute-fault. First
 *                    execute at that PDE fires a dump.
 *
 *   WRITE_THRESHOLD  Marks writable user pages as write-fault. Each
 *                    write NPF increments a per-target counter;
 *                    crossing the operator-supplied threshold fires a
 *                    dump. The initial landing uses a single counter
 *                    per target CR3 rather than a per-region counter
 *                    -- noted as a granularity limitation.
 *
 * Each trigger is per-PID and self-disarms after one fire unless the
 * operator supplied the `rearm` flag. Multiple dumps: operator can
 * re-arm the same trigger immediately for partial-unpack sequences.
 *
 * Implementation notes:
 *
 * NPT edits are performed through npt_hide_range at the 2 MB
 * granularity -- the only published API that clears a PDE's P/W/U
 * bits. Clearing all three makes any access through the PDE fault,
 * not only writes or executes: the trigger then consults exit_info_1
 * on the fault (ID bit 4 for instruction fetch, W/R bit 1 for write)
 * to decide whether this fault was the one the trigger cared about.
 * If the fault bits do not match the trigger kind, the trigger
 * transparently re-maps the page via npt_map_page so the access
 * completes without the guest observing a spurious fault.
 *
 * This keeps the trigger module inside the Wave-6 scope (driver/npt.c
 * is unchanged). A follow-up pass that exposes per-permission PDE
 * edits in npt.c would let WX and WRITE_THRESHOLD trap only the
 * relevant access class directly.
 */

#ifndef THE_CHAMBER_DUMP_TRIGGER_H
#define THE_CHAMBER_DUMP_TRIGGER_H

#include "the_chamber.h"
#include "svm.h"

/* Lifecycle. Called from DriverEntry / UnloadRoutine. The arm/disarm
 * primitives expect the registry to be live. */
NTSTATUS dump_trigger_init(void);
void     dump_trigger_shutdown(void);

/* Arm / disarm. All three arm paths take an operator-VA output buffer
 * that the subsequent dump writes TLV records into. target_pid == 0
 * is refused (a trigger without a target makes no sense). */
NTSTATUS dump_trigger_arm_wx(ULONGLONG target_pid,
                              PVOID     output_buffer_va,
                              ULONGLONG output_buffer_size,
                              BOOLEAN   rearm);

NTSTATUS dump_trigger_arm_oep(ULONGLONG target_pid,
                               ULONGLONG suspected_oep_gva,
                               PVOID     output_buffer_va,
                               ULONGLONG output_buffer_size,
                               BOOLEAN   rearm);

NTSTATUS dump_trigger_arm_write_threshold(ULONGLONG target_pid,
                                           ULONGLONG threshold_bytes,
                                           PVOID     output_buffer_va,
                                           ULONGLONG output_buffer_size,
                                           BOOLEAN   rearm);

/* Operator-direct manual / payload dump. The output buffer is a kernel
 * copy of the operator buffer (IRP buffered-IO), so no probe needed
 * here. Returns bytes written (0 on error). */
ULONGLONG dump_trigger_manual(ULONGLONG target_pid,
                               PVOID     kernel_output_buf,
                               ULONGLONG output_capacity);

ULONGLONG dump_trigger_payload(ULONGLONG target_pid,
                                PVOID     kernel_output_buf,
                                ULONGLONG output_capacity);

/* Disarm. target_pid == 0 clears all triggers across all PIDs.
 * trigger_mask filters by kind (CHAMBER_TRIGGER_WX | CHAMBER_TRIGGER_OEP
 * ...). Zero mask is equivalent to CHAMBER_TRIGGER_ANY. */
NTSTATUS dump_trigger_disarm(ULONGLONG target_pid, ULONG trigger_mask);

/* NPF callback. Called from vmexit.c handle_npf when a fault lands on
 * a GPA that may belong to one of our triggers. Returns TRUE if the
 * fault was handled by the trigger path (handler must NOT advance RIP
 * or inject a fault; the trigger has already restored the PDE for
 * retry). Returns FALSE if the GPA is not in any trigger's set, in
 * which case handle_npf falls through to the ordinary
 * install-on-demand path. */
BOOLEAN dump_trigger_on_npf(VMCB *vmcb, ULONGLONG fault_gpa,
                             ULONGLONG fault_info);

#endif /* THE_CHAMBER_DUMP_TRIGGER_H */
