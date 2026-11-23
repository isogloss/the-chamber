/* timing.h -- host-interval TSC accumulator for THE_CHAMBER.
 *
 * Phase 1.2/1.3 redesign: vmrun.asm captures two TSC timestamps per
 * iteration (START right after `vmrun rax` returns, END right before the
 * next `vmrun rax`) in each per-CPU context. timing_update(ctx) sums the
 * delta plus the calibrated microcode cost into a SINGLE global accumulator
 * g_total_accumulated_cycles (Phase 1.3). Each CPU writes
 * -g_total_accumulated_cycles into its own VMCB->ctl.tsc_offset so the
 * host-time penalty applies uniformly on every logical processor.
 *
 * See timing.c for the full rationale including the cross-core drift
 * trade-off that the single-global design intentionally accepts.
 */
#pragma once
#include "the_chamber.h"
#include "svm.h"

/* Single, system-wide TSC penalty accumulator. Every CPU's VMCB
 * tsc_offset is -g_total_accumulated_cycles. Writes go through
 * InterlockedAdd64 from timing_update(). */
extern volatile LONG64 g_total_accumulated_cycles;

/* Pessimistic microcode round-trip cost (VMRUN entry + VMEXIT return),
 * populated at bringup by timing_calibrate(). */
extern ULONGLONG       g_fixed_vmexit_cost;

/* Trailing host cycles between TIMING_HOST_INTERVAL_END capture and the
 * next VMRUN (GPR reload + jmp).  Folded into each delta so the guest
 * does not see them. */
extern ULONGLONG       g_timing_tail_cycles;

/* Called from vmrun.asm immediately after the TIMING_HOST_INTERVAL_END
 * capture, before the next `vmrun rax`. */
void timing_update(PER_CPU_CTX *ctx);

/* Called from DriverEntry once, after svm_init_all_cpus() succeeds. */
void timing_calibrate(void);
