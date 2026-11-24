/* timing.h -- host-interval TSC accumulator for THE_CHAMBER.
 *
 * Phase 1.2 / Wave 8 design: vmrun.asm captures two TSC timestamps per
 * iteration (START right after `vmrun rax` returns, END right before the
 * next `vmrun rax`) in each per-CPU context. timing_update(ctx) sums the
 * delta plus the calibrated microcode cost into a PER-CORE accumulator
 * (g_cpu_cycles[cpu_index]); each CPU writes -g_cpu_cycles[cpu_index]
 * into its own VMCB->ctl.tsc_offset so per-core RDTSC monotonicity is
 * preserved. Per-exit deltas are clamped to TIMING_PER_EXIT_CLAMP so a
 * one-off pathological handler cannot step the offset far enough
 * negative to make the guest's next same-core RDTSC run backwards.
 *
 * Pause-window carve-out: dump.c's pause DPC spins for up to 2 seconds
 * while the host TSC keeps running; that delta (~8 Gcyc at 4 GHz) is
 * ~33000x the per-exit clamp and would leak straight through to the
 * guest's RDTSC. timing_add_pause_cycles() is the only sanctioned path
 * that bypasses the clamp, charging the full pre-release TSC delta to
 * the paused CPU's offset and refreshing the VMCB in place.
 *
 * See timing.c for the full rationale including the cross-core drift
 * trade-off that the per-core design accepts.
 */
#pragma once
#include "the_chamber.h"
#include "svm.h"

/* Diagnostic-only cumulative host-cycle total across every CPU. Not used
 * to drive tsc_offset any more; each CPU now writes -g_cpu_cycles[cpu]
 * into its own VMCB via timing_update() on the ordinary exit path or
 * timing_add_pause_cycles() for the carve-out. */
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

/* Pause-window compensation. Called from dump.c's pause DPC on the CPU
 * being paused, with the TSC delta observed across its spin. Adds the
 * delta to this CPU's accumulator BYPASSING the per-exit clamp, then
 * refreshes vmcb->ctl.tsc_offset and clears the Intercepts clean bit so
 * the guest's first VMRUN after the DPC returns serves a tsc_offset
 * that cancels the full spin -- the ordinary per-exit path would cap
 * the compensation at ~60us and leak the rest of the ~2s window to
 * guest-visible RDTSC. Caller must be running on the CPU identified by
 * cpu_idx (the DPC is pinned, so this holds by construction). */
void timing_add_pause_cycles(ULONG cpu_idx, ULONGLONG cycles);

/* Called from DriverEntry once, after svm_init_all_cpus() succeeds. */
void timing_calibrate(void);

/* Called from the guest-side calibration pass once host_interval_sum
 * and guest_delta are known; refines g_fixed_vmexit_cost. */
void timing_calibrate_record(ULONGLONG guest_delta,
                             ULONGLONG host_interval_sum,
                             ULONG     sample_count);
