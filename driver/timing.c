/* timing.c -- host-interval TSC accumulator for THE_CHAMBER.
 *
 * Why we care
 * -----------
 * Each VMEXIT costs real host cycles. If a guest brackets an intercepted
 * instruction (e.g. CPUID) with RDTSC, the observed delta is inflated by
 * host-handler time plus the VMRUN/VMEXIT microcode round-trip. AMD SVM
 * exposes vmcb->ctl.tsc_offset: hardware adds it to RDTSC before the guest
 * sees the value. We accumulate host-side cycles and write -accumulated
 * back into every CPU's VMCB tsc_offset so the guest sees bare-metal-looking
 * deltas across intercepts.
 *
 * Phase 1.2 interval design
 * -------------------------
 * The earlier scheme sampled only handler entry and exit, which missed the
 * VMEXIT->vmsave->shadow-save and the vmload->vmrun segments. vmrun.asm now
 * brackets the entire host interval:
 *
 *   TIMING_HOST_INTERVAL_START : first instruction after `vmrun rax` returns,
 *                                BEFORE `vmsave`. Captures all host time
 *                                including vmsave, GPR save, the C handler,
 *                                GPR restore and any vmload.
 *   TIMING_HOST_INTERVAL_END   : just before the next `vmrun rax`.
 *
 * timing_update() = (END - START) + g_fixed_vmexit_cost.
 *
 * What the interval misses: the VMRUN microcode that initiates guest entry
 * (after END) and the VMEXIT microcode that unwinds it back to the host
 * (before START). That residue is the "fixed vmexit cost" measured by
 * timing_calibrate() at bringup. The spec says to err slightly high
 * (over-subtract by 50-100 cycles) so the guest-visible RDTSC never drifts
 * *positive* -- that is the catastrophic failure mode where handler latency
 * leaks through.
 *
 * Wave 8 per-core accumulators
 * ----------------------------
 * Earlier phases used a SINGLE global accumulator for cross-core TSC
 * uniformity, at the cost of per-core RDTSC monotonicity.  Under
 * concurrent VMEXIT pressure from other CPUs, a tight same-core RDTSC
 * pair could step BACKWARDS by exactly the amount other CPUs added to the
 * shared accumulator -- a direct monotonicity violation on an
 * invariant-TSC part, which a per-core microarch probe can see.
 *
 * Wave 8 flips the trade-off: each logical processor owns its own
 * accumulator (g_cpu_cycles[cpu_index]) and writes -g_cpu_cycles[i] into
 * its own VMCB tsc_offset.  Monotonicity on each core is preserved
 * exactly; cross-core deltas can drift by up to the difference in
 * handler time, but that drift is bounded by the per-exit clamp and is
 * indistinguishable from ordinary cross-core TSC skew on multi-CCX Zen 4
 * parts (every Zen 4 CCX has its own TSC domain in practice even though
 * the architecture is invariant).  Modern VM-presence probes (VMAware,
 * pafish) check within-core monotonicity more aggressively than
 * cross-core uniformity, so per-core state is the stronger choice.
 */
#include "the_chamber.h"
#include "svm.h"
#include "timing.h"

/* AMD APM Vol 2 Table 15-5: VMCB clean bits.
 * Bit 0 ("I" - Intercepts) covers the intercept vectors PLUS tsc_offset
 * PLUS pause-filter counts. The earlier macro was (1U << 10) (LBR group,
 * the wrong group entirely). Keep the name VMCB_CLEAN_BIT_TSC for continuity
 * with the Phase 1.2 spec, but it actually names clean bit 0 -- which means
 * any change to the intercept vectors must also clear this bit, otherwise
 * hardware keeps serving the stale cached control area. */
#define VMCB_CLEAN_BIT_TSC (1U << 0)

/* Clean-bits sentinel: writing ~0u declares every group clean.  Helpers
 * then clear specific groups whose fields they mutate. */
#define VMCB_CLEAN_ALL     (~0u)

/* Phase 1.3: compile-time sanity check that the asm EQUs in vmrun.asm
 * match the C struct layout. If this fires, vmrun.asm's timing captures
 * are writing into unrelated fields and every guest tsc_offset is
 * garbage -- a one-line correctness disaster. */
C_ASSERT(FIELD_OFFSET(PER_CPU_CTX, vmcb_pa)             ==   8);
C_ASSERT(FIELD_OFFSET(PER_CPU_CTX, host_save_pa)        ==  24);
C_ASSERT(FIELD_OFFSET(PER_CPU_CTX, shutdown_requested)  ==  52);
C_ASSERT(FIELD_OFFSET(PER_CPU_CTX, gpr_save)            ==  64);
C_ASSERT(FIELD_OFFSET(PER_CPU_CTX, host_interval_start) == 192);
C_ASSERT(FIELD_OFFSET(PER_CPU_CTX, host_interval_end)   == 200);
C_ASSERT(FIELD_OFFSET(PER_CPU_CTX, fxsave_area)         == 256);

/* Wave 8: per-core accumulators.  Indexed by PER_CPU_CTX.cpu_index.
 * Zen 4 Threadripper tops out at 192 threads; 256 is a safe static ceiling
 * that avoids an allocation dependency during the IPI-level bringup path.
 * Each CPU reads and writes only its own slot, so no interlock is needed
 * and the per-exit store is a single mov -- the previous design's
 * LOCK-prefixed InterlockedAdd64 added measurable serialization to every
 * exit on busy hosts. */
#define TIMING_MAX_CPUS 256
static LONG64 g_cpu_cycles[TIMING_MAX_CPUS] = { 0 };

/* Backwards-compat alias: a few diagnostic paths still read this symbol.
 * Kept as a monotonic sum of every exit's per-CPU add so a single counter
 * reflects total handler time without pretending to be the TSC-offset
 * driver any more. */
volatile LONG64 g_total_accumulated_cycles = 0;

/* Per-exit upper-bound clamp.  A pathological exit (long-running handler,
 * nested SMI interposition, cross-CPU TLB shootdown stall) can produce a
 * delta of millions of cycles; feeding that straight into the per-core
 * accumulator would snap tsc_offset far enough negative that the guest's
 * next RDTSC underruns the last one.  Clamp each exit to ~250k cycles
 * (about 60us at 4 GHz) so a one-off stall cannot produce backward
 * guest-visible RDTSCs.  Longer true-handler bursts (Wave 3 integrity,
 * Wave 6 CR3 dump) are expected to chunk themselves into
 * sub-millisecond slices; this clamp catches the tail that chunking
 * misses. */
#define TIMING_PER_EXIT_CLAMP 250000ULL

/* Default microcode round-trip cost until timing_calibrate() refines it.
 * See timing_calibrate() comment block for the measurement protocol. */
ULONGLONG g_fixed_vmexit_cost = 800;

/* Trailing host cycles between TIMING_HOST_INTERVAL_END and the next
 * VMRUN: FXRSTOR64 (~80 cycles on Zen 4), the GPR reload sled (14 x mov),
 * the vmload / vmsave path at the top of the loop, and the timing_update
 * body itself.  The earlier 200-cycle value was measured against a loop
 * that captured END AFTER timing_update and before FXRSTOR, so the whole
 * reload and FPU restore leaked into guest-visible RDTSC.  Raised to 450
 * to cover the full sled; FXRSTOR64 has also been moved before END in
 * vmrun.asm so the common-case delta is now captured directly.  The
 * extra pad here covers the loop-top vmsave/vmload and the timing_update
 * body that runs after END on the current iteration. */
ULONGLONG g_timing_tail_cycles = 450;

/* Pre-START prelude compensation: vmrun.asm executes several instructions
 * (stash guest R15, reload ctx into r15, push rax, lfence, rdtsc,
 * shl rdx/or rax, mov to ctx) between the VMRUN return and the START
 * TSC capture.  Those cycles are host-side work that should be charged
 * to the guest's TSC offset but are not covered by (END-START).  A small
 * explicit constant covers the typical ~20-cycle prelude on Zen 4. */
ULONGLONG g_timing_prelude_cycles = 30;

void timing_update(PER_CPU_CTX *ctx) {
    ULONGLONG host_cycles;
    LONG64    new_total;
    VMCB     *vmcb;
    ULONG     idx;

    if (!ctx) {
        return;
    }

    /* Both captures are plain TSC samples bracketing an lfence; under
     * normal conditions END >= START. If END < START (TSC glitch, warm
     * reset, counter reload), skip this update rather than feeding a
     * wrap-around delta into the accumulator. */
    if (ctx->host_interval_end < ctx->host_interval_start) {
        return;
    }
    host_cycles  = ctx->host_interval_end - ctx->host_interval_start;
    host_cycles += g_fixed_vmexit_cost;
    host_cycles += g_timing_tail_cycles;
    host_cycles += g_timing_prelude_cycles;

    /* Positive upper-bound clamp: a single exit cannot step the offset
     * by more than TIMING_PER_EXIT_CLAMP cycles, so a stall-induced blow-
     * out cannot produce a backward guest-visible RDTSC on the next
     * same-core exit. */
    if (host_cycles > TIMING_PER_EXIT_CLAMP) {
        host_cycles = TIMING_PER_EXIT_CLAMP;
    }

    /* Per-core accumulator: only this CPU writes its slot, so the store
     * is a relaxed mov.  cpu_index is bounded by g_cpu_count at bringup;
     * defend against a malformed ctx anyway. */
    idx = ctx->cpu_index;
    if (idx >= TIMING_MAX_CPUS) {
        return;
    }
    g_cpu_cycles[idx] += (LONG64)host_cycles;
    new_total = g_cpu_cycles[idx];

    /* Diagnostic-only cumulative total.  Not used to drive tsc_offset. */
    InterlockedAdd64(&g_total_accumulated_cycles, (LONG64)host_cycles);

    vmcb = (VMCB *)ctx->vmcb_va;
    if (!vmcb) {
        return;
    }

    /* Guest RDTSC = host TSC + tsc_offset. We want host_tsc - this-core
     * handler time, so tsc_offset = -g_cpu_cycles[cpu_index]. */
    vmcb->ctl.tsc_offset = (ULONGLONG)(-new_total);

    /* Clear the Intercepts-group clean bit so hardware reloads tsc_offset
     * on the next vmrun. */
    vmcb->ctl.vmcb_clean_bits &= ~VMCB_CLEAN_BIT_TSC;
}

/* End-to-end calibration (master_plan Sec 1.2).
 *
 * Protocol when a guest-side driver thread is available:
 *   1. From an early-boot thread, issue N synthetic VMMCALLs with a
 *      calibration-mode magic in RBX so handle_vmmcall emits no side
 *      effect.
 *   2. Guest brackets the N calls with RDTSC, producing guest_delta.
 *   3. Host sums the N captured (END - START) intervals into
 *      host_interval_sum.
 *   4. residue = guest_delta - host_interval_sum.
 *   5. g_fixed_vmexit_cost = residue / N + pessimistic bias (50-100).
 *
 * timing_calibrate_record() is called from the guest-side pass with the
 * residue and sample count; it stores (residue/N) + a 64-cycle bias and
 * publishes the new value atomically.  Until the guest pass runs, the
 * default remains the Zen 4 microcode figure (~600 cycles VMRUN entry +
 * VMEXIT return) plus a 200-cycle pessimistic pad.  Erring high
 * over-subtracts from the guest TSC, which is indistinguishable from
 * memory-subsystem jitter; erring low is the catastrophic "I'm in a
 * hypervisor" tell.
 */
void timing_calibrate(void) {
    /* Default when no guest-side calibration pass has refined the value
     * yet.  Expressed as Zen 4 ~VMRUN entry (400) + ~VMEXIT return (200)
     * + 200-cycle pessimistic pad = 800.  timing_calibrate_record()
     * supersedes this once the guest calibration pass has produced
     * real numbers. */
    g_fixed_vmexit_cost = 800;
}

/* Called from the guest-side calibration pass once host_interval_sum and
 * guest_delta are known.  Writes g_fixed_vmexit_cost with
 * InterlockedExchange64 so every CPU's next timing_update sees the new
 * value without a torn read.  Ignores obviously-bogus inputs so a
 * malformed calibration call cannot drive the cost negative (which would
 * leak handler cycles through to the guest). */
void timing_calibrate_record(ULONGLONG guest_delta,
                             ULONGLONG host_interval_sum,
                             ULONG     sample_count) {
    LONG64    residue;
    ULONGLONG per_exit;
    if (sample_count == 0) {
        return;
    }
    if (guest_delta <= host_interval_sum) {
        /* Measurement noise drove residue to zero or negative: refuse. */
        return;
    }
    residue = (LONG64)(guest_delta - host_interval_sum);
    per_exit = (ULONGLONG)residue / sample_count;
    /* 64-cycle pessimistic bias (within the 50-100 cycle window the
     * phase-1.2 spec recommends). */
    per_exit += 64ULL;
    /* Refuse pathological values: a well-formed Zen 4 residue should
     * sit in [200, 4000]; anything outside is a measurement artifact. */
    if (per_exit < 200ULL || per_exit > 4000ULL) {
        return;
    }
    InterlockedExchange64((volatile LONG64 *)&g_fixed_vmexit_cost,
                          (LONG64)per_exit);
}
