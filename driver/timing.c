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
 * Phase 1.3 global accumulator
 * ----------------------------
 * g_total_accumulated_cycles is a SINGLE global, not per-CPU. Every CPU's
 * VMCB tsc_offset is -g_total_accumulated_cycles. This bounds cross-core
 * drift: if CPU A takes a long VMEXIT, CPU B's next tsc_offset refresh
 * (whenever it happens) picks up the same accumulated total. Without this,
 * a cross-core RDTSC probe sees two cores running at different apparent
 * rates (one with 1000 handler-cycles subtracted, another with 20000),
 * which is a strong tell on an invariant-TSC system (Zen 4 is).
 *
 * Trade-off we accept
 * -------------------
 * Per-core RDTSC monotonicity is NOT preserved. Between CPU A's own exits,
 * other CPUs may add cycles to the shared accumulator, so A's own
 * tsc_offset grows more negative. If a probe pins to CPU A and calls RDTSC
 * repeatedly, successive values can step backwards by exactly the amount
 * OTHER CPUs accumulated in between. This is the standard trade-off every
 * thin HV makes when it unifies the TSC view across cores; a tight-loop
 * same-core RDTSC pair can see monotonicity breakage, but only under
 * concurrent VMEXIT pressure from other CPUs. Guests that need strict
 * per-core RDTSC monotonicity (lock-free data-structure primitives,
 * microarchitectural benchmarks) would need to disable the global
 * accumulator and go back to per-CPU state at the cost of cross-core
 * consistency. For a detection-avoidance HV, cross-core uniformity wins:
 * modern VM-presence probes (VMAware, pafish) specifically compare TSC
 * samples across logical processors, so per-core drift is a stronger
 * signal than rare, under-load local regression. Phase 1.3 formalizes
 * the choice.
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

/* Phase 1.3: ONE global accumulator shared by every CPU. */
volatile LONG64 g_total_accumulated_cycles = 0;

/* Pessimistic default so timing_update() does the right thing even before
 * timing_calibrate() has run. Overwritten at bringup. 64-bit aligned reads
 * and writes are atomic on x86_64 so no interlock is required for the
 * write-once, read-many access pattern. */
ULONGLONG g_fixed_vmexit_cost = 800;

/* Trailing host cycles between the TIMING_HOST_INTERVAL_END capture and
 * the next VMRUN (reload-GPR sled + jmp).  Historically these cycles
 * leaked to guest-visible RDTSC; charging them here keeps the guest
 * seeing bare-metal-looking deltas across intercepts. */
ULONGLONG g_timing_tail_cycles = 200;

void timing_update(PER_CPU_CTX *ctx) {
    ULONGLONG host_cycles;
    LONG64    new_total;
    VMCB     *vmcb;

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

    /* InterlockedAdd64 returns the post-add value. A separate load would
     * see any number of intervening adds from other CPUs and race with
     * them; capturing the return value is mandatory here. */
    new_total = InterlockedAdd64(&g_total_accumulated_cycles,
                                 (LONG64)host_cycles);

    vmcb = (VMCB *)ctx->vmcb_va;
    if (!vmcb) {
        return;
    }

    /* Guest RDTSC = host TSC + tsc_offset. We want host_tsc - accumulated,
     * so tsc_offset = -accumulated. */
    vmcb->ctl.tsc_offset = (ULONGLONG)(-new_total);

    /* Clear the Intercepts-group clean bit so hardware reloads tsc_offset
     * on the next vmrun. */
    vmcb->ctl.vmcb_clean_bits &= ~VMCB_CLEAN_BIT_TSC;
}

/* Calibrate the microcode round-trip cost (VMRUN entry + VMEXIT return)
 * that falls OUTSIDE the vmrun.asm START..END interval.
 *
 * The rigorous measurement is:
 *   1. Guest issues N synthetic VMMCALLs.
 *   2. Guest measures its own RDTSC delta across the N calls.
 *   3. Host sums the N captured (END - START) intervals.
 *   4. residue = (guest delta) - (host interval sum).
 *   5. g_fixed_vmexit_cost = residue / N, biased 50-100 cycles high.
 *
 * That protocol requires a running guest, which the Phase 1 bringup path
 * does not exercise (svm_launch runs post-DriverEntry and the guest does
 * no synthetic calibration workload in this phase). Until a guest-side
 * calibration pass runs and refines g_fixed_vmexit_cost in place, we set
 * a conservative constant derived from AMD Zen 4 (family 19h) documented
 * microcode costs:
 *
 *   VMRUN entry latency     ~ 400 cycles
 *   VMEXIT return latency   ~ 200 cycles
 *   Subtotal                ~ 600 cycles
 *   Pessimistic safety pad  + 200 cycles  (per Phase 1.2 guidance)
 *   ---------------------------------
 *   g_fixed_vmexit_cost     = 800 cycles
 *
 * Erring high means we over-subtract from the guest TSC: if the guest
 * measures a workload of 10000 cycles across an intercepted instruction,
 * it may see 9900 instead of 10000. 100 cycles of understatement is
 * indistinguishable from ordinary memory-subsystem jitter and is far less
 * detectable than the reverse (overstatement -- which is the "I'm in a
 * hypervisor" tell).
 *
 * If a guest-side pass is added later, it should write with
 * InterlockedExchange64 to make the refresh visible to every timing_update
 * caller atomically, even though 64-bit stores are architecturally atomic
 * on x86_64 for aligned addresses.
 */
void timing_calibrate(void) {
    g_fixed_vmexit_cost = 800;
}
