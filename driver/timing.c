/* timing.c -- TSC offset accumulator for THE_CHAMBER.
 *
 * Each VMEXIT costs real cycles on the host. A guest measuring RDTSC
 * bracketing an intercepted instruction (CPUID etc.) sees a delta inflated
 * by host-handler time. AMD SVM gives us vmcb->ctl.tsc_offset; guest RDTSC
 * returns host_tsc + tsc_offset. We subtract the accumulated handler time
 * so the guest skips over our VMEXIT cost.
 *
 * Call site contract:
 *   - timing_before_handler(ctx) is called as the FIRST action in vmexit_handler
 *   - timing_after_vmexit(ctx)   is called as the LAST action in vmexit_handler
 */
#include "the_chamber.h"
#include "svm.h"
#include "timing.h"

PER_CPU_TIMING g_timing[TIMING_MAX_CPUS] = { 0 };

/* VMCB clean-bit for TSC offset (AMD Table 15-5, bit 10). */
#define VMCB_CLEAN_BIT_TSC (1U << 10)

void timing_before_handler(PER_CPU_CTX *ctx) {
    if (!ctx || ctx->cpu_index >= TIMING_MAX_CPUS) return;
    g_timing[ctx->cpu_index].handler_entry_tsc = __rdtsc();
}

void timing_after_vmexit(PER_CPU_CTX *ctx) {
    ULONGLONG now;
    ULONGLONG delta;
    VMCB *vmcb;
    ULONG idx;

    if (!ctx || ctx->cpu_index >= TIMING_MAX_CPUS) return;
    idx = ctx->cpu_index;
    now = __rdtsc();
    if (g_timing[idx].handler_entry_tsc == 0 || now < g_timing[idx].handler_entry_tsc) {
        /* First call or timestamp rollback -- skip this update. */
        g_timing[idx].handler_entry_tsc = 0;
        return;
    }
    delta = now - g_timing[idx].handler_entry_tsc;
    g_timing[idx].handler_entry_tsc = 0;
    g_timing[idx].host_cycles_accumulated += delta;

    vmcb = (VMCB *)ctx->vmcb_va;
    if (!vmcb) return;

    vmcb->ctl.tsc_offset = (ULONGLONG)(-(LONGLONG)g_timing[idx].host_cycles_accumulated);
    vmcb->ctl.vmcb_clean_bits &= ~VMCB_CLEAN_BIT_TSC;
}

ULONGLONG timing_total_host_cycles(ULONG cpu_index) {
    if (cpu_index >= TIMING_MAX_CPUS) return 0;
    return g_timing[cpu_index].host_cycles_accumulated;
}
