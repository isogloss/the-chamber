/* timing.h -- per-CPU VMEXIT handler cycle accumulator for the VMCB TSC
 * offset. See timing.c. */
#pragma once
#include "the_chamber.h"
#include "svm.h"

#define TIMING_MAX_CPUS 256

typedef struct _PER_CPU_TIMING {
    ULONGLONG handler_entry_tsc;
    ULONGLONG host_cycles_accumulated;
} PER_CPU_TIMING;

extern PER_CPU_TIMING g_timing[TIMING_MAX_CPUS];

void      timing_before_handler(PER_CPU_CTX *ctx);
void      timing_after_vmexit(PER_CPU_CTX *ctx);
ULONGLONG timing_total_host_cycles(ULONG cpu_index);
