/* identity.h -- seed-derived machine-identity format wrappers and
 * per-vCPU identity lookup tables.
 *
 * Two surfaces live here:
 *
 *   1. identity_compute_all(): called by the installer's patcher to
 *      expand a 32-byte master seed into a fully populated
 *      CHAMBER_CFG_V2 blob before signing. Driver code never calls it;
 *      the driver reads the already-expanded blob written by the
 *      patcher. Exposed in this header so a shared build between the
 *      patcher and the driver source tree pulls one definition.
 *
 *   2. identity_apply() + identity_get_* helpers: called once from the
 *      driver at DriverEntry after SVM bringup, to materialize per-vCPU
 *      identity values (APIC ID, TSC_AUX latch) and single-valued
 *      derived state (microcode revision, platform ID, CPU signature,
 *      TSC/clock frequency fields) from the cfg blob. VMEXIT handlers
 *      consult identity_get_* at rewrite time.
 *
 * The HV driver never touches g_cpu_identity outside identity.c and the
 * handful of VMEXIT getters; the table is sized to g_cpu_count and
 * allocated at init. */

#ifndef CHAMBER_IDENTITY_H
#define CHAMBER_IDENTITY_H

#include "the_chamber.h"
#include "crypt.h"

/* Per-vCPU runtime identity state. Stored in a parallel array indexed by
 * cpu number (same index as g_cpu_ctx), so PER_CPU_CTX stays untouched
 * and vmrun.asm's hardcoded offsets remain valid. */
typedef struct _CHAMBER_CPU_IDENTITY {
    ULONG     apic_id;                 /* CPUID 0x1 EBX[31:24] */
    ULONG     x2apic_id;               /* CPUID 0xB/0x1F EDX */
    ULONGLONG tsc_aux_latched;         /* MSR 0xC0000103 */
    BOOLEAN   tsc_aux_latched_valid;   /* set on first guest WRMSR */
    UCHAR     pad[7];
} CHAMBER_CPU_IDENTITY;

/* Allocated by identity_apply at PASSIVE_LEVEL; sized to g_cpu_count. */
extern CHAMBER_CPU_IDENTITY *g_cpu_identity;

/* Single-valued derived state, computed once in identity_apply. */
extern ULONGLONG g_identity_microcode_rev;   /* MSR 0x8B upper 32 (patch level) */
extern ULONGLONG g_identity_platform_id;     /* MSR 0x17 */
extern ULONG     g_identity_cpu_signature;   /* CPUID 0x1 EAX */
extern ULONG     g_identity_cpu_ext_feat_ecx; /* CPUID 0x80000001 ECX */
extern ULONG     g_identity_cpu_ext_feat_edx; /* CPUID 0x80000001 EDX */
extern ULONG     g_identity_tsc_denom;       /* CPUID 0x15 EAX */
extern ULONG     g_identity_tsc_numer;       /* CPUID 0x15 EBX */
extern ULONG     g_identity_tsc_crystal;     /* CPUID 0x15 ECX */
extern ULONG     g_identity_cpu_base_mhz;    /* CPUID 0x16 EAX */
extern ULONG     g_identity_cpu_max_mhz;     /* CPUID 0x16 EBX */
extern ULONG     g_identity_cpu_bus_mhz;     /* CPUID 0x16 ECX */
extern BOOLEAN   g_identity_valid;           /* TRUE after successful apply */

/* Full installer-side expansion. Derives every seed-controlled field of
 * CHAMBER_CFG_V2 out of cfg->seed; does NOT touch magic/version/total_length
 * (installer owns those) and does NOT overwrite the toggle bits. Returns
 * STATUS_SUCCESS; shaped as NTSTATUS for driver-side callers that want a
 * uniform error channel. */
NTSTATUS identity_compute_all(const UCHAR seed[32], CHAMBER_CFG_V2 *cfg);

/* Driver-side initialization. Call after svm_init_all_cpus (so g_cpu_ctx
 * and g_cpu_count are both populated). Allocates g_cpu_identity, derives
 * the single-valued state from cfg->seed, and seeds per-vCPU tsc_aux
 * latches with seed-stable initial values (overwritten by the first guest
 * WRMSR). Returns STATUS_INSUFFICIENT_RESOURCES if allocation fails. */
NTSTATUS identity_apply(const CHAMBER_CFG_V2 *cfg);

/* Teardown pair for identity_apply; called from UnloadRoutine. */
void identity_release(void);

/* VMEXIT-time getters. Bounded by vcpu < g_cpu_count; callers check or
 * the implementation returns 0 on an out-of-range index. */
ULONG      identity_get_apic_id(ULONG vcpu);
ULONG      identity_get_x2apic_id(ULONG vcpu);
ULONGLONG  identity_get_tsc_aux(ULONG vcpu);
void       identity_set_tsc_aux(ULONG vcpu, ULONGLONG value);

#endif /* CHAMBER_IDENTITY_H */
