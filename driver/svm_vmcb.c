/* svm_vmcb.c -- AMD SVM VMCB builder.
 * Reference: AMD64 APM Vol 2, Ch 15 (SVM), Tables 15-1 (control area) and
 * 15-3 (state-save area). Target: AMD Zen 4 (Ryzen 7 7700X, family 19h).
 *
 * Builds one guest VMCB that mirrors the current (host) processor state, so a
 * VMRUN resumes the running system in guest context with Nested Paging active.
 *
 * ASCII only. American spelling. Ring-0 (WDK) build only.
 */
#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "the_chamber.h"
#include "svm.h"

/* ---- MSR numbers needed for the state-save mirror (AMD Appendix A / 15.5) ---- */
#define MSR_IA32_PAT         0x00000277ULL   /* G_PAT          */
#define MSR_STAR             0xC0000081ULL   /* legacy SYSCALL  */
#define MSR_LSTAR            0xC0000082ULL   /* long-mode RIP   */
#define MSR_CSTAR            0xC0000083ULL   /* compat RIP      */
#define MSR_SFMASK           0xC0000084ULL   /* SYSCALL flags   */
#define MSR_KERNEL_GS_BASE   0xC0000102ULL   /* KernelGSBase    */

/* Permission bitmap sizes.
 * AMD 15.11:   MSR permission map (MSRPM) is 8 KiB (2 pages).
 * AMD 15.10.2: I/O permission map (IOPM) is 12 KiB (3 pages). */
#define SVM_MSRPM_SIZE   (2 * PAGE_SIZE)
#define SVM_IOPM_SIZE    (3 * PAGE_SIZE)

/* Cached, process-lifetime permission bitmaps shared by every CPU's VMCB.
 * Both are all-zero (no MSR/IO intercepts beyond the vector-3 blanket), so a
 * single physically contiguous copy is referenced by every guest_asid context.
 * Freed by svm_free_bitmaps() during teardown. */
static PVOID     g_msrpm_va = NULL;
static ULONGLONG g_msrpm_pa = 0;
static PVOID     g_iopm_va  = NULL;
static ULONGLONG g_iopm_pa  = 0;

/* Pseudo-descriptor written by sgdt/sidt (AMD 15.5.1, 2-byte limit + base). */
#pragma pack(push, 1)
typedef struct _SVM_DESC_PTR {
    USHORT    limit;
    ULONGLONG base;
} SVM_DESC_PTR;
#pragma pack(pop)

/* Segment-selector reads. MSVC for x64 does not support inline __asm, so the
 * selector loads that AMD 15.5.1 requires are provided by the companion
 * assembly module (same module as svm_launch / vmrun.asm). */
extern USHORT svm_read_es(void);
extern USHORT svm_read_cs(void);
extern USHORT svm_read_ss(void);
extern USHORT svm_read_ds(void);
extern USHORT svm_read_fs(void);
extern USHORT svm_read_gs(void);
extern USHORT svm_read_ldtr(void);
extern USHORT svm_read_tr(void);

/* ------------------------------------------------------------------------- */
/* Permission bitmaps                                                        */
/* ------------------------------------------------------------------------- */

static PVOID svm_alloc_contig_zeroed(SIZE_T size, ULONGLONG *out_pa) {
    PHYSICAL_ADDRESS highest, boundary, lowest;
    PHYSICAL_ADDRESS pa;
    PVOID p;

    lowest.QuadPart = 0;
    boundary.QuadPart = 0;
    highest.QuadPart = (LONGLONG)-1;
    p = MmAllocateContiguousMemorySpecifyCache(size, lowest, highest, boundary, MmCached);
    if (!p) {
        return NULL;
    }
    RtlZeroMemory(p, size);
    pa = MmGetPhysicalAddress(p);
    *out_pa = (ULONGLONG)pa.QuadPart;
    return p;
}

/* Allocate the shared bitmaps on first use. Guarded so a simultaneous
 * KeIpiGenericCall broadcast (all CPUs build at once) allocates exactly once.
 * NOTE: MmAllocateContiguousMemorySpecifyCache requires PASSIVE_LEVEL; warm
 * these once at PASSIVE_LEVEL before the bringup broadcast. */
/* AMD 15.11: MSRPM bit 0 = intercept RDMSR, bit 1 = intercept WRMSR.
 * Zero bitmap means NO MSR intercepts. We must set specific bits for the
 * MSRs we want vmexit_handler to service. */
static void msrpm_set_intercept(PUCHAR bitmap, ULONGLONG msr) {
    ULONG region;
    ULONG offset_msr;
    ULONG bit_pos;
    ULONG byte_idx;
    if (msr <= 0x1FFFULL) {
        region = 0;
        offset_msr = (ULONG)msr;
    } else if (msr >= 0xC0000000ULL && msr <= 0xC0001FFFULL) {
        region = 1;
        offset_msr = (ULONG)(msr - 0xC0000000ULL);
    } else if (msr >= 0xC0010000ULL && msr <= 0xC0011FFFULL) {
        region = 2;
        offset_msr = (ULONG)(msr - 0xC0010000ULL);
    } else {
        return;
    }
    bit_pos = offset_msr * 2;
    byte_idx = (region * 0x800) + (bit_pos / 8);
    bitmap[byte_idx] |= (UCHAR)(0x3 << (bit_pos & 7));
}

static void svm_ensure_bitmaps(void) {
    PVOID p;
    ULONGLONG pa;

    if (g_msrpm_va == NULL) {
        p = svm_alloc_contig_zeroed(SVM_MSRPM_SIZE, &pa);
        if (p != NULL) {
            if (InterlockedCompareExchangePointer(&g_msrpm_va, p, NULL) != NULL) {
                MmFreeContiguousMemory(p);
            } else {
                g_msrpm_pa = pa;
                /* Populate specific MSR intercepts (AMD 15.11). Otherwise a
                 * zero bitmap = no intercept and handle_msr is dead code. */
                {
                    PUCHAR b = (PUCHAR)g_msrpm_va;
                    ULONGLONG m;
                    msrpm_set_intercept(b, 0xC0000080ULL);  /* EFER */
                    msrpm_set_intercept(b, 0xC0010117ULL);  /* VM_HSAVE_PA */
                    msrpm_set_intercept(b, 0xC0010114ULL);  /* VM_CR */
                    for (m = 0x40000000ULL; m <= 0x400000FFULL; m++) {
                        msrpm_set_intercept(b, m);
                    }
                }
            }
        }
    }
    if (g_iopm_va == NULL) {
        p = svm_alloc_contig_zeroed(SVM_IOPM_SIZE, &pa);
        if (p != NULL) {
            if (InterlockedCompareExchangePointer(&g_iopm_va, p, NULL) != NULL) {
                MmFreeContiguousMemory(p);
            } else {
                g_iopm_pa = pa;
            }
        }
    }
}

/* Public wrapper: call at PASSIVE_LEVEL during driver init, before any IPI. */
NTSTATUS svm_init_bitmaps(void) {
    svm_ensure_bitmaps();
    if (!g_msrpm_va || !g_iopm_va) return STATUS_INSUFFICIENT_RESOURCES;
    return STATUS_SUCCESS;
}

VOID svm_free_bitmaps(void) {
    if (g_msrpm_va != NULL) {
        MmFreeContiguousMemory(g_msrpm_va);
        g_msrpm_va = NULL;
        g_msrpm_pa = 0;
    }
    if (g_iopm_va != NULL) {
        MmFreeContiguousMemory(g_iopm_va);
        g_iopm_va = NULL;
        g_iopm_pa = 0;
    }
}

/* ------------------------------------------------------------------------- */
/* VMCB builder                                                              */
/* ------------------------------------------------------------------------- */

void svm_build_vmcb(PER_CPU_CTX *ctx) {
    VMCB                 *vmcb = (VMCB *)ctx->vmcb_va;
    VMCB_CONTROL_AREA    *ctl  = &vmcb->ctl;
    VMCB_STATE_SAVE_AREA *save = &vmcb->save;
    SVM_DESC_PTR gdtr, idtr;

    RtlZeroMemory(vmcb, sizeof(VMCB));

    /* ======================= Control area (Table 15-1) ================== */

    /* AMD 15.9: intercept CPUID and all MSR accesses (intercept vector 3). */
    ctl->intercept_vec3 |= IVEC3_CPUID | IVEC3_MSR;

    /* AMD 15.9 / 15.5.1: VMRUN must be intercepted; VMMCALL is the guest ->
     * host hypercall path (intercept vector 4). */
    ctl->intercept_vec4 |= IVEC4_VMRUN | IVEC4_VMMCALL;

    /* AMD 15.11 / 15.10.2: install the shared (all-zero) permission bitmaps. */
    svm_ensure_bitmaps();
    ctl->msrpm_base_pa = g_msrpm_pa;   /* AMD 15.11   MSR permission map  */
    ctl->iopm_base_pa  = g_iopm_pa;    /* AMD 15.10.2 I/O permission map  */

    /* AMD 15.16.1: guest ASID must be non-zero for TLB tagging. */
    ctl->guest_asid_tlb = 1;

    /* AMD 15.25.3: enable Nested Paging and install the NPT top-level table. */
    ctl->np_enable = NP_ENABLE;
    ctl->n_cr3     = g_npt_cr3_pa;

    /* ==================== State-save area (Table 15-3) ================== */

    /* Segment selectors (AMD 15.5.1) via the companion assembly readers. */
    save->es.selector   = svm_read_es();     /* AMD 15.5.1 ES selector   */
    save->cs.selector   = svm_read_cs();     /* AMD 15.5.1 CS selector   */
    save->ss.selector   = svm_read_ss();     /* AMD 15.5.1 SS selector   */
    save->ds.selector   = svm_read_ds();     /* AMD 15.5.1 DS selector   */
    save->fs.selector   = svm_read_fs();     /* AMD 15.5.1 FS selector   */
    save->gs.selector   = svm_read_gs();     /* AMD 15.5.1 GS selector   */
    save->ldtr.selector = svm_read_ldtr();   /* AMD 15.5.1 LDTR selector */
    save->tr.selector   = svm_read_tr();     /* AMD 15.5.1 TR selector   */

    /* GDTR / IDTR base + limit (AMD 15.5.1) via sgdt / sidt. */
    _sgdt(&gdtr);
    save->gdtr.base  = gdtr.base;            /* AMD 15.5.1 GDTR base  */
    save->gdtr.limit = gdtr.limit;           /* AMD 15.5.1 GDTR limit */
    __sidt(&idtr);
    save->idtr.base  = idtr.base;            /* AMD 15.5.1 IDTR base  */
    save->idtr.limit = idtr.limit;           /* AMD 15.5.1 IDTR limit */

    /* Control registers (AMD 15.5.1). */
    save->cr0 = __readcr0();                 /* AMD 15.5.1 CR0 */
    save->cr3 = __readcr3();                 /* AMD 15.5.1 CR3 */
    save->cr4 = __readcr4();                 /* AMD 15.5.1 CR4 */

    /* Debug registers (AMD 15.5.1). */
    save->dr6 = __readdr(6);                 /* AMD 15.5.1 DR6 */
    save->dr7 = __readdr(7);                 /* AMD 15.5.1 DR7 */

    /* RFLAGS (AMD 15.5.1). */
    save->rflags = __readeflags();           /* AMD 15.5.1 RFLAGS */

    /* Model-specific registers mirrored into the save area (AMD 15.5.1). */
    save->efer           = __readmsr(SVM_MSR_EFER);         /* AMD 15.5.1 EFER          */
    save->star           = __readmsr(MSR_STAR);             /* AMD 15.5.1 STAR          */
    save->lstar          = __readmsr(MSR_LSTAR);            /* AMD 15.5.1 LSTAR         */
    save->cstar          = __readmsr(MSR_CSTAR);            /* AMD 15.5.1 CSTAR         */
    save->sfmask         = __readmsr(MSR_SFMASK);           /* AMD 15.5.1 SFMASK        */
    save->kernel_gs_base = __readmsr(MSR_KERNEL_GS_BASE);   /* AMD 15.5.1 KernelGSBase  */
    save->g_pat          = __readmsr(MSR_IA32_PAT);         /* AMD 15.5.1 G_PAT         */

    /* AMD 15.5.1: RIP is patched by vmrun.asm to the guest entry point. */
    save->rip = 0;

    /* AMD 15.5.1: guest RSP = top of this CPU's private host stack. */
    save->rsp = (ULONGLONG)((ULONG_PTR)ctx->host_stack_va + ctx->host_stack_size);

    CHAMBER_LOG("VMCB built CPU %u (msrpm=%llx, iopm=%llx, n_cr3=%llx, rsp=%llx)\n",
                ctx->cpu_index, g_msrpm_pa, g_iopm_pa, (ULONGLONG)ctl->n_cr3, save->rsp);
}
