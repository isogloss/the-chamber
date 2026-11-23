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

/* Long-mode FS/GS base MSRs (IA32_FS_BASE / IA32_GS_BASE). */
#define MSR_IA32_FS_BASE     0xC0000100ULL
#define MSR_IA32_GS_BASE     0xC0000101ULL

/* Raw 8-byte GDT entry (code/data) and 16-byte TSS/LDT entry layout.
 * AMD APM Vol 2 §4.8, Intel SDM Vol 3A §3.4.5. */
#pragma pack(push, 1)
typedef struct _GDT_ENTRY64 {
    USHORT limit_low;
    USHORT base_low;
    UCHAR  base_mid;
    UCHAR  access;       /* P|DPL|S|type bits */
    UCHAR  flags_limit;  /* G|D/B|L|AVL|limit_high */
    UCHAR  base_high;
} GDT_ENTRY64;
#pragma pack(pop)

/* Decode one 8-byte GDT entry into VMCB_SEG (attrib / limit / base).
 * attrib: AMD APM Vol 2 Table 15-2 packs the 12 descriptor bits:
 *   bits 0-3  type
 *   bit  4    S
 *   bits 5-6  DPL
 *   bit  7    P
 *   bit  8    AVL
 *   bit  9    L
 *   bit 10    D/B
 *   bit 11    G
 * Byte 5 of the GDT holds P|DPL|S|type (bits 7..0 of the first attrib byte).
 * Byte 6 nibble high holds G|D/B|L|AVL (bits 4..7 of the second attrib byte). */
static void svm_decode_seg(USHORT selector, PVOID gdt_base, VMCB_SEG *out) {
    ULONG idx = (ULONG)(selector >> 3) & 0x1FFFU;
    GDT_ENTRY64 *e;
    ULONG lim;
    ULONGLONG base;
    USHORT attrib;

    out->selector = selector;
    out->attrib   = 0;
    out->limit    = 0;
    out->base     = 0;

    if (selector == 0 || gdt_base == NULL) {
        return;
    }

    e = (GDT_ENTRY64 *)((UCHAR *)gdt_base + ((SIZE_T)idx * sizeof(GDT_ENTRY64)));
    lim  = (ULONG)e->limit_low | (((ULONG)(e->flags_limit & 0x0Fu)) << 16);
    base = (ULONGLONG)e->base_low
         | ((ULONGLONG)e->base_mid  << 16)
         | ((ULONGLONG)e->base_high << 24);
    attrib = (USHORT)((e->access & 0xFFu) | (((USHORT)(e->flags_limit & 0xF0u)) << 4));
    if ((e->flags_limit & 0x80u) != 0) {
        /* G=1 means limit is in 4 KiB units: hardware reports limit_bytes =
         * (limit * 4096) + 0xFFF, but VMCB wants the raw 20-bit field. The
         * VMCB_SEG.limit is 32 bits and holds the raw limit value. */
    }
    out->limit  = lim;
    out->base   = base;
    out->attrib = attrib;
}

/* Long-mode system descriptor (TR, LDTR) is 16 bytes: the base straddles
 * the next 8-byte slot. */
static void svm_decode_sys_seg(USHORT selector, PVOID gdt_base, VMCB_SEG *out) {
    ULONG idx = (ULONG)(selector >> 3) & 0x1FFFU;
    GDT_ENTRY64 *lo;
    ULONG  *hi;
    ULONG   lim;
    ULONGLONG base;
    USHORT  attrib;

    out->selector = selector;
    out->attrib   = 0;
    out->limit    = 0;
    out->base     = 0;

    if (selector == 0 || gdt_base == NULL) {
        return;
    }

    lo = (GDT_ENTRY64 *)((UCHAR *)gdt_base + ((SIZE_T)idx * sizeof(GDT_ENTRY64)));
    hi = (ULONG *)((UCHAR *)gdt_base + ((SIZE_T)idx * sizeof(GDT_ENTRY64)) + 8);
    lim  = (ULONG)lo->limit_low | (((ULONG)(lo->flags_limit & 0x0Fu)) << 16);
    base = (ULONGLONG)lo->base_low
         | ((ULONGLONG)lo->base_mid  << 16)
         | ((ULONGLONG)lo->base_high << 24)
         | (((ULONGLONG)hi[0]) << 32);
    attrib = (USHORT)((lo->access & 0xFFu) | (((USHORT)(lo->flags_limit & 0xF0u)) << 4));
    out->limit  = lim;
    out->base   = base;
    out->attrib = attrib;
}

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
 * Zero bitmap means NO MSR intercepts, BUT per APM Vol 2 §15.11 any
 * MSR access outside the three MSRPM windows is unconditionally
 * intercepted regardless of bitmap contents.  So the only MSRs the
 * bitmap can affect are in-window addresses that we want the host to
 * see.  Out-of-window MSRs (e.g. Hyper-V 0x40000000+) will always exit
 * and be serviced by handle_msr; calling msrpm_set_intercept on them
 * is a no-op worth flagging. */
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
        /* Out-of-window: the MSR is already auto-intercepted and will
         * reach handle_msr via IVEC3_MSR.  Flag misuse via NT_ASSERT. */
        NT_ASSERT(FALSE);
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
                /* AMD 15.11: bitmap only matters for in-window MSRs.
                 * Hyper-V (0x40000000..) and KVM (0x4B564D00..) are
                 * outside all three windows and auto-intercept via
                 * IVEC3_MSR; handle_msr services them. */
                {
                    PUCHAR b = (PUCHAR)g_msrpm_va;
                    /* Core SVM-state hiding. */
                    msrpm_set_intercept(b, 0xC0000080ULL);  /* EFER */
                    msrpm_set_intercept(b, 0xC0010117ULL);  /* VM_HSAVE_PA */
                    msrpm_set_intercept(b, 0xC0010114ULL);  /* VM_CR */
                    /* SMM shadow registers: guest reads must return a
                     * bare-metal-looking default (0). */
                    msrpm_set_intercept(b, 0xC0010112ULL);  /* SMM_ADDR */
                    msrpm_set_intercept(b, 0xC0010113ULL);  /* SMM_MASK */
                    /* TSC_RATIO: return 8.32 fixed-point 1.0 so a guest
                     * that queries it reads the hardware default. */
                    msrpm_set_intercept(b, 0xC0000104ULL);  /* TSC_RATIO */
                    /* PMU: intercept every WRMSR to PerfEvtSelCoreN
                     * (even MSRs; odd PerfCtrCoreN stays passthrough and
                     * is shadowed inside the VMEXIT handler). Tracks
                     * which counters the guest armed so handle_rdpmc
                     * can serve the matching snapshot. */
                    msrpm_set_intercept(b, 0xC0010200ULL);  /* PerfEvtSelCore0 */
                    msrpm_set_intercept(b, 0xC0010202ULL);  /* PerfEvtSelCore1 */
                    msrpm_set_intercept(b, 0xC0010204ULL);  /* PerfEvtSelCore2 */
                    msrpm_set_intercept(b, 0xC0010206ULL);  /* PerfEvtSelCore3 */
                    msrpm_set_intercept(b, 0xC0010208ULL);  /* PerfEvtSelCore4 */
                    msrpm_set_intercept(b, 0xC001020AULL);  /* PerfEvtSelCore5 */
                    /* MSRs NOT intercepted here (deliberately passthrough):
                     *   0x48 SPEC_CTRL, 0x49 PRED_CMD       mitigation controls
                     *   0xE7 MPERF, 0xE8 APERF              frequency readouts
                     *   0x277 IA32_PAT                       guest-owned PAT
                     *   0xC0000103 TSC_AUX                  RDTSCP tag
                     *   0xC0010015 HWCR                     no SVM-state bits
                     *   0xC0010201/03/05/07/09/0B PerfCtrCore0..5
                     *   STAR/LSTAR/CSTAR/SFMASK/FS_BASE/GS_BASE/KernelGSBase
                     * handle_msr still services them when another exit
                     * route (e.g. out-of-window MSR) delivers them. */
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

    /* AMD 15.9: intercept CPUID and all MSR accesses (intercept vector 3).
     * Phase 2.1 PMU stealth also arms IVEC3_RDPMC (bit 15) so handle_rdpmc
     * serves counter reads from the per-CPU snapshot instead of the raw
     * PMC that drifted inside the handler. */
    ctl->intercept_vec3 |= IVEC3_CPUID | IVEC3_MSR | IVEC3_RDPMC;

    /* AMD 15.9 / 15.5.1: VMRUN must be intercepted; VMMCALL is the guest ->
     * host hypercall path (intercept vector 4).
     *
     * Deliberately NOT intercepted: VMLOAD, VMSAVE, CLGI, STGI, INVLPGA,
     * SKINIT, ICEBP, WBINVD, MONITOR, MWAIT, MWAIT_COND, XSETBV. Bare-metal
     * Zen 4 with SVM available delivers #GP(0) on each of these at CPL > 0
     * (XSETBV also faults on OSXSAVE=0); #UD only when SVM is unavailable
     * or EFER.SVME is clear. Letting hardware deliver the fault matches
     * what a probe at CPL 3 would see on a bare-metal box. OR'ing any of
     * the IVEC4_VMLOAD/VMSAVE/CLGI/STGI/SKINIT/MONITOR/MWAIT/MWAIT_COND/
     * XSETBV bits here would create a VMEXIT where bare metal would have
     * delivered a fault at the trojan instruction. Don't add them. */
    ctl->intercept_vec4 |= IVEC4_VMRUN | IVEC4_VMMCALL;

    /* No DR intercepts.  Phase 6.3 HW-breakpoint capture is out of scope
     * for passive dump; the HV has no use for guest DR0-DR3 state and
     * intercepting without a handler case produced noisy #UD injections
     * via the default arm (Wave 1.5 regression). Guest DR use remains
     * the guest's concern. */
    ctl->intercept_dr = 0;

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

    /* GDTR / IDTR base + limit (AMD 15.5.1) via sgdt / sidt. */
    _sgdt(&gdtr);
    save->gdtr.base  = gdtr.base;            /* AMD 15.5.1 GDTR base  */
    save->gdtr.limit = gdtr.limit;           /* AMD 15.5.1 GDTR limit */
    __sidt(&idtr);
    save->idtr.base  = idtr.base;            /* AMD 15.5.1 IDTR base  */
    save->idtr.limit = idtr.limit;           /* AMD 15.5.1 IDTR limit */

    /* Segment selector + attrib/limit/base (AMD 15.5.1). The selector alone
     * fails VMRUN consistency checks (CS P=0/L=0 rejected) and GS.Base=0
     * destroys the KPCR. Walk the GDT we just captured to decode each
     * descriptor; FS/GS base come from the long-mode base MSRs. */
    svm_decode_seg(svm_read_es(), (PVOID)gdtr.base, &save->es);
    svm_decode_seg(svm_read_cs(), (PVOID)gdtr.base, &save->cs);
    svm_decode_seg(svm_read_ss(), (PVOID)gdtr.base, &save->ss);
    svm_decode_seg(svm_read_ds(), (PVOID)gdtr.base, &save->ds);
    svm_decode_seg(svm_read_fs(), (PVOID)gdtr.base, &save->fs);
    svm_decode_seg(svm_read_gs(), (PVOID)gdtr.base, &save->gs);
    save->fs.base = __readmsr(MSR_IA32_FS_BASE);
    save->gs.base = __readmsr(MSR_IA32_GS_BASE);
    svm_decode_sys_seg(svm_read_ldtr(), (PVOID)gdtr.base, &save->ldtr);
    svm_decode_sys_seg(svm_read_tr(),   (PVOID)gdtr.base, &save->tr);

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

    /* vmrun.asm overwrites save->rsp with the caller's live RSP before
     * every VMRUN, so this initial value is only a placeholder. */
    save->rsp = 0;

    /* AMD 15.15.1: on a full VMCB write set vmcb_clean_bits = ~0u so
     * hardware reloads nothing it has cached; update paths then clear
     * only the groups whose fields changed (see timing.c for an
     * example of clearing the Intercepts bit after a tsc_offset
     * write). */
    ctl->vmcb_clean_bits = ~0u;

    /* CHAMBER_LOG unsafe at IPI_LEVEL -- DbgPrintEx acquires pool locks
     * and may block.  First-CPU summary logged by svm_init_all_cpus
     * once the broadcast returns. */
}
