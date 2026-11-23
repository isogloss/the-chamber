/* vmexit.c -- THE_CHAMBER #VMEXIT dispatcher.
 *
 * Entered from vmrun.asm after each guest #VMEXIT, with the shadow GPR
 * save area (ctx->gpr_save) already populated. Decodes vmcb->ctl.exit_code
 * and services the intercepted event per AMD64 APM Vol 2, Chapter 15.
 *
 * GPR save index map (see the_chamber.h):
 *   0=rax 1=rbx 2=rcx 3=rdx 4=rsi 5=rdi 6=rbp 7=rsp 8..15=r8..r15
 * rax lives authoritatively in vmcb->save.rax (loaded/stored by VMRUN).
 *
 * No-migration rule (RDTSCP consistency): the handler runs on the physical
 * CPU that trapped. Nothing here issues an IPI, queues a DPC that migrates
 * work to another CPU, or otherwise causes the guest to resume on a
 * different CPU than the one that VMEXITed. Guest RDTSCP therefore
 * reads back a stable TSC_AUX across intercepts, as it would on bare
 * metal with a pinned thread.
 *
 * No-inline-patch rule: this file never patches guest instructions. All
 * hooks (when Phase 6 adds them) go through NPT split-view -- the HV
 * swaps the physical page under the guest's read instead of modifying
 * its text. Keeps the guest-visible code bytes stable, which matters for
 * PatchGuard's tracked-module hashes and for integrity-check probes.
 */

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "the_chamber.h"
#include "svm.h"
#include "timing.h"
#include "npt.h"
#include "dump.h"
#include "dump_trigger.h"
#include "integrity.h"
#include "identity.h"

volatile ULONGLONG g_vmexit_count = 0;

static void handle_cpuid(PER_CPU_CTX *ctx, VMCB *vmcb);
static void handle_msr(PER_CPU_CTX *ctx, VMCB *vmcb);
static void handle_rdpmc(PER_CPU_CTX *ctx, VMCB *vmcb);
static void handle_vmmcall(PER_CPU_CTX *ctx, VMCB *vmcb);
static void handle_npf(PER_CPU_CTX *ctx, VMCB *vmcb);

/* Zen 4 extended Core PMC: PerfCtrCoreI lives at the odd MSR
 * 0xC0010201 + 2*i. Six counters total on family 19h. */
#define PMC_CTR_MSR(i)   (0xC0010201ULL + 2ULL * (ULONGLONG)(i))

/* Snapshot every armed counter at VMEXIT entry so values accrued by the
 * handler do not leak into subsequent guest RDPMC/__readmsr. */
static void pmu_snapshot_in(PER_CPU_CTX *ctx)
{
    ULONG i;
    for (i = 0; i < 6; i++) {
        if (ctx->guest_pmc_armed[i]) {
            __try {
                ctx->guest_pmc_snapshot[i] = __readmsr(PMC_CTR_MSR(i));
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
    }
}

/* Restore the snapshot before VMRUN so the guest resumes with the same
 * counter value it had at VMEXIT. Handler-side increments are discarded. */
static void pmu_snapshot_out(PER_CPU_CTX *ctx)
{
    ULONG i;
    for (i = 0; i < 6; i++) {
        if (ctx->guest_pmc_armed[i]) {
            __try {
                __writemsr(PMC_CTR_MSR(i), ctx->guest_pmc_snapshot[i]);
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
    }
}

/* AMD Table 15-5 event_inject layout:
 *   bits 0-7   : vector (6 = #UD)
 *   bits 8-10  : type  (3 = exception)
 *   bit  11    : error-code valid
 *   bit  31    : valid
 *   bits 32-63 : error code
 *
 * Inject #UD at current RIP without advancing it; the processor
 * re-fetches the faulting instruction after guest resume. */
static void vmexit_inject_ud(VMCB *vmcb)
{
    vmcb->ctl.event_inject = (1ULL << 31) | (3ULL << 8) | 6ULL;
}

/* ------------------------------------------------------------------ */
/* Top-level dispatcher.                                              */
/* ------------------------------------------------------------------ */

void vmexit_handler(PER_CPU_CTX *ctx)
{
    VMCB *vmcb;
    ULONGLONG exit_code;

    InterlockedIncrement64((LONG64 *)&g_vmexit_count);

    vmcb = (VMCB *)ctx->vmcb_va;
    exit_code = vmcb->ctl.exit_code;

    /* Freeze every armed guest counter at its current value before any
     * handler-side RDMSR/WRMSR touches the PMU hardware. Paired with
     * pmu_snapshot_out at function exit. */
    pmu_snapshot_in(ctx);

    switch (exit_code) {
    case VMEXIT_CPUID:
        handle_cpuid(ctx, vmcb);
        break;

    case VMEXIT_MSR:
        handle_msr(ctx, vmcb);
        break;

    case VMEXIT_RDPMC:
        handle_rdpmc(ctx, vmcb);
        break;

    case VMEXIT_VMMCALL:
        handle_vmmcall(ctx, vmcb);
        break;

    case VMEXIT_NPF:
        handle_npf(ctx, vmcb);
        break;

    default:
        /* next_rip is architecturally defined ONLY for the decoded
         * intercepts (CPUID / IOIO / MSR / VMMCALL / INVD / INVLPG /
         * HLT / MONITOR / MWAIT / RDTSC / RDTSCP).  For VMEXIT_INVALID
         * (-1), fault-class exits, and anything else, advancing RIP
         * to next_rip jumps the guest into undefined memory and
         * infinite-loops via immediate re-exit.  Inject #UD at the
         * current RIP instead so the guest sees a deterministic
         * invalid-opcode fault at the responsible instruction. */
        CHAMBER_LOG("unhandled VMEXIT code=%llx info1=%llx info2=%llx\n",
                    exit_code, vmcb->ctl.exit_info_1, vmcb->ctl.exit_info_2);
        vmexit_inject_ud(vmcb);
        break;
    }

    /* Restore the guest PMC values before VMRUN so counts the handler
     * ran up are invisible on the next guest-side RDMSR/RDPMC. Paired
     * with pmu_snapshot_in at function entry. */
    pmu_snapshot_out(ctx);

    /* Phase 1.2: no more per-handler timing hooks here. vmrun.asm captures
     * the host-interval START right after `vmrun rax` returns (before
     * vmsave) and the host-interval END just before the next `vmrun rax`
     * (after any vmload); it then calls timing_update(ctx) which folds the
     * delta plus g_fixed_vmexit_cost into the global accumulator and
     * refreshes this CPU's VMCB tsc_offset. */
}

/* ------------------------------------------------------------------ */
/* CPUID interception (AMD 15.8).                                     */
/* ------------------------------------------------------------------ */

/* TRUE when the launcher's seed-derived identity blob is live and the
 * machine-identity spoof toggle is set. Guards every seed-driven
 * CPUID rewrite path so an un-patched developer build still returns
 * raw host values. */
static BOOLEAN identity_rewrites_enabled(void)
{
    return g_chamber_cfg_v2_valid && g_identity_valid &&
           ((g_chamber_cfg_v2.toggles &
             CHAMBER_TOGGLE_MACHINE_IDENTITY_SPOOF) != 0);
}

/* Pack 16 bytes of the 48-byte cpu_brand_string into EAX/EBX/ECX/EDX for
 * one of the three brand-string leaves (0x80000002..4). `slot` is the
 * zero-based leaf offset: 0 for 0x80000002, 1 for 0x80000003, 2 for
 * 0x80000004. Each of the four registers receives 4 consecutive bytes,
 * little-endian (byte 0 goes in bits 7:0 of EAX). */
static void brand_slot_to_regs(ULONG slot, int regs[4])
{
    const UCHAR *base = &g_chamber_cfg_v2.cpu_brand_string[slot * 16];
    ULONG i, r;
    for (r = 0; r < 4; r++) {
        ULONG v = 0;
        for (i = 0; i < 4; i++) {
            v |= ((ULONG)base[r * 4 + i]) << (i * 8);
        }
        regs[r] = (int)v;
    }
}

/* CPUID 0x1 EBX layout: EBX[31:24] initial APIC ID. */
static void rewrite_leaf_1(PER_CPU_CTX *ctx, int regs[4])
{
    ULONG apic = identity_get_apic_id(ctx->cpu_index) & 0xFFu;
    ULONG ebx = (ULONG)regs[1];
    ebx = (ebx & 0x00FFFFFFu) | (apic << 24);
    regs[1] = (int)ebx;
    if (g_identity_cpu_signature) regs[0] = (int)g_identity_cpu_signature;
    /* Clear the hypervisor-present bit (ECX[31]). */
    regs[2] &= ~(1u << 31);
}

/* CPUID 0x7 subleaf 0: extended feature flags. Mask off bits that would
 * leak uArch generation across the rewrite. For now we pass the host
 * flags unchanged; a future pass can trim features that correlate with
 * the chosen brand. */
static void rewrite_leaf_7(int regs[4])
{
    (void)regs;
}

/* CPUID 0xB / 0x1F extended topology: EDX carries the x2APIC ID. */
static void rewrite_leaf_topology(PER_CPU_CTX *ctx, int regs[4])
{
    regs[3] = (int)identity_get_x2apic_id(ctx->cpu_index);
}

/* CPUID 0x15 TSC/crystal ratio. */
static void rewrite_leaf_15(int regs[4])
{
    regs[0] = (int)g_identity_tsc_denom;
    regs[1] = (int)g_identity_tsc_numer;
    regs[2] = (int)g_identity_tsc_crystal;
    regs[3] = 0;
}

/* CPUID 0x16 processor frequency fields (MHz). */
static void rewrite_leaf_16(int regs[4])
{
    regs[0] = (int)(g_identity_cpu_base_mhz & 0xFFFFu);
    regs[1] = (int)(g_identity_cpu_max_mhz  & 0xFFFFu);
    regs[2] = (int)(g_identity_cpu_bus_mhz  & 0xFFFFu);
    regs[3] = 0;
}

/* CPUID 0x80000001 extended feature flags: overlay seed-derived ECX/EDX
 * bits onto the host-reported baseline so a reseed shifts observable
 * extended features without turning any bit on that the host lacks. */
static void rewrite_leaf_80000001(int regs[4])
{
    ULONG host_ecx = (ULONG)regs[2];
    ULONG host_edx = (ULONG)regs[3];
    /* Mask the overlay to the host's advertised bits; never claim a
     * feature the hardware does not support. */
    regs[2] = (int)(host_ecx & (host_ecx ^ g_identity_cpu_ext_feat_ecx));
    regs[3] = (int)(host_edx & (host_edx ^ g_identity_cpu_ext_feat_edx));
    /* Union with host feature set so core capabilities (LM, SYSCALL,
     * NX, LAHF, SSE4A) stay reported; the overlay only shifts the
     * uncovered high-bit landscape. */
    regs[2] = (int)((ULONG)regs[2] | (host_ecx & 0x000003FFu));
    regs[3] = (int)((ULONG)regs[3] | (host_edx & 0x3FFFFFFFu));
}

/* CPUID 0x8000001F SEV/SME capability: must always report SEV off so
 * the HV's own use of SVM does not leak. Design doc rule. */
static void rewrite_leaf_8000001F(int regs[4])
{
    regs[0] &= ~0x7;  /* EAX[0]=SME, EAX[1]=SEV, EAX[2]=Page flush */
    regs[1] = 0;
    regs[2] = 0;
    regs[3] = 0;
}

static void handle_cpuid(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONG leaf = (ULONG)vmcb->save.rax;
    ULONG subleaf = (ULONG)ctx->gpr_save[2];   /* rcx */
    int regs[4];
    BOOLEAN rewrite = identity_rewrites_enabled();

    __cpuidex(regs, (int)leaf, (int)subleaf);

    if (leaf == 1) {
        if (rewrite) {
            rewrite_leaf_1(ctx, regs);
        } else {
            /* Minimum: clear hypervisor-present bit (ECX[31]). */
            regs[2] &= ~(1u << 31);
        }
    } else if (leaf == 7 && subleaf == 0) {
        if (rewrite) rewrite_leaf_7(regs);
    } else if (leaf == 0xB || leaf == 0x1F) {
        if (rewrite) rewrite_leaf_topology(ctx, regs);
    } else if (leaf == 0x15) {
        if (rewrite) rewrite_leaf_15(regs);
    } else if (leaf == 0x16) {
        if (rewrite) rewrite_leaf_16(regs);
    } else if (leaf == 0x80000001U) {
        if (rewrite) rewrite_leaf_80000001(regs);
    } else if (leaf == 0x80000002U) {
        if (rewrite) brand_slot_to_regs(0, regs);
    } else if (leaf == 0x80000003U) {
        if (rewrite) brand_slot_to_regs(1, regs);
    } else if (leaf == 0x80000004U) {
        if (rewrite) brand_slot_to_regs(2, regs);
    } else if (leaf == 0x80000008U) {
        /* EAX[7:0] physical address bits, EAX[15:8] virtual address bits,
         * ECX[7:0] NC (logical processor count minus 1). Pass through for
         * now; the identity table does not currently vary core count. */
    } else if (leaf == 0x8000001DU || leaf == 0x8000001EU) {
        /* Cache / core topology extended. Pass through unchanged — the
         * identity rewrite varies APIC IDs and brand string, not core
         * topology. */
    } else if (leaf == 0x8000001FU) {
        /* Must zero SEV/SME regardless of rewrite toggle: the HV's own
         * SVM use should never leak a hardware SEV advertisement to the
         * guest. */
        rewrite_leaf_8000001F(regs);
    }

    if (leaf >= 0x40000000U && leaf <= 0x4FFFFFFFU) {
        /* Zero the entire hypervisor-reserved range so VMAware / pafish
         * probes at well-known leaves (0x40000080, 0x40000100) see the
         * same all-zero response bare-metal AMD returns. */
        regs[0] = 0;
        regs[1] = 0;
        regs[2] = 0;
        regs[3] = 0;
    }

    vmcb->save.rax = (ULONGLONG)(ULONG)regs[0];   /* eax */
    ctx->gpr_save[1] = (ULONGLONG)(ULONG)regs[1]; /* ebx */
    ctx->gpr_save[2] = (ULONGLONG)(ULONG)regs[2]; /* ecx */
    ctx->gpr_save[3] = (ULONGLONG)(ULONG)regs[3]; /* edx */

    /* CPUID is a DECODED intercept: next_rip is architecturally valid.
     * On Zen 4 CPUID 8000_000A EDX bit 3 (NRIP_SAVE) is set, so the
     * processor populates next_rip for this exit. See handle_npf() for
     * the list of other exits where next_rip is valid and the full list
     * of fault-class exits where it is NOT. */
    vmcb->save.rip = vmcb->ctl.next_rip;
}

/* ------------------------------------------------------------------ */
/* RDPMC interception (AMD 15.9, IVEC3 bit 15).                       */
/* ------------------------------------------------------------------ */

/* Return the shadowed counter value stashed by pmu_snapshot_in so the
 * guest never observes host-side counts accrued during VMEXIT handling.
 * Minimum-viable handler: emit the snapshot directly. A future pass may
 * fold in a cycle-delta approximation to estimate counts that would have
 * accrued natively during the host window. */
static void handle_rdpmc(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONG     idx = (ULONG)ctx->gpr_save[2] & 0x7U;   /* rcx low bits */
    ULONGLONG val = 0;

    if (idx < 6) {
        val = ctx->guest_pmc_snapshot[idx];
    }

    vmcb->save.rax   = (ULONGLONG)(ULONG)val;
    ctx->gpr_save[3] = (ULONGLONG)(ULONG)(val >> 32);

    /* RDPMC is one of the decoded intercepts with next_rip populated. */
    vmcb->save.rip = vmcb->ctl.next_rip;
}

/* ------------------------------------------------------------------ */
/* MSR interception (AMD 15.11).                                      */
/* ------------------------------------------------------------------ */

/* MSRs we service on behalf of the guest with explicit host-visible side
 * effects.  Every other MSR path returns 0 on RDMSR and absorbs WRMSR
 * so a guest sweep of the MSR space cannot bugcheck the host.
 *
 * The identity MSRs (0x17, 0x8B, 0xC0000103, 0xC0010015) are listed
 * here so the SEH-wrapped pass branch stays reachable in case the
 * dedicated rewrite short-circuits are ever disabled; the normal path
 * handles them before this allowlist is consulted. */
static BOOLEAN handle_msr_allowlist_pass(ULONG msr)
{
    switch (msr) {
    case 0x00000010UL:   /* IA32_TIME_STAMP_COUNTER      */
    case 0x00000017UL:   /* IA32_PLATFORM_ID             */
    case 0x0000001BUL:   /* IA32_APIC_BASE               */
    case 0x00000048UL:   /* SPEC_CTRL                    */
    case 0x00000049UL:   /* PRED_CMD                     */
    case 0x0000008BUL:   /* IA32_BIOS_SIGN_ID            */
    case 0x000000E7UL:   /* MPERF                        */
    case 0x000000E8UL:   /* APERF                        */
    case 0x000000FEUL:   /* IA32_MTRRCAP                 */
    case 0x00000277UL:   /* IA32_PAT                     */
    case 0x000002FFUL:   /* IA32_MTRR_DEF_TYPE           */
    case 0xC0000080UL:   /* IA32_EFER                    */
    case 0xC0000081UL:   /* STAR                         */
    case 0xC0000082UL:   /* LSTAR                        */
    case 0xC0000083UL:   /* CSTAR                        */
    case 0xC0000084UL:   /* SFMASK                       */
    case 0xC0000100UL:   /* FS_BASE                      */
    case 0xC0000101UL:   /* GS_BASE                      */
    case 0xC0000102UL:   /* KERNEL_GS_BASE               */
    case 0xC0000103UL:   /* TSC_AUX (RDTSCP tag)         */
    case 0xC0010015UL:   /* HWCR (no SVM-state bits)     */
        return TRUE;
    default:
        return FALSE;
    }
}

/* Return TRUE if the MSR is one of the identity-rewrite set. The
 * per-MSR handler short-circuits before __readmsr / __writemsr is
 * called, so none of these ever reaches real hardware from the guest
 * side when the machine-identity spoof toggle is set. */
static BOOLEAN handle_msr_identity_rewrite(PER_CPU_CTX *ctx, VMCB *vmcb,
                                           ULONG msr, BOOLEAN is_write)
{
    ULONGLONG value = 0;
    BOOLEAN spoof = g_chamber_cfg_v2_valid && g_identity_valid &&
                    ((g_chamber_cfg_v2.toggles &
                      CHAMBER_TOGGLE_MACHINE_IDENTITY_SPOOF) != 0);

    switch (msr) {
    case 0x0000008BUL: /* IA32_BIOS_SIGN_ID -- microcode patch level */
        if (is_write) {
            /* Writes are architecturally used by the OS to poke the
             * patch-loader; absorb them. */
        } else {
            value = spoof ? g_identity_microcode_rev : 0;
            vmcb->save.rax   = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
        return TRUE;

    case 0x00000017UL: /* IA32_PLATFORM_ID */
        if (!is_write) {
            value = spoof ? g_identity_platform_id : 0;
            vmcb->save.rax   = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
        return TRUE;

    case 0xC0000103UL: /* TSC_AUX */
        if (is_write) {
            value = (ULONGLONG)(ULONG)vmcb->save.rax |
                    ((ULONGLONG)(ULONG)ctx->gpr_save[3] << 32);
            if (spoof) {
                identity_set_tsc_aux(ctx->cpu_index, value);
            } else {
                /* Without the spoof toggle, fall through to host
                 * passthrough so RDTSCP keeps its usual tag. */
                __try {
                    __writemsr(0xC0000103UL, value);
                } __except (EXCEPTION_EXECUTE_HANDLER) { }
            }
        } else {
            if (spoof) {
                value = identity_get_tsc_aux(ctx->cpu_index);
            } else {
                __try {
                    value = __readmsr(0xC0000103UL);
                } __except (EXCEPTION_EXECUTE_HANDLER) { value = 0; }
            }
            vmcb->save.rax   = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
        return TRUE;

    case 0xC0010015UL: /* HWCR */
        if (is_write) {
            /* Absorb writes to HWCR; letting the guest flip bits here
             * (McStatusWrEn, TscFreqSel, TlbCacheDis, SmmLock) would
             * either fault, compromise host integrity, or betray that
             * the HV is intercepting SVM state. */
        } else {
            /* Report a conservative Zen-default HWCR view. Bit 3
             * (TlbCacheDis) is architecturally reset-zero; bit 4
             * (INVD-to-WBINVD) is reset-one on current Zen; the rest
             * stay zero. Spoof unconditionally — this is HV-safety,
             * not machine identity. */
            value = (1ULL << 4);
            vmcb->save.rax   = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
        return TRUE;

    default:
        return FALSE;
    }
}

/* EFER writes must update VMCB.save.efer, not the host's physical EFER.
 * At VMEXIT the CPU is in host context, so WRMSR mutates host policy.
 * Whitelist only the bits AMD permits the guest to flip, force SVME on. */
#define EFER_WRITABLE_MASK (EFER_SVME | 0x1ULL /*SCE*/ | (1ULL<<8) /*LME*/ | \
                            (1ULL<<10) /*LMA*/ | (1ULL<<11) /*NXE*/ |        \
                            (1ULL<<12) /*LMSLE*/ | (1ULL<<13) /*FFXSR*/ |    \
                            (1ULL<<15) /*TCE*/)

/* VMCB clean-bits group 1 ("Interrupts" on AMD APM Table 15-5 but on
 * current Zen the state-save clean group is group 1). Any mutation of
 * vmcb.save.efer (or other save-area fields hardware caches) must clear
 * it so VMRUN reloads the save area on the next entry. */
#define VMCB_CLEAN_BIT_CR    (1U << 5)

static void handle_msr(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    BOOLEAN   is_write = (vmcb->ctl.exit_info_1 & 1) != 0;
    ULONG     msr = (ULONG)ctx->gpr_save[2];   /* rcx */
    ULONGLONG value = 0;

    /* Paravirt MSR bands that must NEVER reach __readmsr / __writemsr:
     *   0x40000000..0x400001FF - Hyper-V enlightenment + crash +
     *                            re-enlightenment + synthetic debug
     *   0x4B564D00..0x4B564DFF - KVM
     * Absorb writes; return zero on reads. */
    if ((msr >= 0x40000000U && msr <= 0x400001FFU) ||
        (msr >= 0x4B564D00U && msr <= 0x4B564DFFU)) {
        if (!is_write) {
            vmcb->save.rax   = 0;
            ctx->gpr_save[3] = 0;
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    /* Identity rewrite path: TSC_AUX, platform_id, microcode patch
     * level, HWCR. Each is handled without reaching the host MSR so
     * reseeds change the guest-visible value and the host state is
     * not touched. */
    if (handle_msr_identity_rewrite(ctx, vmcb, msr, is_write)) {
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    /* Zen 4 extended Core PMC event-selects. Observe arming on WRMSR and
     * pass the value through so the guest's counter actually counts. EN
     * is bit 22; any non-zero write with EN set marks the counter armed
     * for save/restore and handle_rdpmc. Reads pass through too. */
    if (msr >= 0xC0010200UL && msr <= 0xC001020AUL && (msr & 1U) == 0U) {
        ULONG idx = (msr - 0xC0010200UL) >> 1;
        if (is_write) {
            value = (ULONGLONG)(ULONG)vmcb->save.rax |
                    ((ULONGLONG)(ULONG)ctx->gpr_save[3] << 32);
            ctx->guest_pmc_armed[idx] =
                (value != 0 && (value & (1ULL << 22)) != 0) ? TRUE : FALSE;
            __try {
                __writemsr(msr, value);
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        } else {
            __try {
                value = __readmsr(msr);
            } __except (EXCEPTION_EXECUTE_HANDLER) { value = 0; }
            vmcb->save.rax   = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    if (msr == (ULONG)SVM_MSR_EFER) {
        if (is_write) {
            /* Update VMCB.save.efer only; do NOT mutate the host's
             * physical EFER.  Force SVME on (otherwise VMRUN rejects the
             * VMCB) and mask off reserved/bogus bits. */
            value = (ULONGLONG)(ULONG)vmcb->save.rax |
                    ((ULONGLONG)(ULONG)ctx->gpr_save[3] << 32);
            value &= EFER_WRITABLE_MASK;
            value |= EFER_SVME;
            vmcb->save.efer = value;
            vmcb->ctl.vmcb_clean_bits &= ~VMCB_CLEAN_BIT_CR;
        } else {
            /* Report the guest's stored EFER view with SVME masked out. */
            value = vmcb->save.efer & ~EFER_SVME;
            vmcb->save.rax   = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    if (msr == (ULONG)SVM_MSR_VM_HSAVE_PA || msr == (ULONG)SVM_MSR_VM_CR) {
        /* Hide our SVM host-save pointer and VM control from the guest. */
        if (!is_write) {
            vmcb->save.rax   = 0;
            ctx->gpr_save[3] = 0;
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    /* SMM_ADDR (0xC0010112), SMM_MASK (0xC0010113): hide SMM configuration;
     * guest reads the bare-metal default of 0 and writes are absorbed. */
    if (msr == 0xC0010112UL || msr == 0xC0010113UL) {
        if (!is_write) {
            vmcb->save.rax   = 0;
            ctx->gpr_save[3] = 0;
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    /* TSC_RATIO (0xC0000104): 8.32 fixed-point identity 1.0.  Integer
     * part 1 goes in bits [39:32]; fraction + reserved are zero.  This
     * is what stock Linux and Windows read back from an unprogrammed
     * part; returning 0 would itself be an anomaly. */
    if (msr == 0xC0000104UL) {
        if (!is_write) {
            ULONGLONG v = 0x0000000100000000ULL;
            vmcb->save.rax   = (ULONGLONG)(ULONG)v;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(v >> 32);
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    if (!handle_msr_allowlist_pass(msr)) {
        /* Unknown MSR: absorb write, return 0 on read.  Never let the
         * guest choose which MSR the host RDMSRs / WRMSRs. */
        if (!is_write) {
            vmcb->save.rax   = 0;
            ctx->gpr_save[3] = 0;
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    /* Allowed MSR: wrap __readmsr / __writemsr in SEH so a #GP from a
     * microarch-reserved encoding reflects as absorb/zero instead of a
     * host bugcheck. */
    __try {
        if (is_write) {
            value = (ULONGLONG)(ULONG)vmcb->save.rax |
                    ((ULONGLONG)(ULONG)ctx->gpr_save[3] << 32);
            __writemsr(msr, value);
        } else {
            value = __readmsr(msr);
            vmcb->save.rax   = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (!is_write) {
            vmcb->save.rax   = 0;
            ctx->gpr_save[3] = 0;
        }
    }

    vmcb->save.rip = vmcb->ctl.next_rip;
}

/* ------------------------------------------------------------------ */
/* VMMCALL -- private host call interface.                            */
/* ------------------------------------------------------------------ */

/* VMMCALL is used as a private hypercall; a one-instruction presence probe
 * is a trivial detection vector. We respond only to a shared-secret magic
 * value. Any other VMMCALL gets an injected #UD (invalid opcode exception),
 * which is what bare metal would deliver on a legitimate VMMCALL attempt
 * (VMMCALL raises #UD when SVME is clear in EFER). The magic value itself
 * (THE_CHAMBER_HYPERCALL_MAGIC) lives in the_chamber.h so integrity.c and
 * dump.c share the same definition. */
#define THE_CHAMBER_HCALL_VERSION     1
#define THE_CHAMBER_HCALL_SHUTDOWN    2
/* CHAMBER_HCALL_DUMP_CR3 (3) is defined in dump.h and dispatched below. */

static void inject_ud(VMCB *vmcb) {
    /* AMD Table 15-5: event_inject layout:
     *   bits 0-7   : vector (6 = #UD)
     *   bits 8-10  : type (3 = exception)
     *   bit  11    : error-code valid (0 = no)
     *   bit  31    : valid (1)
     *   bits 32-63 : error code (unused for #UD)
     */
    vmcb->ctl.event_inject = (1ULL << 31) | (3ULL << 8) | 6ULL;
    /* Do NOT advance RIP -- #UD fires at the VMMCALL instruction. */
}

static void handle_vmmcall(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONGLONG code;
    ULONGLONG rbx_magic;

    /* Our private protocol: RBX must equal the shared-secret magic. */
    rbx_magic = ctx->gpr_save[1];
    if (rbx_magic != THE_CHAMBER_HYPERCALL_MAGIC) {
        inject_ud(vmcb);
        return;
    }

    code = vmcb->save.rax;
    switch (code) {
    case THE_CHAMBER_HCALL_VERSION:
        vmcb->save.rax = THE_CHAMBER_VERSION;
        break;
    case THE_CHAMBER_HCALL_SHUTDOWN:
        InterlockedExchange(&ctx->shutdown_requested, 1);
        break;
    case CHAMBER_HCALL_SELF_INTEGRITY:
        /* Phase 7.2 code-integrity self-check. First call latches the
         * known-good hash; subsequent calls compare and set the
         * failure flag on mismatch. HV code is mapped in root
         * context's kernel VA without NPT translation, so reading it
         * here is a plain pool-memory access.
         *
         * NOTE: integrity.c's DPC currently can bypass this handler
         * and call integrity_handle_hcall() directly when
         * CHAMBER_HV_INTROSPECTION_RESIST is OFF, avoiding the need
         * for a kernel-side VMMCALL emitter. Future work: write an
         * asm thunk in asm_helpers.asm that emits VMMCALL with RAX =
         * code and RBX = magic, and make the DPC use it
         * unconditionally. */
        integrity_handle_hcall();
        break;
    case CHAMBER_HCALL_DUMP_CR3: {
        /* Phase 6.2 pause-the-world capture. Operator calling convention
         * (also documented in dump.h):
         *
         *   rax = CHAMBER_HCALL_DUMP_CR3
         *   rbx = THE_CHAMBER_HYPERCALL_MAGIC (checked above)
         *   rcx = target PID
         *   rdx = output buffer VA (operator AS)
         *   rsi = output buffer size (bytes)
         *
         * Return value in rax: bytes written, or 0 on error.
         *
         * IRQL: the VMMCALL handler runs at the IRQL the guest VMMCALL'd
         * at. For a user-mode operator thread that is PASSIVE_LEVEL,
         * which is what dump_snapshot_pause_target requires (it uses
         * KeStackAttachProcess and ZwQueryVirtualMemory). An operator
         * that issues VMMCALL from a DISPATCH-level DPC gets 0 back and
         * is expected to retry from PASSIVE context -- we do NOT queue
         * a passive work item internally because userland sees the
         * VMMCALL as synchronous and expects the result in rax on the
         * instruction's return. */
        CHAMBER_DUMP_REQ req;
        req.target_pid         = ctx->gpr_save[2];  /* rcx */
        req.output_buffer_va   = ctx->gpr_save[3];  /* rdx */
        req.output_buffer_size = ctx->gpr_save[4];  /* rsi */
        vmcb->save.rax = dump_snapshot_pause_target(&req);
        break;
    }
    default:
        inject_ud(vmcb);
        return;
    }

    vmcb->save.rip = vmcb->ctl.next_rip;
}

/* ------------------------------------------------------------------ */
/* Nested page fault (AMD 15.19.1).                                   */
/*                                                                    */
/* NPF is a FAULT-class VMEXIT: the faulting instruction has not been */
/* retired. The handler fixes the mapping (grants permissions, maps a */
/* missing page) and returns WITHOUT advancing RIP so hardware retries */
/* the same instruction. Previous code advanced RIP to next_rip -- that */
/* is catastrophic for a fault: the guest would skip the faulting      */
/* instruction, miss its intended side effects, and on a reread of the */
/* same address re-fault at the same RIP -> infinite loop if the next  */
/* instruction also accesses the unmapped page.                        */
/*                                                                    */
/* About next_rip (vmcb->ctl.next_rip, offset 0xC8): AMD APM Vol 2    */
/* 15.9 restricts next_rip to the DECODED intercepts only -- CPUID,   */
/* IN/OUT (IOIO), MSR access, VMMCALL, INVD, INVLPG, HLT, MONITOR,    */
/* MWAIT, RDTSC and RDTSCP -- and only when the processor advertises  */
/* NRIP_SAVE (CPUID 8000_000A EDX bit 3, a.k.a. "Decode Assists" on   */
/* older silicon). For fault-class VMEXITs (NPF, #DB, #BP, #UD, #GP,  */
/* #PF, SS, #NMI) next_rip is UNDEFINED and must not be read.         */
/* ------------------------------------------------------------------ */

static void handle_npf(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONGLONG fault_gpa;
    ULONGLONG fault_info;
    ULONGLONG fault_page;
    NPT_MONITOR *mon;

    UNREFERENCED_PARAMETER(ctx);

    fault_gpa  = vmcb->ctl.exit_info_2;   /* GPA that caused the fault */
    fault_info = vmcb->ctl.exit_info_1;   /* fault error-code bits     */
    fault_page = fault_gpa & ~0xFFFULL;   /* 4 KiB alignment for lookup */

    /* Passive-trigger routing. If the fault lands on a GPA that an
     * armed dump trigger (WX / OEP / WRITE_THRESHOLD) staked out, the
     * trigger module classifies the access via fault_info, re-maps
     * the PDE so the instruction retry completes, and fires a dump
     * when the access class matches the trigger kind. Returning TRUE
     * means the fault is handled: do NOT advance RIP (fault-class
     * exit) and do NOT fall through to npt_map_page below. */
    if (dump_trigger_on_npf(vmcb, fault_gpa, fault_info)) {
        return;
    }

    mon = npt_monitor_find(fault_page);
    if (mon) {
        /* Phase 6 real implementation; Phase 1.6 stub returns NULL so
         * this path is dead. If a future caller matches a monitored
         * page, the monitor does whatever it needs (toggle perms,
         * single-step, log) and we retry -- NO rip advance. */
        npt_monitor_handle_fault(mon, vmcb, fault_info);
        return;
    }

    /* Phase 7.1: if the fault lands inside a hidden range (HV image
     * pages when CHAMBER_HV_INTROSPECTION_RESIST is compiled in), do
     * NOT remap. Inject #PF into the guest so it sees a page fault at
     * the probing instruction and must handle it; the PDE stays
     * cleared so a retry refaults the same way. */
    if (npt_is_hidden(fault_page)) {
        /* AMD Table 15-5: event_inject, vector 14 (#PF), type 3
         * (exception), ec-valid bit 11 set, valid bit 31 set. The
         * NPF exit_info_1 carries the fault attributes in bits:
         *   bit 0  P    (1 if present, 0 if not; hidden => 0)
         *   bit 1  W/R  (1 on write, 0 on read)
         *   bit 2  U/S  (1 on user, 0 on supervisor)
         * Forward those into the injected #PF error code (bits [32:35])
         * so an introspector that inspects the EC sees a fault
         * consistent with its probing access rather than a fixed
         * pattern. P stays 0 by construction (page is not present).
         * CR2 is left stale -- the VMEXIT reports GPA, not GVA. */
        {
            ULONGLONG ec = ((fault_info >> 1) & 1ULL) << 1 |   /* W/R */
                           ((fault_info >> 2) & 1ULL) << 2;    /* U/S */
            vmcb->ctl.event_inject = (ec << 32) |
                                     (1ULL << 31) | (1ULL << 11) |
                                     (3ULL << 8) | 14ULL;
        }
        return;
    }

    /* Grow the NPT on demand: install a 2 MB identity mapping covering
     * the faulting guest-physical address. Phase 1 grants full
     * Present|Writable|User permissions; Phase 6 may tighten this. */
    (void)npt_map_page(fault_page, fault_page,
                       NPT_PRESENT | NPT_WRITABLE | NPT_USER);

    /* Do NOT advance RIP. Hardware retries the faulting instruction with
     * the new mapping. vmcb->ctl.next_rip is undefined for NPF (see the
     * block comment above) and must not be read here. */
}

/* ------------------------------------------------------------------ */
/* Teardown reporting.                                               */
/* ------------------------------------------------------------------ */

void vmexit_cleanup(void)
{
    CHAMBER_LOG("final vmexit count = %llu\n", g_vmexit_count);
}
