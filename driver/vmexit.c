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
static void handle_vmrun(PER_CPU_CTX *ctx, VMCB *vmcb);

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

    case VMEXIT_VMRUN:
        handle_vmrun(ctx, vmcb);
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

/* Leaves 0x15 (TSC/crystal ratio) and 0x16 (processor base/max/bus MHz) are
 * Intel-only reporting leaves. Zen 4 does not implement them and the
 * unconditional AMD zero-scrub below zeros both. There is therefore no
 * dedicated rewrite_leaf_15 / rewrite_leaf_16 -- any output a seed-derived
 * rewrite produced would be immediately overwritten by the scrub, so the
 * previous versions of those functions were dead code; they have been
 * removed. */

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

/* Architectural post-CPUID / post-VMMCALL single-step trap: if guest
 * RFLAGS.TF is set at the point of an intercepted instruction, hardware
 * on bare metal would deliver #DB after that instruction retires. SVM
 * VMEXIT handlers never auto-deliver the #DB; we have to inject it
 * ourselves. Caller must have already advanced vmcb->save.rip to
 * next_rip so the #DB fires at the post-instruction RIP (matching the
 * bare-metal trap-class semantics where RIP at delivery points to the
 * next instruction).
 *
 * event_inject layout (AMD Table 15-5):
 *   bits 0-7  vector (1 = #DB)
 *   bits 8-10 type   (3 = exception)
 *   bit  11   error-code valid (0 = no EC for #DB)
 *   bit  31   valid (1)
 *   bits 32-63 error code (unused for #DB) */
#define RFLAGS_TF   (1ULL << 8)
static void inject_db_if_tf(VMCB *vmcb)
{
    if ((vmcb->save.rflags & RFLAGS_TF) != 0) {
        vmcb->ctl.event_inject = (1ULL << 31) | (3ULL << 8) | 1ULL;
    }
}

/* Serve one cached leaf into the save/gpr registers. Shared by the
 * cacheable-leaf and the HV/invalid-band fast paths. */
static void cpuid_serve_regs(PER_CPU_CTX *ctx, VMCB *vmcb,
                             ULONG eax, ULONG ebx, ULONG ecx, ULONG edx)
{
    vmcb->save.rax   = (ULONGLONG)eax;
    ctx->gpr_save[1] = (ULONGLONG)ebx;
    ctx->gpr_save[2] = (ULONGLONG)ecx;
    ctx->gpr_save[3] = (ULONGLONG)edx;
    vmcb->save.rip   = vmcb->ctl.next_rip;
    inject_db_if_tf(vmcb);
}

static void handle_cpuid(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONG leaf = (ULONG)vmcb->save.rax;
    ULONG subleaf = (ULONG)ctx->gpr_save[2];   /* rcx */
    int regs[4];
    BOOLEAN rewrite = identity_rewrites_enabled();
    const CHAMBER_CPUID_REWRITE_CACHE *cache = NULL;

    /* Hot-path CPUID servicing (TIMER defence against the sibling-SMT
     * software clock). When identity rewrites are enabled and the
     * per-vCPU cache is populated, serve the common leaves directly
     * from the cached (EAX, EBX, ECX, EDX) rather than re-running the
     * __cpuidex + per-leaf rewrite pipeline. Trims handler wallclock
     * -- the only honest fix for a probe that counts on a sibling
     * logical processor. Leaves outside the cacheable set (including
     * every leaf with dynamic state: TSC-backed 0x15/0x16, RDPMC-
     * related, or 0xB/0x1F subleaves beyond CHAMBER_CPUID_*_SUBLEAVES)
     * fall through to the slow path below. */
    if (rewrite) {
        cache = identity_get_cpuid_cache(ctx->cpu_index);
        if (cache && cache->valid) {
            const CHAMBER_CPUID_LEAF *entry = NULL;

            switch (leaf) {
            case 1U:
                entry = &cache->leaf_1;
                break;
            case 7U:
                if (subleaf == 0) entry = &cache->leaf_7_0;
                break;
            case 0xBU:
                if (subleaf < CHAMBER_CPUID_B_SUBLEAVES)
                    entry = &cache->leaf_B[subleaf];
                break;
            case 0x1FU:
                if (subleaf < CHAMBER_CPUID_1F_SUBLEAVES)
                    entry = &cache->leaf_1F[subleaf];
                break;
            case 0x80000001U:
                entry = &cache->leaf_80000001;
                break;
            case 0x80000002U:
                entry = &cache->leaf_80000002;
                break;
            case 0x80000003U:
                entry = &cache->leaf_80000003;
                break;
            case 0x80000004U:
                entry = &cache->leaf_80000004;
                break;
            case 0x8000001EU:
                entry = &cache->leaf_8000001E;
                break;
            default:
                break;
            }

            if (entry) {
                cpuid_serve_regs(ctx, vmcb,
                                 entry->eax, entry->ebx,
                                 entry->ecx, entry->edx);
                return;
            }

            /* Zero-shaped bands: the HV-reserved range (0x40000000..
             * 0x4FFFFFFF) and the invalid-basic-leaf collapse
             * (leaves above max_basic_leaf but below the HV range).
             *
             * The invalid-basic case closes a VMAware CPUID_SIGNATURE
             * sub-check: a probe that reads leaf 0x40000000 (zeroed)
             * and an invalid basic leaf like 0x04201337 should see the
             * same all-zero shape. Without this case, Zen 4 reflows
             * invalid leaves above max-basic into a NON-ZERO max-basic
             * fill, so the two reads differ -- itself the tell. We
             * anchor the collapse at leaf > 0x0D (the last real basic
             * leaf we care about) on top of leaf > max_basic_leaf so a
             * misreported max_basic cannot accidentally zero a leaf
             * we actually want to pass through. */
            if ((leaf >= 0x40000000U && leaf <= 0x4FFFFFFFU) ||
                (leaf > cache->max_basic_leaf && leaf > 0x0DU &&
                 leaf < 0x40000000U)) {
                cpuid_serve_regs(ctx, vmcb, 0, 0, 0, 0);
                return;
            }
        }
    }

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
    } else if (leaf == 0x8000001DU) {
        /* Cache topology. The NumSharingCache field at EAX[25:14]
         * reports the number of logical processors sharing each cache
         * level; it must agree with the per-level logical-processor
         * counts advertised at CPUID 0xB EBX. Both this leaf and 0xB
         * EBX are host-passthrough today -- rewrite_leaf_topology only
         * replaces the x2APIC ID at 0xB/0x1F EDX -- so the two stay
         * self-consistent. If a future rewrite varies 0xB EBX counts,
         * this leaf must be adjusted in lockstep. */
    } else if (leaf == 0x8000001EU) {
        /* EAX = Extended APIC ID. Host passthrough advertises the
         * physical CPU's extended APIC ID, which contradicts the
         * per-vCPU x2APIC ID that rewrite_leaf_topology stamps into
         * 0xB/0x1F EDX. Rewrite EAX here to the same seed-derived
         * x2apic_id so a probe cross-checking the two leaves sees one
         * identity. EBX (compute-unit / threads-per-CU) and ECX (node
         * ID / nodes-per-package) stay passthrough -- they describe
         * hardware topology, not the vCPU identity. */
        if (rewrite) {
            regs[0] = (int)identity_get_x2apic_id(ctx->cpu_index);
        }
    } else if (leaf == 0x8000001FU) {
        /* Must zero SEV/SME regardless of rewrite toggle: the HV's own
         * SVM use should never leak a hardware SEV advertisement to the
         * guest. */
        rewrite_leaf_8000001F(regs);
    }

    /* Wave 8: vendor-gate + SVM-cap scrub (unconditional, runs after any
     * optional rewrite_leaf_* call above).
     *
     * Leaf 0x8000_0001 ECX advertises long-mode extensions. On bare-metal
     * Zen 4 bit 2 (SVM) is set. We intercept VMRUN as code 0x80 and have
     * no faithful SVM emulation, so leaving SVM advertised makes a guest
     * `wrmsr(EFER, ... | SVME)` followed by VMRUN see an arch-illegal #UD
     * from our default handler -- a tell. The least-invasive repair is to
     * clear the advertised SVM capability so a well-behaved guest never
     * tries VMRUN. Pin TOPO_EXT (bit 22) and PerfCtrExtCore (bit 23) on
     * (they are set by Zen 4 bare metal; forcing them keeps the ECX image
     * stable even on partial-passthrough paths). */
    if (leaf == 0x80000001U) {
        regs[2] &= ~(1u << 2);                       /* SVM off           */
        regs[2] |=  (1u << 22) | (1u << 23);         /* TOPO_EXT / PCtrEx */
    }

    /* Leaf 0x15 (TSC/crystal-clock ratio) and 0x16 (processor base/max/bus
     * MHz) are Intel-only reporting leaves. Zen 4 does not define them; a
     * host passthrough would return either zeros or garbage depending on
     * micro-arch revision, and either is a vendor-mismatch tell on an
     * AuthenticAMD vendor string. Force them to all-zero explicitly.
     *
     * Leaf 0x1F is NOT Intel-only: on Zen 4 (family 0x19) the processor
     * implements it as the V2 Extended Topology Enumeration, strictly
     * supersetting the information at 0xB. A guest that reads a non-zero
     * 0xB but zero 0x1F on a Zen 4-shaped CPU signature would itself be a
     * topology-vs-generation mismatch. The rewrite_leaf_topology path
     * above stamps the per-vCPU x2apic_id into 0x1F EDX for the same
     * reason it does at 0xB; do NOT scrub the leaf back to zero here. */
    if (leaf == 0x15U || leaf == 0x16U) {
        regs[0] = 0;
        regs[1] = 0;
        regs[2] = 0;
        regs[3] = 0;
    }

    /* Leaf 0x8000_001F (encrypted-memory capabilities): preserve SME
     * (EAX bit 0) from host passthrough because Zen 4 silicon reports it
     * as-defined, but clear SEV (bit 1), SEV-ES (bit 3) and the SEV-related
     * ASID / cbit fields in EBX/ECX/EDX. A guest that reads a non-zero
     * SEV ASID count would infer either an EPYC-class part (wrong SKU) or
     * an active SEV guest context (wrong environment). */
    if (leaf == 0x8000001FU) {
        regs[0] &= 0x1u;    /* keep SME, drop SEV / SEV-ES / SNP / VMPL */
        regs[1] = 0;        /* Cbit position / PhysAddrReduction / ASIDs */
        regs[2] = 0;        /* total encrypted guests */
        regs[3] = 0;        /* minimum SEV-enabled ASID */
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

    /* Invalid-basic-leaf collapse (slow-path mirror of the fast-path
     * case above). Reached when the fast-path cache was not consulted
     * (rewrites disabled or cache not populated yet). Needs the host
     * max-basic leaf, which we read via CPUID.0 on demand. Anchored at
     * leaf > 0x0D for the same safety reason the fast path uses: an
     * unreported max-basic from the host must not accidentally zero a
     * basic leaf we rewrite elsewhere. Closes the VMAware
     * CPUID_SIGNATURE invalid-basic-leaf-collapse sub-check, where the
     * probe reads leaf 0x40000000 (zero) and an invalid basic leaf
     * like 0x04201337; on Zen 4 the invalid leaf reflows to a NON-ZERO
     * max-basic fill and the two reads differ -- itself the tell. */
    if (leaf > 0x0DU && leaf < 0x40000000U) {
        int basic[4];
        __cpuidex(basic, 0, 0);
        if (leaf > (ULONG)basic[0]) {
            regs[0] = 0;
            regs[1] = 0;
            regs[2] = 0;
            regs[3] = 0;
        }
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

    /* Architectural post-CPUID single-step trap: if guest RFLAGS.TF is
     * set, bare metal would deliver #DB after CPUID retires. SVM VMEXIT
     * handlers do not auto-deliver the trap, so inject it here after
     * RIP has advanced to next_rip. Closes the VMAware SINGLE_STEP
     * gap, where the probe sets TF and expects the trap at the
     * post-CPUID RIP. */
    inject_db_if_tf(vmcb);
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
 * The identity-sensitive TSC_AUX (0xC0000103) and HWCR (0xC0010015) stay
 * listed so the SEH-wrapped pass branch stays reachable in case the
 * dedicated rewrite short-circuits are ever disabled; those two the
 * identity_rewrite path handles before this allowlist is consulted.
 *
 * MSR 0x17 (IA32_PLATFORM_ID) and MSR 0x8B (IA32_BIOS_SIGN_ID) are NOT
 * in the allowlist. A host __readmsr(0x17) on an AuthenticAMD part
 * either raises #GP or returns an Intel-only pattern -- both are tells
 * -- and a host __readmsr(0x8B) returns the bare-metal host's real
 * microcode patch level, undermining the seed-derived identity view.
 * Both are routed to the explicit shadow / #GP block below. */
static BOOLEAN handle_msr_allowlist_pass(ULONG msr)
{
    switch (msr) {
    case 0x00000010UL:   /* IA32_TIME_STAMP_COUNTER      */
    case 0x0000001BUL:   /* IA32_APIC_BASE               */
    case 0x00000048UL:   /* SPEC_CTRL                    */
    case 0x00000049UL:   /* PRED_CMD                     */
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
 * side when the machine-identity spoof toggle is set.
 *
 * MSR 0x17 (IA32_PLATFORM_ID) and MSR 0x8B (IA32_BIOS_SIGN_ID) are
 * deliberately NOT handled here. On an AuthenticAMD vendor string:
 *   - 0x17 is Intel-only; the correct bare-metal shape is #GP(0).
 *   - 0x8B returns the microcode patch level in EAX with EDX = 0.
 * The prior short-circuit kept them from ever reaching the fallback's
 * explicit shapes: it absorbed writes, served zero (or a left-shifted
 * value that landed in EDX, with EAX = 0) on reads, and skipped the
 * #GP injection entirely. Routing both to the fallback block gives
 * the hardware-accurate behaviour. */
static BOOLEAN handle_msr_identity_rewrite(PER_CPU_CTX *ctx, VMCB *vmcb,
                                           ULONG msr, BOOLEAN is_write)
{
    ULONGLONG value = 0;
    BOOLEAN spoof = g_chamber_cfg_v2_valid && g_identity_valid &&
                    ((g_chamber_cfg_v2.toggles &
                      CHAMBER_TOGGLE_MACHINE_IDENTITY_SPOOF) != 0);

    switch (msr) {
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
 * Whitelist only the bits AMD permits the guest to flip, force SVME on.
 *
 * Wave 8 correction: the prior mask had comment-vs-bit errors. AMD APM Vol 2
 * section 3.1.7 defines:
 *   bit  0  SCE   bit  8  LME   bit 10  LMA   bit 11  NXE
 *   bit 12  SVME  bit 13  LMSLE bit 14  FFXSR bit 15  TCE
 * The previous mask labelled bit 12 as "LMSLE" (it is SVME, already covered
 * by EFER_SVME), bit 13 as "FFXSR" (it is LMSLE), and omitted FFXSR (bit 14)
 * entirely so a guest WRMSR that turned on FFXSR silently dropped the bit on
 * read-back -- a Zen 4 round-trip tell. */
#define EFER_WRITABLE_MASK (EFER_SVME | 0x1ULL /*SCE*/ | (1ULL<<8)  /*LME*/  | \
                            (1ULL<<10) /*LMA*/ | (1ULL<<11) /*NXE*/ |         \
                            (1ULL<<13) /*LMSLE*/ | (1ULL<<14) /*FFXSR*/ |     \
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
     *
     * Wave 8: bare-metal AuthenticAMD raises #GP(0) on both RDMSR and
     * WRMSR to these ranges because they are not implemented. Silently
     * returning zero / absorbing writes was itself a hypervisor tell:
     * every real AMD part faults, every HV-with-hint-serving stub does
     * not. Inject #GP(0) here instead; the guest observes an
     * instruction fault at the RDMSR/WRMSR site, which is the correct
     * bare-metal shape. Do NOT advance RIP -- the fault fires at the
     * MSR instruction itself. */
    if ((msr >= 0x40000000U && msr <= 0x400001FFU) ||
        (msr >= 0x4B564D00U && msr <= 0x4B564DFFU)) {
        /* event_inject: valid | ec_valid | type=exception | vector=0x0D (#GP) */
        vmcb->ctl.event_inject = (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;
        return;
    }

    /* Identity rewrite path: TSC_AUX (per-vCPU RDTSCP tag) and HWCR
     * (SVM-detection hiding). Each is handled without reaching the
     * host MSR so a reseed changes the guest-visible value and the
     * host state is not touched. Platform_id (0x17) and microcode
     * patch level (0x8B) are intentionally served further down in the
     * explicit shadow / #GP fallback instead of here: the AMD-correct
     * shapes (#GP on 0x17, EAX=patch id / EDX=0 on 0x8B) could not be
     * produced from the rewrite short-circuit without the caller then
     * advancing RIP, which short-circuited the #GP. */
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
            /* Mask SVME out of the guest-visible EFER read while keeping
             * SVME=1 in VMCB.save.efer (required for VMRUN). The SVM
             * story the HV tells the guest is "firmware disabled SVM":
             *   - CPUID.80000001.ECX[2] cleared (handle_cpuid)
             *   - VM_CR LOCK=1 / SVMDIS=1 (below)
             *   - EFER.SVME reads as 0 here
             *   - A guest VMLOAD/VMSAVE/CLGI/STGI at CPL3 therefore has
             *     nothing to probe against: the capability bit is off,
             *     the firmware lock is set, and the EFER view agrees.
             * The prior behaviour reported vmcb->save.efer AS-STORED
             * with SVME=1, which handed VMAware's SVM_EXCEPTIONS arm (b)
             * an exact CPUID-vs-EFER mismatch tell (CPUID hides SVM
             * while EFER advertises SVME=1). A guest write path still
             * ORs SVME=1 back into the stored VMCB.save.efer so VMRUN's
             * consistency check continues to pass; the host's physical
             * EFER is never touched by this handler.
             *
             * Round-trip note: a guest `v = rdmsr(EFER); wrmsr(EFER, v)`
             * reads SVME=0, writes SVME=0, sees SVME=0 on re-read -- the
             * internal re-OR of SVME into VMCB.save.efer is invisible
             * to the guest observer, so the round-trip is stable. The
             * only guest-visible asymmetry is a guest that explicitly
             * writes SVME=1 and then reads back SVME=0, which exactly
             * matches the "VM_CR.LOCK=1 absorbs the write" story. */
            value = vmcb->save.efer & ~EFER_SVME;
            vmcb->save.rax   = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    if (msr == (ULONG)SVM_MSR_VM_HSAVE_PA) {
        /* Hide our SVM host-save pointer from the guest. HSAVE_PA reads
         * back as 0 on a Zen 4 part when the OS has not programmed SVM
         * host-save, which matches a guest that sees SVM-capability
         * cleared in CPUID (see handle_cpuid). */
        if (!is_write) {
            vmcb->save.rax   = 0;
            ctx->gpr_save[3] = 0;
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    if (msr == (ULONG)SVM_MSR_VM_CR) {
        /* Wave 8: VM_CR (0xC001_0114) must look like firmware that locked
         * SVM OFF via the standard BIOS toggle. Bits per APM Vol 2 15.30:
         *   bit 0 DPD, bit 1 R_INIT, bit 2 DIS_A20M
         *   bit 3 LOCK  (writes to VM_CR take effect; cleared only by
         *                           a non-standard pre-boot path -- stays 1
         *                           in-session on virtually every retail box)
         *   bit 4 SVMDIS (SVM disabled in BIOS)
         * Report LOCK=1 and SVMDIS=1 on read so a guest that reads VM_CR to
         * confirm the cleared CPUID SVM bit sees a consistent "firmware
         * disabled SVM" story. A zero return here (with SVM cleared in
         * CPUID) would be an inconsistent pairing that no shipping BIOS
         * produces. Absorb writes -- LOCK=1 means a well-behaved guest
         * would see its writes rejected; silent-absorb is the closest
         * bare-metal-shaped outcome without an #GP. */
        if (!is_write) {
            ULONGLONG v = (1ULL << 3) | (1ULL << 4);   /* LOCK | SVMDIS */
            vmcb->save.rax   = (ULONGLONG)(ULONG)v;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(v >> 32);
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }

    /* Wave 8: SMM_ADDR (0xC001_0112) / SMM_MASK (0xC001_0113). A zero return
     * is itself anomalous: every shipping Zen 4 board ships with TSEG
     * programmed by the UEFI SMM relocation path, so SMM_ADDR holds the
     * TSEG base and SMM_MASK has the AVALID (bit 0) and TVALID (bit 1) bits
     * set plus the TSEG size field populated. Return a plausible non-zero
     * pair: SMM_ADDR = 0x0 (keep base stub-visible) + SMM_MASK with AVALID
     * and TVALID set and a 2 MiB TSEG size encoded in bits [17:2]. This is
     * conservative -- it does not leak the real host TSEG geometry, and it
     * matches the "SMM is set up" story every retail firmware emits. */
    if (msr == 0xC0010112UL) {
        if (!is_write) {
            vmcb->save.rax   = 0;
            ctx->gpr_save[3] = 0;
        }
        vmcb->save.rip = vmcb->ctl.next_rip;
        return;
    }
    if (msr == 0xC0010113UL) {
        if (!is_write) {
            /* AVALID | TVALID | TSEG size encoded (2 MiB region). */
            ULONGLONG v = (1ULL << 0) | (1ULL << 1) | (0x15ULL << 2);
            vmcb->save.rax   = (ULONGLONG)(ULONG)v;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(v >> 32);
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
        /* Wave 8: inject #GP(0) by default on unknown MSRs rather than
         * silent-zero. Serving zero for every unmapped encoding is a
         * uniform-shape tell: bare metal faults, hints-serving stubs
         * return zero. The default is now the bare-metal shape and
         * explicit MSRs that *should* read zero live above (VM_HSAVE_PA,
         * SMM_ADDR). Writes still absorb -- a stray WRMSR must not reach
         * the host -- but by injecting #GP we also make the guest see
         * the fault the hardware would have produced.
         *
         * Microcode-patch level (MSR 0x8B) is a frequent probe target.
         * On AuthenticAMD a RDMSR 0x8B returns the patch id in EAX with
         * EDX=0. Pick from a small pool of real published Zen 4 B2
         * patch ids using g_identity_microcode_rev (seed-derived) so a
         * reseed rotates the id; if the identity path isn't primed
         * yet (zero), fall back to a single fixed real value. Writes
         * are absorbed. */
        if (msr == 0x8BUL) {
            if (!is_write) {
                /* Real published AMD family 0x19 model 0x61 stepping 2
                 * (Raphael B2) microcode patch ids. Keeping the pool to
                 * known-good values avoids emitting a bit pattern no
                 * shipped CPU has carried -- itself a fingerprint a
                 * sample can cross-check against a public patch list. */
                static const ULONG zen4_b2_patch_ids[] = {
                    0x0A601203UL, 0x0A601206UL, 0x0A601209UL,
                    0x0A60120AUL, 0x0A60120CUL,
                };
                ULONG v;
                if (g_identity_microcode_rev != 0) {
                    v = zen4_b2_patch_ids[
                        (ULONG)(g_identity_microcode_rev & 0xFFFFFFFFUL) %
                        RTL_NUMBER_OF(zen4_b2_patch_ids)];
                } else {
                    v = 0x0A601206UL;
                }
                vmcb->save.rax   = (ULONGLONG)v;
                ctx->gpr_save[3] = 0;
            }
            vmcb->save.rip = vmcb->ctl.next_rip;
            return;
        }

        /* MSR 0x17 (IA32_PLATFORM_ID) is Intel-only. On AuthenticAMD it
         * raises #GP; honour that shape rather than returning a shadow. */
        if (msr == 0x17UL) {
            vmcb->ctl.event_inject =
                (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;
            return;
        }

        if (is_write) {
            /* Absorb the write -- never choose the MSR hw actually sees --
             * but still inject #GP so a guest that WRMSRs an unknown
             * encoding sees the same fault as bare metal. */
            vmcb->ctl.event_inject =
                (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;
            return;
        }

        /* Read: inject #GP(0) at the RDMSR site. */
        vmcb->ctl.event_inject =
            (1ULL << 31) | (1ULL << 11) | (3ULL << 8) | 13ULL;
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
/* Wave 8: slot for the syscall-rewrite result descriptor. See the
 * handle_vmmcall case comment for the binding contract. */
#ifndef THE_CHAMBER_HCALL_REWRITE_RESULT
#define THE_CHAMBER_HCALL_REWRITE_RESULT  5
#endif

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
    case THE_CHAMBER_HCALL_REWRITE_RESULT:
        /* Wave 8: slot reserved for the syscall-rewrite path. The
         * operator-side rewrite loop in launcher/injector hands a
         * result descriptor back through this hypercall (RCX = result
         * pointer, RDX = size). The handler currently returns success
         * unconditionally -- the rewrite path consumer in another
         * bucket binds the real sink. Keep the slot wired so the guest
         * hypercall does not land in the inject_ud default. */
        vmcb->save.rax = 0;
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

    /* VMMCALL is a TF-sensitive decoded intercept, same as CPUID.
     * Mirror the post-CPUID #DB inject: if guest RFLAGS.TF is set,
     * deliver the architectural single-step trap at the post-VMMCALL
     * RIP after we have advanced vmcb->save.rip to next_rip. Keeps
     * the guest-visible trap sequencing consistent whether a TF-set
     * guest hits CPUID or VMMCALL. */
    inject_db_if_tf(vmcb);
}

/* ------------------------------------------------------------------ */
/* VMRUN intercept (AMD 15.5).                                        */
/*                                                                    */
/* Wave 8: handle_cpuid clears the SVM capability bit at CPUID        */
/* 0x8000_0001 ECX[2], and handle_msr reports VM_CR with LOCK=1 and   */
/* SVMDIS=1. A well-behaved guest will therefore never issue VMRUN:   */
/* it believes SVM is unavailable. A probe that issues VMRUN anyway   */
/* -- to force the "am I in a VM" oracle -- would, on bare metal with */
/* SVM disabled by firmware, see #UD (the processor raises #UD on     */
/* VMRUN when EFER.SVME is clear). Model that exactly by injecting    */
/* #UD at the current RIP without advancing. */
/* ------------------------------------------------------------------ */

static void handle_vmrun(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    UNREFERENCED_PARAMETER(ctx);
    vmexit_inject_ud(vmcb);
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
