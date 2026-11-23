/* vmexit.c -- THE_CHAMBER #VMEXIT dispatcher.
 *
 * Entered from vmrun.asm after each guest #VMEXIT, with the shadow GPR
 * save area (ctx->gpr_save) already populated. Decodes vmcb->ctl.exit_code
 * and services the intercepted event per AMD64 APM Vol 2, Chapter 15.
 *
 * GPR save index map (see the_chamber.h):
 *   0=rax 1=rbx 2=rcx 3=rdx 4=rsi 5=rdi 6=rbp 7=rsp 8..15=r8..r15
 * rax lives authoritatively in vmcb->save.rax (loaded/stored by VMRUN).
 */

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "the_chamber.h"
#include "svm.h"
#include "timing.h"

volatile ULONGLONG g_vmexit_count = 0;

static void handle_cpuid(PER_CPU_CTX *ctx, VMCB *vmcb);
static void handle_msr(PER_CPU_CTX *ctx, VMCB *vmcb);
static void handle_vmmcall(PER_CPU_CTX *ctx, VMCB *vmcb);
static void handle_npf(PER_CPU_CTX *ctx, VMCB *vmcb);

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

    switch (exit_code) {
    case VMEXIT_CPUID:
        handle_cpuid(ctx, vmcb);
        break;

    case VMEXIT_MSR:
        handle_msr(ctx, vmcb);
        break;

    case VMEXIT_VMMCALL:
        handle_vmmcall(ctx, vmcb);
        break;

    case VMEXIT_NPF:
        handle_npf(ctx, vmcb);
        break;

    default:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "WinHvMon: unhandled VMEXIT code=%llx info1=%llx info2=%llx\n",
                   exit_code, vmcb->ctl.exit_info_1, vmcb->ctl.exit_info_2);
        vmcb->save.rip = vmcb->ctl.next_rip;
        break;
    }

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

static void handle_cpuid(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONG leaf = (ULONG)vmcb->save.rax;
    ULONG subleaf = (ULONG)ctx->gpr_save[2];   /* rcx */
    int regs[4];

    __cpuidex(regs, (int)leaf, (int)subleaf);

    if (leaf == 1) {
        /* Clear the hypervisor-present bit (ECX[31]). */
        regs[2] &= ~(1 << 31);
    }

    if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF) {
        /* Phase 1.1: widen the hypervisor-brand zero band to the full
         * 0x40000000..0x4FFFFFFF reserved range.
         *
         * Rationale: the VMware/hypervisor convention is that this entire
         * CPUID range is dedicated to hypervisor use. Mainstream hypervisors
         * (Hyper-V, KVM, Xen, VMware, QEMU-KVM) all follow it, and AMD Zen 4
         * bare metal returns all-zeros for every leaf in the band (observed
         * behavior; not APM-mandated). VMAware and pafish probe specific
         * leaves such as 0x40000080 and 0x40000100 that lie well above the
         * previous 0x40000010 ceiling, which left a trivial detection vector:
         * any non-zero value returned by the native host __cpuidex in that
         * range would fingerprint us as a hypervisor. Zeroing the whole band
         * mirrors bare-metal behavior and closes that gap. */
        regs[0] = 0;
        regs[1] = 0;
        regs[2] = 0;
        regs[3] = 0;
    }

    vmcb->save.rax = (ULONGLONG)(ULONG)regs[0];   /* eax */
    ctx->gpr_save[1] = (ULONGLONG)(ULONG)regs[1]; /* ebx */
    ctx->gpr_save[2] = (ULONGLONG)(ULONG)regs[2]; /* ecx */
    ctx->gpr_save[3] = (ULONGLONG)(ULONG)regs[3]; /* edx */

    vmcb->save.rip = vmcb->ctl.next_rip;
}

/* ------------------------------------------------------------------ */
/* MSR interception (AMD 15.11).                                      */
/* ------------------------------------------------------------------ */

static void handle_msr(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    BOOLEAN is_write = (vmcb->ctl.exit_info_1 & 1) != 0;
    ULONG msr = (ULONG)ctx->gpr_save[2];   /* rcx */
    ULONGLONG value;

    if (msr >= 0x40000000 && msr <= 0x400000FF) {
        /* Hyper-V enlightenment MSR range: swallow it. */
        if (is_write) {
            /* Absorb the write; take no action. */
        } else {
            vmcb->save.rax = 0;       /* eax */
            ctx->gpr_save[3] = 0;     /* edx */
        }
    } else if (msr == (ULONG)SVM_MSR_EFER) {
        if (is_write) {
            /* Guest can write EFER but must NEVER clear SVME on the real MSR,
             * or the host loses virtualization. OR SVME back in before commit. */
            value = (ULONGLONG)(ULONG)vmcb->save.rax |
                    ((ULONGLONG)(ULONG)ctx->gpr_save[3] << 32);
            value |= EFER_SVME;
            __writemsr(msr, value);
        } else {
            value = __readmsr(msr) & ~EFER_SVME;   /* mask SVME out of guest view */
            vmcb->save.rax = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
        }
    } else if (msr == (ULONG)SVM_MSR_VM_HSAVE_PA || msr == (ULONG)SVM_MSR_VM_CR) {
        /* Hide our SVM host-save pointer and VM control from the guest. */
        if (is_write) {
            /* Absorb write. */
        } else {
            vmcb->save.rax = 0;
            ctx->gpr_save[3] = 0;
        }
    } else {
        if (is_write) {
            value = (ULONGLONG)(ULONG)vmcb->save.rax |
                    ((ULONGLONG)(ULONG)ctx->gpr_save[3] << 32);
            __writemsr(msr, value);
        } else {
            value = __readmsr(msr);
            vmcb->save.rax = (ULONGLONG)(ULONG)value;
            ctx->gpr_save[3] = (ULONGLONG)(ULONG)(value >> 32);
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
 * (VMMCALL raises #UD when SVME is clear in EFER). */
#define THE_CHAMBER_HYPERCALL_MAGIC   0x5452484D4648434AULL  /* "JCHFMHRT" */
#define THE_CHAMBER_HCALL_VERSION     1
#define THE_CHAMBER_HCALL_SHUTDOWN    2

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
    default:
        inject_ud(vmcb);
        return;
    }

    vmcb->save.rip = vmcb->ctl.next_rip;
}

/* ------------------------------------------------------------------ */
/* Nested page fault (AMD 15.19.1).                                   */
/* ------------------------------------------------------------------ */

static void handle_npf(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    UNREFERENCED_PARAMETER(ctx);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "WinHvMon: NPF at PA=%llx info=%llx\n",
               vmcb->ctl.exit_info_2, vmcb->ctl.exit_info_1);

    vmcb->save.rip = vmcb->ctl.next_rip;
}

/* ------------------------------------------------------------------ */
/* Teardown reporting.                                               */
/* ------------------------------------------------------------------ */

void vmexit_cleanup(void)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "WinHvMon: final vmexit count = %llu\n", g_vmexit_count);
}
