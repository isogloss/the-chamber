/* svm_bringup.c -- AMD SVM per-CPU bringup + teardown.
 * Reference: AMD64 APM Vol 2, Ch 15 (SVM).
 *
 * IRQL correctness: all memory allocations happen at PASSIVE_LEVEL in
 * svm_preallocate_cpu(); the KeIpiGenericCall path only touches MSRs and
 * the already-allocated VMCB. This avoids the IPI_LEVEL allocation bug
 * that fable52 flagged in the first draft.
 */
#include "the_chamber.h"
#include "svm.h"

PER_CPU_CTX *g_cpu_ctx = NULL;
ULONG        g_cpu_count = 0;

extern NTSTATUS svm_init_bitmaps(void);  /* svm_vmcb.c */
extern VOID     svm_free_bitmaps(void);

BOOLEAN svm_is_supported(void) {
    int regs[4];
    ULONGLONG vm_cr;

    __cpuid(regs, (int)CPUID_EXT_FEATURES);
    if ((regs[2] & CPUID_SVM_BIT) == 0) {
        CHAMBER_LOG_ERR("SVM not reported by CPUID\n");
        return FALSE;
    }
    vm_cr = __readmsr(SVM_MSR_VM_CR);
    if (vm_cr & VM_CR_SVMDIS) {
        CHAMBER_LOG_ERR("SVM disabled by BIOS (VM_CR.SVMDIS=1)\n");
        return FALSE;
    }
    return TRUE;
}

static PVOID alloc_contiguous(SIZE_T size, ULONGLONG *out_pa) {
    PHYSICAL_ADDRESS highest, zero, pa;
    PVOID p;
    highest.QuadPart = (LONGLONG)-1;
    zero.QuadPart = 0;
    p = MmAllocateContiguousMemorySpecifyCache(size, zero, highest, zero, MmCached);
    if (!p) return NULL;
    RtlZeroMemory(p, size);
    pa = MmGetPhysicalAddress(p);
    *out_pa = (ULONGLONG)pa.QuadPart;
    return p;
}

/* ---- PASSIVE_LEVEL phase -------------------------------------------- */

static NTSTATUS svm_preallocate_cpu(ULONG cpu_index) {
    PER_CPU_CTX *ctx;

    ctx = &g_cpu_ctx[cpu_index];
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->cpu_index = cpu_index;

    /* host_save: 4 KiB (AMD 15.30) */
    ctx->host_save_va = alloc_contiguous(PAGE_SIZE, &ctx->host_save_pa);
    if (!ctx->host_save_va) return STATUS_INSUFFICIENT_RESOURCES;

    /* VMCB: 4 KiB */
    ctx->vmcb_va = alloc_contiguous(sizeof(VMCB), &ctx->vmcb_pa);
    if (!ctx->vmcb_va) {
        MmFreeContiguousMemory(ctx->host_save_va);
        ctx->host_save_va = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Phase 2.0: dedicated host stack. svm_launch switches rsp to
     * host_stack_top before CLGI so the vmrun-loop host side runs on
     * memory the HV owns. Without this, VM_HSAVE_PA.host_rsp saves a
     * pointer into the loader thread's kernel stack, which the OS
     * reclaims for other calls after DriverEntry returns -- first
     * VMEXIT then reads garbage.  16 KiB per CPU, 16-byte aligned.
     *
     * BIG POOL NOTE: 16 KiB > 4080 (POOL_BUDDY_MAX, ~PAGE_SIZE -
     * POOL_HEADER_SIZE), so this allocation lands in the big-pool
     * allocator and is enumerable via !bigpool / SystemBigPoolInformation.
     * Pool-tag randomization alone does NOT hide it; the allocation
     * size + address pattern remains identifiable. Accept the surface
     * and keep the tag indistinguishable from common minifilter tags. */
    ctx->host_stack_size = 16 * 1024;
    ctx->host_stack_va   = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, ctx->host_stack_size,
        POOLTAG("host_stack"));
    if (!ctx->host_stack_va) {
        MmFreeContiguousMemory(ctx->host_save_va);
        ctx->host_save_va = NULL;
        MmFreeContiguousMemory(ctx->vmcb_va);
        ctx->vmcb_va = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Top of stack, 16-byte aligned. Pool base is 16-byte aligned on
     * x64 so (base + size) & ~0xF == (base + size). */
    ctx->host_stack_top = (PUCHAR)ctx->host_stack_va + ctx->host_stack_size;
    return STATUS_SUCCESS;
}

/* ---- IPI_LEVEL phase ------------------------------------------------ */

/* Enabled on each CPU by the broadcast; no allocations, only MSR writes + VMCB fill. */
static VOID svm_online_cpu(PER_CPU_CTX *ctx) {
    __writemsr(SVM_MSR_EFER, __readmsr(SVM_MSR_EFER) | EFER_SVME);
    __writemsr(SVM_MSR_VM_HSAVE_PA, ctx->host_save_pa);
    svm_build_vmcb(ctx);           /* uses pre-allocated bitmaps + per-CPU ctx */
    ctx->active = TRUE;
}

static ULONG_PTR ipi_online(ULONG_PTR arg) {
    ULONG cpu = KeGetCurrentProcessorNumber();
    UNREFERENCED_PARAMETER(arg);
    if (cpu < g_cpu_count && g_cpu_ctx[cpu].vmcb_va) {
        svm_online_cpu(&g_cpu_ctx[cpu]);
    }
    return 0;
}

NTSTATUS svm_init_all_cpus(void) {
    NTSTATUS st;
    ULONG i;

    g_cpu_count = KeQueryActiveProcessorCount(NULL);
    if (g_cpu_count == 0) return STATUS_UNSUCCESSFUL;

    /* BIG POOL NOTE: PER_CPU_CTX is ~1 KiB/CPU; on a 7700X (16 logical
     * CPUs) the array is ~16 KiB. Comfortably above POOL_BUDDY_MAX
     * (~4080), so this allocation sits in big pool and is enumerable
     * via !bigpool / SystemBigPoolInformation. No way around this -- a
     * per-CPU array of variable size has to be a single allocation for
     * cache-line adjacency. Accept the surface. */
    g_cpu_ctx = (PER_CPU_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(PER_CPU_CTX) * g_cpu_count,
        POOLTAG("per_cpu_ctx"));
    if (!g_cpu_ctx) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_cpu_ctx, sizeof(PER_CPU_CTX) * g_cpu_count);

    /* PASSIVE_LEVEL: warm the shared MSRPM/IOPM bitmaps once. */
    st = svm_init_bitmaps();
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(g_cpu_ctx, POOLTAG("per_cpu_ctx"));
        g_cpu_ctx = NULL; g_cpu_count = 0;
        return st;
    }

    /* PASSIVE_LEVEL: per-CPU allocations. */
    for (i = 0; i < g_cpu_count; i++) {
        st = svm_preallocate_cpu(i);
        if (!NT_SUCCESS(st)) {
            CHAMBER_LOG_ERR("pre-alloc failed on CPU %u (0x%x)\n", i, st);
            (void)svm_shutdown_all_cpus();
            return st;
        }
    }

    /* IPI_LEVEL: enable SVM on every CPU synchronously. */
    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)ipi_online, 0);

    /* Verify every CPU came up. */
    for (i = 0; i < g_cpu_count; i++) {
        if (!g_cpu_ctx[i].active) {
            CHAMBER_LOG_ERR("CPU %u failed to activate\n", i);
            (void)svm_shutdown_all_cpus();
            return STATUS_UNSUCCESSFUL;
        }
    }

    CHAMBER_LOG("SVM initialized on %u CPUs\n", g_cpu_count);
    return STATUS_SUCCESS;
}

/* ---- Guest entry ---------------------------------------------------- */

/* Pin the current thread to each active CPU and issue VMRUN there. The
 * affinity-switched PASSIVE_LEVEL path is required: svm_launch issues CLGI
 * + VMLOAD + VMRUN, which must run at PASSIVE_LEVEL, not the IPI_LEVEL that
 * KeIpiGenericCall would impose. KeSetSystemAffinityThreadEx accepts a
 * KAFFINITY mask within the current thread's processor group; the 7700X
 * fits in a single group so one-bit-set is sufficient.
 *
 * After svm_launch() returns via guest_entry_point's ret, that physical
 * CPU is live in guest mode. The loop continues to pin and launch the
 * next CPU. Re-entry into a ctx already in guest mode is refused via the
 * guest_entered latch. */
NTSTATUS svm_launch_all_cpus(void) {
    PROCESSOR_NUMBER proc_num;
    KAFFINITY        prev_aff;
    NTSTATUS         st;
    ULONG            i;

    if (!g_cpu_ctx || g_cpu_count == 0) return STATUS_UNSUCCESSFUL;

    for (i = 0; i < g_cpu_count; i++) {
        PER_CPU_CTX *ctx = &g_cpu_ctx[i];

        if (!ctx->active)       continue;
        if (ctx->guest_entered) continue;

        st = KeGetProcessorNumberFromIndex(i, &proc_num);
        if (!NT_SUCCESS(st)) {
            CHAMBER_LOG_ERR("KeGetProcessorNumberFromIndex(%u) failed 0x%08x\n",
                            i, st);
            return st;
        }

        prev_aff = KeSetSystemAffinityThreadEx(
            (KAFFINITY)1 << proc_num.Number);

        /* Latch BEFORE svm_launch so a concurrent/duplicate caller that
         * reads guest_entered observes the in-progress state. */
        ctx->guest_entered = TRUE;

        svm_launch(ctx, ctx->host_stack_top);

        KeRevertToUserAffinityThreadEx(prev_aff);
    }

    CHAMBER_LOG("guest live on %u CPUs\n", g_cpu_count);
    return STATUS_SUCCESS;
}

/* ---- Teardown ------------------------------------------------------- */

static VOID svm_offline_cpu(PER_CPU_CTX *ctx) {
    InterlockedExchange(&ctx->shutdown_requested, 1);
    /* AMD APM Appendix B: WRMSR to VM_HSAVE_PA with EFER.SVME=0 raises
     * #GP(0).  Zero VM_HSAVE_PA FIRST (while SVME is still set), then
     * clear SVME.  Matches Linux KVM's cpu_svm_disable sequence. */
    __writemsr(SVM_MSR_VM_HSAVE_PA, 0);
    __writemsr(SVM_MSR_EFER, __readmsr(SVM_MSR_EFER) & ~EFER_SVME);
    ctx->active = FALSE;
}

static ULONG_PTR ipi_offline(ULONG_PTR arg) {
    ULONG cpu = KeGetCurrentProcessorNumber();
    UNREFERENCED_PARAMETER(arg);
    if (cpu < g_cpu_count) svm_offline_cpu(&g_cpu_ctx[cpu]);
    return 0;
}

static VOID svm_free_cpu(PER_CPU_CTX *ctx) {
    if (ctx->host_stack_va) {
        ExFreePoolWithTag(ctx->host_stack_va, POOLTAG("host_stack"));
        ctx->host_stack_va = NULL;
        ctx->host_stack_top = NULL;
        ctx->host_stack_size = 0;
    }
    if (ctx->vmcb_va)        { MmFreeContiguousMemory(ctx->vmcb_va);        ctx->vmcb_va = NULL; }
    if (ctx->host_save_va)   { MmFreeContiguousMemory(ctx->host_save_va);   ctx->host_save_va = NULL; }
}

NTSTATUS svm_shutdown_all_cpus(void) {
    ULONG i;
    if (!g_cpu_ctx) return STATUS_SUCCESS;

    /* Cooperative shutdown: GIF=0 on the host side between VMEXIT and
     * the next VMRUN blocks IPIs.  Setting shutdown_requested on every
     * CPU FIRST lets each CPU exit its vmrun loop on its own next
     * VMEXIT and fall out to host_done (which issues STGI), so the
     * IPI broadcast below is deliverable. */
    for (i = 0; i < g_cpu_count; i++) {
        InterlockedExchange(&g_cpu_ctx[i].shutdown_requested, 1);
    }

    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)ipi_offline, 0);

    /* PASSIVE_LEVEL: free per-CPU memory. */
    for (i = 0; i < g_cpu_count; i++) svm_free_cpu(&g_cpu_ctx[i]);

    svm_free_bitmaps();
    ExFreePoolWithTag(g_cpu_ctx, POOLTAG("per_cpu_ctx"));
    g_cpu_ctx = NULL;
    g_cpu_count = 0;
    CHAMBER_LOG("SVM shutdown complete\n");
    return STATUS_SUCCESS;
}
