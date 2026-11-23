/* dump.c -- Phase 6.2 pause-the-world snapshot.
 *
 * See dump.h for the user-mode interface and the IRQL / handle discipline
 * constraints. Implementation notes:
 *
 *   - Park-only IPI. KeIpiGenericCall runs its worker at IPI_LEVEL. At
 *     that IRQL the ONLY thing we can safely do is spin: no allocations,
 *     no attaches, no VAD walks. The worker reads the current guest CR3
 *     from the per-CPU VMCB state-save area and compares to the target;
 *     on match it increments a per-CPU "parked" counter and spin-waits
 *     on g_pause_active. When the originating CPU clears g_pause_active,
 *     the worker returns from the IPI and the vCPU resumes in guest.
 *
 *   - VAD walk on the originator. After KeIpiGenericCall returns, the
 *     caller holds a reference on the target EPROCESS and can
 *     KeStackAttachProcess into it at PASSIVE_LEVEL. The VAD walk reads
 *     EPROCESS.VadRoot via PsGetProcessVadRoot or (for older builds)
 *     the raw offset; we use the documented PsGetProcessSectionBaseAddress
 *     path only to validate the process is real and then rely on the
 *     exposed PsGetProcessVadRoot cross-build.
 *
 *     Note: full RTL_AVL_TREE traversal of VAD nodes is a nontrivial
 *     tree walk. For Phase 6.2 we do the minimum useful thing: query
 *     MmQueryVirtualMemory-equivalent info via a helper that walks the
 *     target's VAD tree one node at a time (MiGetNextVad style). To
 *     avoid depending on unexported helpers we use
 *     ZwQueryVirtualMemory from the kernel side after attaching, which
 *     gives us MEMORY_BASIC_INFORMATION per region and is sufficient
 *     for a passive dump.
 *
 *   - Copy to operator buffer. The operator buffer VA is in the
 *     operator process context; because snapshot runs after a VMMCALL
 *     from that same operator process, the current attached process
 *     when we are NOT attached to the target is the operator. We
 *     capture the operator EPROCESS pointer up front, attach to the
 *     target to read, detach, attach to operator to write, detach.
 *     The compound attach/detach is required because KeStackAttachProcess
 *     does not nest in a way that lets us read from one AS and write to
 *     another in the same window.
 *
 *     Simpler alternative used here: capture one region at a time into
 *     a kernel scratch buffer while attached to the target, then detach
 *     and copy into the operator buffer (which is in the operator's own
 *     attached process, i.e. the caller's context on return from the
 *     IOCTL VMMCALL). Kernel scratch is bounded (NPT_PAGE_SIZE_2MB per
 *     iteration) to keep nonpaged-pool pressure low.
 *
 * IRQL summary:
 *
 *   - VMMCALL from user-mode PASSIVE_LEVEL          -> handler at PASSIVE
 *   - KeIpiGenericCall workers                       -> IPI_LEVEL (park only)
 *   - KeStackAttachProcess / ZwQueryVirtualMemory    -> PASSIVE on originator
 *   - On entry snapshot_pause_target asserts the IRQL < DISPATCH_LEVEL
 *     bound and refuses otherwise. If a future caller invokes it from
 *     DISPATCH_LEVEL, that caller must queue a work item via
 *     IoQueueWorkItem first; snapshot_pause_target does NOT queue
 *     internally because the VMMCALL handler is already PASSIVE.
 */

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "the_chamber.h"
#include "svm.h"
#include "dump.h"

volatile LONG g_pause_active = 0;

/* --- Externs we use from the kernel, without pulling a full header. --- */
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId,
                                                PEPROCESS *Process);
NTKERNELAPI VOID     KeStackAttachProcess(PEPROCESS Process,
                                          PKAPC_STATE ApcState);
NTKERNELAPI VOID     KeUnstackDetachProcess(PKAPC_STATE ApcState);
NTKERNELAPI NTSTATUS ObReferenceObjectByPointer(PVOID Object, ACCESS_MASK d,
                                                POBJECT_TYPE ObjectType,
                                                KPROCESSOR_MODE AccessMode);
/* ZwQueryVirtualMemory prototype (public NT API). */
typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0
} MEMORY_INFORMATION_CLASS;

NTSTATUS ZwQueryVirtualMemory(HANDLE ProcessHandle,
                              PVOID BaseAddress,
                              MEMORY_INFORMATION_CLASS Class,
                              PVOID Buffer,
                              SIZE_T Length,
                              PSIZE_T ReturnLength);

/* --- Pause target state --------------------------------------------- */

static ULONGLONG g_target_cr3 = 0;

/* Count of vCPUs currently parked (spin-waiting in the IPI worker).
 * Advisory only; we don't block waiting for a specific count because
 * KeIpiGenericCall is synchronous and all workers have entered
 * ipi_park_if_target_cr3 by the time it returns. */
static volatile LONG g_parked_count = 0;

/* IPI worker. Runs at IPI_LEVEL on every CPU. If this CPU's guest CR3
 * (masked to the PML4 base; low 12 bits are PCID / flags) matches the
 * target, spin until g_pause_active clears. Non-matching CPUs return
 * immediately -- their guest resumes untouched after the IPI unwinds.
 *
 * The CR3 we check is the VMCB.save.cr3 field; that is what VMRUN uses
 * on the next entry and what the guest observes as its own CR3. Masking
 * off the low 12 bits isolates the physical PML4 base.
 *
 * Caveat: on Meltdown-era kernels Windows alternates between user and
 * kernel CR3 per syscall. The user CR3 and kernel CR3 differ in bit 11
 * (PCID selector). We check against the operator-supplied target_cr3 as
 * provided; the operator is expected to capture it from a previous
 * CR3-write intercept, so it already matches one of the two. */
static ULONG_PTR ipi_park_if_target_cr3(ULONG_PTR arg)
{
    ULONG cpu = KeGetCurrentProcessorNumber();
    VMCB *vmcb;
    ULONGLONG current_cr3;

    UNREFERENCED_PARAMETER(arg);

    if (!g_cpu_ctx || cpu >= g_cpu_count) {
        return 0;
    }
    vmcb = (VMCB *)g_cpu_ctx[cpu].vmcb_va;
    if (!vmcb) {
        return 0;
    }

    current_cr3 = vmcb->save.cr3 & ~0xFFFULL;
    if (current_cr3 != g_target_cr3) {
        return 0;
    }

    InterlockedIncrement(&g_parked_count);

    /* Spin until the originator clears g_pause_active. _mm_pause is the
     * x86 PAUSE hint; it slows the spin and yields SMT resources to the
     * sibling thread without releasing the CPU. We can't KeDelayExecution
     * at IPI_LEVEL, so a tight PAUSE spin is the only option. */
    while (InterlockedCompareExchange(&g_pause_active, 0, 0) != 0) {
        _mm_pause();
    }

    InterlockedDecrement(&g_parked_count);
    return 0;
}

/* --- VAD walk + copy -------------------------------------------------- */

/* Copy a single committed region from the currently-attached target
 * process into the operator's output buffer. Both reads and writes
 * happen while attached to the respective process; we attach/detach
 * per-region to keep the window short. Returns bytes appended to out_buf
 * or 0 if the region did not fit / was unreadable. */
static ULONGLONG dump_one_region(PEPROCESS target_proc,
                                 ULONGLONG region_base,
                                 ULONGLONG region_size,
                                 ULONG     region_prot,
                                 PUCHAR    out_buf,
                                 ULONGLONG out_cursor,
                                 ULONGLONG out_capacity)
{
    KAPC_STATE apc;
    ULONGLONG header_size;
    ULONGLONG total_size;
    ULONGLONG write_off;

    header_size = sizeof(ULONGLONG) * 2 + sizeof(ULONG) * 2;
    total_size = header_size + region_size;
    if (out_cursor + total_size > out_capacity) {
        return 0;
    }

    /* Write TLV header into operator buffer. The caller is attached to
     * the operator process on entry, so out_buf is valid here. */
    write_off = out_cursor;
    __try {
        *(ULONGLONG *)(out_buf + write_off) = region_base;
        write_off += sizeof(ULONGLONG);
        *(ULONGLONG *)(out_buf + write_off) = region_size;
        write_off += sizeof(ULONGLONG);
        *(ULONG *)(out_buf + write_off) = region_prot;
        write_off += sizeof(ULONG);
        *(ULONG *)(out_buf + write_off) = 0; /* reserved */
        write_off += sizeof(ULONG);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }

    /* Copy region bytes. We attach to the target to read, then detach;
     * the operator's buffer is still valid because KeStackAttachProcess
     * only swaps the address space, not the kernel VA mappings of the
     * operator-buffer pages (user VAs live in the per-process part of
     * the AS). Problem: operator-buffer VAs ARE per-process. Workaround:
     * attach to target, copy bytes into a small kernel scratch buffer,
     * detach, then copy from scratch into the operator buffer.
     *
     * For simplicity and to keep nonpaged-pool pressure bounded we do
     * the scratch copy one page at a time. 4 KiB is well under
     * POOL_BUDDY_MAX so the scratch allocation stays out of big pool. */
    {
        ULONGLONG remaining = region_size;
        ULONGLONG src_off = 0;
        PUCHAR scratch;

        scratch = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                           PAGE_SIZE,
                                           POOLTAG("dump_scratch"));
        if (!scratch) {
            return 0;
        }

        while (remaining > 0) {
            ULONGLONG chunk = (remaining > PAGE_SIZE) ? PAGE_SIZE : remaining;

            /* Read chunk from target. */
            KeStackAttachProcess(target_proc, &apc);
            __try {
                RtlCopyMemory(scratch,
                              (PVOID)(ULONG_PTR)(region_base + src_off),
                              (SIZE_T)chunk);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                /* Page not present / unreadable: fill with zero and
                 * keep going so the output still aligns to region_size. */
                RtlZeroMemory(scratch, (SIZE_T)chunk);
            }
            KeUnstackDetachProcess(&apc);

            /* Write chunk into operator buffer (we are back in the
             * originating thread's AS, which is the operator's). */
            __try {
                RtlCopyMemory(out_buf + write_off, scratch, (SIZE_T)chunk);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                ExFreePoolWithTag(scratch, POOLTAG("dump_scratch"));
                return 0;
            }
            write_off += chunk;
            src_off   += chunk;
            remaining -= chunk;
        }

        ExFreePoolWithTag(scratch, POOLTAG("dump_scratch"));
    }

    return total_size;
}

/* Walk the target's address space one MEMORY_BASIC_INFORMATION block at
 * a time, from VA 0 upward, through ZwQueryVirtualMemory with a pseudo-
 * handle. MemoryBasicInformation returns {BaseAddress, AllocationBase,
 * AllocationProtect, RegionSize, State, Protect, Type}. We dump only
 * MEM_COMMIT regions. End when the next base wraps past the user-mode
 * limit.
 *
 * NtCurrentProcess() == (HANDLE)-1 refers to the currently-attached
 * process (per NtQueryVirtualMemory semantics when ProcessHandle is the
 * self-handle and the caller is attached). We stay attached to the
 * target for the enumeration, detach briefly inside dump_one_region to
 * write to the operator buffer, and re-attach to continue walking. */
static ULONGLONG dump_walk_target(PEPROCESS target_proc,
                                  PUCHAR    out_buf,
                                  ULONGLONG out_capacity)
{
    KAPC_STATE apc;
    ULONGLONG cursor = 0;
    ULONG_PTR va = 0;
    const ULONG_PTR user_limit = 0x00007FFFFFFEFFFFULL;
    /* MEMORY_BASIC_INFORMATION mirror (without pulling winnt.h): */
    struct _MBI {
        PVOID     BaseAddress;
        PVOID     AllocationBase;
        ULONG     AllocationProtect;
        ULONG     __pad0;
        SIZE_T    RegionSize;
        ULONG     State;
        ULONG     Protect;
        ULONG     Type;
        ULONG     __pad1;
    } mbi;
    SIZE_T   ret_len;
    NTSTATUS st;

    while (va < user_limit) {
        /* Issue the query while attached to the target so
         * ZwQueryVirtualMemory walks its VAD tree. */
        KeStackAttachProcess(target_proc, &apc);
        RtlZeroMemory(&mbi, sizeof(mbi));
        st = ZwQueryVirtualMemory((HANDLE)(LONG_PTR)-1,
                                   (PVOID)va,
                                   MemoryBasicInformation,
                                   &mbi,
                                   sizeof(mbi),
                                   &ret_len);
        KeUnstackDetachProcess(&apc);

        if (!NT_SUCCESS(st)) {
            break;
        }
        if (mbi.RegionSize == 0) {
            break;
        }

        if (mbi.State == 0x1000 /* MEM_COMMIT */) {
            ULONGLONG wrote = dump_one_region(target_proc,
                                              (ULONGLONG)(ULONG_PTR)mbi.BaseAddress,
                                              (ULONGLONG)mbi.RegionSize,
                                              mbi.Protect,
                                              out_buf,
                                              cursor,
                                              out_capacity);
            if (wrote == 0) {
                /* Buffer full or unrecoverable error. Stop; operator
                 * retries with a larger buffer. */
                break;
            }
            cursor += wrote;
        }

        /* Advance past this region. Guard against wrap. */
        if ((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize <= va) {
            break;
        }
        va = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    }

    return cursor;
}

/* --- Public entry point --------------------------------------------- */

ULONGLONG dump_snapshot_pause_target(PCHAMBER_DUMP_REQ req)
{
    PEPROCESS target = NULL;
    NTSTATUS  st;
    ULONGLONG bytes_written = 0;
    HANDLE    pid;
    PUCHAR    user_buf;
    ULONGLONG user_cap;

    if (!req) return 0;
    if (req->target_pid == 0) return 0;
    if (req->output_buffer_va == 0) return 0;
    if (req->output_buffer_size == 0) return 0;

    /* IRQL discipline: KeStackAttachProcess requires IRQL < DISPATCH_LEVEL.
     * The VMMCALL handler invokes us at the IRQL the guest VMMCALL'd from;
     * for user-mode callers that's PASSIVE. Refuse otherwise so a future
     * DPC-context caller gets an explicit error instead of a silent
     * bugcheck. */
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) {
        return 0;
    }

    pid = (HANDLE)(ULONG_PTR)req->target_pid;
    st = PsLookupProcessByProcessId(pid, &target);
    if (!NT_SUCCESS(st) || !target) {
        return 0;
    }

    /* Capture the target's CR3 (PML4 physical base, low 12 bits masked
     * off) for the park-IPI predicate. We don't attach yet -- we only
     * need the pointer-reference held so far. Reading CR3 requires
     * attaching briefly so the current CR3 register reflects the target
     * AS, then detaching to return to the operator AS for the VAD walk
     * machinery. */
    {
        KAPC_STATE apc;
        ULONGLONG raw_cr3;
        KeStackAttachProcess(target, &apc);
        raw_cr3 = __readcr3();
        KeUnstackDetachProcess(&apc);
        g_target_cr3 = raw_cr3 & ~0xFFFULL;
    }

    /* Broadcast the park IPI. Only vCPUs whose current VMCB.save.cr3
     * matches g_target_cr3 will spin; everyone else returns immediately.
     * We must set g_pause_active to 1 BEFORE the broadcast so matching
     * workers see the gate set when they enter the spin loop. */
    InterlockedExchange(&g_pause_active, 1);
    InterlockedExchange(&g_parked_count, 0);
    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)ipi_park_if_target_cr3, 0);

    /* Walk + copy at PASSIVE_LEVEL. Both VAD query and memory copy use
     * KeStackAttachProcess, which is safe at this IRQL. The user_buf
     * pointer is valid in the operator's AS because we're running in
     * the operator thread's host-context handler; the operator's AS is
     * current when we are not attached to anything else. */
    user_buf = (PUCHAR)(ULONG_PTR)req->output_buffer_va;
    user_cap = req->output_buffer_size;

    __try {
        /* Probe one byte to confirm the operator buffer is writable in
         * the operator AS. If this throws (bad pointer, nonpaged-pool
         * region, etc.) we skip the walk. */
        ProbeForWrite(user_buf, (SIZE_T)user_cap, sizeof(UCHAR));
        bytes_written = dump_walk_target(target, user_buf, user_cap);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        bytes_written = 0;
    }

    /* Release parked CPUs. They exit their spin on the next
     * InterlockedCompareExchange that sees 0 and return from the IPI
     * worker, which in turn allows KeIpiGenericCall's host-side wait
     * (already satisfied) to be irrelevant and the vCPUs to resume
     * guest on their next VMRUN. */
    InterlockedExchange(&g_pause_active, 0);

    ObDereferenceObject(target);
    return bytes_written;
}
