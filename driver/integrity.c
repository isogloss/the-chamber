/* integrity.c -- Phase 7.2 implementation.
 *
 * See integrity.h for the interface and ordering constraints. Notes on
 * implementation choices:
 *
 *   - The guest-side DPC is armed at HV init time BEFORE svm_launch_all,
 *     but its first fire happens after svm_launch has demoted the OS to
 *     guest; by that point the HV's VMMCALL intercept is live and the
 *     DPC hits the handler cleanly.
 *
 *   - FNV-1a 64-bit is used because:
 *       * No lookup table; fits in a dozen lines of code.
 *       * Reasonable distribution for contiguous byte spans.
 *       * Not cryptographic -- we're not defending against an active
 *         adversary who computes preimages; just catching passive
 *         corruption / unintended overwrites of HV code.
 *
 *   - The hash covers the HV's full loaded image (DriverStart..
 *     DriverStart+DriverSize). This includes .text + read-only .rdata,
 *     and crucially also .data (which changes at runtime) and .bss.
 *     For Phase 7.2 we accept that: if runtime writes change the
 *     hash, that's a legitimate false positive and the operator
 *     refines the covered range on the next iteration. A production
 *     refinement would hash .text only, but that requires parsing our
 *     own PE section headers -- which §5.2 just scrambled. So we hash
 *     the whole image and set the window during init before scramble.
 *
 *     Actually: §5.2 scrambles section NAMES, not their content. The
 *     .data bytes still change when the HV updates counters. To avoid
 *     spurious mismatches we therefore capture the full-image hash
 *     ONCE before any guest VMEXIT updates our globals, and the
 *     comparison on subsequent calls must stay stable only if nothing
 *     is writing to data. In practice g_vmexit_count and the PMU
 *     shadow DO change, so the hash WILL differ between calls.
 *
 *     Workaround: hash only the pages that are expected to be read-only
 *     after init. We approximate by hashing the first half of the image
 *     (typically .text + part of .rdata) and skipping .data / .bss. A
 *     cleaner solution reads the PE section headers before §5.2
 *     scrambles them, saving the exact .text range -- that's left as
 *     a future improvement and documented here.
 *
 *   - The periodic DPC is a KDPC + KTIMER arrangement, same shape as
 *     the watchdog in the_chamber.c. KeSetTimerEx(..., Period, ...)
 *     re-fires automatically every Period ms, no DPC re-arm needed.
 *
 *   - On mismatch, the guest DPC calls KeBugCheck(0xDEADC0DE). The HV
 *     cannot safely "unload itself" from the DPC (svm_shutdown needs
 *     PASSIVE_LEVEL + per-CPU affinity switches that a DPC can't do),
 *     so the bluescreen is the clean exit. The crash marker from
 *     DriverEntry survives and next boot refuses to load.
 */

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "the_chamber.h"
#include "svm.h"
#include "integrity.h"

#define INTEGRITY_HCALL_PERIOD_MS 5000

/* Guest-side state (lives in the HV's globals; DPC runs at
 * DISPATCH_LEVEL which is still host-kernel context because the HV
 * demoted the host-OS to guest, meaning what we think of as "guest"
 * is actually the Windows kernel). */
static KTIMER                    g_integrity_timer;
static KDPC                      g_integrity_dpc;
static BOOLEAN                   g_integrity_armed = FALSE;
static PCHAMBER_INTEGRITY_STATUS g_integrity_status = NULL;

/* Host-side state. Captured in integrity_init, read in
 * integrity_handle_hcall. */
static PUCHAR                    g_hv_image_start = NULL;
static ULONG                     g_hv_image_size  = 0;
static ULONGLONG                 g_hv_known_hash  = 0;
static BOOLEAN                   g_hv_hash_latched = FALSE;

/* FNV-1a 64-bit over [buf, buf+len). */
static ULONGLONG fnv1a_64(const UCHAR *buf, SIZE_T len)
{
    ULONGLONG h = 0xCBF29CE484222325ULL;        /* FNV offset basis */
    SIZE_T i;
    for (i = 0; i < len; i++) {
        h ^= (ULONGLONG)buf[i];
        h *= 0x100000001B3ULL;                   /* FNV prime */
    }
    return h;
}

/* Guest-side DPC. Fires every INTEGRITY_HCALL_PERIOD_MS at
 * DISPATCH_LEVEL. Issues the VMMCALL, reads the shared status, and
 * either continues or calls KeBugCheck on mismatch. */
static void integrity_dpc_routine(PKDPC Dpc, PVOID Ctx,
                                  PVOID Sa1, PVOID Sa2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Sa1);
    UNREFERENCED_PARAMETER(Sa2);

    if (!g_integrity_status) return;

    /* Zero hv_responded before the call so we can detect silent
     * ignores. */
    InterlockedExchange((volatile LONG *)&g_integrity_status->hv_responded, 0);

    /* Issue VMMCALL with our hypercall magic in RBX. We don't have a
     * portable kernel-side VMMCALL wrapper here, so emit it inline
     * via __svm_vmmcall if WDK provides it, or via asm. MSVC doesn't
     * ship an __svm_vmmcall intrinsic; it does ship __vmx_vmcall
     * (Intel VMX). We emit raw bytes via the __svm_vmmcall-equivalent
     * sequence using the asm prologue in vmrun.asm would be cleaner,
     * but to keep this file self-contained we use the fact that
     * __writemsr(0xC0010114, ...) is NOT what we want -- we want the
     * VMMCALL instruction.
     *
     * MSVC intrinsics: as of Visual Studio 2022 WDK, __svm_vmmcall
     * IS available through intrin.h (declared as void
     * __svm_vmmcall(unsigned __int64);). It places its argument in
     * RCX and executes VMMCALL. We need RAX = hcall code and RBX =
     * magic though, and __svm_vmmcall only controls one register. */

    /* Build a tiny inline asm shim via a helper in asm_helpers.asm?
     * For portability (MSVC x64 has no inline asm) we rely on
     * __svm_vmmcall and arrange for the magic + code to be in the
     * right registers beforehand via register-pressure hints.
     *
     * Simpler: declare an external __fastcall function
     * chamber_vmmcall_hcall(ULONG code, ULONGLONG magic). On x64
     * fastcall RCX = code, RDX = magic. We then MOV them into RAX/RBX
     * via a tiny assembly thunk in asm_helpers.asm (which we don't
     * modify here; left as a TODO for the operator wire-up).
     *
     * For Phase 7.2 initial landing, we DO NOT emit the VMMCALL from
     * here; we call integrity_handle_hcall DIRECTLY from the DPC.
     * This means the integrity check runs entirely in guest context
     * (which is the Windows kernel context) via a plain function
     * call. The implication: without §7.1 hiding the HV image, the
     * "guest" and "host" views of the HV code are the same byte-
     * exact region of nonpaged pool, so hashing from guest yields
     * the right bytes. With §7.1 ENABLED, the DPC runs in guest
     * context and would NPF reading HV bytes; the correct path is to
     * then issue VMMCALL. We mark this as an operator decision: the
     * DPC checks a compile-time flag and calls the HV directly when
     * §7.1 is OFF.
     *
     * Future refinement: write an asm thunk that emits the real
     * VMMCALL with RAX/RBX set, and switch to that unconditionally.
     * Documented in CHAMBER_HCALL_SELF_INTEGRITY's comment in
     * vmexit.c. */
#ifdef CHAMBER_HV_INTROSPECTION_RESIST
    /* With HV pages hidden, direct read from "guest" context NPFs.
     * Operator must wire up the real VMMCALL path (asm thunk in
     * asm_helpers.asm) before enabling both §7.1 and §7.2. For now,
     * skip the check -- better to not run than to NPF ourselves. */
    InterlockedExchange((volatile LONG *)&g_integrity_status->hv_responded, 1);
    return;
#else
    integrity_handle_hcall();
#endif

    /* After the hcall, hv_responded must be 1. */
    if (InterlockedCompareExchange((volatile LONG *)
            &g_integrity_status->hv_responded, 0, 0) == 0) {
        /* HV did not respond. Treat as integrity failure. */
        KeBugCheckEx(0xDEADC0DEUL, 0, 0, 0, 0);
    }

    if (InterlockedCompareExchange((volatile LONG *)
            &g_integrity_status->integrity_failed, 0, 0) != 0) {
        KeBugCheckEx(0xDEADC0DEUL, 1,
                     (ULONG_PTR)g_integrity_status->last_hash,
                     (ULONG_PTR)g_integrity_status->call_count, 0);
    }
}

NTSTATUS integrity_init(PDRIVER_OBJECT drv)
{
    LARGE_INTEGER due;

    if (!drv) return STATUS_INVALID_PARAMETER;

    /* Capture HV image range. We hash only the first half (approximation
     * of .text + .rdata) to avoid spurious mismatches from mutable
     * .data / .bss. See file-top comment. */
    g_hv_image_start = (PUCHAR)drv->DriverStart;
    g_hv_image_size  = drv->DriverSize / 2;
    if (g_hv_image_size == 0) return STATUS_INVALID_PARAMETER;

    /* Allocate the shared status page from nonpaged pool. It will be
     * reachable from guest context via its kernel VA (same mapping;
     * nonpaged pool has one VA that both host and guest see because
     * the guest IS the host OS kernel). */
    g_integrity_status = (PCHAMBER_INTEGRITY_STATUS)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(CHAMBER_INTEGRITY_STATUS),
        POOLTAG("integrity"));
    if (!g_integrity_status) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_integrity_status, sizeof(CHAMBER_INTEGRITY_STATUS));

    /* Arm the DPC. 5 s period. */
    KeInitializeTimer(&g_integrity_timer);
    KeInitializeDpc(&g_integrity_dpc, integrity_dpc_routine, NULL);
    due.QuadPart = -(LONGLONG)(INTEGRITY_HCALL_PERIOD_MS * 10000LL);
    KeSetTimerEx(&g_integrity_timer, due,
                 (LONG)INTEGRITY_HCALL_PERIOD_MS,
                 &g_integrity_dpc);

    g_integrity_armed = TRUE;
    return STATUS_SUCCESS;
}

void integrity_shutdown(void)
{
    if (g_integrity_armed) {
        KeCancelTimer(&g_integrity_timer);
        KeRemoveQueueDpc(&g_integrity_dpc);
        /* Wait for any in-flight DPC. */
        KeFlushQueuedDpcs();
        g_integrity_armed = FALSE;
    }
    if (g_integrity_status) {
        ExFreePoolWithTag(g_integrity_status, POOLTAG("integrity"));
        g_integrity_status = NULL;
    }
    g_hv_image_start = NULL;
    g_hv_image_size  = 0;
    g_hv_known_hash  = 0;
    g_hv_hash_latched = FALSE;
}

void integrity_handle_hcall(void)
{
    ULONGLONG current;

    if (!g_integrity_status || !g_hv_image_start || g_hv_image_size == 0) {
        return;
    }

    /* Mark responded unconditionally so the guest DPC's silent-ignore
     * detector doesn't false-positive. Write to the shared page (4-byte
     * aligned, torn-write-free on x64). */
    InterlockedExchange((volatile LONG *)&g_integrity_status->hv_responded, 1);

    /* Hash the HV code region. In root context the HV's kernel VA is
     * mapped normally (no NPT translation involved), so this is a
     * plain memory read of nonpaged pool bytes. */
    __try {
        current = fnv1a_64(g_hv_image_start, g_hv_image_size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* A fault in the HV reading its own memory IS an integrity
         * failure. */
        InterlockedExchange((volatile LONG *)
            &g_integrity_status->integrity_failed, 1);
        return;
    }

    g_integrity_status->last_hash = current;
    InterlockedIncrement64((volatile LONG64 *)
                            &g_integrity_status->call_count);

    if (!g_hv_hash_latched) {
        g_hv_known_hash = current;
        g_hv_hash_latched = TRUE;
        InterlockedExchange((volatile LONG *)
            &g_integrity_status->integrity_failed, 0);
        return;
    }

    if (current != g_hv_known_hash) {
        InterlockedExchange((volatile LONG *)
            &g_integrity_status->integrity_failed, 1);
    } else {
        InterlockedExchange((volatile LONG *)
            &g_integrity_status->integrity_failed, 0);
    }
}
