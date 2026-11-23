/* npt.c -- AMD Nested Page Table construction for THE_CHAMBER.
 *
 * Builds an identity map (guest physical == host physical) over all host
 * RAM reported by MmGetPhysicalMemoryRanges(), using 2 MB large pages at
 * the PDE level per AMD64 APM Vol 2, section 15.19 / 15.25.
 *
 * Level layout: PML4 -> PDPT -> PD (2 MB pages).
 */

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "the_chamber.h"
#include "svm.h"
#include "npt.h"

/* Host physical address of the PML4 root (nested CR3). */
ULONGLONG g_npt_cr3_pa = 0;

/* ------------------------------------------------------------------ */
/* Allocation bookkeeping.                                            */
/*                                                                    */
/* Every contiguous page we allocate (PML4, PDPTs, PDs) is recorded   */
/* in g_npt_pages so npt_free_tables() can hand each one back to      */
/* MmFreeContiguousMemory().  Architectural ceiling for 32 PDPT slots */
/* is 1 + 32 + 32*512 = 16417 pages; round up to 16448 so sustained   */
/* sparse NPFs cannot push an allocation past the tracker.            */
/* ------------------------------------------------------------------ */

#define NPT_MAX_TRACKED_PAGES 16448

static PVOID  g_npt_pages[NPT_MAX_TRACKED_PAGES];
static ULONG  g_npt_page_count = 0;

static PVOID  g_npt_pml4_va = NULL;

/* A PDPT slot tracks one PDPT page (one per populated PML4 entry) and
 * the virtual addresses of the PD pages hanging off it, so we can find
 * an already-allocated PD for a given PDPT index without re-walking the
 * physical tables. 128 GB of RAM fits inside a single PDPT (512 x 1 GB),
 * so the slot array only ever needs a handful of entries. */
typedef struct _NPT_PDPT_SLOT {
    ULONG  pml4_index;
    PVOID  pdpt_va;
    PVOID  pd_va[512];
} NPT_PDPT_SLOT;

static NPT_PDPT_SLOT g_npt_slots[32];
static ULONG         g_npt_slot_count = 0;

/* ------------------------------------------------------------------ */
/* Low-level page allocation.                                         */
/* ------------------------------------------------------------------ */

static PVOID npt_alloc_page(void)
{
    PHYSICAL_ADDRESS lowest;
    PHYSICAL_ADDRESS highest;
    PHYSICAL_ADDRESS boundary;
    PVOID va;

    /* Refuse the allocation if the tracker is full.  Previously we
     * returned a usable VA the caller held without recording it, so
     * teardown leaked it. */
    if (g_npt_page_count >= RTL_NUMBER_OF(g_npt_pages)) {
        return NULL;
    }

    lowest.QuadPart = 0;
    highest.QuadPart = (LONGLONG)0xFFFFFFFFFFFFFFFFULL;
    boundary.QuadPart = 0;

    va = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE,
                                                lowest,
                                                highest,
                                                boundary,
                                                MmCached);
    if (va == NULL) {
        return NULL;
    }

    RtlZeroMemory(va, PAGE_SIZE);

    g_npt_pages[g_npt_page_count++] = va;
    return va;
}

/* ------------------------------------------------------------------ */
/* Table-pointer management.                                          */
/* ------------------------------------------------------------------ */

/* Return the PDPT slot for a given PML4 index, allocating the PDPT page
 * and writing the PML4E (child_pa | PRESENT|WRITABLE|USER) on first use. */
static NPT_PDPT_SLOT *npt_ensure_pdpt(ULONG pml4_index)
{
    ULONG s;
    NPT_PDPT_SLOT *slot;
    PVOID pdpt;
    PHYSICAL_ADDRESS pdpt_pa;
    ULONGLONG *pml4e;

    for (s = 0; s < g_npt_slot_count; s++) {
        if (g_npt_slots[s].pml4_index == pml4_index &&
            g_npt_slots[s].pdpt_va != NULL) {
            return &g_npt_slots[s];
        }
    }

    if (g_npt_slot_count >= RTL_NUMBER_OF(g_npt_slots)) {
        return NULL;
    }

    pdpt = npt_alloc_page();
    if (pdpt == NULL) {
        return NULL;
    }

    slot = &g_npt_slots[g_npt_slot_count++];
    slot->pml4_index = pml4_index;
    slot->pdpt_va = pdpt;
    RtlZeroMemory(slot->pd_va, sizeof(slot->pd_va));

    pdpt_pa = MmGetPhysicalAddress(pdpt);
    pml4e = (ULONGLONG *)g_npt_pml4_va + pml4_index;
    *pml4e = (ULONGLONG)pdpt_pa.QuadPart | 0x7ULL;   /* PRESENT|WRITABLE|USER */

    return slot;
}

/* Return the PD page for a given PDPT index within a slot, allocating it
 * and writing the PDPTE (child_pa | PRESENT|WRITABLE|USER) on first use. */
static ULONGLONG *npt_ensure_pd(NPT_PDPT_SLOT *slot, ULONG pdpt_index)
{
    PVOID pd;
    PHYSICAL_ADDRESS pd_pa;
    ULONGLONG *pdpte;

    if (slot->pd_va[pdpt_index] != NULL) {
        return (ULONGLONG *)slot->pd_va[pdpt_index];
    }

    pd = npt_alloc_page();
    if (pd == NULL) {
        return NULL;
    }

    slot->pd_va[pdpt_index] = pd;

    pd_pa = MmGetPhysicalAddress(pd);
    pdpte = (ULONGLONG *)slot->pdpt_va + pdpt_index;
    *pdpte = (ULONGLONG)pd_pa.QuadPart | 0x7ULL;     /* PRESENT|WRITABLE|USER */

    return (ULONGLONG *)pd;
}

/* ------------------------------------------------------------------ */
/* Public API.                                                        */
/* ------------------------------------------------------------------ */

/* NPT_UC: uncached leaf attribute.  Bit 4 = PCD on a 2 MB PDE. */
#define NPT_UC_PCD      (1ULL << 4)

/* Pre-allocate every PDPT and PD that covers [0, NPT_MAX_PHYS_GB) so a
 * later Nested Page Fault at DISPATCH_LEVEL does NOT need to call
 * MmAllocateContiguousMemorySpecifyCache (which requires PASSIVE_LEVEL).
 * The handler can then just write the leaf PDE under g_npt_hide_lock.
 *
 * 128 GB coverage = 128 PDPT entries = 1 PDPT slot (512 PDs under one
 * PDPT = 512 GB), but we're mapping identity so PML4[0]'s PDPT covers
 * 0..512 GB; pre-allocate 128 PDs under it. */
static NTSTATUS npt_preallocate_tables(void)
{
    NPT_PDPT_SLOT *slot;
    ULONGLONG       cap_bytes;
    ULONG           pdpt_i;
    ULONG           pdpt_count;

    cap_bytes = (ULONGLONG)NPT_MAX_PHYS_GB * 1024ULL * 1024ULL * 1024ULL;
    pdpt_count = (ULONG)((cap_bytes + (1ULL << 30) - 1) >> 30);
    if (pdpt_count > 512) pdpt_count = 512;

    slot = npt_ensure_pdpt(0);
    if (slot == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    for (pdpt_i = 0; pdpt_i < pdpt_count; pdpt_i++) {
        if (npt_ensure_pd(slot, pdpt_i) == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS npt_init(void)
{
    PPHYSICAL_MEMORY_RANGE ranges;
    PVOID pml4;
    PHYSICAL_ADDRESS pml4_pa;
    ULONGLONG total_mapped = 0;
    ULONGLONG cap_bytes;
    NTSTATUS  st;
    ULONG i;

    g_npt_page_count = 0;
    g_npt_slot_count = 0;
    g_npt_pml4_va = NULL;
    g_npt_cr3_pa = 0;

    cap_bytes = (ULONGLONG)NPT_MAX_PHYS_GB * 1024ULL * 1024ULL * 1024ULL;

    /* Root PML4 page. */
    pml4 = npt_alloc_page();
    if (pml4 == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_npt_pml4_va = pml4;

    /* Pre-allocate every PDPT and PD at PASSIVE_LEVEL.  Later NPFs can
     * only write PDE leaves while holding the spin lock. */
    st = npt_preallocate_tables();
    if (!NT_SUCCESS(st)) {
        npt_free_tables();
        return st;
    }

    ranges = MmGetPhysicalMemoryRanges();
    if (ranges == NULL) {
        npt_free_tables();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* The array is terminated by a zeroed entry {Base=0, Bytes=0}. */
    for (i = 0;
         ranges[i].BaseAddress.QuadPart != 0 ||
         ranges[i].NumberOfBytes.QuadPart != 0;
         i++) {

        ULONGLONG start = (ULONGLONG)ranges[i].BaseAddress.QuadPart;
        ULONGLONG len   = (ULONGLONG)ranges[i].NumberOfBytes.QuadPart;
        ULONGLONG end   = start + len;
        ULONGLONG f;

        /* Round the range outward to 2 MB boundaries. */
        start &= ~(NPT_PAGE_SIZE_2MB - 1);
        end = (end + (NPT_PAGE_SIZE_2MB - 1)) & ~(NPT_PAGE_SIZE_2MB - 1);

        /* M-15: round-down previously pulled low RAM down to 0, which
         * identity-mapped VGA 0xA0000-0xBFFFF and ROM shadow
         * 0xC0000-0xFFFFF as cached-writable-user-exec.  Bump the floor
         * to 0x100000 so the first MB (with its legacy MMIO holes) is
         * not covered by the WB-cached leaf; we install explicit UC
         * leaves for VGA and the ROM shadow below. */
        if (start < 0x100000ULL) start = 0x100000ULL;
        if (end <= start)       continue;
        /* Realign up after bumping start. */
        start &= ~(NPT_PAGE_SIZE_2MB - 1);

        for (f = start; f < end; f += NPT_PAGE_SIZE_2MB) {
            ULONG pml4_i = (ULONG)((f >> 39) & 0x1FF);
            ULONG pdpt_i = (ULONG)((f >> 30) & 0x1FF);
            ULONG pd_i   = (ULONG)((f >> 21) & 0x1FF);
            NPT_PDPT_SLOT *slot;
            ULONGLONG *pd;

            if (total_mapped >= cap_bytes) {
                goto done;
            }

            slot = npt_ensure_pdpt(pml4_i);
            if (slot == NULL) {
                ExFreePool(ranges);
                npt_free_tables();
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            pd = npt_ensure_pd(slot, pdpt_i);
            if (pd == NULL) {
                ExFreePool(ranges);
                npt_free_tables();
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            /* 2 MB leaf: PRESENT|WRITABLE|USER|PS over the frame. */
            pd[pd_i] = (f & ~0x1FFFFFULL) | 0x87ULL;

            total_mapped += NPT_PAGE_SIZE_2MB;
        }
    }

    /* Legacy MMIO holes in the first 2 MB: install a dedicated 2 MB UC
     * leaf at frame 0 so VGA (0xA0000-0xBFFFF) and the ROM shadow
     * (0xC0000-0xFFFFF) are reachable with the correct cache attribute
     * instead of either being unmapped or covered by a WB leaf.
     *
     * Master plan 2.6 ideally splits VGA (UC+Writable) from ROM shadow
     * (UC+ReadOnly). A 2 MB large page cannot represent that split, so
     * this leaf maps both regions UC+Writable as a passive-dump
     * compromise. Splitting into 4 KB leaves to differentiate attributes
     * is a future enhancement, not a Phase 1 requirement. */
    {
        NPT_PDPT_SLOT *slot = npt_ensure_pdpt(0);
        if (slot != NULL) {
            ULONGLONG *pd = npt_ensure_pd(slot, 0);
            if (pd != NULL) {
                /* Frame 0 identity-mapped, PRESENT|WRITABLE|USER|PCD|PS. */
                pd[0] = 0ULL | 0x87ULL | NPT_UC_PCD;
            }
        }
    }

done:
    ExFreePool(ranges);

    pml4_pa = MmGetPhysicalAddress(pml4);
    g_npt_cr3_pa = (ULONGLONG)pml4_pa.QuadPart;

    return STATUS_SUCCESS;
}

void npt_free_tables(void)
{
    ULONG i;

    for (i = 0; i < g_npt_page_count; i++) {
        if (g_npt_pages[i] != NULL) {
            MmFreeContiguousMemory(g_npt_pages[i]);
            g_npt_pages[i] = NULL;
        }
    }

    g_npt_page_count = 0;
    g_npt_slot_count = 0;
    g_npt_pml4_va = NULL;
    g_npt_cr3_pa = 0;
}

/* ------------------------------------------------------------------ */
/* NPT hide / unhide: clear/restore Present|Writable|User on 2 MB     */
/* PDEs covering a physical range.                                    */
/*                                                                    */
/* A file-static side table (capacity 256 entries, 512 MB of hidden   */
/* range at the 2 MB granule) remembers the original PDE value so     */
/* npt_unhide_range() can put it back verbatim. The table is guarded  */
/* by a KSPIN_LOCK that relies on static zero initialization for its  */
/* unheld state, which is valid for KSPIN_LOCK on x64 Windows.        */
/*                                                                    */
/* The caller is responsible for TLB invalidation across every CPU's  */
/* VMCB after the PDE edits: write TLB_CONTROL_FLUSH_GUEST (0x03) to  */
/* vmcb->ctl.tlb_control on each per-CPU VMCB (see npt_tlb_flush).    */
/* The guest_asid_tlb field is the 32-bit ASID; ORing bit 31 into it  */
/* silently raises the ASID instead of flushing.                       */
/* ------------------------------------------------------------------ */

/* Write TLB_CONTROL_FLUSH_GUEST into the low byte of tlb_control so
 * hardware flushes the guest's TLB entries on the next VMRUN.  Caller
 * must invoke this on every per-CPU VMCB after a PDE edit. */
void npt_tlb_flush(VMCB *vmcb)
{
    if (!vmcb) return;
    vmcb->ctl.tlb_control = TLB_CONTROL_FLUSH_GUEST;
}

typedef struct _NPT_HIDE_ENTRY {
    ULONGLONG pa;
    ULONGLONG original_pde;
} NPT_HIDE_ENTRY;

#define NPT_HIDE_CAPACITY 256

static NPT_HIDE_ENTRY g_npt_hide_table[NPT_HIDE_CAPACITY];
static ULONG          g_npt_hide_count = 0;
static KSPIN_LOCK     g_npt_hide_lock;   /* zero-initialized = unheld */

/* Walk g_npt_slots[] to locate the live 2 MB PDE for a 2 MB-aligned
 * physical address. Returns NULL if the range was never mapped by
 * npt_init(). */
static ULONGLONG *npt_find_pde(ULONGLONG pa_2mb)
{
    ULONG pml4_i = (ULONG)((pa_2mb >> 39) & 0x1FF);
    ULONG pdpt_i = (ULONG)((pa_2mb >> 30) & 0x1FF);
    ULONG pd_i   = (ULONG)((pa_2mb >> 21) & 0x1FF);
    ULONG s;

    for (s = 0; s < g_npt_slot_count; s++) {
        if (g_npt_slots[s].pml4_index != pml4_i) {
            continue;
        }
        if (g_npt_slots[s].pd_va[pdpt_i] == NULL) {
            return NULL;
        }
        return (ULONGLONG *)g_npt_slots[s].pd_va[pdpt_i] + pd_i;
    }

    return NULL;
}

NTSTATUS npt_hide_range(ULONGLONG start_pa, SIZE_T size)
{
    ULONGLONG aligned_start;
    ULONGLONG aligned_end;
    ULONGLONG pa;
    KIRQL     old_irql;
    NTSTATUS  status = STATUS_SUCCESS;

    if (size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((ULONGLONG)size > ((ULONGLONG)0xFFFFFFFFFFFFFFFFULL - start_pa)) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((start_pa + (ULONGLONG)size) >
        ((ULONGLONG)0xFFFFFFFFFFFFFFFFULL - (NPT_PAGE_SIZE_2MB - 1))) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_npt_pml4_va == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    aligned_start = start_pa & ~(NPT_PAGE_SIZE_2MB - 1);
    aligned_end   = (start_pa + (ULONGLONG)size + (NPT_PAGE_SIZE_2MB - 1)) &
                    ~(NPT_PAGE_SIZE_2MB - 1);

    KeAcquireSpinLock(&g_npt_hide_lock, &old_irql);

    for (pa = aligned_start; pa < aligned_end; pa += NPT_PAGE_SIZE_2MB) {
        ULONGLONG *pde;
        ULONG     i;
        BOOLEAN   already_hidden = FALSE;

        /* Idempotent: skip 2 MB regions already in the side table. */
        for (i = 0; i < g_npt_hide_count; i++) {
            if (g_npt_hide_table[i].pa == pa) {
                already_hidden = TRUE;
                break;
            }
        }
        if (already_hidden) {
            continue;
        }

        if (g_npt_hide_count >= NPT_HIDE_CAPACITY) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        pde = npt_find_pde(pa);
        if (pde == NULL) {
            /* 2 MB region not mapped by npt_init(); nothing to do. */
            continue;
        }

        g_npt_hide_table[g_npt_hide_count].pa = pa;
        g_npt_hide_table[g_npt_hide_count].original_pde = *pde;
        g_npt_hide_count++;

        *pde = *pde & ~((ULONGLONG)0x7);
    }

    KeReleaseSpinLock(&g_npt_hide_lock, old_irql);

    /* Caller must broadcast a TLB flush across every CPU's VMCB via
     * npt_tlb_flush(vmcb) because that per-CPU broadcast lives outside
     * this translation unit. */
    return status;
}

/* ------------------------------------------------------------------ */
/* Phase 1.6: handle_npf fault-recovery path.                         */
/*                                                                    */
/* npt_init() identity-maps every range MmGetPhysicalMemoryRanges()   */
/* reports. A guest access to RAM outside that reported set (e.g.     */
/* firmware-reserved region revealed by a later ACPI walk) takes a    */
/* Nested Page Fault. handle_npf() calls npt_map_page() here to       */
/* grow the NPT on demand at the 2 MB PDE granularity and retries the */
/* faulting instruction by NOT advancing RIP.                         */
/* ------------------------------------------------------------------ */

NTSTATUS npt_map_page(ULONGLONG gpa, ULONGLONG hpa, ULONGLONG flags)
{
    ULONGLONG gpa_2mb;
    ULONGLONG hpa_2mb;
    ULONG     pml4_i;
    ULONG     pdpt_i;
    ULONG     pd_i;
    NPT_PDPT_SLOT *slot;
    ULONGLONG *pd;
    KIRQL     old_irql;

    if (g_npt_pml4_va == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    gpa_2mb = gpa & ~(NPT_PAGE_SIZE_2MB - 1);
    hpa_2mb = hpa & ~(NPT_PAGE_SIZE_2MB - 1);
    pml4_i  = (ULONG)((gpa_2mb >> 39) & 0x1FF);
    pdpt_i  = (ULONG)((gpa_2mb >> 30) & 0x1FF);
    pd_i    = (ULONG)((gpa_2mb >> 21) & 0x1FF);

    /* npt_init preallocates every PDPT and PD under PML4[0] (the first
     * NPT_MAX_PHYS_GB of address space).  Addresses in any other PML4
     * slot (>= 512 GB) would require an allocation at DISPATCH_LEVEL
     * under the hide-lock, which the WDK forbids.  Passive-dump guests
     * never see >512 GB of address space -- reject the fault instead. */
    if (pml4_i != 0) {
        return STATUS_INVALID_ADDRESS;
    }

    /* The side table is guarded by g_npt_hide_lock to keep the PDPT /
     * PD allocation and the final PDE write atomic against a concurrent
     * npt_hide_range() / npt_unhide_range() on the same PDE. */
    KeAcquireSpinLock(&g_npt_hide_lock, &old_irql);

    slot = npt_ensure_pdpt(pml4_i);
    if (slot == NULL) {
        KeReleaseSpinLock(&g_npt_hide_lock, old_irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pd = npt_ensure_pd(slot, pdpt_i);
    if (pd == NULL) {
        KeReleaseSpinLock(&g_npt_hide_lock, old_irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* 2 MB leaf PDE: frame | PS | caller-supplied perms. Drop any bits
     * of `flags` above the low 12 that would collide with the PFN. */
    pd[pd_i] = (hpa_2mb & ~0x1FFFFFULL) | NPT_LARGE_PS | (flags & 0xFFF);

    KeReleaseSpinLock(&g_npt_hide_lock, old_irql);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Phase 1.6 NPT monitor stubs. Phase 6 replaces these with the real  */
/* per-page execute-only / read-only / write-trap bookkeeping used    */
/* for tracing specific guest-physical regions. For Phase 1 they      */
/* always report "not monitored" so handle_npf() falls through to     */
/* npt_map_page().                                                    */
/* ------------------------------------------------------------------ */

NPT_MONITOR *npt_monitor_find(ULONGLONG gpa_page)
{
    UNREFERENCED_PARAMETER(gpa_page);
    return NULL;
}

void npt_monitor_handle_fault(NPT_MONITOR *mon,
                              VMCB       *vmcb,
                              ULONGLONG   fault_info)
{
    UNREFERENCED_PARAMETER(mon);
    UNREFERENCED_PARAMETER(vmcb);
    UNREFERENCED_PARAMETER(fault_info);
}

NTSTATUS npt_unhide_range(ULONGLONG start_pa, SIZE_T size)
{
    ULONGLONG aligned_start;
    ULONGLONG aligned_end;
    ULONGLONG pa;
    KIRQL     old_irql;
    NTSTATUS  status = STATUS_SUCCESS;

    if (size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((ULONGLONG)size > ((ULONGLONG)0xFFFFFFFFFFFFFFFFULL - start_pa)) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((start_pa + (ULONGLONG)size) >
        ((ULONGLONG)0xFFFFFFFFFFFFFFFFULL - (NPT_PAGE_SIZE_2MB - 1))) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_npt_pml4_va == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    aligned_start = start_pa & ~(NPT_PAGE_SIZE_2MB - 1);
    aligned_end   = (start_pa + (ULONGLONG)size + (NPT_PAGE_SIZE_2MB - 1)) &
                    ~(NPT_PAGE_SIZE_2MB - 1);

    KeAcquireSpinLock(&g_npt_hide_lock, &old_irql);

    for (pa = aligned_start; pa < aligned_end; pa += NPT_PAGE_SIZE_2MB) {
        ULONG   i;
        BOOLEAN found = FALSE;

        for (i = 0; i < g_npt_hide_count; i++) {
            if (g_npt_hide_table[i].pa == pa) {
                ULONGLONG *pde = npt_find_pde(pa);
                if (pde != NULL) {
                    *pde = g_npt_hide_table[i].original_pde;
                }
                /* Swap-with-last to delete the entry. */
                g_npt_hide_table[i] =
                    g_npt_hide_table[g_npt_hide_count - 1];
                g_npt_hide_count--;
                found = TRUE;
                break;
            }
        }

        if (!found) {
            status = STATUS_NOT_FOUND;
        }
    }

    KeReleaseSpinLock(&g_npt_hide_lock, old_irql);

    /* Caller must broadcast a TLB flush across every CPU's VMCB via
     * npt_tlb_flush(vmcb) because that per-CPU broadcast lives outside
     * this translation unit. */
    return status;
}
