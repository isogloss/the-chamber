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
/* MmFreeContiguousMemory().                                          */
/* ------------------------------------------------------------------ */

static PVOID  g_npt_pages[8192];
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

    if (g_npt_page_count < RTL_NUMBER_OF(g_npt_pages)) {
        g_npt_pages[g_npt_page_count++] = va;
    }

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

NTSTATUS npt_init(void)
{
    PPHYSICAL_MEMORY_RANGE ranges;
    PVOID pml4;
    PHYSICAL_ADDRESS pml4_pa;
    ULONGLONG total_mapped = 0;
    ULONGLONG cap_bytes;
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
/* VMCB after the PDE edits (conceptually by OR-ing (1u << 31) into   */
/* vmcb->ctl.guest_asid_tlb on each per-CPU VMCB) because that        */
/* broadcast lives outside this translation unit.                     */
/* ------------------------------------------------------------------ */

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

    /* Caller must broadcast a TLB flush across every CPU's VMCB
     * (conceptually: vmcb->ctl.guest_asid_tlb |= (1u << 31)) because
     * that per-CPU broadcast lives outside this translation unit. */
    return status;
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

    /* Caller must broadcast a TLB flush across every CPU's VMCB
     * (conceptually: vmcb->ctl.guest_asid_tlb |= (1u << 31)) because
     * that per-CPU broadcast lives outside this translation unit. */
    return status;
}
