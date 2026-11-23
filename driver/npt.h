/* npt.h -- AMD Nested Page Table (NPT) setup for THE_CHAMBER.
 *
 * References: AMD64 Architecture Programmer's Manual Vol 2 (System
 * Programming), Chapter 15 (Secure Virtual Machine), section 15.19
 * (Nested Paging) and 15.25 (page-table formats).
 *
 * The nested page tables are a 4-level structure that translates guest
 * physical addresses (gPA) to host physical addresses (hPA). THE_CHAMBER
 * uses an identity map (gPA == hPA) so the guest sees the same physical
 * layout as the host. To keep the table small we map host RAM with 2 MB
 * large pages at the PDE level:
 *
 *     PML4  (level 4) -> PDPT (level 3) -> PD (level 2, 2 MB pages)
 *
 * NPT entries use the ordinary long-mode paging bit layout (AMD 15.25):
 *   bit 0   present
 *   bit 1   writable
 *   bit 2   user
 *   bit 7   PS   (page size; set on a PDE => 2 MB large page)
 *   bits 12-51  page frame number (physical base address)
 *   bit 63  NX   (no-execute)
 */

#ifndef THE_CHAMBER_NPT_H
#define THE_CHAMBER_NPT_H

#include "the_chamber.h"

/* NPT entry bit layout (AMD64 APM Vol 2, 15.25). */
#define NPT_PRESENT        (1ULL << 0)
#define NPT_WRITABLE       (1ULL << 1)
#define NPT_USER           (1ULL << 2)
#define NPT_LARGE_PS       (1ULL << 7)   /* PDE: map a 2 MB page */
#define NPT_NX             (1ULL << 63)

/* Page frame number field: physical base, bits 12-51. */
#define NPT_PFN_MASK       0x000FFFFFFFFFF000ULL

/* 2 MB large page covered by one PDE. */
#define NPT_PAGE_SIZE_2MB  (2ULL * 1024 * 1024)

/* Upper bound on host physical RAM that we will identity-map. */
#define NPT_MAX_PHYS_GB    128

/* Host physical address of the NPT PML4 root; loaded into VMCB n_cr3. */
extern ULONGLONG g_npt_cr3_pa;

NTSTATUS npt_init(void);
void     npt_free_tables(void);

/* Mark a range of host physical addresses as not-present in the NPT so
 * reads/writes through the nested page tables fault. Operates at the
 * 2 MB PDE granularity: the input range is rounded outward. The side
 * table has capacity for 256 live 2 MB regions (512 MB total). After
 * the PDE writes the caller must broadcast a TLB flush across every
 * CPU's VMCB (conceptually by OR-ing (1u << 31) into
 * vmcb->ctl.guest_asid_tlb on each per-CPU VMCB). */
NTSTATUS npt_hide_range(ULONGLONG start_pa, SIZE_T size);
NTSTATUS npt_unhide_range(ULONGLONG start_pa, SIZE_T size);

#endif /* THE_CHAMBER_NPT_H */
