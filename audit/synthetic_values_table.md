# THE_CHAMBER -- Synthetic Values Table

Canonical record of every value the hypervisor substitutes for the
guest.  Each row documents what is returned, what bare-metal would
return, and the authoritative source.  Rows flagged *(unverified)*
require a measurement pass on a reference 7700X before the HV ships.

Scope: Ryzen 7 7700X (Zen 4, family 19h model 61h).  Microcode
revisions tested: *(unverified -- populate when driver reads MSR 0x8B
during load; see `docs/operations/ceilings.md` 10.2)*.

Legend for `Spoofed Value`:
- `PASSTHROUGH` -- handler delegates to `__readmsr` / `__cpuidex`.
- A literal value -- handler returns exactly that value on read.
- A derived rule -- handler computes per rules described in Notes.

## MSR table

> **Note on interfaces.**  Each hypervisor-vendor paravirt interface has
> TWO disjoint address spaces: a CPUID-leaf range (read via CPUID, used
> for signature + feature discovery) and an MSR range (read via RDMSR,
> used for hypercall transports, feature-enable bits, etc.).  Confusing
> the two is a recurring documentation hazard: the CPUID leaves are
> dense around `0x40000000`, the MSRs are scattered in the vendor-
> specific space (KVM at `0x4B564D00..0x4B564DFF`, Hyper-V at
> `0x40000000..0x400000FF` which happens to numerically overlap its own
> CPUID range but is a disjoint address space on the MSR port).  The
> MSR table below lists MSR addresses only; CPUID leaves are in the
> CPUID table.

| MSR / Field | Address | Spoofed Value | Bare-metal Expected | Source | Notes |
|-------------|---------|---------------|---------------------|--------|-------|
| EFER | `0xC0000080` | On read: real value with bit 12 (SVME) cleared. On write: real value OR'd with bit 12 (SVME forced on). Other bits passthrough. | SVME=0 on a Windows host where no HV is loaded; other bits reflect OS use (LME=1, NXE=1, SCE=1 typical). | AMD64 APM Vol 2 §15.4 (Extended Feature Enable Register). | Handler exists in `driver/vmexit.c`; MSRPM bit for 0xC0000080 must be set for it to fire -- see archived audit §EFER row. |
| KVM paravirt MSRs | `0x4B564D00` .. `0x4B564DFF` | On read: `0`. On write: absorbed. | Bare metal with no HV loaded: KVM MSR range is unsupported; RDMSR raises #GP. The HV absorbs it instead of pass-through to prevent a #GP -> host bluescheck on any KVM-aware probe sweep. | KVM Documentation `Documentation/virt/kvm/x86/msr.rst`. | Separate from the KVM CPUID signature at `0x40000000..0x40000001` (see CPUID table).  This row is the MSR port; the CPUID port is a disjoint address space. |
| VM_CR | `0xC0010114` | On read: `0`. On write: absorbed (no-op). | Bare metal: SVM-related control bits typically cleared by firmware (SVMDIS=0 when SVM is enabled in BIOS, LOCK=0 or 1 depending on vendor). | AMD64 APM Vol 2 §15.30 (SVM Control MSRs). | Returning `0` presents "SVM available, not locked, not disabled" which is consistent with the EFER.SVME=0 story only if the detector does not cross-check against the SVM-feature CPUID leaf. Review pending. |
| VM_HSAVE_PA | `0xC0010117` | On read: `0`. On write: absorbed. | Bare metal with no HV loaded: `0`. | AMD64 APM Vol 2 §15.30 (VM_HSAVE_PA MSR). | Correct: a bare-metal Windows host with no HV has not executed VMSAVE/VMLOAD against a host-save area and the field is zero. |
| TSC_RATIO | `0xC0000104` | On read: `0x0000_0001_0000_0000`. On write: absorbed. | Bare metal: `0x0000_0001_0000_0000` (ratio = 1.0 in 8.32 fixed-point: int[39:32]=1, frac[31:0]=0, bits [63:40] reserved MBZ). | AMD64 APM Vol 2 §15.30 (TSC Ratio MSR). | NOT Q32.32 -- earlier project drafts had this wrong.  Correct format is 8.32: integer part in bits [39:32], fraction in bits [31:0], bits [63:40] reserved and must be zero. |
| SMM_ADDR | `0xC0010112` | On read: bare-metal default value (platform-specific; captured at driver load from pre-VMCB-build read). On write: absorbed. | Platform firmware configures at reset; on 7700X typically a physical address within the SMRAM region set by BIOS. | AMD64 APM Vol 2 §10.2 (SMM MSRs). | Requires per-box capture at driver load before SVME is set.  Store captured value in a per-CPU structure; return on read. Mark *(unverified)* until capture path implemented. |
| SMM_MASK | `0xC0010113` | On read: bare-metal default value (captured at driver load). On write: absorbed. | Platform-configured at reset; mask length matches SMM_ADDR region. | AMD64 APM Vol 2 §10.2. | Same capture pattern as SMM_ADDR. *(unverified)* until capture implemented. |
| HWCR | `0xC0010015` | `PASSTHROUGH`. | Reflects OS and firmware configuration (TLBCacheDis, SMMLOCK, various performance toggles). | AMD64 APM Vol 2 §B.4 "MSRs -- MSRC001_0015 Hardware Configuration (HWCR)". | HWCR contains no SVM-state bits; SVM lock/disable live in VM_CR.  Passthrough is correct and does not leak HV presence. |
| IA32_UCODE_REV | `0x0000008B` | `PASSTHROUGH`. | AMD patch level in low 32 bits; high 32 bits reserved zero on AMD. | AMD64 APM Vol 2 §B.2 "MSRs -- MSR0000_008B IA32_UCODE_REV / PATCH_LEVEL". | Used by driver's microcode-revision gate at load time (see `docs/operations/ceilings.md` 10.2).  Not spoofed. |
| STAR, LSTAR, CSTAR, SFMASK, KernelGSBase | `0xC0000081` .. `0xC0000102` | `PASSTHROUGH`. | OS-configured syscall entry state. | AMD64 APM Vol 2 §B.2. | No synthetic value needed; OS writes and reads consistently.  Covered in archived audit §STAR/LSTAR row. |
| APERF, MPERF | `0xE8`, `0xE7` | `PASSTHROUGH`. | Raw host counters; advance during host handler cycles too. | AMD64 APM Vol 2 §17.2 (Performance Monitoring). | Spoofing these conflicts with TSC consistency; see archived audit §APERF/MPERF row.  Fix TSC path first; APERF/MPERF stay passthrough. |

## CPUID table

| CPUID Field | Leaf.Sub | Bit / Reg | Spoofed Value | Bare-metal Expected | Source | Notes |
|-------------|----------|-----------|---------------|---------------------|--------|-------|
| Hypervisor Present bit | `0x00000001` | ECX[31] | `0` (bit cleared). Other bits of ECX passthrough. | `0` on a box with no HV loaded. | AMD64 APM Vol 3 "CPUID Fn0000_0001_ECX" + Intel SDM Vol 2A "CPUID -- EAX=1" reserved-ECX[31] note. | Handled in `driver/vmexit.c` lines 81-84 per audit. |
| Reserved HV range -- generic | `0x40000000` .. `0x4FFFFFFF` | all regs (EAX, EBX, ECX, EDX) | `0, 0, 0, 0` on all leaves in the full range. | Measured on Zen 4 7700X bare metal: all four registers = `0` for the full range `0x40000000..0x4FFFFFFF` *(unverified -- confirm on reference box; per observed behavior and VMware convention)*. AMD APM is silent on the specific sub-range; the 0x4xxxxxxx range is reserved by convention for HV paravirt interfaces, not architectural. | AMD64 APM silent; VMware convention + observed Zen 4 bare-metal behavior. | Current build zeroes `0x40000000..0x40000010` only; audit §CPUID-vendor-leaves row recommends widening to `0x4FFFFFFF`.  *(unverified)*: pending a probe-battery run on a reference 7700X with no HV loaded. |
| Hyper-V paravirt range | `0x40000000` .. `0x400001FF` | all regs | Read as `0`. Write: N/A (CPUID is read-only). | On a Hyper-V host guest: Hyper-V signature etc. in registers. On non-Hyper-V bare metal: all zero for this sub-range. | Microsoft Hyper-V Top-Level Functional Specification v6.0 §2.3 (CPUID Leaves). | Covered by the generic 0x4xxxxxxx rule above; retained as separate row to document the specific standard the zero happens to match. |
| KVM CPUID signature | `0x40000000` .. `0x40000001` | all regs | Read as `0, 0, 0, 0`. | On a KVM guest: `EBX='KVMK' ECX='VMKV' EDX='M\0\0\0'` at leaf 0x40000000; feature bits at 0x40000001.  On bare metal with no HV loaded: all four regs `0` (or, on some Intel CPUs, basic-leaf echo -- cross-check against leaf-1 ECX bit 31). | KVM CPUID Documentation (kernel docs `Documentation/virt/kvm/x86/cpuid.rst`). | Covered by the generic `0x40000000..0x4FFFFFFF` zero band in `driver/vmexit.c`; retained as a separate row so the CPUID port is paired with the MSR port in the MSR table.  The KVM MSR range `0x4B564D00..0x4B564DFF` is a DIFFERENT, disjoint address space; see MSR table. |
| SVM feature leaf | `0x8000000A` | ECX, EDX | *Policy pending* -- currently passthrough per audit.  Recommended: with EFER.SVME=0 story, return `EAX=0, EBX=0, ECX=0, EDX=0` to match "SVM not available". | On bare metal with SVM on: EAX=SVM revision (typically `0x00000001`), EBX=NASID count, EDX=feature bits (NRIPS, NPT etc.). | AMD64 APM Vol 3 "CPUID Fn8000_000A". | Not currently intercepted.  Audit lists as a gap because current build clears CPUID.1:ECX[31] but still reports SVM features at `0x8000000A`.  Patch pending. *(unverified)*: recommended handler not yet implemented. |

## Rules and invariants

1. Every row in this table must correspond to code in
   `driver/vmexit.c` or `driver/svm_vmcb.c`.  A code change that adds,
   removes, or alters a handler must update the corresponding row in
   the same commit (enforced by the optional pre-commit hook in
   `docs/operations/discipline.md` 9.6.3).

2. Every row marked *(unverified)* must have its "Bare-metal Expected"
   value confirmed by measurement on a reference 7700X with no HV
   loaded.  Use `pentest\run_all.ps1 -Label baseline_clean` to capture;
   compare the summary.md against this table.  Once confirmed, remove
   the *(unverified)* tag and record the microcode revision from which
   the measurement was taken.

3. Microcode-sensitive rows (marked in Notes) must be re-measured
   after any BIOS update or Windows microcode update.  See
   `docs/operations/ceilings.md` 10.2.

4. Passthrough rows (`PASSTHROUGH`) assert that no synthetic value is
   needed.  If audit later finds a detection path that exploits one of
   these, the row is changed from `PASSTHROUGH` to a specific value
   and the handler is added.

5. This table is the single source of truth.  Any comment in the
   driver source that claims a different spoofed value than this table
   is wrong and must be reconciled.

## Change log for the table itself

| Version | Date | Tested microcode | Change |
|---------|------|------------------|--------|
| 0.1 | 2026-11-23 | *(unverified)* | Initial skeleton.  EFER, VM_CR, VM_HSAVE_PA, TSC_RATIO, SMM_ADDR, SMM_MASK, HWCR, IA32_UCODE_REV rows plus CPUID Hypervisor Present, HV paravirt range, KVM range, SVM feature leaf.  All *(unverified)* bare-metal expectations pending reference-box measurement. |
