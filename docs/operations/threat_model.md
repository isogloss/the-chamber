# THE_CHAMBER -- Threat Model

A one-page map of who THE_CHAMBER is built to defeat, what each
adversary can bring to bear, and where the project draws its scope
line.

## Framing

THE_CHAMBER is a thin AMD-SVM hypervisor running on a Ryzen 7 7700X
(Zen 4) used as a cybersecurity-research sandbox for analyzing packed
malware -- Themida, VMProtect, Enigma, custom crypters.

Scope limits that are permanent, not ambition:

- NOT attempting Vanguard, EAC in online mode, or BattlEye in online
  mode.  These require hardware attestation and ring-0 physmem defeat
  that the current architecture cannot provide (see `ceilings.md`
  10.1 and 10.3).
- NOT attempting hardware attestation forgery (TPM quotes, AMD
  SEV-SNP, Intel SGX).  The signing key is in silicon; the HV has no
  access to it.
- NOT attempting defense against hypervisor-aware microarchitectural
  side-channels (Spectre-family, port-contention via SMT, ZenBleed /
  Inception).  Academic research and SMT-specific; unused by
  in-scope targets as of 2026.  See `ceilings.md` 10.5.

## Adversary classes

### A1 -- Public VM benchmarks (pafish, VMAware, InviZzzible, al-khaser)

- **Capabilities.** Ring-3 only.  CPUID checks, MSR reads via bundled
  signed driver in some cases.  Timing probes (RDTSC with and without
  CPUID bracketing).  Enumerate running processes, services, drivers
  by name.  Enumerate `\Device` object directory.  Check Windows
  product registry keys, SMBIOS fields, MAC OUI prefixes, running
  display driver names.
- **What THE_CHAMBER covers.** Once the three blocking bugs in
  `audit/detection_surface.md` are fixed (MSRPM populated, timing
  path wired, r15 ctx replaced with host-stack save): CPUID 1 ECX[31]
  hidden, Hyper-V paravirt range zeroed, EFER.SVME masked, TSC
  monotonic.  Timing-with-CPUID-bracketing probes defeated by
  tsc_offset.  Service / device / registry / filename literals
  closed once the "THE_CHAMBER" string campaign is cleaned
  (`audit/detection_surface.md` prioritized gap list items 6-9).
- **What THE_CHAMBER does not cover.** Nothing in this adversary
  class that is unreachable; this class is entirely in-scope and
  defeatable with the audit's prioritized fixes.

### A2 -- Commercial packers (Themida 3.x, VMProtect 3.x, Enigma 7.x)

- **Capabilities.** Ring-3 with aggressive anti-debug + anti-VM.  Mix
  of pafish-class probes plus:
  - Vendor-specific VMEXIT-latency measurement via APERF/MPERF cross-
    reference against RDTSC (Themida 3.x).
  - Per-protector unique CPUID brand-string check (some bind to
    specific brand strings; a wrong string is itself a tell).
  - Imports-hashing of the running process to check for standard
    debugger DLLs, Procmon hooks, Scylla.
  - On first run: HWID pin to registry or file (see `discipline.md`
    9.2.1 and 9.2.3 for per-protector residue map).
- **What THE_CHAMBER covers.** All CPUID + MSR probes.  TSC-anchored
  timing probes if the tsc_offset path is fixed.  Not
  HWID-pinning per se, but HWID pin is a snapshot-hygiene problem
  (revert snapshot, no pin persists).
- **What THE_CHAMBER does not cover.** Per-core tsc_offset drift
  under heavy VMEXIT load; cross-core RDTSC comparison may still
  flag a tell (see `audit/detection_surface.md` §Cross-core
  shared-counter probe, "HIGH" residual signal).  Mitigation
  proposed in audit; requires a global accumulated-cycles broadcast.

### A3 -- Offline cheat loaders and crypters (custom, not-in-the-wild)

- **Capabilities.** Highly variable.  Typically ring-3 with
  occasional driver-based ring-0 helpers.  Target researchers on a
  known workstation profile; therefore probe for common VM setups
  (VirtualBox, VMware, Hyper-V).
- **What THE_CHAMBER covers.** Entire class, once the audit's
  blocking bugs are fixed.  Ring-3 probes are defeated the same way
  as A1/A2.
- **What THE_CHAMBER does not cover.** A ring-0 helper that can
  scan physmem for VMCB signatures beats the architecture; see
  `ceilings.md` 10.3.  But offline crypters almost never ship such
  drivers; the engineering cost is not justified for an offline
  threat model.

### A4 -- Ring-0 anti-cheat (Vanguard, EAC-online, BattlEye-online)

- **Capabilities.** Boot-time kernel driver.  Direct physmem read via
  `MmMapIoSpace` or via BYOVD.  CPUID + MSR probes from ring 0.  TR,
  GDT, IDT, LDTR per-core comparison.  VMCB-signature search of
  physical memory.  TPM-based attestation sent to vendor server;
  ML-ensemble classifier server-side.  KPP (Patch Guard) assistance
  via Microsoft's HVCI.
- **What THE_CHAMBER covers.** CPUID + MSR intercepts (once MSRPM
  populated) answer their ring-0 reads the same as ring-3.  Nothing
  else.
- **What THE_CHAMBER does not cover.** OUT OF SCOPE PERMANENTLY.
  Physmem scans find the VMCB; TPM attestation cannot be forged;
  Patch Guard trips on the `PsLoadedModuleList` unlink.  See
  `ceilings.md` 10.1 and 10.3.  A build aimed at this class would
  require Intel VT-x + EPT + VMFUNC page swapping, a cooperative
  firmware stack, and an attestation forgery path.  Different
  project.

### A5 -- ML-based ensemble detection (research-tier, not yet
deployed in in-scope targets)

- **Capabilities.** Reads many features (CPUID returns, MSR values,
  timing distributions, scheduler jitter, cache-miss patterns, APIC
  jitter), classifies with a model trained on a diverse set of real
  and virtualized boxes.  No single check decisive.
- **What THE_CHAMBER covers.** Each individual feature can be
  spoofed to match a correct bare-metal value, but matching the
  *distribution* over many features is architecturally harder.
  Partial mitigation via behavioral diversity (session-to-session
  jitter in handler timing, variance in intercept ordering) -- see
  `ceilings.md` 10.4.
- **What THE_CHAMBER does not cover.** A well-trained ensemble
  that uses features the HV does not spoof (e.g. L3 cache-miss
  pattern over long loops) classifies accurately despite
  per-feature spoofing.  Theoretical ceiling; revisit quarterly.

## Defender's posture

For in-scope targets (A1, A2, A3): deployable after the three
blocking bugs in `audit/detection_surface.md` are fixed AND the
"THE_CHAMBER" string campaign is cleaned.  Residual detection
surface after that is in the LOW-to-MEDIUM range for the probe
classes commercial protectors actually ship.

For out-of-scope targets (A4, A5): the HV offers no advantage.  Do
not load it in a session that targets A4; it adds detection surface
without adding defeat capability.  For A5, revisit if a commercial
protector picks up ML-ensemble detection.

## See also

- `audit/detection_surface.md` -- per-class residual exposure table
  with signal strengths.
- `audit/synthetic_values_table.md` -- canonical list of spoofed
  values with sources.
- `docs/operations/discipline.md` -- operational hygiene checklist.
- `docs/operations/ceilings.md` -- long-form treatment of the
  permanent scope limits.
