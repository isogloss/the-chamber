# Phase 10 -- Honest Ceilings

THE_CHAMBER is a thin AMD-SVM hypervisor that intercepts a short list of
CPUID leaves and MSRs on Ryzen 7 7700X.  It makes a certain class of
VM-detection probe fail.  It does NOT make every detection probe fail,
and the design has well-defined ceilings above which no amount of
patching the current codebase helps.

This document catalogs those ceilings honestly.  The intent is to give
the operator a clear map of what to attempt, what to decline, and what
would require a different project.

Scope: this doc covers only what the HV cannot hide.  For the inverse --
what it can hide, and what breaks the current build before that question
even applies -- see `audit/detection_surface.md`.

## 10.1 Hardware attestation

### What it is

Hardware-rooted identity.  A TPM 2.0 chip (or AMD fTPM running in a
secure enclave on the SoC), Intel SGX, or AMD SEV-SNP generate signed
attestations over a chain that terminates in a vendor-held private key
burned into silicon or into a vendor-signed secure firmware blob.

Concrete examples encountered in anti-tamper:

- **TPM 2.0 Quote** (`TPM2_Quote`).  Signs the current PCR values with
  the TPM's Attestation Key (AK), which chains to the Endorsement Key
  (EK) certified by the TPM vendor.  A server receiving the quote can
  verify the AK certificate chain back to the vendor root, read the PCR
  values, and compare them against expected measured-boot sequences.
- **AMD SEV-SNP attestation report** (`SNP_GUEST_REPORT`).  An AMD CPU
  in SNP mode produces a signed report over guest state, signed by the
  AMD Versioned Chip Endorsement Key (VCEK), which is signed by AMD's
  ARK/ASK root.
- **Intel SGX quotes** via DCAP.  Same shape, Intel-rooted.

### Why THE_CHAMBER cannot forge

The private signing key lives in silicon or in vendor-signed firmware
and never leaves.  The HV has no access to it.  Even a bug-free
hypervisor at ring -1 cannot sign an attestation that validates against
the vendor root.  Intercepting the TPM MMIO and returning fabricated
values would produce a quote with a signature that fails verification on
first inspection.

Note that the AMD VCEK is per-CPU-and-microcode: a report signed by VCEK
on a 7700X with microcode revision X is bound to that exact combination.
A spoofed microcode revision (see 10.2) produces a report that
verifies against the wrong VCEK and fails at the server.

### When it matters

Attestation matters when:

1. The target loader issues an attestation challenge and sends the
   result to a server that verifies the signature against the vendor
   root.
2. The server's acceptance of the session depends on a specific set of
   PCR values or SNP report fields.

If the target only reads PCRs locally without signing them, the HV can
sometimes intercept the TPM driver traffic and return whatever PCRs it
wants -- but note this is TPM 2.0 driver interception, not quote
forgery, and it only works if the local verifier does not then call
`TPM2_Quote` to confirm.

### Mitigation options (unclean)

Three nominal paths, each with a fatal flaw:

- **Cooperative software TPM.**  Present a software TPM driver that the
  target accepts in place of the physical TPM.  Works only if the
  target was built to accept software TPMs, which modern anti-tamper is
  not; the signature chain still has to validate, and a software TPM
  does not have a vendor-certified EK.

- **Attack server-side verification.**  Compromise or spoof the server
  that checks the quote.  Out of scope for a defensive research lab.
  Likely illegal for any target not operated by the researcher.  DO NOT
  PURSUE; documented here only to be candid that it is the one path
  that could work and is the one path we will not take.

- **Replay attested quotes from a known-good reference box.**  Produce
  a quote on a real 7700X with a real TPM in a real boot, then replay
  the signed blob to the server from the analysis VM.  Blocked by
  nonce-in-quote: every reputable attestation protocol mixes a
  server-chosen nonce into the signed payload, which changes per
  session.

### Operational guidance

If a target issues an attestation challenge and ships the result to a
server, move it out of THE_CHAMBER's scope.  Analyze it statically, or
on a cooperative test environment where the server verifier is under
your control (this is the only legitimate reason to touch
server-side -- a self-hosted target, e.g. an in-house build, used for
research).

## 10.2 Microcode updates

### What it is

AMD CPUs ship with an updatable microcode blob that rewires edge-case
instruction behavior, errata workarounds, and -- relevant to a
spoofing HV -- occasionally changes the observable values of certain
MSRs or reserved CPUID fields.  Microcode updates reach boxes via:

- BIOS/UEFI updates (motherboard vendor packages microcode into AGESA
  firmware).
- Linux `linux-firmware` package `amd-ucode` tree
  (https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/amd-ucode)
  loaded at early boot by the OS.
- On Windows, Microsoft ships AMD microcode updates via
  `mcupdate_AuthenticAMD.dll` in Windows Update, which Windows loads at
  boot before the HAL.

### Why it hurts a spoofing HV

A hypervisor that returns a specific "bare-metal expected" value for an
MSR is implicitly asserting that the value is correct for the microcode
revision in play.  Once microcode changes:

- The previously-correct value may now be stale -- bare-metal 7700X
  under new microcode returns a different value, and the HV's constant
  does not.
- The microcode revision itself is readable by the guest via MSR
  `0x0000008B` (`IA32_UCODE_REV` / AMD `PATCH_LEVEL`).  A probe can
  cross-check: CPUID signature (family 19h model 61h stepping 2) plus
  microcode revision 0x0A601209 implies, by vendor documentation, a
  specific value in MSR X.  If the HV returns a different value for
  MSR X, the inconsistency is a tell.

### How to detect microcode in play

```c
// Ring 0 only.
unsigned long long ucode_rev = __readmsr(0x0000008B);
// Low 32 bits: the patch level on AMD. Upper bits: zero on AMD.
```

Equivalent in userland on Windows is unavailable without a driver; the
ring-3 route is to shell to PowerShell:

```powershell
(Get-CimInstance Win32_Processor).ProcessorId
# Returns CPU signature. Microcode revision requires a driver read of
# MSR 0x8B; the installed driver (THE_CHAMBER itself, or a signed
# utility like RWEverything) is required.
```

AMD exposes released microcode patch numbers through the
`linux-firmware` tree README and through AMD Security Bulletins
(https://www.amd.com/en/resources/product-security.html).  The current
7700X (Zen 4 Raphael, family 19h model 61h) patch levels and their
publication dates are tracked there.

### Mitigation

A policy, not a code path:

1. Record the microcode revision the HV was tested against at build
   time.  Store it in the synthetic-values table
   (`audit/synthetic_values_table.md`) as a per-table-version tag.
2. At driver load, read MSR `0x8B` and refuse to proceed if the
   detected revision is not in a known-tested set.  Print the detected
   revision and the acceptable set to the kernel debugger and exit.
   Operator updates the table + redeploys.

Pseudo:

```c
// In svm_bringup.c, after CPU detection, before VMRUN broadcast.
#define CHAMBER_UCODE_TESTED { 0x0A601209, 0x0A60120A }  // example
unsigned long long rev = __readmsr(0x8B) & 0xFFFFFFFFULL;
unsigned long long tested[] = CHAMBER_UCODE_TESTED;
int ok = 0;
for (unsigned i = 0; i < ARRAYSIZE(tested); i++)
    if (tested[i] == rev) { ok = 1; break; }
if (!ok) {
    // DbgPrintEx and refuse to continue.
    return STATUS_NOT_SUPPORTED;
}
```

3. Review the AMD security bulletin and `linux-firmware` tree quarterly.
   For each new microcode revision affecting family 19h model 61h,
   re-run the probe battery on a reference 7700X with that revision
   loaded and update the synthetic-values table accordingly.  Increment
   the table version.
4. For BIOS updates on the analysis box: do them on the schedule, then
   re-run the baseline manifest (see `discipline.md` 9.1.5) and the
   full pentest probe battery; do not assume a BIOS update left the
   HV's synthetic values valid.

### Caveat

The `CPUID 0x8000001F` leaf cited in the task description reports
*Encrypted Memory Capabilities* (SEV, SEV-ES, SME support), not
microcode revision.  Microcode revision reads from MSR `0x8B` (also
callable as `IA32_UCODE_REV`); on AMD the low 32 bits hold the patch
level.  The task's reference to "CPUID 0x8000001F on AMD" is noted as
an error; this doc uses MSR `0x8B`.

## 10.3 Ring-0 adversary code

The HV runs at ring -1 (host SVM) and intercepts guest CPUID + MSR.
Everything at ring 3 in the guest sees the spoofed values.  Everything
at ring 0 in the guest sees the spoofed values IF the handler for that
instruction class actually intercepts it.

### Probes that already work from ring 0

Even with a clean ring-0 adversary driver loaded as a sibling to
THE_CHAMBER inside the guest, the current architecture handles:

- **CPUID leaf 0x80000000A** (SVM features): on bare metal with SVM off
  in EFER returns zero in EDX for SVM-Lock etc; with SVM on returns
  feature bits.  THE_CHAMBER intercepts CPUID and (per audit) clears
  leaf 1 ECX[31] but not the SVM-feature leaf.  Fix in progress.
- **RDMSR 0xC0000080 EFER**: the handler masks SVME bit 12.  Once the
  MSRPM is populated (audit §EFER row) this intercept fires.
- **VMRUN executed from guest ring 0**: faults with `#UD` because
  EFER.SVME is cleared in the guest's view of EFER; the guest OS
  believes SVM is unavailable, and the CPU raises `#UD` before VMRUN
  decodes.  Bare metal with SVM enabled would execute (and either
  succeed or fault with `#GP` depending on VMCB state); THE_CHAMBER
  presenting SVME=0 gives consistent "no SVM here".  Nested-virt
  scenarios where the guest OS is itself a hypervisor (Hyper-V, KVM)
  need different handling and are out of scope; a target that forces
  nested SVM is already a specialized probe.

### Probes the HV cannot credibly answer

Several ring-0 probes defeat the architecture as written:

- **Direct VMCB physical access.**  A ring-0 driver in the guest can
  allocate a page, call `MmGetPhysicalAddress` to get its physical
  address, and then compare adjacent physical pages looking for the
  VMCB byte signature (the save-state area has distinctive layout:
  CS/DS/SS selectors + CR3 + RIP at known offsets).  THE_CHAMBER's
  VMCB lives in NonPagedPool; if the target has unrestricted access to
  physical memory via `MmMapIoSpace` or via a signed vulnerable driver
  (BYOVD), it can find the VMCB and read the real guest state.  The HV
  cannot hide its VMCB from a ring-0 reader that has arbitrary
  physmem read.

- **TR task register per-CPU comparison.**  Read `TR` from each core
  (`str` instruction), compare limits.  On bare metal with Windows the
  TSS has a known limit (0x67 for the 32-bit TSS on legacy code paths,
  `sizeof(KTSS64)-1` for 64-bit).  If THE_CHAMBER's VMCB build sets a
  slightly different TR limit per core -- or if the CPU reflects
  host TR limits into guest view inconsistently -- a cross-core STR
  comparison flags it.  Mitigable but unimplemented.

- **VMCB clean-bits timing.**  A ring-0 probe can issue a long
  sequence of trivial VMEXIT-inducing instructions and measure
  distribution of exit latencies via APERF (which the HV does not
  intercept and cannot plausibly intercept without introducing new
  tells).  Statistical fingerprint of the handler is possible.

- **`SVM_VERIFY_REVISION` via `VMLOAD/VMSAVE` bracketing.**  On bare
  metal with SVM disabled, VMLOAD/VMSAVE both `#UD`.  With SVM enabled
  but no HV, they execute and modify host state.  In a THE_CHAMBER
  guest they trap (IVEC2_VMLOAD / IVEC2_VMSAVE in the intercept
  vectors -- except the current build does not set these, see
  svm_vmcb.c).  A ring-0 probe that executes VMLOAD in a `__try` sees
  the fault class and knows: `#UD` means no SVM; no fault means bare
  metal with SVM; `#VMEXIT` (which the probe cannot observe directly
  but sees as a time anomaly) means an HV.

### Specifically: Vanguard-class adversaries

Riot Vanguard is a kernel-mode anti-cheat (ring 0 driver, boot-time
load, HVCI-friendly) that explicitly enumerates hypervisor presence
with the ring-0 probes above AND submits attestation to Riot's server.
Vanguard has, in public reporting:

- Probed CPUID.1:ECX[31] (trivial, we handle).
- Probed `MSR 0xC0000080 EFER` and `MSR 0xC0010117 VM_HSAVE_PA` (we
  handle once MSRPM is populated).
- Enumerated `PsLoadedModuleList` structural invariants from ring 0
  (we trip; see `audit/detection_surface.md` §PatchGuard row).
- Submitted a software TPM attestation report to Riot server-side (see
  10.1).
- Probed for VMCB signatures in physical memory (public reports around
  2023 describe this).

Taken together, Vanguard is outside the scope of THE_CHAMBER.  Not
because the HV is poorly built; because this architecture cannot hide
a VMCB from a ring-0 adversary with physmem access, and cannot
produce a valid TPM attestation.  A build that would have a chance at
Vanguard requires:

- Intel VT-x with EPT rather than AMD SVM with NPT, so that
  VMFUNC-based page swapping can hide pages from guest ring 0;
- a cooperative firmware stack or a vendor-signed TPM fake that passes
  attestation;
- a per-VMEXIT handler small enough that statistical timing analysis
  cannot fingerprint it.

That is a different project.  Mentioning it here only to be clear: the
current THE_CHAMBER does not aim at Vanguard and will not be patched
there.

### Non-Vanguard targets

For the actual in-scope target set -- Themida, VMProtect, Enigma,
custom crypters, EAC and BattlEye in **offline** reversing only --
all probes observed in public samples are ring-3 probes.  These
targets are reversing-prevention, not anti-cheat; their threat model
is a reverser, not a running cheat.  Ring-3 probes are:

- CPUID leaves (we cover).
- RDMSR from a ring-3 helper driver bundled with the loader (rare
  outside anti-cheat; most commercial protectors do not ship kernel
  drivers).
- Timing probes (RDTSC with and without CPUID bracketing -- we cover
  once the tsc_offset bug in `audit/detection_surface.md` is fixed).
- Debugger-presence probes (`NtQueryInformationProcess` with
  `ProcessDebugPort`, PEB `BeingDebugged`, `CheckRemoteDebuggerPresent`,
  int 2d, etc -- these are target-of-opportunity for the HV but not
  the primary scope; existing debugger-anti-anti-debug techniques cover
  them).
- `IsProcessorFeaturePresent(PF_VIRT_FIRMWARE_ENABLED)` -- wraps
  `HvCallGetHypervisorInfo`; satisfied by clearing CPUID.1:ECX[31]
  and zeroing the Hyper-V paravirt CPUID range.

For this scope the architecture is sufficient once the audit's three
blocking bugs are fixed (MSRPM dead code, timing_before_vmrun not
called, r15 as ctx across VMRUN).

## 10.4 Statistical ML-based detection

### What it is

A detector that reads not one tell but many -- CPUID returns, MSR
values, timing distributions, page-fault patterns, scheduler jitter,
APIC timer regularity, interrupt-rate density -- and classifies with a
trained model.  No single feature is decisive; the ensemble is.

### Why it is hard to defeat

No single intercept fix helps.  The spoofing HV can match the expected
value for every feature it knows about and still lose, because:

- The detector may use a feature the HV does not spoof (e.g. the pattern
  of instruction-cache misses across a long loop, which is almost
  impossible to synthesize).
- The detector was trained on a diverse set of real boxes and the
  spoofed HV's output sits outside the training-set cluster even though
  no single value is out-of-spec.
- The HV's own code paths produce a characteristic timing jitter
  profile that the detector recognizes as a HV-side pattern.

### Mitigation

Partial, not complete.  Two posture choices:

1. **Behavioral diversity.**  Randomize the parts of HV behavior that
   are otherwise constant.  Per-session:
   - Vary the per-exit RDTSC jitter added to tsc_offset by a small
     random amount on top of the accumulated host cycles (sub-handler
     cycle budget, not noticeable individually but breaks constant
     signatures).
   - Vary the ordering of unimportant intercepts (e.g. the sequence of
     MSRPM-check and short-circuit optimizations) so that the
     handler's instruction trace is not byte-identical run-to-run.
   - Vary the set of innocuous MSRs that pass through vs trap-and-
     passthrough-with-small-latency, so that a per-MSR latency
     fingerprint shifts.

2. **Match more of the base distribution.**  Keep a reference box
   running the clean baseline, and periodically measure the
   distribution of each feature the probe-battery covers on it.  Use
   those distributions as the target the spoofed HV aims for -- not a
   single expected value but a range with a known mean and variance.
   Then fit the HV's responses to that distribution.

Both are expensive and partial.  Neither fully defeats a well-trained
ensemble.

### Current status in deployed protectors

ML-ensemble VM detection is research-tier.  Published tooling (pafish,
VMAware, InviZzzible, al-khaser) is deterministic feature-check-based,
not ML-based.  Commercial protectors (Themida, VMProtect, Enigma) are
not known to ship ML-ensemble classifiers; they ship the deterministic
feature checks plus timing-based heuristics.

Anti-cheat vendors (Vanguard, EAC-online) do have ML on the
server-side but that is a different ceiling (attestation and
server-side trust; see 10.1).

For the in-scope target set, this ceiling is theoretical, not
operational, in 2026.  Revisit quarterly.

## 10.5 Side-channel attacks from the guest

### What they are

Microarchitectural side-channels: Spectre v1/v2/v4, Meltdown (not on
AMD Zen), Foreshadow (Intel), ZenBleed (AMD Zen 2), Inception (AMD
Zen 3/4), Zenhammer, Downfall (Intel), DIV-by-zero timing, TSX-based
asynchronous aborts, LVI, port-contention via SMT.  The relevant class
here: *cache-timing attacks that leak HV state to a guest*, either by
observing cache lines the HV touched during a VMEXIT, or by observing
branch-predictor pressure induced by the HV handler.

### Why it matters

A ring-0 probe in the guest with SMT can measure latency variations
caused by HV handler cache footprint.  The HV's `handle_cpuid` touches
specific pages (code + VMCB + stack); the attacker's SMT-sibling
thread that primes L1D and later re-measures can observe which lines
were evicted, and over many samples infer that the exit path was
"CPUID-intercept-with-spoof" vs "pass-through".  This is a theoretical
leak of the fact of interception beyond the ability to intercept the
return value.

### Current threat landscape

Not weaponized in commercially shipped packers as of 2026.  Published
and reproducible in academic papers: HVKey leak (USENIX 2020), several
Spectre-on-hypervisor results, the SEV/SEV-SNP side-channel literature
(CVE-2024-45334 CacheWarp, CVE-2023-20593 ZenBleed etc.).  Themida,
VMProtect, Enigma have not been observed using them.

### Mitigation (expensive)

If the ceiling becomes operational, the responses are hardware-level
and performance-costly:

- `IBRS` / `STIBP` / `SSBD` enabled on the HV path (slows VMEXIT
  significantly).
- AMD cache partitioning via QoS (`MSR 0xC0000300` family) to restrict
  the HV handler to a dedicated L3 slice -- 7700X supports this via
  AMD CBS CPU QoS features; carries a throughput cost and complicates
  the VMCB layout.
- Speculative barriers (`lfence` / `sfence`) sprinkled through the
  handler at every indirect branch or every memory load that depends
  on guest-controlled data.  Costs a measurable fraction of handler
  cycles per VMEXIT.
- Disable SMT in BIOS (no SMT-sibling thread = no port-contention
  probe).  Cheapest mitigation; halves effective CPU throughput.

### Guidance

Leave the microarchitectural side-channel ceiling documented but do
not mitigate until a live sample is observed using the technique.  The
cost is real and the threat is theoretical for the in-scope target
set.  Set a quarterly review to re-read the AMD Security Bulletin feed
and relevant USENIX/CCS proceedings; if a commercial protector picks
up Zen 4 side-channel probes, revisit.
