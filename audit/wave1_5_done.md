# Wave 1.5 Audit Fix Verification

## Summary

Wave 1.5 queued 153 Wave 1 audit fixes across four batches (`driver`,
`launcher`, `probes`, `infra`), each nominally cross-checked by three
adversarial lenses (`correctness-trace`, `spec-conformance`,
`regression-hunt`) — twelve verification runs in total. The payload the
synthesis step received from the orchestrator contained **one** of
those twelve runs: the `driver` batch's `correctness-trace` lens, 66
findings, all verdicts `pass`. The JSON was truncated mid-regression
entry (the last value in the `regressions` array ended at
`"sever"`), so even that one lens's regression list is partial. The
`spec-conformance` and `regression-hunt` driver lenses, and all three
lenses for `launcher`, `probes`, and `infra`, were not delivered; a
strict `>=2 of 3` majority therefore cannot be computed on the batches
that were not supplied, and the driver verdicts below rest on a single
vote per finding rather than the majority the rule calls for.
Verdicts for the 66 driver findings are recorded here as **confirmed
(single-lens)**: the traces the delivered lens supplied are specific
to file/line/function with mechanism commentary, so promoting them on
one unanimous vote is defensible, but a Wave 1.6 re-run of the two
missing driver lenses is still required before the batch is closed.
One regression was captured in the delivered data
(`driver/vmrun.asm:152` — timing interval END/START ordering flip from
S/M-9 makes `timing_update` always early-return, silently disabling
the TSC-offset accumulator). Top concerns for Wave 1.6: (a) fetch and
aggregate the eleven missing lens runs; (b) fix the timing-END
placement regression; (c) once (a) is done, re-verify any finding the
full majority flips away from confirmed.

## Per-batch results

### `driver` (66 findings)

**Confirmed (single-lens, `correctness-trace` pass, missing 2 of 3
lenses):**

- Segment / VMCB structure: S-2, S-10, S-13, S-22 (svm_build_vmcb
  attrib/limit/base via live GDT, FS/GS from MSRs, TR/LDTR via
  svm_decode_sys_seg).
- VMRUN / VMEXIT asm bracket: S-3, S-9, S-12, S-19, S-24, H-8, H-12
  (guest R15 scratch slot, host vmsave/vmload bracket).
- Host-state FPU save / stack alignment: H-2, H-3, H-13, H-16, H-17.
- SVM bringup / teardown ordering: S-4 (MSR order on offline), H-5,
  H-14 (KeFlushQueuedDpcs before free), H-9 (DriverEntry marker
  ordering), H-15 (cooperative pre-IPI shutdown), M-1, M-2, L-6, L-7.
- MSR handler: S-5, S-20, S-25, H-1, H-10 (allowlist + SEH +
  absorb/zero default).
- Paravirt MSR bands: S-6, S-7, H-4, M-11 (Hyper-V `0x40000000..
  0x400001FF`, KVM `0x4B564D00..0x4B564DFF`).
- EFER virtualization: S-11, S-14, H-6, H-18 (writes land in
  `vmcb->save.efer`, SVME forced, clean bit cleared).
- NPT: S-15, H-19 (pre-alloc at PASSIVE_LEVEL), M-12 (tracker ceiling
  + fail-closed allocator), M-15 (sub-1-MB UC leaf for legacy MMIO).
- Unhandled-exit default: S-16, M-3, M-6 (`#UD` injection replaces
  advancing to `next_rip`).
- VMCB control-area offsets: S-21.
- Device object hardening: H-11, M-10, M-13 (`IoCreateDeviceSecure` +
  SDDL + `FILE_WRITE_ACCESS` on KICK/SHUTDOWN).
- Stealth apply/revert gating: M-14.
- Crash marker fail-closed: M-7, M-8, L-8.
- Noise length accounting: M-4.
- TLB flush path: M-5 (dedicated `tlb_control` field at 0x5C).
- Install bundle: L-1 (drop `the_chamber.inx`).
- MSRPM intercept hygiene: L-2, L-4, L-9, N-3.
- VMCB clean bits: L-3.
- DR0-DR3 intercept: L-5.
- Timing END placement: M-9 (END moved after `timing_update`) —
  **fix lands, but introduces the regression tracked below.**
- Unsigned-shift fix: N-1, N-2 (`1u << 31`).

**Broken (single-lens, `correctness-trace` fail):** none.

**Needs deeper review (single-lens, `correctness-trace` unverified):**
none. (All 66 traces were accepted by the delivered lens; the
"deeper review" caveat is at the batch level — see Open follow-ups.)

### `launcher`

No verification data was delivered for this batch. Status: **NEEDS
DEEPER REVIEW (no-input)** — all launcher findings must be re-queued
to Wave 1.6 so the three-lens vote can actually run.

### `probes`

No verification data was delivered for this batch. Status: **NEEDS
DEEPER REVIEW (no-input)** — same remediation as `launcher`.

### `infra`

No verification data was delivered for this batch. Status: **NEEDS
DEEPER REVIEW (no-input)**. The Wave 1.5 `infra` commits
(`6d0aacd`, `6a39178`, `ced3268`, `37fdd69`, `cc87c20`) landed via
merge `0384d0c` and are therefore in-tree, but have not been checked
against adversarial traces in the data supplied to this synthesis.

## Regressions introduced

| file | line | severity | mechanism |
|------|------|----------|-----------|
| `driver/vmrun.asm` | 152 | high | Timing interval END is now captured at lines 159-163 **after** the `call timing_update` at line 152. When `timing_update` runs it reads `ctx->host_interval_end` (written in the **previous** iteration, before the preceding VMRUN) and `ctx->host_interval_start` (written in the **current** iteration, right after the VMEXIT at line 103). Because guest execution advances the TSC between those two captures, `END < START` will hold on every iteration after the first, so `timing.c:121` early-returns and `g_total_accumulated_cycles` is never advanced. The guest-visible RDTSC therefore no longer has host-handler cycles subtracted, which is exactly the VM-presence signal the TSC-offset machinery exists to erase. S/M-9 correctly removes the "handler cycles leak into guest-visible RDTSC" bug the audit flagged, but the fix as applied substitutes a silent no-op for the subtraction instead. The intended placement is: capture END first (right before `jmp host_vmexit_loop` for the next VMRUN), then call `timing_update` with the matched pair. |

The delivered `correctness-trace` lens's regression array was
truncated mid-entry, so there may be additional regressions it
surfaced that are not visible here.

## Open follow-ups

1. **Re-queue the eleven missing lens runs.** The synthesis input
   contained only `driver` / `correctness-trace`; the orchestrator
   should re-dispatch:
   - `driver` × {spec-conformance, regression-hunt}
   - `launcher` × {correctness-trace, spec-conformance, regression-hunt}
   - `probes` × {correctness-trace, spec-conformance, regression-hunt}
   - `infra` × {correctness-trace, spec-conformance, regression-hunt}
   Only after a true 3-lens vote closes may the 66 single-lens
   "confirmed" verdicts above be treated as full majority-rule passes.
2. **Fix the timing-END regression (Wave 1.6, driver).** Move the
   END capture (`vmrun.asm:159-163`) back ahead of the
   `call timing_update` at line 152, but keep it on the host side of
   `fxrstor64` so the FPU save doesn't inflate the interval. One
   acceptable shape: capture END right after `add rsp, 40` at line
   140, then do `fxrstor64` and only then `call timing_update`;
   `fxrstor64`'s cost is bounded by `g_timing_tail_cycles` which the
   calibration can be biased to cover. Verify by watching
   `g_total_accumulated_cycles` monotonically grow under load and by
   confirming guest RDTSC deltas across a `CPUID` intercept drop back
   below bare-metal pre-fix values.
3. **Audit the truncated `regressions` array.** The delivered lens's
   output was cut off mid-entry; re-dispatch the lens or pull its
   full stdout from the per-batch worker so any additional regressions
   it caught are not lost.
4. **Phase 2 attention.** Nothing in the driver batch's accepted
   fixes removes Phase 2 scope (microarchitectural + MSR + instruction
   stealth), and the timing regression above tightens the case for
   Phase 2's TSC-handling rework: if `tsc_offset` cannot be relied on
   because of an END/START ordering slip, a probe with a cross-core
   RDTSC + CPUID + RDTSC sandwich will read the host-handler latency
   directly. Phase 2 should not begin until the regression is cleared
   and the three-lens vote has been re-run.
