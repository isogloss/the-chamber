# Wave 2 Verification — Synthesis

## Summary

Wave 2 verification covered 8 items across Phases 2, 3, and 4 (SVM bring-up,
PMU virtualization, MSR intercept matrix, instruction-intercept policy,
VMCB state-save offsets, no-migration and no-inline-patch invariants).
Three adversarial lenses were planned — correctness-trace, spec-conformance,
and regression-hunt — but only the correctness-trace pass returned verdicts;
the spec-conformance and regression-hunt lenses produced no verdicts for this
wave. Applying the stated majority rule to each item (>=2 agreeing verdicts
required), one pass vote plus two missing votes yields two "unverified"
positions per item, so every item lands in NEEDS REVIEW despite having a
clean correctness-trace walk. Separately, correctness-trace flagged two
showstopper regressions introduced by commit bb02cd0 ("dedicated per-CPU
host stack for the vmrun loop"): the host-stack switch left the stale
`sub rsp, 40` scratch at both CALL sites in `vmrun.asm`, so calls into
`vmexit_handler` and `timing_update` now enter with `rsp % 16 == 8` in
violation of the MS x64 ABI — a latent bugcheck on any aligned 128-bit
stack temp inside those callees. Both items are mechanical fixes but block
boot on real hardware and must land before the next wave.

## Per-item results

### CONFIRMED (>=2 pass votes)
_none — spec-conformance and regression-hunt lenses did not return verdicts
for this wave, so no item reached the two-vote threshold._

### BROKEN (>=2 fail votes)
_none._

### NEEDS REVIEW (>=2 unverified)
All eight items — one pass vote from correctness-trace plus two missing
verdicts, which the majority rule classifies as NEEDS REVIEW:

- **P2.0** — svm_launch_all_cpus per-CPU iteration, affinity bind, and
  DriverEntry ordering (`driver/svm_bringup.c:172-207`,
  `driver/the_chamber.c:488-504`).
- **P2.0b** — dedicated 16 KiB per-CPU host stack captured into
  `VM_HSAVE_PA.host_rsp` by VMRUN; host_done enters cli/hlt rather than
  returning on a foreign stack (`driver/svm_bringup.c:75-89`,
  `driver/vmrun.asm:80-85,199-213`).
- **P2.1** — guest-side PMU virtualization: snapshot bracket around every
  intercepted exit, RDPMC return-from-snapshot, PerfEvtSelCore0..5
  interception with arm-on-EN latch (`driver/the_chamber.h:156-157`,
  `driver/svm_vmcb.c:244-249,314`,
  `driver/vmexit.c:47-71,104,145,214-228,304-323`).
- **P3** — MSR intercept matrix: EFER, VM_HSAVE_PA, VM_CR, SMM_ADDR,
  SMM_MASK, TSC_RATIO lie; SPEC_CTRL, PRED_CMD, MPERF, APERF, TSC_AUX,
  HWCR pass through under SEH (`driver/svm_vmcb.c:229-249`,
  `driver/vmexit.c:239-262,346-379,395-410`).
- **P3.4** — VMCB state-save offset C_ASSERTs for CR0/CR2/CR3/CR4 pass
  (`driver/svm.h:207-210`).
- **P4.1** — intercept_vec4 contains only VMRUN and VMMCALL; VMLOAD/VMSAVE,
  STGI/CLGI, SKINIT, RDTSCP, ICEBP, WBINVD, MONITOR/MWAIT/MWAIT_COND,
  XSETBV are all left unintercepted on purpose
  (`driver/svm_vmcb.c:328` with the rationale block at 319-327).
- **P4.3** — no IPI, no DPC retarget, no `KeSetSystemAffinityThreadEx`
  inside the VM-exit handler path (`driver/vmexit.c:11-16`).
- **P4.4** — no inline patching of guest text pages; all hooks go through
  NPT split-view (`driver/vmexit.c:18-22`,
  handle_npf at `driver/vmexit.c:489-521`).

### SPLIT (1/1/1)
_none._

## Regressions introduced

Both findings come from correctness-trace and are attributed to commit
`bb02cd0 "driver: dedicated per-CPU host stack for the vmrun loop"`,
which switched the host VM-exit loop from the caller's kernel stack to a
dedicated 16 KiB per-CPU allocation but did not update the pre-CALL
scratch sizes that were tuned against the old stack arithmetic.

| File | Line | Severity | Mechanism |
|---|---|---|---|
| `driver/vmrun.asm` | 152 | showstopper | Host-stack switch leaves `rsp % 16 == 0` at the top of `host_vmexit_loop`; the pre-existing `sub rsp, 40` before `call vmexit_handler` now lands `rsp % 16 == 8` at the CALL, violating the MS x64 ABI. Any aligned 128-bit stack temp inside `vmexit_handler` (MSVC movaps/movdqa spill, local `__m128`, SEH xmm save) raises #GP at CPL0 — instant bugcheck. Fix: `sub rsp, 32` / `add rsp, 32` here and update the stale `rsp % 16` comments at vmrun.asm:88, 113, 119. |
| `driver/vmrun.asm` | 174 | showstopper | Same regression at the second CALL site: `sub rsp, 40` before `call timing_update` produces `rsp % 16 == 8` on the dedicated host stack. Same bugcheck mechanism; same fix (`sub rsp, 32` / `add rsp, 32`). |

## Open follow-ups

- **Phase 7.3 clean unload** — not in Wave 2 scope and not covered by any
  of the three lenses this round. Needs its own trace pass: per-CPU
  `stgi` + `EFER.SVME` clear ordering on unload, VMCB and host_save
  pool free sequence, PMU snapshot/MSRPM restore, confirmation that
  the host_vmexit_loop exits cleanly (currently via cli/hlt, which is
  fine during steady-state but must transition to real unload on
  driver `DriverUnload`).
- **Missing lens coverage** — spec-conformance and regression-hunt
  produced no verdicts this wave. Every item is NEEDS REVIEW purely
  because those two voices are absent, not because correctness-trace
  found doubt. Re-running both lenses once the two showstoppers above
  are landed should flip most items to CONFIRMED.
- **Stale stack-math documentation** — the `rsp % 16` annotations on
  `driver/vmrun.asm:88, 113, 119` were accurate pre-bb02cd0 and now
  describe geometry that no longer holds. Even once the `sub rsp, 32`
  fix lands, those comments need refreshing so the next reader does
  not re-introduce the same bug by trusting them.
- **No systemic regression beyond vmrun.asm** — correctness-trace's
  grep for the migration and inline-patch anti-patterns returned
  clean, so the two showstoppers appear to be a localized fallout of
  the host-stack switch rather than a broader invariant break.
