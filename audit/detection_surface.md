# THE_CHAMBER detection-surface entry point

## Current state

The pre-Phase-1 detection-surface audit that used to live here cited code
paths (RemoveEntryList in `stealth.c:93-95`, the never-called
`timing_before_vmrun` in `timing.c:25-28`, the SCM-registered
`\Device\THE_CHAMBER` object, etc.) that no longer describe the driver.
Phase 1 replaced those code paths wholesale; keeping the superseded audit
in place as "current state" was itself a hazard, because downstream docs
(for example `docs/operations/README.md`) treated it as authoritative.

The pre-Phase-1 audit has been moved to
[`archived/2026-11-pre-phase1.md`](archived/2026-11-pre-phase1.md) as a
historical record of the state the driver came from.  A handful of
"Suggested patch" blocks in that archived file were corrected inline so a
future reader is not misdirected (MSRPM bits for out-of-window paravirt
MSRs, the round-2 TSC bracket, and the VMMCALL EFER-decoder-gating
framing).  The archived file is otherwise unchanged.

For what has actually landed, read
[`phase1_done.md`](phase1_done.md): it lists every Phase 1 item,
the file:line where the change lives, the exit-criteria map, and the
remaining non-goals (Phase 2+ items such as wiring `svm_launch` into
DriverEntry).  For every CPUID / MSR value the hypervisor substitutes,
read [`synthetic_values_table.md`](synthetic_values_table.md).

## When to re-run a full detection-surface audit

A new per-class audit (replacing this stub with the output of an
audit-pass against post-Phase-1 code) is in scope for whichever phase
first widens the intercept set beyond what Phase 1 locked down.  Until
then, incremental detection-surface deltas get reviewed against
`phase1_done.md`'s exit-criteria map and the synthetic-values table, not
against the archived pre-Phase-1 file.
