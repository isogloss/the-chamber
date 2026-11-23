# THE_CHAMBER -- Operations

Documentation covering how to operate THE_CHAMBER as a
malware-analysis sandbox, and an honest statement of what the design
cannot do.

## Documents

- [`discipline.md`](discipline.md) -- Phase 9.  Operational
  discipline: hardware isolation, snapshot hygiene, network
  segmentation, kernel-debugger readiness, change management, and
  synthetic-value documentation policy.  Checklist a one-person lab
  follows before, during, and after every analysis session.

- [`ceilings.md`](ceilings.md) -- Phase 10.  Honest ceilings:
  hardware attestation, microcode drift, ring-0 adversaries,
  ML-ensemble detection, and microarchitectural side channels.  What
  the design cannot hide and why.

- [`threat_model.md`](threat_model.md) -- One-page map of adversary
  classes (public VM benchmarks, commercial packers, offline
  crypters, ring-0 anti-cheat, ML detection) with capabilities and
  defender coverage.

## Related

- [`../../audit/synthetic_values_table.md`](../../audit/synthetic_values_table.md)
  -- Canonical table of every CPUID / MSR value the hypervisor
  spoofs, with sources.  Updated in lock-step with any VMCB handler
  change.

- [`../../audit/detection_surface.md`](../../audit/detection_surface.md)
  -- Entry point for the detection-surface audit.  Stub that points at
  `phase1_done.md` for current state and at
  `archived/2026-11-pre-phase1.md` for the historical per-class audit
  that preceded Phase 1.

- [`../../audit/phase1_done.md`](../../audit/phase1_done.md) --
  Phase 1 completion marker with the exit-criteria map and the
  file:line locus of every Phase 1 change.

- [`../../audit/full_audit_v2.md`](../../audit/full_audit_v2.md) --
  Full-audit skeleton.

- [`../../README.md`](../../README.md) -- Project root readme:
  architecture summary, install / daily use / recovery.

## Reading order

For a new operator joining the lab:

1. Project `README.md` -- what the project is and how to install.
2. `threat_model.md` -- who THE_CHAMBER is defeating and who it is
   not.
3. `ceilings.md` -- what the design cannot do, so that scope stays
   realistic.
4. `discipline.md` -- the operational checklist.
5. `audit/phase1_done.md` -- the current state of the driver as of
   the Phase 1 completion marker, with the exit-criteria map.
6. `audit/synthetic_values_table.md` -- the single source of truth
   for every spoofed value.
7. `audit/detection_surface.md` -- entry point for the
   detection-surface audit (pre-Phase-1 pass archived under
   `audit/archived/2026-11-pre-phase1.md`).
