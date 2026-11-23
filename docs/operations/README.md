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
  -- Per-class detection-surface audit of the current driver with
  signal-strength rankings and prioritized gap list.

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
5. `audit/detection_surface.md` -- the current state of the driver
   and what still needs to be fixed before it is deployable.
6. `audit/synthetic_values_table.md` -- the single source of truth
   for every spoofed value.
