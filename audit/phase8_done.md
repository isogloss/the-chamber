# Phase 8 - Exit-criteria map

One row per sub-criterion from the Phase 8 brief. Every path is
relative to the repository root. All paths exist on
`worktree-agent-ada304d08bbdd4d3c`.

## 8.1 Continuous benchmark suite

| exit criterion                                                       | deliverable                                                                                                 |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| load HV in test VM (`$env:CHAMBER_TEST_VM`, PSSession, parameterized) | `pentest/ci/run_benchmarks.ps1` - `-VmHost` + `-Credential`, default `$env:CHAMBER_TEST_VM`                  |
| run VMAware, Pafish, InviZzzible, Al-Khaser (paths parameterized)    | `pentest/ci/run_benchmarks.ps1` - `-PafishPath`, `-VmAwarePath`, `-InviZzziblePath`, `-AlKhaserPath`         |
| run custom probe battery                                             | `pentest/ci/run_benchmarks.ps1` - `Invoke-ProbeBattery` enumerates `pentest/probes/*`                        |
| capture scores to timestamped JSON `pentest/results/<utc>/`          | `pentest/ci/run_benchmarks.ps1` - writes `pentest/results/<utc>/scores.json`                                |
| exit non-zero on any regression vs `pentest/baseline.json`           | `pentest/ci/run_benchmarks.ps1` -> `pentest/ci/compare_scores.ps1` -> exit 1 on regression or dropped keys  |
| human-readable diff + `pentest/ci/diff.json`                         | `pentest/ci/compare_scores.ps1` - prints coloured table, writes `pentest/ci/diff.json`                      |
| `-Baseline` / `-Current` args                                        | both scripts accept them                                                                                     |

Seed baseline: `pentest/baseline.json` (empty).
Supporting doc: `pentest/ci/README.md`.

## 8.2 Custom probe battery

| probe                       | source                                                                                             | kernel helper                                         |
| --------------------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------- |
| pmu_vmexit                  | `pentest/probes/pmu_vmexit/pmu_vmexit.c`                                                           | `pentest/probes/pmu_vmexit/pmu_driver.c`              |
| cache_sidechannel           | `pentest/probes/cache_sidechannel/main.c`                                                          | none                                                  |
| tlb_pollution               | `pentest/probes/tlb_pollution/main.c`                                                              | none                                                  |
| ud_delivery                 | `pentest/probes/ud_delivery/main.c`                                                                | none                                                  |
| rdtscp_tsc_aux              | `pentest/probes/rdtscp_tsc_aux/main.c`                                                             | none                                                  |
| syscall_timing              | `pentest/probes/syscall_timing/main.c`                                                             | none                                                  |
| msr_readout                 | `pentest/probes/msr_readout/main.c` + `pentest/probes/msr_readout/expected_7700x.json`             | `pentest/probes/msr_readout/msr_driver.c`             |
| cross_core_rdtsc            | `pentest/probes/cross_core_rdtsc/main.c`                                                           | none                                                  |
| cpuid_hypervisor_range      | `pentest/probes/cpuid_hypervisor_range/main.c`                                                     | none                                                  |

Every probe:

- top-of-file comment with purpose, method, threshold, master-plan ref
- `makefile.cmd` with the exact `cl.exe` command line
- single integer score + `VERDICT: PASS|FAIL` on stdout
- `--json` structured output (timestamp, probe name, measurements,
  threshold, verdict)
- includes only `<windows.h>`, `<stdio.h>`, `<intrin.h>`, `<stdint.h>`
  and the standard glue (`<string.h>`, `<stdlib.h>`, `<excpt.h>`)

Overview: `pentest/probes/README.md`.

## 8.3 Target corpus

| exit criterion                               | deliverable                                                                       |
| -------------------------------------------- | --------------------------------------------------------------------------------- |
| describe layout and update workflow          | `pentest/corpus/README.md`                                                        |
| four flavour folders with `.gitkeep`         | `pentest/corpus/{themida,vmprotect,enigma,custom}/.gitkeep`                       |
| MANIFEST template (sha256 + protector + vintage + behaviour) | `pentest/corpus/MANIFEST.md.template`                                             |
| corpus runner that iterates and logs per-binary under `pentest/results/<timestamp>/corpus/` | `pentest/corpus/run_corpus.ps1`                                                   |
| never push binary samples to git             | gitignore rules in top-level `.gitignore` (only `.gitkeep` in flavour folders)    |

## 8.4 Monthly protector update testing

| exit criterion                                        | deliverable                                                   |
| ----------------------------------------------------- | ------------------------------------------------------------- |
| manifest of expected-latest versions                  | `pentest/maintenance/protector_versions.json`                 |
| log current pinned versions                           | `pentest/maintenance/monthly_check.ps1` step 1                |
| remind operator to download and install               | `pentest/maintenance/monthly_check.ps1` step 2                |
| update `protector_versions.json` after confirmation   | `pentest/maintenance/monthly_check.ps1` steps 3-4             |
| run corpus scripts                                    | `pentest/maintenance/monthly_check.ps1` step 5                |
| append outcomes to history.md (date, versions, regressions) | `pentest/maintenance/monthly_check.ps1` step 7 + `history.md` |

## 8.5 Failure analysis workflow

| exit criterion                                           | deliverable                                                   |
| -------------------------------------------------------- | ------------------------------------------------------------- |
| full seven-step playbook                                 | `pentest/maintenance/FAILURE_WORKFLOW.md`                     |
| tooling citations (WinDbg, IDA, Binary Ninja, drmemtrace) | `pentest/maintenance/FAILURE_WORKFLOW.md` step 1              |
| Intel PT not available on AMD; use IBS / BRS             | `pentest/maintenance/FAILURE_WORKFLOW.md` step 1              |

## Commit log

    phase8.1: CI benchmark runner and score diff tool
    phase8.2: custom probe battery (nine probes)
    phase8.3: protected-binary corpus structure and runner
    phase8.4: monthly protector-update check
    phase8.5: failure analysis workflow

One commit per subsection, no `driver/` edits, no push, no pull request.
