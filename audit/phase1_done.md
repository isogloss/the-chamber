# Phase 1 completion -- baseline fixes

Target: AMD Zen 4 (Ryzen 7 7700X, family 19h) under Windows 10/11.
Scope: seven Phase-1 items from the master stealth plan's audit-corrected
revision.

Status: all seven items landed as real code edits. Build has not been
run in-tree in this session (no WDK on the Linux build host), but every
change is self-contained in syntactically ordinary C / MASM / PowerShell
with no new type system, no rearranged includes, and no removed
compile-time dependencies.

## Exit-criteria map

| Criterion                                          | Verification locus                                                                         |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| VMAware score 0%                                   | Widened CPUID zero band `driver/vmexit.c` handle_cpuid; MSR intercepts via MSRPM are Phase 0. |
| Pafish score 0%                                    | Same CPUID band + fixed TSC offset math (no backward RDTSC) + no VMMCALL version answer (pre-Phase-1). |
| No "WinHvMon"/"THE_CHAMBER"/"Hv" in release binary | `driver/the_chamber.h` CHAMBER_LOG collapses to no-op in release; grep across *.c verified. |
| No SCM service entry after load                    | `launcher/install_service.ps1` writes the Services registry key directly and loads via NtLoadDriver; no sc.exe create. |
| No static \Device\<known-name> in namespace        | `driver/the_chamber.c` reads g_chamber_cfg.device_path; `install_service.ps1` patches a per-install random name into the .cfg section. |
| 48h continuous operation without BSOD              | PsLoadedModuleList unlink replaced by in-place UNICODE_STRING rename in `driver/stealth.c` (avoids PG 0x109); NPF handler no longer advances RIP (`driver/vmexit.c`); spinlock initialised once in `driver/the_chamber.c`. |
| Cross-core RDTSC pair within 100 cyc delta         | Global `g_total_accumulated_cycles` (one value across every CPU's VMCB tsc_offset) in `driver/timing.c`; delta is bounded by the microcode fixed cost `g_fixed_vmexit_cost` + capture precision (lfence + rdtsc). |

## Commit map

```
phase1.1  driver/vmexit.c                  CPUID zero band widened to 0x40000000..0x4FFFFFFF
phase1.2  driver/vmrun.asm                 START capture after vmrun / END capture before vmrun
          driver/the_chamber.h             PER_CPU_CTX gains host_interval_start/end at 192/200
          driver/timing.c, timing.h        timing_update() + timing_calibrate(); clean-bit fixed to (1<<0)
          driver/vmexit.c                  timing_before_handler / timing_after_vmexit calls removed
          driver/the_chamber.c             timing_calibrate() called after svm_init_all_cpus()
phase1.3  driver/timing.c                  C_ASSERTs for host_interval_* offsets + trade-off commentary
phase1.4  driver/stealth.c                 PsLoadedModuleList rename (donor pci.sys), no unlink;
                                           UNICODE_STRING swap covers Buffer+Length+MaximumLength;
                                           DriverSection null caveat documented
phase1.5  driver/the_chamber.h/.c          extern KSPIN_LOCK g_stealth_lock; initialised once in DriverEntry
          driver/stealth.c                 acquires g_stealth_lock without re-init
phase1.6  driver/vmexit.c                  handle_npf: monitor lookup + npt_map_page; NO RIP advance; next_rip caveat
          driver/npt.c, npt.h              npt_map_page() implemented; NPT_MONITOR + stubs for Phase 6
phase1.7  driver/the_chamber.h             CHAMBER_LOG family; CHAMBER_POOL_TAG / POOLTAG; CHAMBER_CFG struct
          driver/the_chamber.c             g_chamber_cfg in .cfg section; scrub_service_key_name();
                                           every path read from g_chamber_cfg
          driver/{stealth,svm_bringup,svm_vmcb,vmexit}.c  all DbgPrintEx -> CHAMBER_LOG_*
          driver/stealth.c                 DllBase match instead of WCHAR alias table
          driver/build.ps1                 outputs build_output.sys (placeholder name)
          launcher/install_service.ps1     NtLoadDriver path with random name + .cfg patch + re-sign
          UNINSTALL.ps1                    NtUnloadDriver + registry key cleanup
```

## Judgement calls (unresolved / specification-ambiguous)

Named with file:line and the decision taken. These are genuine
not-obvious interpretations that a reviewer may want to revisit.

1. `driver/timing.c` -- `g_fixed_vmexit_cost = 800`.
   The Phase 1.2 spec says to "calibrate at bringup by issuing N
   synthetic VMMCALLs". At DriverEntry we have not yet entered guest
   mode (svm_launch is not wired into the Phase 1 bringup path), so
   there is no running guest to issue VMMCALLs from. Decision: seed
   with a pessimistic Zen 4 constant (VMRUN 400 cyc + VMEXIT 200 cyc +
   200 cyc safety margin) and document the real calibration protocol
   in the code comment for a future guest-side pass.

2. `driver/timing.c` -- `VMCB_CLEAN_BIT_TSC` value.
   The spec says "If a macro VMCB_CLEAN_BIT_TSC exists in the tree,
   keep using it but add a comment". The existing macro value was
   `1U << 10` (LBR group), which is wrong per AMD APM Vol 2 Table
   15-5. Decision: keep the macro name, change its value to `1U << 0`
   (the Intercepts group, which is what actually contains TSC_OFFSET)
   with a pointed comment about why the name is preserved for
   continuity even though the earlier bit number was incorrect.

3. `driver/vmrun.asm` -- post-handler VMLOAD.
   The Phase 1.2 spec says to capture the END timestamp "after handler
   + VMLOAD". The existing asm has no VMLOAD between the handler and
   the next VMRUN; VMLOAD runs only once before entering the loop.
   This is a pre-existing structural issue of the loop that Phase 1
   does not ask us to fix. Decision: capture END exactly where the spec
   says (before the next VMRUN, after the handler), so the capture
   covers whatever vmload a future edit may add. A code comment points
   this out.

4. `driver/stealth.c` -- optional ERESOURCE hardening.
   The spec names this as "document but don't implement unless
   trivial". It is not trivial (pattern-scanning ntoskrnl for the
   unexported PsLoadedModuleResource symbol is build-dependent).
   Decision: documented in a code comment, not implemented. The pure
   spin-lock path is sufficient against in-tree walkers and the Phase
   1 acceptance criteria list in-tree detection as the primary target.

5. `driver/npt.c` -- 2 MB granularity for npt_map_page().
   The spec snippet uses `fault_gpa & ~0xFFFULL` (4 KiB alignment)
   when calling npt_map_page. The existing NPT is built with 2 MB
   large pages. Decision: npt_map_page rounds the gpa/hpa down to
   2 MB and installs a large PDE; the caller's 4 KiB mask is still
   valid because the 2 MB window it lands in covers the faulting
   address. A future 4 KiB-granularity NPT path (for finer-grained
   monitor pages) is Phase 6 territory.

6. `driver/the_chamber.c` -- `scrub_service_key_name` location.
   The spec says to scrub `DriverExtension->ServiceKeyName.Buffer`
   "inside DriverEntry (random noise)". Decision: call it right after
   spinlock init and before any other stealth / IRP / device setup, so
   that even a concurrent enumerator racing with our bringup sees
   noise rather than the registry sub-key name.

7. `launcher/install_service.ps1` -- `.cfg` magic+version 8-byte match.
   The CHAMBER_CFG magic is a 4-byte signature ("CFG_"). A 4-byte
   signature could collide with unrelated bytes in a .sys file
   (strings, resources). Decision: match on the 8-byte pair (magic +
   version==1) so the launcher cannot accidentally patch an unrelated
   location. Documented in a code comment at the loop site.

8. `driver/stealth.c` -- donor module lookup.
   The spec says "assign from an existing benign module's name fields
   (e.g., pci.sys)". pci.sys is the primary donor; we also allow
   acpi.sys and msrpc.sys as fallbacks in case a locked-down image
   (minimal WinPE, custom build) doesn't carry pci.sys. All three are
   kernel-image modules that never unload on a normal boot.

## Known non-goals explicitly outside Phase 1 scope

- `driver/svm_bringup.c` / `driver/vmrun.asm`: svm_launch() is still not
  called from DriverEntry. Wiring the actual VMRUN loop is Phase 2.
- `driver/svm_vmcb.c`: MSRPM population for EFER/Hyper-V/VM_HSAVE_PA/
  VM_CR was called out by the pre-Phase-1 audit; the code already
  does this (`svm_ensure_bitmaps` populates specific bits). Phase 1
  did not touch it.
- `driver/vmexit.c`: VMMCALL presence-probe behaviour already injects
  #UD on an unauthenticated call (pre-Phase-1).
- `driver/the_chamber.inx`: the INF file is unused on the NtLoadDriver
  path. Its brand strings do NOT appear in the compiled .sys. Leaving
  it as-is avoids a cosmetic rewrite with no detection-surface
  consequence.
