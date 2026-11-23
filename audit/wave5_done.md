# Wave 5 verification + packaging summary

## Verify pass

Three adversarial lenses (correctness-trace / spec-conformance / regression-hunt)
voted on 13 items covering the Wave 4 merged tree (pre-packaging).

Verdicts: 9+12+11 pass, 4+1+2 fail, 0 unverified.
Surfaced 34 regressions (with cross-lens overlap).

Synthesizer agent tripped `[cyber]` safeguards and did not produce the usual
combined report. This document is the manual summary.

## Confirmed showstopper regressions and their resolution

1. **Seed zeroed in CHAMBER_CFG_V2** — `launcher/ui/Services/CfgPatcher.cs:140`
   wrote 32 zero bytes into the seed slot, but `driver/identity.c:418`
   `identity_apply` derives CPU-identity values (CPU signature, microcode
   rev, platform ID, TSC ratio/freq, APIC ID base, extended feature bits,
   per-vCPU TSC_AUX) directly from `cfg->seed`. Every CPU identity value
   stayed constant across randomize — the user's primary requirement
   broken.
   **Fixed** in commit `527d13b` — `DerivedIdentity.Seed[]` carries the
   32-byte master seed; `SeedService.DeriveAll` populates it;
   `CfgPatcher.WriteFields` writes it into the on-disk blob.

2. **Second driver never loaded** — launcher loaded only `the_chamber.sys`;
   `chamber_fingerprint.sys` was embedded but inert.
   **Resolved** by Wave 5 packaging commit `0f33b3d`
   (`DriverLoader.InstallAndLoadFingerprintAsync`).

3. **CfgBlob never written to fingerprint `Parameters`** — Agent C's
   `cfp_cfg_load` expects a 632-byte REG_BINARY at
   `Services\<fp>\Parameters\CfgBlob`; launcher never created it.
   **Resolved** by Wave 5 packaging commit `0f33b3d`
   (`InstallAndLoadFingerprintAsync` writes CfgBlob then calls
   `NtLoadDriver`).

4. **No Authenticode re-sign after CFG patch** — `CfgPatcher`
   recomputed the PE optional-header checksum but left the Authenticode
   signature from the embedded `.sys` in place. The patched driver would
   fail CI on load.
   **Resolved** by Wave 5 packaging commit `6f2d316`
   (`AuthenticodeSigner` via `mssign32!SignerSignEx2`, three-tier cert
   management, Subject `CN=The Chamber`).

5. **IC trampoline wrote return into RCX slot** —
   `driver/fingerprint/ic_trampoline.asm` popped the rewritten value
   into RCX and jumped to user return RIP. User-mode code after a
   syscall reads RAX (x64 syscall convention), so it saw scratch.
   **Fixed** in commit `527d13b` — rewritten value now mirrored into
   both RAX and RCX save slots.

## Other confirmed regressions and resolution

6. **Donor pool mismatch** — launcher used user-mode executable names
   (`winlogon.sys`, `lsass.sys`, ...); driver used real kernel modules
   (`pci.sys`, `acpi.sys`, ...). RenameDonorIndex is one uint8 shared
   between sides, so the UI showed names the sample would never see.
   **Fixed** in commit `527d13b` — launcher pool aligned to driver.

7. **HV introspection toggle UI-only** — bit 2 of CFG `toggles` was
   written by the launcher but no driver code read it;
   `npt_hide_hv_image` was gated only on the compile-time
   `#ifdef CHAMBER_HV_INTROSPECTION_RESIST`.
   **Fixed** in commit `527d13b` — `DriverEntry` now honours the
   runtime toggle.

8. **`chamber_derive` field-name truncation** — C version truncated at
   32 bytes; C# did not. Composed names like
   `g1:identity.10:digital_product_id` (33 chars at salt=10) would
   diverge between kernel and launcher.
   **Fixed** in commit `527d13b` — buf widened from 64 to 256 bytes;
   truncation threshold now 224 chars.

## Open items punted to Wave 7 detection audit

- `ZwSetInformationProcess(ProcessInstrumentationCallback)` called with
  PreviousMode=KernelMode via `Zw*` from a work item — may be rejected
  by `NtSetInformationProcess` with `STATUS_INVALID_PARAMETER`. Needs
  either a KTHREAD.PreviousMode swap or a syscall dispatch.
- `FltRegisterFilter` with `InstanceSetupCallback = NULL` — FltMgr never
  attaches to volumes, so the pre/post IRP callbacks never fire. Also
  `\Device\Ndis` is not a filesystem volume so the minifilter can't
  cover it anyway; need a different mechanism (NSI provider shim or WFP
  callout).
- `CmRegisterCallbackEx` third argument `NULL` instead of the
  DRIVER_OBJECT — unload safety reference is missed.
- `identity_compute_all` dead C code with field names incompatible with
  the launcher's composed `g1:<group>.<salt>:<field>` scheme. A native
  patcher would produce the wrong bytes; currently only reachable if
  someone wires it up.
- `cfp_ic_dispatch` references kernel-only symbols but is supposed to
  run in the user-mode shim at attach — needs separation into a
  user-mode compilation unit copied into the target's address space.

## Packaging landed (Wave 5 worktree, merged as commit `e0ef44e`-adjacent)

- W1 second-driver load with CfgBlob write.
- W2 Authenticode re-sign with three-tier cert management.
- W3 user-mode shim DLL (`launcher/shim/chamber_shim.dll`) with
  `chamber_shim_trampoline` mirroring the kernel reference contract.
- W4 build pipeline for both drivers plus the shim DLL, shared
  self-signed cert.
- W5 GitHub Actions release workflow on `v*` tags.
- W6 RELEASES.md + project_status Wave 4+5 complete section.

## Wave 6 next

Dump rework (targeted-DPC pause, four passive triggers, multi-dump
history, operator Dump tab) queued.
