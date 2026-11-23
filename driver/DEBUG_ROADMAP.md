# THE_CHAMBER debugger subsystem — roadmap

Goal: turn THE_CHAMBER from a stealth-only thin HV into an HV-based debugger
capable of unpacking, breakpoint instrumentation, and payload capture of
heavily protected targets (VMProtect, Themida, custom VMs, server-staged
payloads).

This is the top-level plan. Each subsystem has its own `*_debug.md` sitting
next to the source file it touches.

## The capability gap

Current driver intercepts CPUID and specific MSRs. That's it. It has no
mechanism to:

- Observe execution of guest memory (no execute tracing)
- Observe writes to guest memory (no write tracing)
- Place breakpoints that survive self-CRC (no NPT split views)
- Dump guest memory on demand (no snapshot API)
- Scope any of this to one process (no CR3 filtering)
- Expose any of this to a userland analyst (no control plane beyond
  status / shutdown)

Everything below is additive. None of it changes the existing stealth story;
the new intercepts fire only when a monitor is armed by a userland agent
via the hypercall API.

## Design principle: lazy intercepts

Each new VMEXIT class is OFF by default. When the user-mode agent arms a
breakpoint, a memory watch, or a snapshot, the corresponding intercept bit
is set (and only then). This keeps the resting VMEXIT rate at CPUID + MSR
levels (near zero after Windows boot steadies), so detection probes that
measure average VMEXIT latency see nothing until you ask the HV to do
something.

The only always-on new intercept is the NPF handler extension (already
required for NPT) — and that is a no-op unless the faulting GPA matches
an armed monitor entry in the hash table.

## Subsystems (implementation order)

Build in this order. Each depends on the one above.

### Phase 1 — plumbing

1. **Process targeting** → `process_target_debug.md`
   Intercept CR3 writes (or watch at PsSetCreateProcessNotifyRoutineEx),
   match CR3 to known target PID, set `ctx->target_cr3`. Everything below
   consults this.

2. **Hypercall API expansion** → `the_chamber_debug.md`
   Extend the VMMCALL interface (already behind a shared secret) with new
   codes. Add matching IOCTLs so a non-VMMCALL-capable userland tool can
   still drive it. The control plane is the only place the user-mode
   agent interacts with the HV.

### Phase 2 — the core instrument

3. **NPT page splitting + monitors + invisible hooks** → `npt_debug.md`
   This is the heart of the debugger. 2MB large pages split to 512x 4KB
   on demand; per-GPA execute/read/write permissions; two-view page swap
   for hooks invisible to self-CRC. Everything downstream is built on this.

4. **VMEXIT handler extensions** → `vmexit_debug.md`
   New handlers for NPF (monitor hits), #DB (hardware breakpoint hits),
   #BP (software breakpoint hits), DR access (shadow DR relay), MOV CR3
   (process targeting), and expanded VMMCALL (control plane).

5. **VMCB intercept wiring** → `svm_vmcb_debug.md`
   Which intercept bits get armed when. Static bits at bringup vs
   dynamic bits set when a monitor is armed.

### Phase 3 — deliverables

6. **Memory snapshot** → `snapshot_debug.md`
   Walk a guest VA range using the target's CR3, dump the backing pages
   to a user-mode buffer. Core unpacking primitive.

7. **Hardware breakpoint relay** → `breakpoints_debug.md`
   Userland can set DR0-DR3 on the guest without the guest seeing the
   DRs set. #DB is intercepted at HV level and relayed to userland
   instead of delivered to the guest.

### Phase 4 — operator workflow

8. **Unpacking workflow doc** → `/pentest/UNPACKING_WORKFLOW.md`
   How to actually use all of the above against a packed/VMed/net-staged
   target. The operator-facing recipe.

## Target capability matrix after full build

| Capability | Mechanism | Defeats |
|---|---|---|
| Execute tracing | NPT !X + NPF | TLS callbacks, late-loaded PE, unpacking stub |
| Write tracing | NPT !W + NPF | Self-decrypting code, string deobf, VM table writes |
| Invisible breakpoint | NPT split R/X views | Themida/VMProtect self-CRC |
| HW breakpoint relay | Shadow DR0-DR3 + #DB intercept | Anti-debug DR read checks |
| Memory snapshot | VA→PA walk + copy | In-memory-only PE loaders |
| Single-step | TF in RFLAGS + #DB intercept + MTF emulation | Any single-step-blocking protector |
| Pause-anywhere | Interrupt-window trap + hold | Real-time protectors |
| Process scope | CR3 filtering | Observing the right thing |

## Non-goals (honest limits)

Say this up front. There are things no HV-based debugger can magic away:

- **VMProtect virtualization**: you can observe every x86 instruction the
  VM dispatcher executes, but the semantics are in opaque opcodes. You
  still have to write a devirtualizer for the specific VM dialect. HV
  gives you trace fidelity, not deobfuscation.
- **Encrypted RAM / SEV-SNP guests**: not relevant to our target class but
  mentioning for completeness — the HV cannot inspect SEV-encrypted guest
  memory.
- **Hardware attestation**: if the target asks a TPM or Intel SGX enclave
  something, the HV cannot forge the response. We don't touch SGX/SEV.
- **TLS cert pinning in the loader**: HTTPS payload interception requires
  either a cert dropped on the host trust store, or a TLS MITM that
  handles whatever pinning scheme the loader uses. This is out of scope
  for the HV and belongs in a separate tool (burp, mitmproxy, custom WFP
  callout).

## Rule: never regress the stealth posture

Every change below must preserve:

- CPUID leaf 1 ECX[31] cleared
- Hypervisor vendor leaves zeroed through 0x4FFFFFFF (once widened; see
  `vmexit_debug.md` item 7)
- EFER.SVME hidden on guest read
- VMMCALL answers only with the shared secret
- TSC offset compensates handler latency

If a new intercept raises the resting VMEXIT rate, it must be off by
default and only armed on demand. See "lazy intercepts" above.
