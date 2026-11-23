# VMEXIT debugger extensions — notes for `vmexit.c`

New exit codes to handle, existing handlers that need fixing, and the
state machine for single-step / hook-swap. Reference: AMD64 APM Vol 2
§15.7 (Table 15-7, exit codes) and §15.20 (exception intercepts).

## Current state

`vmexit_handler` dispatches CPUID, MSR, VMMCALL, NPF. NPF is broken
(logs + advances RIP; see `npt_debug.md`). Nothing else is intercepted.

## New exit codes to add

Add these to the dispatch switch in `vmexit_handler`:

| Code | Name | Handler | Armed by |
|---|---|---|---|
| `0x40` | `VMEXIT_EXCP_DB` (#DB vector 1) | `handle_db` | Phase 2 HOOK + Phase 3 HW breakpoints |
| `0x43` | `VMEXIT_EXCP_BP` (#BP vector 3) | `handle_bp` | Phase 3 SW breakpoints |
| `0x00..0x0F` | `VMEXIT_CR0_READ..CR15_READ` | `handle_cr_access` | Phase 1 process targeting (CR3 write) |
| `0x10..0x1F` | `VMEXIT_CR0_WRITE..CR15_WRITE` | `handle_cr_access` | same |
| `0x20..0x27` | `VMEXIT_DR0_READ..DR7_READ` | `handle_dr_access` | Phase 3 HW breakpoint relay |
| `0x30..0x37` | `VMEXIT_DR0_WRITE..DR7_WRITE` | `handle_dr_access` | same |

The exception exit codes are `0x40 + vector`. Enabled via
`vmcb.ctl.intercept_exceptions` bit N for exception vector N.

## Handler specs

### 1. `handle_cr_access` — process targeting

The MOV CR3 write is the signal a context switch happened in the guest.

```c
static void handle_cr_access(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONGLONG exit_code = vmcb->ctl.exit_code;
    BOOLEAN is_write = (exit_code >= 0x10 && exit_code <= 0x1F);
    ULONG cr_num = (ULONG)(exit_code & 0xF);

    if (cr_num == 3 && is_write) {
        /* exit_info_1 encodes the GPR source (AMD 15.14) */
        ULONG gpr = (ULONG)(vmcb->ctl.exit_info_1 & 0xF);
        ULONGLONG new_cr3 = gpr_read_by_index(ctx, vmcb, gpr);

        process_target_on_cr3_switch(new_cr3);

        /* Emulate the write: load the real CR3 */
        /* On AMD with NPT, guest MOV CR3 modifies guest's CR3 (gCR3),
         * not host's (nCR3). We can just let it through by advancing
         * RIP; the write was effectively already applied at the VMCB
         * save area. But — we intercepted precisely to observe it,
         * which means we need to apply it manually. */
        vmcb->save.cr3 = new_cr3;
        vmcb->ctl.vmcb_clean_bits &= ~CLEAN_CR;
    }

    vmcb->save.rip = vmcb->ctl.next_rip;
}
```

Enable with `vmcb.ctl.intercept_cr_write |= (1 << 3)`. See
`process_target_debug.md` for the full flow.

### 2. `handle_npf` — monitor lookup

Replace the current broken handler:

```c
static void handle_npf(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONGLONG fault_gpa = vmcb->ctl.exit_info_2;  /* AMD 15.25.6 */
    ULONGLONG fault_info = vmcb->ctl.exit_info_1;  /* access type */
    ULONGLONG fault_4k = fault_gpa & ~0xFFFULL;

    NPT_MONITOR *m = npt_monitor_find(fault_4k);
    if (!m) {
        /* Unmapped region. Install an identity mapping so guest
         * MMIO / ACPI probes don't hang. See npt_debug.md item 1. */
        npt_fault_fill(fault_gpa);
        return;  /* No RIP advance — retry the faulting insn */
    }

    /* Honor CR3 filter */
    if (m->target_cr3 && vmcb->save.cr3 != m->target_cr3) {
        /* Not our target process — grant the access just this once.
         * Re-revoke after a single step so the next process-switch
         * resumes trapping. */
        npt_grant_temporary(m, fault_info);
        enable_single_step(ctx, vmcb);
        return;
    }

    npt_monitor_handle_fault(m, vmcb, fault_info);
    report_hit_to_userland(m, vmcb, fault_info);

    /* Re-arm after single step */
    enable_single_step(ctx, vmcb);
    /* Do NOT advance RIP — retry the faulting insn with new perms */
}
```

Access-type decoding (`exit_info_1`):

- bit 0: P (present at time of fault — 0 for us)
- bit 1: W (was a write)
- bit 2: U (user mode access)
- bit 3: RSV (reserved-bit violation)
- bit 4: ID (instruction fetch)

So fetch-type = bit 4; write-type = bit 1; read-type = neither.

### 3. `handle_db` — the single-step state machine

Used for both the hook-swap single-step (phase 2) and hardware
breakpoint relay (phase 3). #DB fires on:

- Single-step after TF=1
- Hardware breakpoint match (DR0-DR3)
- Task-switch (irrelevant here)
- INT1 / ICEBP

```c
static void handle_db(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONGLONG dr6 = __readdr(6);
    BOOLEAN is_bp_hit = (dr6 & 0xF) != 0;      /* B0..B3 */
    BOOLEAN is_single_step = (dr6 & (1 << 14)) != 0;  /* BS */

    if (is_single_step && ctx->step_reason == STEP_HOOK_SWAP) {
        /* Finish the hook-swap: restore hook view, re-revoke read */
        npt_hook_complete_read(ctx->pending_hook);
        clear_single_step(ctx, vmcb);
        ctx->pending_hook = NULL;
        ctx->step_reason = STEP_NONE;
        return;  /* Do NOT reinject #DB to guest */
    }

    if (is_single_step && ctx->step_reason == STEP_CR3_FILTER) {
        /* Re-revoke monitor perms after cross-process grant */
        npt_rearm_after_temporary(ctx->pending_cr3_grant);
        clear_single_step(ctx, vmcb);
        ctx->step_reason = STEP_NONE;
        return;
    }

    if (is_bp_hit) {
        /* Hardware breakpoint fired. Which one? */
        ULONG bp_idx = __lzcnt(dr6 & 0xF) ^ 31;  /* 0..3 */
        if (bp_shadow_is_ours(bp_idx)) {
            report_bp_hit_to_userland(ctx, vmcb, bp_idx);
            /* Clear DR6 so guest doesn't see our hit */
            __writedr(6, dr6 & ~(1ULL << bp_idx));
            /* Set RF so the breakpoint doesn't re-fire on resume */
            vmcb->save.rflags |= RFLAGS_RF;
            return;  /* swallow #DB */
        }
    }

    /* Not ours — inject into guest */
    inject_exception(vmcb, VECTOR_DB, FALSE, 0);
}
```

Enable with `vmcb.ctl.intercept_exceptions |= (1 << 1)` (bit 1 = #DB).

Per-CPU state added to `PER_CPU_CTX`:

```c
typedef enum {
    STEP_NONE = 0,
    STEP_HOOK_SWAP,     /* finish a hook read-swap */
    STEP_CR3_FILTER,    /* finish a cross-process grant */
    STEP_USER_STEP,     /* user-mode requested single step */
} STEP_REASON;

/* Add to PER_CPU_CTX: */
STEP_REASON    step_reason;
NPT_MONITOR   *pending_hook;
NPT_MONITOR   *pending_cr3_grant;
```

### 4. `handle_bp` — software breakpoint catch

If an operator (or we) planted `0xCC` (INT3) in guest memory:

```c
static void handle_bp(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONGLONG rip = vmcb->save.rip;
    SW_BREAKPOINT *sb = sw_bp_find(rip, vmcb->save.cr3);
    if (sb) {
        /* Ours — report, then restore original byte, single-step,
         * replant on next instruction. Same dance as hw-bp hit. */
        report_sw_bp_to_userland(sb, ctx, vmcb);
        sw_bp_restore_original(sb);
        ctx->step_reason = STEP_USER_STEP;
        ctx->pending_sw_bp = sb;
        enable_single_step(ctx, vmcb);
        return;
    }

    /* Not ours — reinject */
    inject_exception(vmcb, VECTOR_BP, FALSE, 0);
    /* #BP is a trap — RIP already past; don't advance again */
}
```

### 5. `handle_dr_access` — hardware breakpoint relay

The core idea: the guest's anti-debug may read DR7 and expect to see
0 (no breakpoints). We want to secretly use DR0-DR3 for our own
breakpoints. Solution: shadow the guest's view.

```c
static void handle_dr_access(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    ULONGLONG exit_code = vmcb->ctl.exit_code;
    BOOLEAN is_write = (exit_code >= 0x30 && exit_code <= 0x37);
    ULONG dr_num = (ULONG)(exit_code & 0x7);
    ULONG gpr = (ULONG)(vmcb->ctl.exit_info_1 & 0xF);

    if (!is_write) {
        /* Guest reads a DR. Return the SHADOW (what the guest
         * believes it set), not the real DR. */
        ULONGLONG shadow = ctx->guest_dr_shadow[dr_num];
        gpr_write_by_index(ctx, vmcb, gpr, shadow);
    } else {
        /* Guest writes a DR. Update shadow; apply to real DR only
         * if we have no debugger BP in that slot. */
        ULONGLONG val = gpr_read_by_index(ctx, vmcb, gpr);
        ctx->guest_dr_shadow[dr_num] = val;
        if (!bp_shadow_slot_taken(dr_num)) {
            __writedr(dr_num, val);
        }
        /* else: silently discard — slot is ours */
    }

    vmcb->save.rip = vmcb->ctl.next_rip;
}
```

Enable with `vmcb.ctl.intercept_dr_read |= 0xFF` and
`intercept_dr_write |= 0xFF` **only when a HW breakpoint is armed**.
Leaving DR intercepts always-on is a measurable VMEXIT-rate signal
(Windows scheduler touches DR7 during context switches).

### 6. `handle_vmmcall` extensions

See `the_chamber_debug.md` for the new hypercall codes. The existing
magic-word check at `vmexit.c:189` is preserved; new RAX codes go in
the switch.

### 7. CPUID: widen the hypervisor-brand band

One-line fix the v1 audit called out at priority 10:

```c
/* vmexit.c:87 */
if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF) {
```

(was `0x40000010`). Catches pafish probes at `0x40000080` and
`0x40000100`.

### 8. Timing: latch RDTSC at VMRUN entry, not handler entry

The current `timing_before_handler` measures handler-only cycles.
Serious probes bracket CPUID with RDTSC and see the VMEXIT microcode
latency we're not accounting for. Fix per `DEBUG_ROADMAP.md`:

- Call `__rdtsc` in `vmrun.asm` right before `vmrun rax` (store in
  per-CPU slot)
- Call `__rdtsc` in `vmrun.asm` right after `vmsave rax` (store)
- `timing_after_vmexit` adds `(exit_rdtsc - entry_rdtsc)` to the
  accumulator, not just the C-handler delta.

Also go global-accumulator (see `DEBUG_ROADMAP.md` phase 2 non-goal
note) so per-core offsets don't drift under cross-core probing.

## Helpers you'll need

```c
/* Read a GPR by SVM's GPR-index encoding (AMD 15.14 Table for
 * exit_info_1 encoding of CR/DR access).
 *   0=rax, 1=rcx, 2=rdx, 3=rbx, 4=rsp, 5=rbp, 6=rsi, 7=rdi, 8-15=r8-r15
 * Note the index order is DIFFERENT from our gpr_save[] (our array
 * is rax,rbx,rcx,rdx,... but SVM encodes rax,rcx,rdx,rbx,...). */
ULONGLONG gpr_read_by_index(PER_CPU_CTX *ctx, VMCB *vmcb, ULONG svm_idx);
void      gpr_write_by_index(PER_CPU_CTX *ctx, VMCB *vmcb, ULONG svm_idx, ULONGLONG v);

/* Inject a vector into the guest */
void      inject_exception(VMCB *vmcb, UCHAR vector, BOOLEAN has_err, ULONG err);

/* Single-step the guest for exactly one instruction, with a reason
 * recorded in ctx->step_reason. */
void      enable_single_step(PER_CPU_CTX *ctx, VMCB *vmcb);
void      clear_single_step(PER_CPU_CTX *ctx, VMCB *vmcb);
```

`enable_single_step` sets `vmcb.save.rflags |= 0x100` (TF). Make sure
`vmcb.ctl.intercept_exceptions` bit 1 (#DB) is set first, else the step
fires in the guest and gets delivered to the guest's own #DB handler,
not us.
