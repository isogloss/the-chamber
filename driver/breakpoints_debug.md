# Breakpoints — new module `breakpoints.c` / `breakpoints.h`

Hardware breakpoints (DR0-DR3) and software breakpoints (INT3 / 0xCC),
set at HV level so the guest's anti-debug cannot detect them.

## Threat model for anti-debug

Modern protectors check for debuggers through a layered set of probes:

- PEB.BeingDebugged (easy to clear)
- PEB.NtGlobalFlag (FLG_HEAP_* bits set under debug heap)
- `NtQueryInformationProcess(ProcessDebugFlags, ProcessDebugPort,
  ProcessDebugObjectHandle)`
- `CheckRemoteDebuggerPresent`
- `OutputDebugString`+SEH timing
- RDTSC-bracketed syscalls
- **DR0-DR3 read via `GetThreadContext`** (mov dr registers from
  usermode fails but kernel syscalls succeed)
- **DR7 read / bit-check**
- SEH-handler unwind presence
- Stack scan for debugger module signatures

HV-relayed breakpoints defeat the DR-read probes because the guest
sees zero DRs even though the hardware actually has breakpoints armed.
The SW breakpoint INT3 is caught at HV level (#BP intercept) so the
guest's own INT3 handler never fires.

## Hardware breakpoint flow

### Set

Userland sends `IOCTL_CHAMBER_SET_HWBP` or `HCALL_SET_HWBP`:

```c
typedef struct _HWBP {
    BOOLEAN   armed;
    ULONG     slot;              /* 0..3 */
    ULONGLONG gva;
    ULONG     condition;         /* 0=exec, 1=write, 2=io, 3=rw */
    ULONG     length;            /* 1,2,4,8 */
    ULONGLONG target_cr3;        /* 0 = any */
    ULONG     user_tag;
} HWBP;

extern HWBP g_hwbp[4];

NTSTATUS hwbp_set(ULONG slot, ULONGLONG gva, ULONG cond,
                   ULONG len, ULONGLONG cr3, ULONG user_tag)
{
    if (slot > 3) return STATUS_INVALID_PARAMETER;
    if (g_hwbp[slot].armed) return STATUS_RESOURCE_IN_USE;

    g_hwbp[slot] = (HWBP){ .armed = TRUE, .slot = slot, .gva = gva,
                            .condition = cond, .length = len,
                            .target_cr3 = cr3, .user_tag = user_tag };

    intercept_arm_dr_shadow();   /* starts intercepting guest DR access */
    intercept_arm_db();          /* starts catching #DB */

    /* Program the real DR on every CPU */
    KeIpiGenericCall(ipi_apply_hwbp, (ULONG_PTR)slot);
    return STATUS_SUCCESS;
}

static ULONG_PTR ipi_apply_hwbp(ULONG_PTR slot_u)
{
    ULONG slot = (ULONG)slot_u;
    HWBP *bp = &g_hwbp[slot];

    ULONGLONG dr7 = __readdr(7);
    /* Clear slot's L/G bits + cond/len bits */
    dr7 &= ~(0x3ULL << (slot * 2));              /* L/G */
    dr7 &= ~(0xFULL << (16 + slot * 4));         /* cond + len */
    /* Set L (local), cond, len */
    dr7 |= (0x1ULL << (slot * 2));                /* local enable */
    dr7 |= ((ULONGLONG)bp->condition << (16 + slot * 4));
    dr7 |= ((ULONGLONG)encode_len(bp->length) << (18 + slot * 4));
    /* Also set GE (global exact) bit 9 */
    dr7 |= (1ULL << 9);

    __writedr(slot, bp->gva);
    __writedr(7, dr7);
    return 0;
}

static ULONGLONG encode_len(ULONG len)
{
    switch (len) {
    case 1: return 0;
    case 2: return 1;
    case 4: return 3;
    case 8: return 2;
    default: return 0;
    }
}
```

### Hit

When the breakpoint fires:

1. CPU raises #DB. `intercept_exceptions` bit 1 is set, so VMEXIT.
2. `handle_db` reads DR6, sees B0..B3 set → HW bp.
3. Looks up which slot(s). For each armed-by-us slot that matches:
   - Push `EVT_HWBP_HIT` event with the user tag and full register state.
   - Clear the corresponding B bit in DR6 (keep others for guest).
4. Set `RFLAGS.RF` in VMCB save area so the breakpoint doesn't re-fire
   on the same instruction when the guest resumes.
5. Do NOT inject #DB to guest. Swallow.

### Guest reads a DR

`handle_dr_access` returns the shadow (zero by default, or whatever
the guest tried to write earlier).

### Guest writes a DR

Update shadow. If the slot is one of ours (`g_hwbp[slot].armed`),
drop the write. Guest's view of DR state is entirely synthetic.

### Clear

Clear the slot, broadcast IPI to rewrite hardware DR7 clearing the
L bit. If all four slots empty, `intercept_disarm_dr_shadow()` and
`intercept_disarm_db()` (unless HOOK monitors or SW BPs still need
#DB).

## Software breakpoint flow

INT3 (0xCC) is one byte, easy to plant anywhere. Downside: it's a
visible byte if the target self-CRCs. For anti-tamper targets, use
NPT HOOK monitors (serves original bytes on read) instead of raw SW
breakpoints. Keep SW BPs for quick scratch work on unprotected code.

### Set

```c
typedef struct _SW_BREAKPOINT {
    LIST_ENTRY link;
    ULONGLONG  gva;
    ULONGLONG  target_cr3;
    UCHAR      original_byte;
    ULONG      user_tag;
    BOOLEAN    armed;
} SW_BREAKPOINT;

NTSTATUS swbp_set(ULONGLONG gva, ULONGLONG cr3, ULONG user_tag)
{
    SW_BREAKPOINT *sb = alloc_sw_bp();
    sb->gva = gva;
    sb->target_cr3 = cr3;
    sb->user_tag = user_tag;

    /* Read original byte */
    if (!snapshot_read_byte(cr3, gva, &sb->original_byte))
        return STATUS_INVALID_ADDRESS;

    /* Write 0xCC */
    if (!snapshot_write_byte(cr3, gva, 0xCC))
        return STATUS_ACCESS_DENIED;

    sb->armed = TRUE;
    list_add_sw_bp(sb);
    intercept_arm_bp();
    return STATUS_SUCCESS;
}
```

`snapshot_write_byte` is a HV-side write to guest physical memory,
same machinery as the snapshot reader (see `snapshot_debug.md`),
just the inverse direction. Must honor whatever write protection is
set at NPT level — if we've revoked write on the page as part of a
monitor, SW BP installation needs to coordinate.

### Hit

In `handle_bp` (see `vmexit_debug.md` item 4):

1. Look up by (rip, cr3). Match → ours.
2. Push `EVT_SWBP_HIT`.
3. Restore original byte in guest memory.
4. Set `ctx->step_reason = STEP_USER_STEP`, `ctx->pending_sw_bp = sb`.
5. Enable single step. Resume.
6. On the step #DB, replant 0xCC, clear step, resume.

#BP is a trap (not a fault), so `rip` on VMEXIT points **after** the
INT3. Back it up by 1 before reporting.

### Clear

Restore original byte. Remove from list. If list empty,
`intercept_disarm_bp()`.

## Shared #DB routing

Both HW BPs and the hook-swap single-step and the SW BP single-step
all use #DB intercept. The `handle_db` dispatcher in `vmexit_debug.md`
checks DR6 and `ctx->step_reason` to decide who owns this event.

## Priority / ordering if multiple fire

A #DB can simultaneously report:
- BS (single-step) bit
- B0-B3 (HW bp) bits

If the single-step stepped PAST a HW bp location, both fire. Handle
step completion first (clear state), then report the HW bp. Match
guest expectations.

## Guest DR save/restore across VMRUN

AMD SVM saves DR6 and DR7 in the VMCB (`vmcb.save.dr6`, `.dr7`) but
DR0-DR3 are shared across host and guest unless you manually save
them. You MUST save/restore DR0-DR3 around VMRUN, else your host DR
values leak into the guest's DR register file. In `vmrun.asm`:

```asm
; Before vmrun:
mov rax, dr0
mov [r15 + host_dr_save + 0], rax
mov rax, dr1
mov [r15 + host_dr_save + 8], rax
; ...dr2, dr3

; Load guest DRs
mov rax, [r15 + guest_dr_save + 0]
mov dr0, rax
; ...

vmrun rax

; After vmrun:
; Save guest DR0-DR3
mov rax, dr0
mov [r15 + guest_dr_save + 0], rax
; ...

; Restore host DRs
mov rax, [r15 + host_dr_save + 0]
mov dr0, rax
; ...
```

Add `host_dr_save[4]` and `guest_dr_save[4]` to `PER_CPU_CTX`. Keep
in the DR-shadow module — only touched when DR intercepts are armed,
else skip the save/restore in the asm hot path with a flag.

## Anti-detection: DR7 "recently touched" probe

A clever probe can tell DR7 was touched by setting DR7 via
`SetThreadContext`, running RDTSC, triggering a context switch,
reading DR7 back via `GetThreadContext`, and comparing cycles with
and without. Our relay introduces a small extra latency on DR7
access.

Defense: for a stealth-first mode, offer a toggle that disables HW
breakpoints entirely (use SW BPs + NPT monitors only). HW BPs are
the fastest and most powerful but have this tell. NPT exec monitors
are slower per-hit (need NPF round-trip) but have no comparable
probe.

## Suggested defaults

- 4 HW breakpoints total; expose all 4 to userland
- SW BPs: unlimited (bounded only by pool)
- NPT monitors: unlimited (bounded only by pool and performance)

## Adding to the build

- `driver/breakpoints.c`
- `driver/breakpoints.h`
- Add to `build.ps1` compile list
- Link `vmexit.c` references to breakpoint handler helpers
