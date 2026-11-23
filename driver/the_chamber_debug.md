# Control plane — notes for `the_chamber.c` / `the_chamber.h`

New IOCTLs and VMMCALL hypercall codes for the userland debugger agent.

## Current state

- IOCTLs: `STATUS` (0x801), `KICK` (0x802), `SHUTDOWN` (0x803)
- VMMCALL: magic-gated; codes `VERSION` (1) and `SHUTDOWN` (2)

## New control-plane surface

Keep IOCTLs + VMMCALL parallel. IOCTL for a userland agent running as
admin. VMMCALL for in-guest tools that have the magic word. Prefer
VMMCALL during live debugging — leaves no handle-table trace.

### New IOCTLs (add to `the_chamber.h`)

```c
#define IOCTL_CHAMBER_SET_TARGET_PID    CTL_CODE(0x8000, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_CLEAR_TARGET      CTL_CODE(0x8000, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_ARM_EXEC          CTL_CODE(0x8000, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_ARM_WRITE         CTL_CODE(0x8000, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_ARM_HOOK          CTL_CODE(0x8000, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_DISARM            CTL_CODE(0x8000, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_SET_HWBP          CTL_CODE(0x8000, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_CLEAR_HWBP        CTL_CODE(0x8000, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_SET_SWBP          CTL_CODE(0x8000, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_CLEAR_SWBP        CTL_CODE(0x8000, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_SNAPSHOT_VA       CTL_CODE(0x8000, 0x840, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_POLL_EVENTS       CTL_CODE(0x8000, 0x841, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_PAUSE_PROCESS     CTL_CODE(0x8000, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_RESUME_PROCESS    CTL_CODE(0x8000, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CHAMBER_SINGLE_STEP       CTL_CODE(0x8000, 0x852, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

### Matching input/output structures

```c
typedef struct _CHAMBER_SET_TARGET {
    HANDLE   pid;
} CHAMBER_SET_TARGET;

typedef struct _CHAMBER_ARM_REQUEST {
    ULONGLONG gva;              /* guest virtual address */
    ULONG     length;           /* bytes to cover; may span 4K pages */
    ULONG     user_tag;         /* opaque to kernel, echoed on hit */
    ULONG     reserved;
} CHAMBER_ARM_REQUEST;

typedef struct _CHAMBER_ARM_HOOK_REQUEST {
    ULONGLONG gva;              /* hook location */
    UCHAR     hook_bytes[32];
    ULONG     hook_len;
    ULONG     user_tag;
} CHAMBER_ARM_HOOK_REQUEST;

typedef struct _CHAMBER_HWBP_REQUEST {
    ULONG     slot;             /* 0..3 for DR0..DR3 */
    ULONGLONG gva;
    ULONG     condition;        /* 0=exec, 1=write, 3=rw */
    ULONG     length;           /* 1, 2, 4, 8 */
    ULONG     user_tag;
} CHAMBER_HWBP_REQUEST;

typedef struct _CHAMBER_SWBP_REQUEST {
    ULONGLONG gva;
    ULONG     user_tag;
} CHAMBER_SWBP_REQUEST;

typedef struct _CHAMBER_SNAPSHOT_REQUEST {
    ULONGLONG gva_start;
    ULONG     length;
    /* Output buffer follows via METHOD_OUT_DIRECT MDL */
} CHAMBER_SNAPSHOT_REQUEST;

typedef enum {
    EVT_EXEC_HIT = 1,
    EVT_WRITE_HIT,
    EVT_HOOK_READ,       /* self-CRC hit; informational */
    EVT_HWBP_HIT,
    EVT_SWBP_HIT,
    EVT_STEP,
    EVT_PROCESS_SWITCH,
} CHAMBER_EVENT_KIND;

typedef struct _CHAMBER_EVENT {
    ULONG      kind;
    ULONG      user_tag;
    ULONGLONG  rip;
    ULONGLONG  faulting_gva;
    ULONGLONG  guest_cr3;
    ULONG      cpu_index;
    ULONG      reserved;
    ULONGLONG  rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    ULONGLONG  r8, r9, r10, r11, r12, r13, r14, r15;
    ULONGLONG  rflags;
} CHAMBER_EVENT;
```

### Event queue

The HV generates events from VMEXIT handlers (cannot sleep, cannot
touch pageable memory, cannot wait). Userland polls them.

In `the_chamber.c`:

```c
#define CHAMBER_EVENT_RING_SIZE 1024   /* power of 2 */

typedef struct _CHAMBER_EVENT_RING {
    volatile LONG   write_idx;     /* producer */
    volatile LONG   read_idx;      /* consumer */
    LONG            mask;          /* size - 1 */
    CHAMBER_EVENT   slots[CHAMBER_EVENT_RING_SIZE];
} CHAMBER_EVENT_RING;

extern CHAMBER_EVENT_RING g_event_ring;

void chamber_event_push(const CHAMBER_EVENT *e);   /* VMEXIT-safe   */
NTSTATUS chamber_event_drain(CHAMBER_EVENT *out,   /* IOCTL handler  */
                              ULONG max,
                              ULONG *filled);
```

`chamber_event_push` is lock-free: `InterlockedIncrement` on
`write_idx`, write the slot, publish. Drop on overrun (bump a drop
counter in globals; userland polls it with STATUS).

Allocate the ring in nonpaged pool at init.

### New VMMCALL hypercall codes (add to `vmexit.c:handle_vmmcall` switch)

Keep the magic-word gate intact at `vmexit.c:189`. Then:

```c
#define HCALL_VERSION           1    /* existing */
#define HCALL_SHUTDOWN          2    /* existing */
#define HCALL_SET_TARGET        10
#define HCALL_CLEAR_TARGET      11
#define HCALL_ARM_EXEC          20
#define HCALL_ARM_WRITE         21
#define HCALL_ARM_HOOK          22
#define HCALL_DISARM            23
#define HCALL_SET_HWBP          30
#define HCALL_CLEAR_HWBP        31
#define HCALL_SET_SWBP          32
#define HCALL_CLEAR_SWBP        33
#define HCALL_SNAPSHOT_VA       40
#define HCALL_POLL_EVENTS       41
#define HCALL_PAUSE_PROCESS     50
#define HCALL_RESUME_PROCESS    51
#define HCALL_SINGLE_STEP       52
#define HCALL_QUERY_INTERCEPTS  60
```

VMMCALL conventions:

- RAX: hypercall code
- RBX: magic (`THE_CHAMBER_HYPERCALL_MAGIC`)
- RCX: argument pointer (guest VA; HV translates via guest CR3)
- RDX: argument length
- On return, RAX holds NTSTATUS-shaped result

For `HCALL_POLL_EVENTS`, RCX points at a user buffer and RDX is the
buffer length in bytes. HV walks the ring, copies events into the
buffer (using the guest CR3 to map user VAs → physical pages), writes
count-filled to the buffer header, returns.

### Pause/resume mechanism

"Pause this shit at any point" is the operator request. Options:

**Option A — flag + spin**: set `ctx->target_paused = TRUE`. On next
VMEXIT where `vmcb.save.cr3 == target_cr3`, instead of resuming, put
the vCPU into a spin-wait on the flag. Problem: only pauses on next
intercepted instruction. If the guest is in a tight uninstrumented
loop, we don't preempt. Low utility.

**Option B — NMI-broadcast pause**: send an NMI to every logical CPU
that might be running the target. `IVEC3_NMI` is OFF (stealth), so the
NMI delivers to the guest's own NMI handler, which is not what we
want. Instead: set `IVEC3_NMI` temporarily, send NMI, in the NMI
VMEXIT handler check CR3 and park the vCPU if it matches target.
Problem: visible NMI intercept.

**Option C — per-page execute revocation**: when pause is requested,
walk the target's loaded modules via EPROCESS, mark the first page
of each executable region `!X`. Next instruction fetched into any of
those pages NPFs, we park the vCPU. This stops execution within one
instruction fetch (~immediate) without an NMI intercept.

**Recommended: Option C.** It's the "interrupt everywhere" trick,
scoped to the target process via CR3 check in the NPF handler.

```c
NTSTATUS chamber_pause_target(HANDLE pid)
{
    ULONGLONG cr3 = process_target_get_cr3(pid);
    if (!cr3) return STATUS_NOT_FOUND;

    /* Walk EPROCESS->VadRoot for executable VADs */
    /* For each 4K-exec page, npt_monitor_arm_exec(gpa, cr3, 0) with a
       "parking" user_tag so the NPF handler knows to spin. */

    /* Separately: catch "parked" events and the resume signal */
    InterlockedExchange(&g_pause_state[pid_slot].requested, 1);
    return STATUS_SUCCESS;
}
```

Resume: clear the pause state, disarm all parking-tag monitors,
wake any parked vCPUs.

The parking spin inside NPF:

```c
void park_until_resume(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    CHAMBER_EVENT e = { .kind = EVT_PROCESS_SWITCH /* reuse */ };
    e.rip = vmcb->save.rip;
    e.guest_cr3 = vmcb->save.cr3;
    e.cpu_index = ctx->cpu_index;
    chamber_event_push(&e);

    while (InterlockedCompareExchange(&g_pause_state[slot].resumed, 0, 0) == 0) {
        _mm_pause();
        /* Service NMIs, kick watchdog, etc. In a VMEXIT context we
         * can safely spin because the guest is not running. */
    }
}
```

Caveat: the watchdog expects regular kicks from userland. Parking a
vCPU for minutes doesn't break the driver (the launcher's watchdog
kicks still arrive on other cores), but if ALL vCPUs are parked
simultaneously the system appears hung. Userland should pause at a
one-vCPU granularity (set only the process's CR3 trap, parked
vCPU releases other vCPUs to run system code).

### Add to `PER_CPU_CTX`

```c
typedef struct _PER_CPU_CTX {
    /* ...existing... */

    /* Debugger */
    ULONGLONG       target_cr3;          /* 0 = no target */
    STEP_REASON     step_reason;
    NPT_MONITOR    *pending_hook;
    NPT_MONITOR    *pending_cr3_grant;
    SW_BREAKPOINT  *pending_sw_bp;
    volatile LONG   pause_requested;
    volatile LONG   pause_ack;

    /* Shadow DRs — what the guest THINKS it set */
    ULONGLONG       guest_dr_shadow[8];
} PER_CPU_CTX;
```

Bump the `[rsp + N]` offsets in `vmrun.asm` that reference `ctx+N` if
you grow the struct. Current offsets: `r15 + 64 + N` indexes
`gpr_save`. Add new fields AFTER `gpr_save` to avoid asm churn, or
update asm offsets in lockstep.

### Device permission model

Current device is created with default DACL. Any admin user can open
it. For a tool this powerful, consider:

- `IoCreateDeviceSecure` with `FILE_DEVICE_SECURE_OPEN` and a SDDL
  restricting to `BA` (built-in admins) — current behavior effectively
- Or: require a nonce at open time. Userland first does VMMCALL with
  the magic; HV returns an open-token. Userland then opens the device
  and sends the token in the first IOCTL. No token = device operates
  in read-only status mode.

The second option reduces the "any local admin can drive the HV"
surface, which matters if the target you're reversing achieves local
privilege escalation (some do). Phase 4.

## IOCTL dispatcher additions

In `the_chamber.c` IOCTL handler, add cases for each new code. Each
calls into the matching module:

- `IOCTL_CHAMBER_SET_TARGET_PID` → `process_target_set(pid)` (see
  `process_target_debug.md`)
- `IOCTL_CHAMBER_ARM_EXEC` → `npt_monitor_arm_exec(...)` after VA→GPA
  conversion (see `snapshot_debug.md` for the VA→GPA walker)
- `IOCTL_CHAMBER_SNAPSHOT_VA` → `chamber_snapshot_va(...)` (see
  `snapshot_debug.md`)
- `IOCTL_CHAMBER_POLL_EVENTS` → `chamber_event_drain(...)`
- `IOCTL_CHAMBER_PAUSE_PROCESS` / `RESUME_PROCESS` → see Option C above

All IOCTL handlers must:

1. Validate input length matches expected struct size
2. Probe user buffers with `ProbeForRead`/`ProbeForWrite` in `__try`
3. Return STATUS_INVALID_PARAMETER on malformed input, not AV

Every IOCTL that mutates HV state must take `g_chamber.state_lock`.
