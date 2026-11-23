# NPT debugger extensions — notes for `npt.c` / `npt.h`

The whole debugger rests on this module. NPT page splitting plus a monitor
table plus two-view invisible hooks gives you execute tracing, write
tracing, and breakpoints that survive self-CRC.

Reference: AMD64 APM Vol 2 §15.25 (Nested Paging).

## Current state

`npt.c` builds an identity-mapped NPT with 2MB large pages (`PDE.PS=1`).
`g_npt_cr3_pa` is the top-level root, loaded into `vmcb.ctl.n_cr3` by
`svm_build_vmcb`. No per-page permission work; every mapped GPA is RWX.

`handle_npf` in `vmexit.c:214` just logs and advances RIP, which is
wrong — NPF `next_rip` points at the faulting instruction, not the one
after. For now NPFs don't happen because everything is identity-mapped
RWX; once we start revoking permissions they will, and the handler needs
real logic.

## What to add

### 1. On-demand page splitting

A helper that takes a 2MB-aligned GPA, finds the PDE that currently has
`PS=1`, allocates a new 4KB page-table of 512 PTEs, copies the 2MB
mapping down into the 512 PTEs (each PTE gets GPA + 4KB*i, same perms),
atomically replaces the PDE to point at the new PT with `PS=0`.

Signature:

```c
NTSTATUS npt_split_2mb_to_4kb(ULONGLONG gpa_2mb_aligned);
```

Pitfalls:

- Must `__invlpga` (or equivalent via INVLPGA intercept) all CPUs for
  the affected GVA range, otherwise another core walks the stale PDE.
  Easier: broadcast a VMCB `.ctl.vmcb_clean_bits &= ~CLEAN_NP` + tlb
  flush via `guest_asid_tlb` increment to that CPU's VMCB.
- Atomicity: the PDE write must be a single 8-byte store after the new
  PT is fully built, else a concurrent walker sees a half-formed PT.
  Use `InterlockedExchange64`.
- Track which PDEs we've split in a bitmap — never split the same PDE
  twice, never merge back (it's harmless to leave split).

### 2. The monitor table

A hash table keyed by GPA (aligned to 4KB) mapping to:

```c
typedef enum {
    NPT_MON_EXEC = 1,   /* fault on execute,  log + optionally break */
    NPT_MON_WRITE = 2,  /* fault on write,    log + optionally break */
    NPT_MON_READ = 4,   /* fault on read,     rarely useful */
    NPT_MON_HOOK = 8,   /* two-view: serve original bytes on read,
                           hook bytes on execute */
} NPT_MON_KIND;

typedef struct _NPT_MONITOR {
    ULONGLONG gpa_4k;         /* key */
    ULONG     kind;           /* mask of NPT_MON_KIND */
    ULONGLONG target_cr3;     /* 0 = any process, else gate by CR3 */
    ULONG     hit_count;
    /* For HOOK kind: */
    PVOID     view_original;  /* VA of copy of original page bytes  */
    PVOID     view_hook;      /* VA of copy with hook bytes patched */
    ULONGLONG pa_original;    /* PA of view_original (4KB-aligned)   */
    ULONGLONG pa_hook;        /* PA of view_hook (4KB-aligned)       */
    /* Optional user callback metadata */
    ULONG     user_tag;       /* opaque to kernel, returned on hit   */
    LIST_ENTRY link;
} NPT_MONITOR;
```

The table is consulted from `handle_npf` (see `vmexit_debug.md` item 2).
Keep it in nonpaged pool, protected by a reader-writer lock
(`ExInitializeResourceLite`) so arm/disarm (writer) doesn't race the
fast path (reader).

Signatures:

```c
NTSTATUS npt_monitor_arm(ULONGLONG gpa_4k, ULONG kind,
                          ULONGLONG target_cr3, ULONG user_tag);
NTSTATUS npt_monitor_disarm(ULONGLONG gpa_4k);
NPT_MONITOR *npt_monitor_lookup(ULONGLONG gpa_4k);
```

Arming an EXEC monitor: split the containing 2MB PDE if needed, then
clear the NX bit in the target 4KB PTE's permission field — wait, SVM's
NPT doesn't use NX; the executable attribute is implicit. For AMD NPT
you revoke execute by setting the entry's reserved bit? No — NPT PTE
permissions are: bit 0 Present, bit 1 Write, bit 2 User. That's it for
the usual set. Execute is not independently revocable at NPT level
unless EFER.NXE is on and NX (bit 63) is used. Zen 4 has NX; use it.

So:

- Revoke execute → set NX (bit 63)
- Revoke write   → clear bit 1 (W)
- Revoke read    → clear bit 0 (P) — this also prevents execute and
                                     write; use only for hard freezes

### 3. Two-view hooks (the invisible-breakpoint trick)

For a target that self-CRCs its own `.text`:

1. Allocate two 4KB buffers of nonpaged pool: `view_original` and
   `view_hook`.
2. Copy the original guest page bytes into both.
3. Write your hook bytes (e.g. `0xCC` INT3, or a JMP to a trampoline)
   into `view_hook` at the offset you want to hook.
4. Split the containing 2MB PDE if needed.
5. Set the PTE's PA to `pa_hook` and revoke READ (clear bit 0 but keep
   execute via NX=0). The PTE is now "executable but not readable".
6. Register in monitor table with kind `NPT_MON_HOOK`.

Fault flow:

- Guest executes the hook location: NX=0 so execute passes, hook bytes
  run. Good.
- Guest reads the hook location (self-CRC): clear-P causes NPF with
  `exit_info_1.read=1`. In `handle_npf`, swap the PTE's PA to
  `pa_original`, set P=1 and NX=1 (block execute). Set the guest's
  MTF-equivalent (on AMD: single-step via `rflags.TF=1` + intercept
  #DB) and resume. Guest reads original bytes, CRC matches.
- On the single step's #DB, swap PTE back to `pa_hook`, clear TF, mask
  the #DB from the guest, resume. Guest's next execute lands on hook.

This is the EPT-hook pattern transplanted to NPT. On AMD you don't have
Monitor Trap Flag like Intel — you use `rflags.TF` and intercept #DB
via `vmcb.ctl.intercept_exceptions |= (1 << 1)`.

**Concurrency warning**: on a multi-core guest, another core can be
executing the hook location at the same moment one core is reading it
for a CRC check. The PTE swap is per-NPT-tree and we have one tree, so
the swap is system-wide. Mitigations:

- Pause other cores during the swap (broadcast NMI; they wait in your
  NMI handler on a spinlock)
- Or: maintain per-CPU NPT trees (big refactor; not phase 2)

Phase 2 ships with the "pause other cores" approach. It adds VMEXIT
cost per hook-read but is correct.

### 4. Permission encoding reference

AMD NPT PTE (standard page, not large):

```
bit  0: P   — present
bit  1: W   — writable
bit  2: U   — user (we always set, guest is ring-X)
bit  3: PWT — write-through (keep as PAT dictates)
bit  4: PCD — cache-disable  (keep as PAT dictates)
bit  5: A   — accessed       (HW writes)
bit  6: D   — dirty          (HW writes; only on W pages)
bit  7: PAT — PAT bit
bits 8-11: AVL — software-available
bits 12-51: PFN — physical frame number (PA >> 12)
bits 52-62: AVL/reserved
bit 63: NX  — no-execute (requires EFER.NXE=1, which Windows sets)
```

For HOOK kind, encode the current view in one of the AVL bits (say
bit 9): 0=original served, 1=hook served. The NPF handler reads this
to decide which direction to swap.

### 5. API summary (for other files to consume)

```c
/* Setup */
NTSTATUS npt_init(void);              /* existing */
NTSTATUS npt_monitor_init(void);      /* NEW: build hash table, resource */
void     npt_monitor_shutdown(void);  /* NEW */

/* Core: arm / disarm */
NTSTATUS npt_monitor_arm_exec(ULONGLONG gpa_4k, ULONGLONG cr3_filter,
                               ULONG user_tag);
NTSTATUS npt_monitor_arm_write(ULONGLONG gpa_4k, ULONGLONG cr3_filter,
                                ULONG user_tag);
NTSTATUS npt_monitor_arm_hook(ULONGLONG gpa_4k, PVOID hook_bytes,
                               SIZE_T hook_len, SIZE_T hook_offset,
                               ULONGLONG cr3_filter, ULONG user_tag);
NTSTATUS npt_monitor_disarm(ULONGLONG gpa_4k);

/* Fast path (called from handle_npf) */
NPT_MONITOR *npt_monitor_find(ULONGLONG gpa_4k);
void         npt_monitor_handle_fault(NPT_MONITOR *m, VMCB *vmcb,
                                       ULONGLONG fault_info);

/* Range convenience: arm every 4K page across a VA range */
NTSTATUS npt_monitor_arm_range_exec(ULONGLONG gpa_start, SIZE_T bytes,
                                     ULONGLONG cr3_filter, ULONG user_tag);
```

### 6. Why this is what defeats self-CRC

Themida/VMProtect periodically compute CRC32 or hash of their own
code sections and compare against a stored value. A traditional
inline hook patches bytes → CRC mismatch → protector refuses to run.

NPT split-view: reads see original bytes (CRC passes), executes see
hook bytes. The split is enforced in hardware at the physical-address
level, below any software integrity check. The protector cannot detect
this without timing (reads from a split page cost ~1 extra NPF round
trip; see `vmexit_debug.md` item 5 for timing masking).

### 7. Phase ordering within this module

1. `npt_split_2mb_to_4kb` + split-tracking bitmap
2. Monitor table + arm/disarm/lookup (EXEC and WRITE only, no HOOK)
3. `handle_npf` extension to consult the monitor table (see
   `vmexit_debug.md` item 2)
4. Single-step state machine (RFLAGS.TF + #DB intercept)
5. HOOK kind with two-view swap
6. Range convenience helpers
