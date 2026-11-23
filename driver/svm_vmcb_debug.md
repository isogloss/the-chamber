# VMCB intercept wiring — notes for `svm_vmcb.c`

Which intercept bits to set at bringup, and which to set on-demand.
Everything here edits `svm_build_vmcb` or adds helpers it calls.

## Current state (`svm_vmcb.c:183-187`)

```c
ctl->intercept_vec3 |= IVEC3_CPUID | IVEC3_MSR;
ctl->intercept_vec4 |= IVEC4_VMRUN | IVEC4_VMMCALL;
```

MSRPM is populated for EFER + VM_HSAVE_PA + VM_CR + Hyper-V range.
IOPM is zero (no I/O intercepts, correct for a thin HV).

## What stays static (always-on)

Keep as-is:

- `IVEC3_CPUID`  — stealth masking of hypervisor bits
- `IVEC3_MSR`    — EFER.SVME hiding, Hyper-V MSR range hiding
- `IVEC4_VMRUN`  — architecturally required
- `IVEC4_VMMCALL` — our hypercall channel (magic-gated)

**Do not add always-on intercepts.** Every new bit raises resting
VMEXIT rate and, with it, the probability a timing probe detects us.

## What becomes dynamic (armed on demand)

Set these ONLY when a monitor/breakpoint is armed, and clear them when
the last one is disarmed.

| Bit | When armed | Why |
|---|---|---|
| `IVEC3_CR0_SEL_WRITE` | first process-target set | catch CR3 switches |
| `intercept_cr_write bit 3` | first process-target set | catch CR3 writes |
| `IVEC3_RDTSC` / `IVEC4_RDTSCP` | **never** by default | breaks our timing model; only arm during very tight probes |
| `intercept_dr_read` / `intercept_dr_write` (all bits) | first HW breakpoint | shadow DR relay |
| `intercept_exceptions bit 1 (#DB)` | first HW bp OR first hook | single-step + bp hit |
| `intercept_exceptions bit 3 (#BP)` | first SW bp | software breakpoint catch |

## Add: intercept refcount module

Multiple arm/disarm callers must not stomp each other. Example: two
HW breakpoints armed → one disarmed → DR intercepts should stay on.

```c
typedef struct _INTERCEPT_REFCOUNT {
    KSPIN_LOCK  lock;
    ULONG       cr3_writers;       /* CR3 write intercept */
    ULONG       dr_shadowers;      /* DR intercepts */
    ULONG       db_catchers;       /* #DB intercept */
    ULONG       bp_catchers;       /* #BP intercept */
} INTERCEPT_REFCOUNT;

extern INTERCEPT_REFCOUNT g_intercept_rc;

NTSTATUS intercept_arm_cr3_write(void);
NTSTATUS intercept_disarm_cr3_write(void);
NTSTATUS intercept_arm_dr_shadow(void);
NTSTATUS intercept_disarm_dr_shadow(void);
NTSTATUS intercept_arm_db(void);
NTSTATUS intercept_disarm_db(void);
NTSTATUS intercept_arm_bp(void);
NTSTATUS intercept_disarm_bp(void);
```

Each takes the lock, increments/decrements the counter, and when the
counter transitions 0↔1, broadcasts a VMCB update IPI to all CPUs
that flips the bit and invalidates the relevant clean bit.

```c
NTSTATUS intercept_arm_db(void)
{
    KIRQL irql;
    BOOLEAN broadcast = FALSE;
    KeAcquireSpinLock(&g_intercept_rc.lock, &irql);
    if (g_intercept_rc.db_catchers++ == 0) broadcast = TRUE;
    KeReleaseSpinLock(&g_intercept_rc.lock, irql);
    if (broadcast) {
        KeIpiGenericCall(ipi_set_db_intercept, 0);
    }
    return STATUS_SUCCESS;
}

static ULONG_PTR ipi_set_db_intercept(ULONG_PTR ignored)
{
    PER_CPU_CTX *ctx = &g_cpu_ctx[KeGetCurrentProcessorNumberEx(NULL)];
    VMCB *vmcb = (VMCB *)ctx->vmcb_va;
    vmcb->ctl.intercept_exceptions |= (1U << 1);
    vmcb->ctl.vmcb_clean_bits &= ~CLEAN_I;  /* intercept vector dirty */
    UNREFERENCED_PARAMETER(ignored);
    return 0;
}
```

Clean-bit constants (AMD Table 15-6):

```c
#define CLEAN_I   (1U << 0)   /* intercepts + IOPM/MSRPM */
#define CLEAN_IOPM (1U << 1)
#define CLEAN_ASID (1U << 2)
#define CLEAN_TPR  (1U << 3)
#define CLEAN_NP   (1U << 4)  /* nested paging + nCR3 */
#define CLEAN_CRX  (1U << 5)
#define CLEAN_DRX  (1U << 6)
#define CLEAN_DT   (1U << 7)  /* IDTR, GDTR, LDTR, TR */
#define CLEAN_SEG  (1U << 8)
#define CLEAN_CR2  (1U << 9)
#define CLEAN_LBR  (1U << 10)
#define CLEAN_AVIC (1U << 11)
```

When you change an intercept vector, clear `CLEAN_I`. When you change
an NPT PTE, clear `CLEAN_NP`. The hardware re-reads the dirty region
on next VMRUN.

## Do NOT intercept these

For stealth:

- `IVEC3_RDTSC` / `IVEC4_RDTSCP` — RDTSC intercept adds huge per-tick
  cost. With `vmcb.ctl.tsc_offset` we achieve guest TSC rewriting
  without intercepting. Only arm during specific instrumentation
  windows (e.g. snapshot capture).
- `IVEC3_INVD` / `IVEC4_WBINVD` — legitimate guest activity, no value
  in catching
- `IVEC3_INTR` / `IVEC3_NMI` / `IVEC3_SMI` — host should not see
  ordinary guest interrupts
- I/O (`IVEC3_IOIO` + IOPM) — leave fully passthrough for stealth
  and performance

## Add: intercept-state query hypercall

Userland debugger agent needs to know what's armed. New VMMCALL code
(see `the_chamber_debug.md`):

```
HCALL_QUERY_INTERCEPTS = 10
  returns in RAX: bitmask of currently-armed debugger intercepts
```

## Small change needed to `svm_build_vmcb`

Currently builds VMCB once per CPU at bringup. If a monitor is armed
AFTER bringup, we need the per-CPU VMCB on each core updated. The
IPI pattern above does that cleanly (each core self-edits its own
VMCB). No change to `svm_build_vmcb` itself needed — just make sure
the per-CPU VMCB pointer is reachable from inside the IPI callback.

`g_cpu_ctx[i].vmcb_va` is already the right pointer.

## Verification

After each arm/disarm pair, dump intercept state via
`HCALL_QUERY_INTERCEPTS` and confirm:

- Bits that should be set after arm are set
- Bits are cleared after disarm when refcount hits zero
- Resting (no monitors) state matches bringup static set exactly
