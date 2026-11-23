# Process targeting — new module `process_target.c` / `process_target.h`

Scope every monitor, breakpoint, and snapshot to one process by its
CR3. Without this, exec/write tracing drowns in system-wide noise.

## The two-step problem

1. **Map PID to CR3.** Windows represents a process by `EPROCESS`,
   which contains `DirectoryTableBase` (the CR3) at a Windows-version-
   dependent offset. Use documented APIs where possible.
2. **Catch CR3 switches.** Windows context-switches between processes
   constantly. Each time the scheduler picks the target process, its
   CR3 is loaded. The HV needs to know when that happens.

## PID → CR3

Three options. Use (a).

**(a) Preferred: PsLookupProcessByProcessId + a stack-attach**

```c
NTSTATUS pt_pid_to_cr3(HANDLE pid, ULONGLONG *out_cr3)
{
    PEPROCESS proc;
    NTSTATUS st = PsLookupProcessByProcessId(pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);
    *out_cr3 = __readcr3() & ~0xFFFULL;   /* strip PCID */
    KeUnstackDetachProcess(&apc);

    ObDereferenceObject(proc);
    return STATUS_SUCCESS;
}
```

Call at PASSIVE_LEVEL. Must be in the IOCTL path, never from VMEXIT.

The result is the **kernel** CR3 of the target (KVA Shadow pairs this
with a user CR3 flipped on syscall return). See
`snapshot_debug.md` "KVA Shadow" for the follow-up — we want both
sides of the pair.

**(b) Direct EPROCESS field read**

Walk `PsInitialSystemProcess`'s ActiveProcessLinks, match PID, read
`EPROCESS->DirectoryTableBase`. Fast but requires the offset to be
correct for the specific Windows build. Use `IoGetCurrentProcess()`
and inspect the structure at known offsets for your target build.
Fragile across Windows updates; (a) is better.

**(c) Loader-provided**: have userland pass CR3 explicitly. Trivially
easy but defeats the point (userland shouldn't need kernel privilege
to read its own CR3 — unless it uses this driver, which is circular).

## Catching CR3 switches

Windows's scheduler writes CR3 during `SwapContext`. Intercepting
`MOV CR3` catches every context switch.

Enable in `svm_build_vmcb` (dynamic, only when a target is set):

```c
ctl->intercept_cr_write |= (1U << 3);  /* CR3 write */
```

Handler in `vmexit.c` (see `vmexit_debug.md` item 1):

```c
static void handle_cr_access(PER_CPU_CTX *ctx, VMCB *vmcb)
{
    /* exit_code 0x13 = MOV TO CR3 */
    if ((vmcb->ctl.exit_code & 0xF) == 3 &&
         vmcb->ctl.exit_code >= 0x10) {

        ULONG gpr_idx = (ULONG)(vmcb->ctl.exit_info_1 & 0xF);
        ULONGLONG new_cr3 = gpr_read_by_index(ctx, vmcb, gpr_idx) & ~0xFFFULL;

        pt_on_cr3_switch(ctx, new_cr3);

        /* Apply the write to the VMCB */
        vmcb->save.cr3 = new_cr3 | (vmcb->save.cr3 & 0xFFFULL);  /* keep PCID */
        vmcb->ctl.vmcb_clean_bits &= ~CLEAN_CR;
    }
    vmcb->save.rip = vmcb->ctl.next_rip;
}
```

## Cost note: CR3 write intercepts are expensive

Context switches are frequent — thousands per second. CR3 write
intercept adds a VMEXIT on every one. Impact:

- Noticeable latency on an interactive guest (mouse feel changes)
- Observable via timing probes (though the switch latency is dwarfed
  by scheduler cost; probably below detection threshold)
- Not free in power: every intercept wakes the HV handler

Mitigations:

- Only arm when a target is active (`intercept_arm_cr3_write()`
  refcounted; see `svm_vmcb_debug.md`)
- Early-exit the handler: if `new_cr3 != target_cr3 && new_cr3 !=
  target_user_cr3`, skip event push, just apply the write.

```c
void pt_on_cr3_switch(PER_CPU_CTX *ctx, ULONGLONG new_cr3)
{
    if (g_pt.target_cr3 == 0) return;
    if (new_cr3 != g_pt.target_cr3 && new_cr3 != g_pt.target_user_cr3)
        return;

    /* Target process just came onto this CPU */
    ctx->target_active_here = (new_cr3 == g_pt.target_cr3 ||
                                new_cr3 == g_pt.target_user_cr3);

    CHAMBER_EVENT e = { .kind = EVT_PROCESS_SWITCH };
    e.rip = /*vmcb*/0;
    e.guest_cr3 = new_cr3;
    e.cpu_index = ctx->cpu_index;
    chamber_event_push(&e);
}
```

## Capturing both CR3s (KVA Shadow)

The target process has two CR3s on modern Windows:
- Kernel CR3 (loaded during kernel execution)
- User CR3 (loaded during user execution)

They differ by a known bit (bit 11 in Windows's scheme). The CR3
switch handler sees both over time; record both the first time we
observe a switch TO the target, so monitors with a CR3 filter catch
both user-mode and kernel-mode execution.

```c
typedef struct _PT_STATE {
    HANDLE     target_pid;
    ULONGLONG  target_cr3;        /* kernel CR3 */
    ULONGLONG  target_user_cr3;   /* user CR3; 0 until observed */
    PEPROCESS  target_eprocess;
    volatile LONG active;
} PT_STATE;

extern PT_STATE g_pt;

NTSTATUS pt_set_target(HANDLE pid);
NTSTATUS pt_clear_target(void);
BOOLEAN  pt_cr3_matches_target(ULONGLONG cr3);
```

## Death handler

If the target process exits (likely, given the "loaded for seconds"
behavior), our CR3 goes stale. Any new process may get the same CR3
value and we'd act on the wrong process.

Install a process-termination callback:

```c
PsSetCreateProcessNotifyRoutineEx(pt_proc_notify, FALSE);

static void pt_proc_notify(PEPROCESS proc, HANDLE pid,
                           PPS_CREATE_NOTIFY_INFO info)
{
    if (!info && pid == g_pt.target_pid) {
        /* Target died — tear down */
        pt_clear_target();
        push_event(EVT_PROCESS_SWITCH, "target exited");
    }
}
```

For a staged loader → downloaded PE → exits in seconds pattern, the
loader process probably persists while the PE runs inside it. But if
the loader forks a child and dies, we want to follow the child.
Catch `info->CreateInfo` on process creation with the parent being
our target, and follow up.

## PID-rotation attack

A sophisticated anti-debug: spawn a sacrificial child that gets our
monitors attached, then spawn a second child that does the real work.
The HV is watching the wrong CR3.

Defense: operator sets target by **image name** not PID. Install a
process-creation callback; auto-set target to the first process of
matching image name after arming; optionally re-target on every
subsequent match. Trade-off: more automation, more opportunity for
us to be fooled by image-name spoofing.

For phase 1, just do PID. Add image-name tracking in phase 4.

## Thread-level targeting

Some protectors run the sensitive work on a specific thread (anti-
debug timer thread, etc.). Thread-level targeting = filter by
ETHREAD + current RIP range. Adds another layer of selectivity. Not
in phase 1; mention for later.

## API summary

```c
NTSTATUS pt_init(void);
void     pt_shutdown(void);

NTSTATUS pt_set_target(HANDLE pid);
NTSTATUS pt_clear_target(void);

ULONGLONG pt_get_target_cr3(void);        /* kernel CR3 */
ULONGLONG pt_get_target_user_cr3(void);   /* user CR3 */
BOOLEAN   pt_cr3_matches_target(ULONGLONG cr3);

void      pt_on_cr3_switch(PER_CPU_CTX *ctx, ULONGLONG new_cr3);
```

## Adding to the build

- `driver/process_target.c`
- `driver/process_target.h`
- `build.ps1`
- Call `pt_init()` from `DriverEntry` after SVM bringup
- Call `pt_shutdown()` from DriverUnload before SVM teardown
