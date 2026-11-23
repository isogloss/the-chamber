# Memory snapshot — new module `snapshot.c` / `snapshot.h`

Core unpacking primitive: given a guest VA range in the target process,
walk the target's page tables to GPAs, read the backing pages, deliver
them to a user-mode buffer. Works for pages that exist for a single
instant — call snapshot from an NPF exec-hit handler and capture the
loaded PE before the loader frees it.

## Why this is non-trivial

- The HV runs with its own host CR3; it cannot just `memcpy` from a
  guest VA. Guest VAs resolve differently under the target's CR3 than
  under any other CR3.
- Guest page tables may be paged out. NtQueryVirtualMemory tells you
  about VADs but not about PTE presence.
- The target process's pages may not be in a valid state continuously
  — they may be committed, freed, remapped. Capture must be atomic
  relative to the guest resume.
- Writing to a user buffer from VMEXIT context: can't sleep, can't
  touch pageable memory, can't take locks that other code paths might
  hold. Use preallocated nonpaged pool as staging, hand off to a
  worker thread for user copy.

## API

```c
/* Resolve a GVA → GPA under a given CR3, walking guest 4-level paging.
 * Returns FALSE if any level is not-present or if the walk exits a
 * bogus physical range (sanity bound). */
BOOLEAN snapshot_gva_to_gpa(ULONGLONG cr3, ULONGLONG gva,
                            ULONGLONG *out_gpa,
                            ULONG *out_page_size);  /* 4K / 2M / 1G */

/* Copy a guest VA range into a kernel buffer. Buffer must be nonpaged
 * and size >= length. Pages that don't resolve are skipped and a
 * holes[] array records which 4K chunks were missing. */
NTSTATUS snapshot_capture_va(ULONGLONG target_cr3,
                              ULONGLONG gva_start,
                              SIZE_T    length,
                              PVOID     out_buf,
                              SIZE_T    out_buf_size,
                              SNAPSHOT_HOLE *holes,
                              ULONG     holes_cap,
                              ULONG    *holes_count);

/* Deliver a captured range to userland via the SNAPSHOT_VA IOCTL. */
NTSTATUS snapshot_deliver_to_user(IRP *irp,
                                   PVOID staging_buf,
                                   SIZE_T length);

typedef struct _SNAPSHOT_HOLE {
    ULONGLONG gva;
    ULONG     length;
    ULONG     reason;   /* SNAPSHOT_HOLE_NOT_PRESENT, _PAGED_OUT, ... */
} SNAPSHOT_HOLE;
```

## Guest page-table walk

AMD 64-bit paging, 4 levels, 48-bit VA (or 57-bit if LA57 — Zen 4
supports but Windows rarely enables). We assume 4-level unless CR4.LA57.

```c
#define PT_ENTRY(x) ((x) & 0x000FFFFFFFFFF000ULL)   /* bits 12..51 */
#define PT_P(x)     ((x) & 1ULL)
#define PT_PS(x)    ((x) & (1ULL << 7))             /* large page */
#define PT_NX(x)    ((x) & (1ULL << 63))

BOOLEAN snapshot_gva_to_gpa(ULONGLONG cr3, ULONGLONG gva,
                             ULONGLONG *out_gpa, ULONG *out_page_size)
{
    ULONGLONG pml4_pa = cr3 & 0xFFFFFFFFFFFFF000ULL;
    ULONGLONG pml4e = read_guest_pa_u64(pml4_pa + ((gva >> 39) & 0x1FF) * 8);
    if (!PT_P(pml4e)) return FALSE;

    ULONGLONG pdpt_pa = PT_ENTRY(pml4e);
    ULONGLONG pdpte = read_guest_pa_u64(pdpt_pa + ((gva >> 30) & 0x1FF) * 8);
    if (!PT_P(pdpte)) return FALSE;
    if (PT_PS(pdpte)) {
        *out_page_size = 0x40000000;   /* 1GB */
        *out_gpa = PT_ENTRY(pdpte) + (gva & 0x3FFFFFFF);
        return TRUE;
    }

    ULONGLONG pd_pa = PT_ENTRY(pdpte);
    ULONGLONG pde = read_guest_pa_u64(pd_pa + ((gva >> 21) & 0x1FF) * 8);
    if (!PT_P(pde)) return FALSE;
    if (PT_PS(pde)) {
        *out_page_size = 0x200000;     /* 2MB */
        *out_gpa = PT_ENTRY(pde) + (gva & 0x1FFFFF);
        return TRUE;
    }

    ULONGLONG pt_pa = PT_ENTRY(pde);
    ULONGLONG pte = read_guest_pa_u64(pt_pa + ((gva >> 12) & 0x1FF) * 8);
    if (!PT_P(pte)) return FALSE;

    *out_page_size = 0x1000;
    *out_gpa = PT_ENTRY(pte) + (gva & 0xFFF);
    return TRUE;
}
```

`read_guest_pa_u64` reads an 8-byte value at a guest physical address:

```c
static ULONGLONG read_guest_pa_u64(ULONGLONG gpa)
{
    PHYSICAL_ADDRESS pa; pa.QuadPart = (LONGLONG)gpa;
    PVOID va = MmMapIoSpaceEx(pa, 8, PAGE_READONLY);
    if (!va) return 0;
    ULONGLONG v = *(volatile ULONGLONG *)va;
    MmUnmapIoSpace(va, 8);
    return v;
}
```

Note: `MmMapIoSpace` is for device memory but works for any PA on x64.
A faster path if the GPA is backed by normal RAM is
`MmGetVirtualForPhysical` after `MmGetPhysicalAddress` — use the fast
path when available. These are PASSIVE_LEVEL APIs, so from a VMEXIT
(which runs at DISPATCH_LEVEL-ish host context) you cannot call them
directly. Instead: enqueue the capture via a worker DPC, capture at
PASSIVE in the worker. For the "catch a PE that only lives for seconds"
case, the round-trip DPC-queue-to-passive is typically <1ms which is
fast enough.

## Capture workflow for "catch the staged payload"

Operator flow:

1. Userland identifies the target PID (the cheat loader).
2. `IOCTL_CHAMBER_SET_TARGET_PID` — HV now watches CR3 switches to
   this process and records its CR3.
3. Userland arms execute monitors on key observability points:
   - `KeStackAttachProcess` return? No — in-process.
   - `ntdll!LdrpMapViewOfSection` — catches every mapped section
     including the loader-decrypted PE.
   - `kernel32!CreateFileMappingW` / `NtCreateSection` — alternative
   - `ntdll!NtAllocateVirtualMemory` where `ProtectionType` has
     `PAGE_EXECUTE_*` — direct allocation path
   - Any RWX→RX transition via `ntdll!NtProtectVirtualMemory`
4. HV reports exec hits via the event ring.
5. On each event, userland queries the target's VAD or memory map
   (via `NtQueryVirtualMemory` from a userland helper, or via a kernel
   helper that walks EPROCESS.VadRoot) to find the region that was
   just committed / transitioned.
6. Userland calls `IOCTL_CHAMBER_SNAPSHOT_VA` on the region.
7. Userland dumps the snapshot to disk with a timestamp + source RIP.

For the "PE lives for seconds then is wiped" case, steps 4-6 round-trip
must complete inside that window. Empirical latency budget:

- NPF VMEXIT → event in ring: ~500ns
- IOCTL_POLL_EVENTS returning: ~1μs
- IOCTL_SNAPSHOT_VA capture of a 10MB region: ~5ms (bounded by
  per-page MmGetVirtualForPhysical)
- Total: <10ms, well inside a multi-second visibility window

If the payload is REALLY fast (ms-order visibility), park the vCPU on
exec hit (see `the_chamber_debug.md` pause/resume). The exec trap
freezes the guest instantly; snapshot happens with the target held.

## Reading pageable guest memory from VMEXIT context

Short answer: don't try. The two-stage approach:

- VMEXIT handler: record (cr3, gva_start, length, event tag) into a
  pending-snapshot queue. Fire the event into the ring.
- PASSIVE worker (KeInitializeWorker DPC): dequeue, call the walker
  and reader at PASSIVE, hand result to a waiting IRP.

Alternative: pre-pin the target's VADs when `SET_TARGET_PID` is
called, by issuing `MmProbeAndLockPages` on each committed VAD.
Downside: pins memory the target process might otherwise page out,
large memory cost, and VADs change over time. Not recommended.

## Hole handling

A snapshot of a 10MB region may hit paged-out pages in the middle.
Options:

- **Skip**: fill with zeros, record in `holes[]`
- **Fault in**: trigger a touch via a user-mode agent injected into
  the target. Risky — the target may detect the touch.
- **Reconstruct from pagefile**: possible via `MmGetPhysicalMemoryRanges`
  + pagefile I/O, but very expensive and may fail.

Default: skip and report. Userland chooses whether to retry later.

## Exporting to disk

The snapshot buffer in nonpaged pool is handed to the IOCTL's MDL
(method OUT_DIRECT). Userland then writes it to disk. Keep the HV
I/O-free — disk writes from HV context are risky.

A user-mode companion tool (`pentest\snapshot_writer.ps1` or similar)
sits in a tight loop:

```powershell
while ($true) {
    $event = Chamber-PollEvents
    if ($event.Kind -eq 'EXEC_HIT') {
        $region = Get-TargetVADContaining $event.FaultingGva
        $dump = Chamber-SnapshotVa $region.Start $region.Length
        $name = "dump_{0}_rip{1:X}_gva{2:X}.bin" -f `
                (Get-Date -Format 'HHmmss.fff'), $event.Rip, $event.FaultingGva
        [IO.File]::WriteAllBytes("captures\$name", $dump)
    }
}
```

## PE reconstruction helper

Dumps are raw memory. For a mapped PE, you want to reconstruct the
file-form layout (sections un-aligned back to file offsets). Use
pe-sieve or Scylla after the fact — don't rebuild inside the HV.

## Integration points

- Add `snapshot.c`, `snapshot.h` to `driver/`
- Add to `build.ps1` compile list
- Add VA→GPA walker signature to `snapshot.h` so `vmexit.c` can use
  it for monitor arm requests (operator passes VA; HV translates to
  GPA under target CR3)

## Gotchas

- **CR3 vs target_cr3**: if the target process has not yet been
  context-switched to since `SET_TARGET_PID`, `target_cr3` may be
  zero. Resolve lazily via `PsLookupProcessByProcessId` →
  `PsGetProcessSectionBaseAddress`-style indirection? Easier: resolve
  via `KeStackAttachProcess` to the target, then `__readcr3`, then
  `KeUnstackDetachProcess`. Do this in the IOCTL handler at PASSIVE.
- **PCID / INVPCID**: Windows uses PCID on modern CPUs; `cr3 & ~0xFFF`
  is the physical PML4 base, low 12 bits are PCID. Always mask off
  before using as a PA.
- **KVA Shadow (Meltdown mitigation)**: Windows switches between a
  user CR3 and a kernel CR3 on every syscall. The target process has
  two CR3s. For user-mode VAs you want the user CR3 (low bit of the
  CR3 value in Windows's convention). Dump both and let userland
  disambiguate, or catch CR3 switches between the pair and pick the
  one corresponding to user-mode VAs.
