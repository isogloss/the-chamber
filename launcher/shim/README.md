# chamber_shim.dll

User-mode shim DLL injected into every PID the operator spoofs. Pairs
with `driver/fingerprint/chamber_fingerprint.sys` -- the kernel side
owns the per-process arming via
`ProcessInstrumentationCallback` and the registry / minifilter
rewriters; the user-mode side owns the trampoline the IC dispatch jumps
to on every syscall return.

## Files

| File | Role |
|---|---|
| `chamber_shim.h` | Shared contract (hypercall code, request/reply structs, surface tags, trampoline signature). |
| `chamber_shim.cpp` | DLL body: `chamber_shim_dispatch`, three per-surface handlers, `safe_vmmcall` SEH wrapper, `DllMain`. |
| `chamber_shim_trampoline.asm` | x64 trampoline (mirror of `driver/fingerprint/ic_trampoline.asm`) + `chamber_shim_vmmcall` emitter. |
| `chamber_shim.def` | DLL exports: trampoline, syscall-number binder. |
| `build.ps1` | cl.exe + ml64 + link.exe build glue. Produces `build/chamber_shim.dll`. |

## Register contract

Kernel-set on entry to `chamber_shim_trampoline`, matching the
sanctioned Windows path:

```
rcx = syscall return value as the caller would see it
rsp = user-mode stack (not guaranteed 16-aligned)
r10 = user return RIP (preserve verbatim; final jmp r10 resumes)
rax = scratch
r11 = scratch
```

The shim's own prologue, laid down one time per thread at attach,
stashes:

```
gs:[0x1480] = NT syscall number (dword)
gs:[0x1488] = rcx at the syscall site (qword; first arg)
```

## Hypercall

The dispatcher issues a single AMD-SVM `vmmcall` instruction with the
Chamber shared-secret in `rbx` and the hypercall code in `rax`:

```
rax = CHAMBER_HCALL_REWRITE_RESULT (0x10)
rbx = THE_CHAMBER_HYPERCALL_MAGIC  (0x5452484D4648434A)
rcx = guest VA of a CHAMBER_SHIM_REWRITE_REQ struct
rdx = 0
```

The HV (`driver/vmexit.c:handle_vmmcall`) verifies the magic and
forwards the request to the fingerprint driver's dispatch. The reply
comes back as a guest VA in `rax` (or 0 on failure); the C body reads
`cookie` + `new_return` out of that reply. The full dispatch table on
the kernel side is a later refinement -- the shim's wire format
already carries the information it needs.

## Covered surfaces (today)

Only three syscalls hit the hypercall path; everything else short-
circuits with `jmp r10` and incurs zero overhead. Growing this table is
cheap (one entry per syscall in `chamber_shim_dispatch`) but every
extra path is a trap for a target to measure, so we keep it small:

| Surface tag | Syscall | Why |
|---|---|---|
| `NT_QUERY_SYSTEM_INFO` | `NtQuerySystemInformation` classes 103 / 144 / 176 | CI state / Secure Boot policy / WDAC policy. |
| `NT_QUERY_VALUE_KEY` | `NtQueryValueKey` | Registry identity (MachineGuid, ProductId, BitLocker, etc.). |
| `NT_DEVICE_IO_CONTROL_FILE` | `NtDeviceIoControlFile` | Storage serial IOCTLs + NDIS MAC queries. |

## Safety

* The `vmmcall` is wrapped in `__try/__except`. On a host without the
  HV loaded, or in a process that has not been armed, VMMCALL raises
  `#UD`. The handler catches it and the shim falls back to pass-through
  (return the kernel-provided value unchanged).
* No ntdll walk in `DllMain` -- loader-lock recursion is a known class
  of hang for syscall-return hooks. The launcher binds syscall numbers
  with `chamber_shim_bind_sysnum` from outside the loader lock.
* The dispatch never touches the caller's output buffer. All buffer
  rewrites happen on the kernel side via `CmRegisterCallbackEx`,
  `FltRegisterFilter`, or the IC rewrite path in
  `syscall_rewrite.c`. The shim's job is to propagate return values
  and give the kernel a per-call synchronization point.
