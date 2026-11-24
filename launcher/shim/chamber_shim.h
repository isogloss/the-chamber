/* chamber_shim.h -- shared contract between the user-mode shim DLL and
 * the chamber_fingerprint.sys kernel interceptor.
 *
 * The shim is injected into every PID the operator spoofs. It mirrors
 * the x64 trampoline documented in driver/fingerprint/ic_trampoline.asm,
 * dispatches on the NT syscall number stashed by its own prologue at
 * gs:[0x1480], and asks the kernel side for a rewritten return value
 * through a lightweight VMMCALL hypercall. The hypercall contract is a
 * minimal extension of the shared-secret hypercall surface the HV
 * driver already validates (see driver/the_chamber.h: field magic
 * THE_CHAMBER_HYPERCALL_MAGIC).
 *
 * Keep this file self-contained — a shim DLL build must not drag in
 * kernel headers. Numeric constants here are mirrored into the kernel
 * side in a later wave when the full dispatch table lands.
 */

#ifndef CHAMBER_SHIM_H
#define CHAMBER_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Hypercall shared-secret magic. Must match
 * driver/the_chamber.h:THE_CHAMBER_HYPERCALL_MAGIC.
 *
 * The HV's handle_vmmcall dispatcher checks rbx against this magic
 * before looking at rax. Mismatch -> #UD (trojan-instruction behaviour,
 * covered in driver/vmexit.c) rather than a visible side-effect, which
 * is what we want from a stray VMMCALL in an unspoofed process. */
#define CHAMBER_SHIM_HYPERCALL_MAGIC   0x5452484D4648434AULL

/* Hypercall code the shim emits when it wants the kernel side to tell
 * it the rewritten syscall return value for a given (pid, sysnum,
 * args) tuple. The driver-side dispatch for this code is planned for a
 * later wave; the full dispatch table in driver/fingerprint/syscall_rewrite.c
 * is already structured around exactly these inputs. See the comment
 * block in driver/fingerprint/README.md on PG safety -- a hypercall is
 * strictly stricter than the alternative ntoskrnl patch and keeps the
 * shim's side effect surface to one documented opcode. */
#define CHAMBER_HCALL_REWRITE_RESULT   0x10u

/* Request shape the shim pushes into kernel-visible memory before
 * VMMCALL. The HV reads it out of rdx (a guest virtual address); the
 * fingerprint driver resolves the physical page once and reads the
 * struct back with the normal ZwReadVirtualMemory + MDL probe path.
 *
 * All fields are tiny so the whole struct fits in one cache line. */
typedef struct _CHAMBER_SHIM_REWRITE_REQ {
    uint64_t  cookie;         /* caller-chosen; echoed in the reply */
    uint32_t  sysnum;         /* NT syscall number, as the shim saw it */
    uint32_t  reserved;
    uint64_t  return_value;   /* the syscall's original return value */
    uint64_t  args[8];        /* up to 8 saved register args */
} CHAMBER_SHIM_REWRITE_REQ;

/* Reply shape. */
typedef struct _CHAMBER_SHIM_REWRITE_REPLY {
    uint64_t  cookie;         /* same as the request's cookie */
    uint64_t  new_return;     /* rewritten return value; or the
                               * original if the kernel declined */
    uint32_t  flags;           /* 1 = buffer was rewritten in place by
                               * the kernel's CM/FLT/IC path; 0 =
                               * untouched */
    uint32_t  reserved;
} CHAMBER_SHIM_REWRITE_REPLY;

/* Syscall number tags the shim's prologue is wired to recognize. These
 * are the NT syscall numbers that the kernel interceptor's full
 * dispatch table (see driver/fingerprint/syscall_rewrite.c) actively
 * rewrites. If a syscall is outside this set, the shim's dispatch
 * short-circuits with `jmp r10` -- no hypercall, no cost.
 *
 * The numbers themselves differ per Windows build. The launcher walks
 * ntdll once at attach time (via the same one-pass scan described in
 * driver/fingerprint/syscall_rewrite.c) and seeds these constants into
 * the shim's per-process memory at load time, so this header carries
 * only the SURFACE identifiers, not the hard-coded ordinals. The three
 * NtQuerySystemInformation classes are the three the kernel acts on.
 */
#define CHAMBER_SHIM_SURF_NT_QUERY_SYSTEM_INFO       0x01u
#define CHAMBER_SHIM_SURF_NT_QUERY_VALUE_KEY         0x02u
#define CHAMBER_SHIM_SURF_NT_DEVICE_IO_CONTROL_FILE  0x03u

/* NtQuerySystemInformation info-classes the dispatch cares about. These
 * match the constants in driver/fingerprint/syscall_rewrite.c and are
 * passed to the kernel inside args[0] of the hypercall request when
 * the surface is NtQuerySystemInformation. */
#define CHAMBER_SHIM_SYSINFO_CI                       103u
#define CHAMBER_SHIM_SYSINFO_SECURE_BOOT_POLICY       144u
#define CHAMBER_SHIM_SYSINFO_CI_POLICY_FULL           176u

/* Shim entry point. Matches the register contract in
 *   driver/fingerprint/ic_trampoline.asm:
 *     rcx = syscall return value
 *     r10 = user return RIP
 *     gs:[0x1480] = syscall number (stashed by the shim's own prologue
 *                  before the detour)
 *
 * Exported by chamber_shim.dll; the ntdll shim's prologue chains to
 * this symbol on each syscall return. */
__declspec(dllexport) void chamber_shim_trampoline(void);

/* Dispatch callback invoked by the trampoline after it has saved
 * every volatile register. Returns the (possibly rewritten) value to
 * place back into rcx before the trailing jmp r10. */
uint64_t chamber_shim_dispatch(uint64_t return_value,
                               uint64_t return_rip,
                               uint32_t sysnum);

#ifdef __cplusplus
}
#endif

#endif /* CHAMBER_SHIM_H */
