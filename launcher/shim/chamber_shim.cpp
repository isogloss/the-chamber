// chamber_shim.cpp -- user-mode instrumentation-callback DLL.
//
// Injected into every spoofed PID by the launcher (via
// NtSetInformationProcess(ProcessInstrumentationCallback) chained
// through the shim's own loader stub, which lays down the ntdll
// syscall-number table and a short per-thread prologue that stashes
// rax into gs:[0x1480] before every syscall site). The kernel-side
// contract is described in driver/fingerprint/ic_trampoline.asm and in
// chamber_shim.h.
//
// This translation unit holds:
//   * chamber_shim_dispatch  -- the C body the trampoline calls into
//   * on_* per-surface handlers for the three syscall surfaces the
//     kernel's chamber_fingerprint.sys interceptor currently rewrites
//   * a minimal VMMCALL emitter that fetches the rewritten return
//     value from the kernel through the CHAMBER_HCALL_REWRITE_RESULT
//     hypercall
//
// The dispatch table is intentionally minimal. The kernel side covers
// ~35 surfaces today; the shim only hot-fast-paths the three the
// design labels highest-signal for user-mode queries. Everything else
// jmp r10's straight back to the caller with no cost. Growing the
// table is a later refinement; the plumbing here is what matters.

#include "chamber_shim.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#pragma intrinsic(__readgsqword)

// --- per-process state ---------------------------------------------------
//
// Populated by the shim's loader stub on DLL_PROCESS_ATTACH (see
// DllMain). The syscall-number -> surface-tag map is a sparse array
// large enough for any single Windows build's ordinal space.

static uint8_t g_sysnum_to_surface[4096] = { 0 };

// Bind one surface tag to a live syscall ordinal. Called N times by
// the loader stub (once per syscall the shim cares about) before the
// first detour fires. Public so the launcher can call it from inside
// the target process after a one-pass ntdll walk resolves the
// per-build syscall ordinals.
extern "C" __declspec(dllexport)
void chamber_shim_bind_sysnum(uint32_t sysnum, uint32_t surface_tag)
{
    if (sysnum < 4096 && surface_tag <= 255) {
        g_sysnum_to_surface[sysnum] = static_cast<uint8_t>(surface_tag);
    }
}

// --- VMMCALL emitter ------------------------------------------------------
//
// AMD-SVM VMMCALL takes no operands at the ISA level; the HV reads
// rax / rbx / rcx / rdx out of the guest's VMCB-save state. MSVC x64
// has no inline asm, so we use a tiny .asm sidecar
// (chamber_shim_vmmcall.asm) that the build.ps1 assembles alongside
// this file and links in.
//
// Convention (matching driver/vmexit.c handle_vmmcall):
//   rax = hypercall code
//   rbx = shared-secret magic (THE_CHAMBER_HYPERCALL_MAGIC)
//   rcx = arg0 (guest VA of the request struct for REWRITE_RESULT)
//   rdx = arg1 (unused for REWRITE_RESULT)
// Return value: rax (interpreted as a guest VA pointing at the reply
// struct, or 0 on failure / unrecognized code).
extern "C" uint64_t chamber_shim_vmmcall(uint64_t rax_code,
                                         uint64_t rbx_magic,
                                         uint64_t rcx_arg0,
                                         uint64_t rdx_arg1);

// SEH wrapper so a misfire (#UD on a host without the HV loaded) does
// not take the host process down. Returns 0 on fault.
static uint64_t safe_vmmcall(uint64_t code, uint64_t rbx,
                             uint64_t rcx, uint64_t rdx)
{
    __try {
        return chamber_shim_vmmcall(code, rbx, rcx, rdx);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// --- per-surface handlers ------------------------------------------------

static uint64_t on_query_system_info(uint64_t return_value,
                                     uint64_t return_rip)
{
    // The syscall-return path for NtQuerySystemInformation already left
    // us with the kernel-populated output buffer. The kernel-side IC
    // dispatch at this point is: if the buffer carries a payload the
    // fingerprint driver rewrites (DMI / CI / SecureBoot / WDAC), the
    // CM filter already mutated the buffer in place on the way back
    // through NtQueryValueKey or the Nt syscall epilogue. The shim's
    // job is to confirm with the kernel that no further rewrite is
    // needed, and to let the kernel override the return status if the
    // rewrite is gated on a toggle the per-process arming already
    // cleared.
    (void)return_rip;

    CHAMBER_SHIM_REWRITE_REQ req{};
    req.cookie       = GetCurrentThreadId();
    req.sysnum       = CHAMBER_SHIM_SURF_NT_QUERY_SYSTEM_INFO;
    req.return_value = return_value;
    // The info-class was the syscall's first argument. The shim's
    // prologue pins rcx (the Nt call's first arg) into gs:[0x1488]
    // alongside the sysnum stash at gs:[0x1480].
    req.args[0] = __readgsqword(0x1488);

    uint64_t reply_addr = safe_vmmcall(
        CHAMBER_HCALL_REWRITE_RESULT,
        CHAMBER_SHIM_HYPERCALL_MAGIC,
        reinterpret_cast<uint64_t>(&req),
        0);
    if (reply_addr == 0) {
        return return_value;
    }
    auto *reply = reinterpret_cast<CHAMBER_SHIM_REWRITE_REPLY *>(reply_addr);
    if (reply->cookie != req.cookie) {
        return return_value;
    }
    return reply->new_return;
}

static uint64_t on_query_value_key(uint64_t return_value,
                                   uint64_t return_rip)
{
    // CmRegisterCallbackEx already rewrote the key's reported value on
    // the way back. The only reason to call into the kernel here is to
    // let an operator toggle request a status rewrite (e.g. report
    // STATUS_OBJECT_NAME_NOT_FOUND for a path the arming toggle hides
    // entirely). The default behaviour is pass-through.
    (void)return_rip;

    CHAMBER_SHIM_REWRITE_REQ req{};
    req.cookie       = GetCurrentThreadId();
    req.sysnum       = CHAMBER_SHIM_SURF_NT_QUERY_VALUE_KEY;
    req.return_value = return_value;

    uint64_t reply_addr = safe_vmmcall(
        CHAMBER_HCALL_REWRITE_RESULT,
        CHAMBER_SHIM_HYPERCALL_MAGIC,
        reinterpret_cast<uint64_t>(&req),
        0);
    if (reply_addr == 0) {
        return return_value;
    }
    auto *reply = reinterpret_cast<CHAMBER_SHIM_REWRITE_REPLY *>(reply_addr);
    if (reply->cookie != req.cookie) {
        return return_value;
    }
    return reply->new_return;
}

static uint64_t on_device_ioctl(uint64_t return_value, uint64_t return_rip)
{
    // Storage / NDIS IOCTL payloads were rewritten by the kernel's
    // syscall_rewrite_device_ioctl path on the way back. The shim
    // forwards the return value to the kernel so the per-IOCTL rewrite
    // toggles can surface here; otherwise we pass through.
    (void)return_rip;

    CHAMBER_SHIM_REWRITE_REQ req{};
    req.cookie       = GetCurrentThreadId();
    req.sysnum       = CHAMBER_SHIM_SURF_NT_DEVICE_IO_CONTROL_FILE;
    req.return_value = return_value;

    uint64_t reply_addr = safe_vmmcall(
        CHAMBER_HCALL_REWRITE_RESULT,
        CHAMBER_SHIM_HYPERCALL_MAGIC,
        reinterpret_cast<uint64_t>(&req),
        0);
    if (reply_addr == 0) {
        return return_value;
    }
    auto *reply = reinterpret_cast<CHAMBER_SHIM_REWRITE_REPLY *>(reply_addr);
    if (reply->cookie != req.cookie) {
        return return_value;
    }
    return reply->new_return;
}

// --- top-level dispatch --------------------------------------------------

extern "C" uint64_t chamber_shim_dispatch(uint64_t return_value,
                                          uint64_t return_rip,
                                          uint32_t sysnum)
{
    if (sysnum >= 4096) {
        return return_value;   // outside the surface-tag table
    }
    uint8_t tag = g_sysnum_to_surface[sysnum];
    switch (tag) {
    case CHAMBER_SHIM_SURF_NT_QUERY_SYSTEM_INFO:
        return on_query_system_info(return_value, return_rip);
    case CHAMBER_SHIM_SURF_NT_QUERY_VALUE_KEY:
        return on_query_value_key(return_value, return_rip);
    case CHAMBER_SHIM_SURF_NT_DEVICE_IO_CONTROL_FILE:
        return on_device_ioctl(return_value, return_rip);
    default:
        // Not a targeted syscall. Pass through; the trampoline will
        // write this back into rcx and `jmp r10` to the caller.
        return return_value;
    }
}

// --- DllMain ------------------------------------------------------------

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        // Nothing to do on attach beyond keeping the DLL loaded. The
        // launcher's injector binds syscall numbers via
        // chamber_shim_bind_sysnum before any syscall site detours in.
        // The shim intentionally does NOT walk ntdll from its own
        // DllMain: a resolver stuck inside the loader lock has bitten
        // this shape of hook in the past.
    }
    return TRUE;
}
