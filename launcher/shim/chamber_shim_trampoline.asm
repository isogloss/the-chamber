; chamber_shim_trampoline.asm -- the user-mode landing stub the
; kernel's InstrumentationCallback path jumps to on every syscall
; return. This is the shim DLL's exported entry point; it mirrors the
; kernel-signed reference copy in
; driver/fingerprint/ic_trampoline.asm byte-for-byte on the register
; contract, so the two stay in step if either is updated.
;
; On entry (set by the kernel's syscall-return path -- see
; nt!KiRaiseUserExceptionDispatcher and the IC dispatch sequence in
; Windows Internals 7e Ch 8):
;
;     rcx = syscall return value as the caller would see it
;     rsp = user-mode stack of the calling thread (NOT guaranteed
;           16-aligned at entry)
;     r10 = real user return RIP (the instruction after the syscall
;           site) -- MUST be preserved verbatim
;     rax = scratch
;     r11 = scratch (RFLAGS was in r11 just before syscall; opaque now)
;
; The shim's own detour prologue, injected one time per thread at
; attach, is responsible for stashing the syscall number into
; gs:[0x1480] and (for NtQuerySystemInformation) its first argument
; into gs:[0x1488] before transferring to the kernel. The trampoline
; here reloads both when it needs them.

.CODE

EXTRN chamber_shim_dispatch:PROC

PUBLIC chamber_shim_trampoline
PUBLIC chamber_shim_vmmcall

; void chamber_shim_trampoline(void)
chamber_shim_trampoline PROC
        ; --- save state. 11 x 8 = 88 bytes. Stack now rsp-88. ---
        push    r11
        push    r10
        push    r9
        push    r8
        push    rdx
        push    rcx                     ; [1] syscall return value lives here
        push    rax
        push    rbx
        push    rsi
        push    rdi
        push    rbp
        mov     rbp, rsp                ; frame anchor for easy teardown

        ; --- align rsp to 16, reserve 32-byte shadow space. ---
        and     rsp, -16
        sub     rsp, 32                 ; x64 ABI shadow space

        ; --- marshal args for chamber_shim_dispatch(ret, return_rip,
        ;     sysnum). Offsets from rbp match ic_trampoline.asm.
        ;   [rbp +  0] rbp     [rbp +  8] rdi    [rbp + 16] rsi
        ;   [rbp + 24] rbx     [rbp + 32] rax    [rbp + 40] rcx <- ret
        ;   [rbp + 48] rdx     [rbp + 56] r8     [rbp + 64] r9
        ;   [rbp + 72] r10 <- user return RIP
        ;   [rbp + 80] r11
        mov     rcx, qword ptr [rbp + 40]   ; syscall return value
        mov     rdx, qword ptr [rbp + 72]   ; user return RIP
        mov     r8d, dword ptr gs:[1480h]   ; shim-stashed syscall number
        call    chamber_shim_dispatch

        ; --- write rewritten return value back into saved rcx slot. ---
        mov     qword ptr [rbp + 40], rax

        ; --- teardown. ---
        mov     rsp, rbp
        pop     rbp
        pop     rdi
        pop     rsi
        pop     rbx
        pop     rax
        pop     rcx                     ; rewritten return value
        pop     rdx
        pop     r8
        pop     r9
        pop     r10                     ; real user return RIP
        pop     r11
        jmp     r10                     ; resume the caller
chamber_shim_trampoline ENDP

; uint64_t chamber_shim_vmmcall(uint64_t rax_code, uint64_t rbx_magic,
;                               uint64_t rcx_arg0, uint64_t rdx_arg1);
;
; Microsoft x64 calling convention:
;   rcx = rax_code
;   rdx = rbx_magic
;   r8  = rcx_arg0
;   r9  = rdx_arg1
;
; We rename those into the AMD-SVM VMMCALL contract and fire. The HV
; dispatcher checks rbx against THE_CHAMBER_HYPERCALL_MAGIC first; a
; mismatch raises #UD, which the C-side SEH handler catches.
chamber_shim_vmmcall PROC
        ; Preserve rbx (callee-saved per MS x64 ABI).
        push    rbx

        mov     rax, rcx         ; hypercall code
        mov     rbx, rdx         ; shared-secret magic
        mov     rcx, r8          ; arg0 (request VA)
        mov     rdx, r9          ; arg1

        vmmcall                  ; AMD-SVM only; #UD on bare metal
                                 ; without the HV, which the caller
                                 ; wraps in __try/__except.

        ; Return value comes back in rax as a guest VA (reply struct)
        ; or 0 for unrecognized / unauthorized.

        pop     rbx
        ret
chamber_shim_vmmcall ENDP

END
