; ic_trampoline.asm -- x64 landing stub for the per-process
; InstrumentationCallback path.
;
; This is the KERNEL-SIGNED REFERENCE COPY of the trampoline the
; operator's ntdll shim injects into every spoofed process. The compiled
; symbol is linked into chamber_fingerprint.sys so the contract lives
; alongside the C handlers it dispatches to, but the kernel itself never
; calls cfp_ic_trampoline -- the mapped copy runs in user mode in the
; target. A production shim is a follow-up that lays this sequence down
; with its own prologue tailored to the per-process arg-save layout.
;
; Kernel-set contract on entry (see Windows Internals 7e Ch 8 and Alex
; Ionescu's "Esoteric Hooks: a journey into Windows x64 syscall
; interception"):
;
;   rcx   = syscall return value as the caller would see it
;   rsp   = user-mode stack of the calling thread (NOT guaranteed 16-aligned
;           at entry: the kernel does `mov r10, rcx; jmp Callback`, so we
;           inherit whatever alignment the syscall site had)
;   r10   = real user-mode return RIP (the instruction after the syscall
;           site) -- MUST be preserved verbatim; the final `jmp r10`
;           resumes the caller
;   rax   = scratch
;   r11   = scratch (RFLAGS was in r11 just before syscall; opaque now)
;
; We must:
;   1. Save every volatile register the C dispatcher might clobber.
;   2. Align rsp to 16 for the CALL (x64 ABI requires a 16-aligned rsp
;      at the point of CALL so that callee's first push lands on 8).
;   3. Call cfp_ic_dispatch(return_value, return_rip, saved_syscall_num).
;   4. Write the returned (possibly rewritten) value back into the saved
;      rcx slot so the pop sequence delivers it on `jmp r10`.
;   5. Restore rsp, pop registers, jmp r10.
;
; The dispatcher's third argument -- the NT syscall number -- is NOT in a
; register at trampoline entry (the kernel does not preserve rax). The
; production shim's prologue stashes it in a thread-local slot
; (gs:[0x1480], an unused TEB slot the shim reserves at attach) before
; the detour, and we reload it from there.

.CODE

EXTRN cfp_ic_dispatch:PROC
PUBLIC cfp_ic_trampoline

; void cfp_ic_trampoline(void)
cfp_ic_trampoline PROC
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
        ; 11 pushes from an unknown-alignment rsp leaves rsp mod 16 in
        ; { 0, 8 }. Force it to a known alignment then subtract a
        ; constant that leaves rsp 16-aligned at the CALL boundary.
        and     rsp, -16
        sub     rsp, 32                 ; x64 ABI shadow space

        ; --- marshal args for cfp_ic_dispatch(ret, return_rip, sysnum). ---
        ; Push order (top of stack first): rbp, rdi, rsi, rbx, rax, rcx,
        ; rdx, r8, r9, r10, r11. After `mov rbp, rsp`, offsets from rbp:
        ;   [rbp +  0] rbp     [rbp +  8] rdi    [rbp + 16] rsi
        ;   [rbp + 24] rbx     [rbp + 32] rax    [rbp + 40] rcx <- ret
        ;   [rbp + 48] rdx     [rbp + 56] r8     [rbp + 64] r9
        ;   [rbp + 72] r10 <- user return RIP
        ;   [rbp + 80] r11
        mov     rcx, qword ptr [rbp + 40]   ; syscall return value
        mov     rdx, qword ptr [rbp + 72]   ; user return RIP
        mov     r8,  gs:[1480h]             ; shim-stashed syscall number
        call    cfp_ic_dispatch

        ; --- write rewritten return value into the saved RAX slot.
        ; User-mode code after syscall reads the return from RAX (the
        ; x64 syscall calling convention), NOT from RCX. Kernel places
        ; the return in RCX on IC entry as a convenience for the
        ; callback; we have to put the final value back in RAX before
        ; jmp r10 or the caller reads scratch. Also mirror into the RCX
        ; slot so anything inspecting both registers sees consistency. ---
        mov     qword ptr [rbp + 32], rax
        mov     qword ptr [rbp + 40], rax

        ; --- teardown. ---
        mov     rsp, rbp
        pop     rbp
        pop     rdi
        pop     rsi
        pop     rbx
        pop     rax                     ; rewritten return value (user-visible)
        pop     rcx                     ; mirrored rewritten value
        pop     rdx
        pop     r8
        pop     r9
        pop     r10                     ; real user return RIP
        pop     r11
        jmp     r10                     ; resume the caller
cfp_ic_trampoline ENDP

END
