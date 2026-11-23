; ic_trampoline.asm -- x64 landing stub for the per-process
; InstrumentationCallback path.
;
; This file is the KERNEL-SIDE skeleton of the ASM stub that would be
; mapped into every spoofed process's user space by the launcher's ntdll
; shim. It documents the exact register state the kernel delivers on a
; syscall-return detour and the save/restore contract the C rewrite
; handlers rely on. The user-mode shim calls this symbol by relative VA
; after copying the trampoline page into the target.
;
; Kernel contract (see Windows Internals 7e, Ch 8, and Alex Ionescu's
; "Esoteric Hooks"):
;
;   On syscall-return detour, the kernel does roughly:
;     mov r10, rcx         ; preserve the return RIP (user-mode syscall site)
;     jmp  KPROCESS.InstrumentationCallback
;
;   Register state at the trampoline entry:
;     rcx   = syscall return value (as if the caller already got it)
;     rsp   = user-mode stack of the calling thread
;     r10   = real user-mode return RIP (the instruction after the syscall site)
;     rax   = scratch
;     all other GPRs = whatever the syscall left them as
;
;   The trampoline MUST at the end: `jmp r10` to resume the caller, with
;   rcx set to whatever return value the caller should see. We intercept
;   rcx on the way through and rewrite it when the syscall matches one
;   our C handler cares about; otherwise we pass rcx through unchanged.
;
;   This file is kernel-signed and lives in the driver purely so the
;   contract stays alongside the C handlers. At runtime the mapped copy
;   lives in user memory — the kernel driver never calls this label.

.CODE

PUBLIC cfp_ic_trampoline

; void cfp_ic_trampoline(void)
;   Register inputs described above.
;   Jumps to r10 at the end; never returns through the stack.

cfp_ic_trampoline PROC
        ; Preserve volatile state the C handler might clobber.
        ; We save on the user stack with a 160-byte shadow + argbuf.
        push    rax
        push    rcx
        push    rdx
        push    r8
        push    r9
        push    r10
        push    r11
        sub     rsp, 128                ; red zone + 16-byte shadow + arg space
        and     rsp, -16                ; align

        ; Call the C dispatcher. It receives:
        ;   rcx = syscall return value
        ;   rdx = r10 (real return RIP) — the handler uses this to look
        ;         up which syscall we just came back from by walking the
        ;         preceding page for a `syscall` opcode marker
        ;   r8  = original rax at syscall entry (passed as rbx spill via
        ;         the shim's prologue; see shim.c once that lands)
        ;
        ; Returns the new value in rax; we write it back to the stashed
        ; rcx slot so the pop sequence delivers it.
        mov     rdx, r10
        ; rcx is already the return value; keep it.
        ; r8 left as-is (the ntdll shim writes it before jumping here).
        extern  cfp_ic_dispatch:PROC
        call    cfp_ic_dispatch

        ; rax now carries the rewritten return value (or the original).
        ; Patch the stashed rcx slot.
        mov     qword ptr [rsp + 128 + 8*2 + (16 - ((rsp) and 15))], rax
        ; (The complex offset is computed at assemble time by the shim's
        ; final link; keep it symbolic here — the production shim is a
        ; follow-up that regenerates this offset against the actual
        ; prologue it chose.)

        ; Tear down scratch.
        mov     rsp, rbp
        pop     r11
        pop     r10
        pop     r9
        pop     r8
        pop     rdx
        pop     rcx                     ; rewritten return value
        pop     rax
        jmp     r10                     ; resume at the real user return RIP
cfp_ic_trampoline ENDP

END
