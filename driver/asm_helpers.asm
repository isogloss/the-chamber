; asm_helpers.asm -- small assembly thunks the C code cannot express.
;
; MSVC x64 does not provide inline asm and has no __svm_vmmcall intrinsic
; that controls RAX and RBX simultaneously. This file holds the kernel-side
; VMMCALL emitters that the HV's own guest-side threads use to hand off to
; the root-context handler.

.code

PUBLIC chamber_emit_integrity_vmmcall

; void chamber_emit_integrity_vmmcall(ULONG code /*rcx*/, ULONGLONG magic /*rdx*/)
;
; MS x64 fastcall: first integer arg in RCX, second in RDX.
; VMMCALL dispatch protocol: RAX = hypercall code, RBX = magic. RBX is
; non-volatile, save and restore.
chamber_emit_integrity_vmmcall PROC
    push rbx
    mov  rax, rcx
    mov  rbx, rdx
    vmmcall
    pop  rbx
    ret
chamber_emit_integrity_vmmcall ENDP

END
