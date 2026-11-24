; asm_helpers.asm -- small assembly thunks the C code cannot express.
;
; MSVC x64 does not provide inline asm and has no __svm_vmmcall intrinsic
; that controls RAX and RBX simultaneously. This file holds the kernel-side
; VMMCALL emitters that the HV's own guest-side threads use to hand off to
; the root-context handler.

.code

PUBLIC chamber_emit_integrity_vmmcall
PUBLIC svm_read_es
PUBLIC svm_read_cs
PUBLIC svm_read_ss
PUBLIC svm_read_ds
PUBLIC svm_read_fs
PUBLIC svm_read_gs
PUBLIC svm_read_ldtr
PUBLIC svm_read_tr

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

; Segment-selector readers — MSVC has no intrinsic for reading segment
; registers, so svm_vmcb.c calls these to populate the VMCB save area at
; CPU bring-up time. Return value in AX; zero-extended to RAX per the
; `USHORT` C signature. All of these are safe to call at any IRQL on
; the current CPU.

svm_read_es PROC
    xor  rax, rax
    mov  ax, es
    ret
svm_read_es ENDP

svm_read_cs PROC
    xor  rax, rax
    mov  ax, cs
    ret
svm_read_cs ENDP

svm_read_ss PROC
    xor  rax, rax
    mov  ax, ss
    ret
svm_read_ss ENDP

svm_read_ds PROC
    xor  rax, rax
    mov  ax, ds
    ret
svm_read_ds ENDP

svm_read_fs PROC
    xor  rax, rax
    mov  ax, fs
    ret
svm_read_fs ENDP

svm_read_gs PROC
    xor  rax, rax
    mov  ax, gs
    ret
svm_read_gs ENDP

; LDTR and TR need sldt / str — plain `mov ax, ldtr` is not an encoding.
svm_read_ldtr PROC
    xor  rax, rax
    sldt ax
    ret
svm_read_ldtr ENDP

svm_read_tr PROC
    xor  rax, rax
    str  ax
    ret
svm_read_tr ENDP

END
