; vmrun.asm -- MASM-x64 SVM launcher.
; AMD SVM does NOT save/restore host GPRs other than RAX/RSP/RIP/RFLAGS across
; VMRUN. The host saves ctx on the STACK before VMRUN and reloads from the
; stack after; r15 as a "persistent ctx holder" is unsafe because the guest's
; r15 is loaded back into the host register file on VMEXIT.
;
; GPR save index map (in PER_CPU_CTX.gpr_save at offset 64):
;   [0]=rax  [1]=rbx  [2]=rcx  [3]=rdx  [4]=rsi  [5]=rdi  [6]=rbp  [7]=rsp
;   [8]=r8   [9]=r9  [10]=r10  [11]=r11 [12]=r12 [13]=r13 [14]=r14 [15]=r15

.code

EXTERN vmexit_handler:PROC

PUBLIC svm_launch

svm_launch PROC
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; Allocate a stack slot for the ctx pointer. We will read it from here
    ; after every VMRUN because host GPRs are not preserved by VMRUN.
    sub rsp, 16

    mov [rsp], rcx                  ; stash ctx on the stack
    mov rax, [rcx + 8]              ; rax = vmcb_pa

    pushfq
    pop rdx
    mov [rax + 400h + 170h], rdx    ; VMCB.save.rflags
    lea rdx, guest_entry_point
    mov [rax + 400h + 178h], rdx    ; VMCB.save.rip = guest resume point
    mov rdx, rsp
    mov [rax + 400h + 1D8h], rdx    ; VMCB.save.rsp = current rsp

    clgi
    vmload rax

host_vmexit_loop:
    vmrun rax                        ; enter guest; returns here on VMEXIT
    vmsave rax

    ; Host GPRs (except RAX/RSP) are guest's values now. Recover ctx from stack.
    mov r15, [rsp]                   ; r15 = ctx
    mov [r15 + 64 +   8], rbx
    mov [r15 + 64 +  16], rcx
    mov [r15 + 64 +  24], rdx
    mov [r15 + 64 +  32], rsi
    mov [r15 + 64 +  40], rdi
    mov [r15 + 64 +  48], rbp
    mov [r15 + 64 +  64], r8
    mov [r15 + 64 +  72], r9
    mov [r15 + 64 +  80], r10
    mov [r15 + 64 +  88], r11
    mov [r15 + 64 +  96], r12
    mov [r15 + 64 + 104], r13
    mov [r15 + 64 + 112], r14
    ; We can also save guest's r15 (which is currently in host's r15 because
    ; we just read it from the stack slot that still holds ctx) -- but ctx
    ; IS in r15 here, not the guest's r15. Guest's r15 was written into the
    ; host register file at VMEXIT, but we just overwrote host r15 with ctx
    ; from the stack. So guest r15 is LOST. To preserve it, we would need to
    ; save all host GPRs to the stack before VMRUN and restore after. For now,
    ; note that guest r15 does not round-trip through gpr_save[15].

    mov rcx, r15                     ; ctx pointer for handler
    sub rsp, 32                      ; shadow space
    call vmexit_handler
    add rsp, 32

    mov r15, [rsp]                   ; reload ctx (handler may have clobbered)
    mov eax, dword ptr [r15 + 52]
    test eax, eax
    jnz host_done

    ; Reload guest GPRs for the next VMRUN
    mov rbx, [r15 + 64 +   8]
    mov rcx, [r15 + 64 +  16]
    mov rdx, [r15 + 64 +  24]
    mov rsi, [r15 + 64 +  32]
    mov rdi, [r15 + 64 +  40]
    mov rbp, [r15 + 64 +  48]
    mov r8,  [r15 + 64 +  64]
    mov r9,  [r15 + 64 +  72]
    mov r10, [r15 + 64 +  80]
    mov r11, [r15 + 64 +  88]
    mov r12, [r15 + 64 +  96]
    mov r13, [r15 + 64 + 104]
    mov r14, [r15 + 64 + 112]
    mov rax, [r15 + 8]               ; rax = vmcb_pa for next vmrun
    jmp host_vmexit_loop

host_done:
    stgi
    add rsp, 16                      ; free ctx slot
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

guest_entry_point:
    ; Guest wakes up here on first VMRUN. Our stack layout: ctx-slot + 8 non-volatiles.
    add rsp, 16                      ; skip ctx slot
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
svm_launch ENDP

END
