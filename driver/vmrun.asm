; vmrun.asm -- MASM-x64 SVM launcher.
;
; Per-iteration state bracket (AMD APM Vol 2 15.5.2 / 15.6):
;   vmsave host_save_pa     ; save host hidden state (TR/LDTR, KernelGsBase,
;                           ; STAR/LSTAR/CSTAR/SFMASK, SYSENTER_*) that VMRUN
;                           ; does NOT auto-save via VM_HSAVE_PA
;   vmload guest_vmcb_pa    ; load guest hidden state from the guest VMCB
;   vmrun  guest_vmcb_pa    ; enter guest
;   vmsave guest_vmcb_pa    ; save guest hidden state back
;   vmload host_save_pa     ; restore host hidden state so the handler runs
;                           ; with host GS.Base / KernelGsBase
;   FXSAVE64 ctx.fxsave     ; preserve x87/SSE across the C handler
;   call   vmexit_handler
;   FXRSTOR64 ctx.fxsave
;   call   timing_update
;
; Guest R15 preservation: on VMEXIT the host register file holds the guest's
; values for every GPR except RAX (in vmcb.save.rax) / RSP (in vmcb.save.rsp)
; / RIP / RFLAGS.  The first host memory access clobbers one register.  To
; keep guest R15, we reserve a second 8-byte scratch slot adjacent to the
; ctx pointer slot and stash guest R15 into it as the first host-side
; write, before using R15 to hold ctx.
;
; Stack alignment: MS x64 ABI requires rsp mod 16 == 0 immediately before
; CALL (so rsp mod 16 == 8 inside the callee).  After 8 pushes (rsp%16=8),
; sub rsp,16 (rsp%16=8), sub rsp,40 (rsp%16=0) aligns correctly.

TIMING_HOST_INTERVAL_START EQU 192          ; offset 0xC0
TIMING_HOST_INTERVAL_END   EQU 200          ; offset 0xC8
FXSAVE_AREA                EQU 256          ; offset 0x100
VMCB_PA_OFFSET             EQU 8            ; PER_CPU_CTX.vmcb_pa
HOST_SAVE_PA_OFFSET        EQU 24           ; PER_CPU_CTX.host_save_pa
SHUTDOWN_REQ_OFFSET        EQU 52           ; PER_CPU_CTX.shutdown_requested
GPR_SAVE_OFFSET            EQU 64           ; PER_CPU_CTX.gpr_save[0]

.code

EXTERN vmexit_handler:PROC
EXTERN timing_update:PROC

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

    ; Allocate 16-byte stack frame:
    ;   [rsp+0] = ctx pointer (host-side authoritative)
    ;   [rsp+8] = guest R15 scratch (written on every VMEXIT)
    ; sub rsp, 16 keeps rsp%16 == 8.
    sub rsp, 16
    mov [rsp], rcx                      ; stash ctx on stack
    mov qword ptr [rsp + 8], 0          ; scratch slot init
    mov rax, [rcx + VMCB_PA_OFFSET]     ; rax = guest vmcb_pa

    pushfq
    pop rdx
    mov [rax + 400h + 170h], rdx        ; VMCB.save.rflags
    lea rdx, guest_entry_point
    mov [rax + 400h + 178h], rdx        ; VMCB.save.rip = guest resume point
    mov rdx, rsp
    mov [rax + 400h + 1D8h], rdx        ; VMCB.save.rsp = current rsp

    clgi

host_vmexit_loop:
    ; rsp = top of ctx frame.  rsp%16 == 8.
    mov r15, [rsp]                      ; r15 = ctx

    ; vmsave host_save_pa: save host hidden state (TR/LDTR, KernelGsBase,
    ; STAR/LSTAR/CSTAR/SFMASK, SYSENTER_*) that VMRUN does not auto-save.
    ; Without this, the C handler runs with guest FS.Base / GS.Base /
    ; KernelGsBase, and any __readgsqword(KPCR) crashes.
    mov rax, [r15 + HOST_SAVE_PA_OFFSET]
    vmsave rax

    ; vmload guest hidden state, then enter guest.
    mov rax, [r15 + VMCB_PA_OFFSET]
    vmload rax
    vmrun rax                           ; guest runs; returns here on VMEXIT

    ; ---- VMEXIT returns here.  Host register file is guest state (except
    ;      rax = guest vmcb_pa preserved by VMRUN, rsp restored by VM_HSAVE). ----

    ; First memory touch: stash guest R15 to scratch slot before it is
    ; clobbered by ctx recovery.
    mov [rsp + 8], r15                  ; scratch = guest R15
    mov r15, [rsp]                      ; r15 = ctx (host authoritative)

    ; Host-interval START captured right after vmrun returns, BEFORE
    ; vmsave + handler.  Preserve guest vmcb_pa in rax across rdtsc.
    push rax                            ; [rsp]=guest vmcb_pa; rsp%16=0
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [r15 + TIMING_HOST_INTERVAL_START], rax
    pop rax                             ; rsp%16=8; rax=guest vmcb_pa

    ; vmsave guest hidden state back; vmload host hidden state for handler.
    vmsave rax                          ; vmsave guest_vmcb_pa
    mov rax, [r15 + HOST_SAVE_PA_OFFSET]
    vmload rax                          ; vmload host_save_pa

    ; Save guest GPRs.  RAX lives in vmcb.save.rax; RSP in vmcb.save.rsp.
    ; Guest R15 is in the scratch slot we just wrote.
    mov [r15 + GPR_SAVE_OFFSET +   8], rbx
    mov [r15 + GPR_SAVE_OFFSET +  16], rcx
    mov [r15 + GPR_SAVE_OFFSET +  24], rdx
    mov [r15 + GPR_SAVE_OFFSET +  32], rsi
    mov [r15 + GPR_SAVE_OFFSET +  40], rdi
    mov [r15 + GPR_SAVE_OFFSET +  48], rbp
    mov [r15 + GPR_SAVE_OFFSET +  64], r8
    mov [r15 + GPR_SAVE_OFFSET +  72], r9
    mov [r15 + GPR_SAVE_OFFSET +  80], r10
    mov [r15 + GPR_SAVE_OFFSET +  88], r11
    mov [r15 + GPR_SAVE_OFFSET +  96], r12
    mov [r15 + GPR_SAVE_OFFSET + 104], r13
    mov [r15 + GPR_SAVE_OFFSET + 112], r14
    mov rax, [rsp + 8]                  ; rax = guest R15 (from scratch)
    mov [r15 + GPR_SAVE_OFFSET + 120], rax

    ; FXSAVE64 to the 16-byte-aligned per-CPU scratch area.  MSVC emits
    ; XMM / YMM against the kernel stack through memcpy, DbgPrintEx
    ; varargs classification, and inline float lowering; without this
    ; save / restore the handler leaks guest x87/SSE state to the host
    ; and corrupts the guest's vector state across the exit.
    lea rax, [r15 + FXSAVE_AREA]
    fxsave64 [rax]

    mov rcx, r15                        ; first arg = ctx
    sub rsp, 40                         ; shadow + 8 pad for 16-byte align
    call vmexit_handler
    add rsp, 40

    mov r15, [rsp]                      ; reload ctx
    lea rax, [r15 + FXSAVE_AREA]
    fxrstor64 [rax]

    mov eax, dword ptr [r15 + SHUTDOWN_REQ_OFFSET]
    test eax, eax
    jnz host_done

    mov rcx, r15                        ; first arg = ctx
    sub rsp, 40                         ; shadow + 8 pad for 16-byte align
    call timing_update
    add rsp, 40
    mov r15, [rsp]                      ; reload ctx after call

    ; Host-interval END captured AFTER timing_update so its own cycles
    ; (locked add, VMCB tsc_offset write, clean-bit clear) are included
    ; in the delta the NEXT iteration adds to g_total_accumulated_cycles.
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov [r15 + TIMING_HOST_INTERVAL_END], rax

    ; Reload guest GPRs for the next VMRUN.  R15 last so ctx access ends.
    mov rbx, [r15 + GPR_SAVE_OFFSET +   8]
    mov rcx, [r15 + GPR_SAVE_OFFSET +  16]
    mov rdx, [r15 + GPR_SAVE_OFFSET +  24]
    mov rsi, [r15 + GPR_SAVE_OFFSET +  32]
    mov rdi, [r15 + GPR_SAVE_OFFSET +  40]
    mov rbp, [r15 + GPR_SAVE_OFFSET +  48]
    mov r8,  [r15 + GPR_SAVE_OFFSET +  64]
    mov r9,  [r15 + GPR_SAVE_OFFSET +  72]
    mov r10, [r15 + GPR_SAVE_OFFSET +  80]
    mov r11, [r15 + GPR_SAVE_OFFSET +  88]
    mov r12, [r15 + GPR_SAVE_OFFSET +  96]
    mov r13, [r15 + GPR_SAVE_OFFSET + 104]
    mov r14, [r15 + GPR_SAVE_OFFSET + 112]
    mov r15, [r15 + GPR_SAVE_OFFSET + 120]
    jmp host_vmexit_loop

host_done:
    stgi
    add rsp, 16                         ; free ctx + scratch slot
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
    ; Guest wakes up here on first VMRUN.  Stack layout: 16-byte ctx+scratch
    ; frame + 8 non-volatiles saved by the host prologue.
    add rsp, 16                         ; skip ctx + scratch slot
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
