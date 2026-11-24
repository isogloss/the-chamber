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
;   FXRSTOR64 ctx.fxsave    ; restore guest FPU BEFORE capturing END so the
;                           ;   fxrstor latency is inside (END - START),
;                           ;   not leaking into guest-visible RDTSC.
;   capture TIMING_HOST_INTERVAL_END
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
; CALL (so rsp mod 16 == 8 inside the callee).  The vmrun loop runs on the
; dedicated 16 KiB per-CPU host stack (allocated in svm_preallocate_cpu).
; host_stack_top is 16-byte aligned; after sub rdx,16 for the ctx+scratch
; frame, rsp%16 == 0 at the top of host_vmexit_loop.  `sub rsp,32` (shadow
; space) keeps rsp%16 == 0 at each CALL.

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

; svm_launch(PER_CPU_CTX *ctx /*rcx*/, PVOID host_stack_top /*rdx*/)
svm_launch PROC
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    ; Allocate guest-wake frame on the CALLER'S stack:
    ;   [caller_rsp + 0] = ctx pointer
    ;   [caller_rsp + 8] = scratch (unused on guest-side wake)
    ; The guest wakes here via guest_entry_point, which unwinds this
    ; frame and the 8 non-volatiles then rets to svm_launch's caller.
    sub rsp, 16
    mov [rsp], rcx                      ; [caller-80] = ctx
    mov qword ptr [rsp + 8], 0
    mov rax, [rcx + VMCB_PA_OFFSET]     ; rax = guest vmcb_pa

    pushfq
    pop r8
    mov [rax + 400h + 170h], r8         ; VMCB.save.rflags
    lea r8, guest_entry_point
    mov [rax + 400h + 178h], r8         ; VMCB.save.rip = guest resume point
    mov r8, rsp
    mov [rax + 400h + 1D8h], r8         ; VMCB.save.rsp = caller rsp - 16

    ; Switch rsp to the dedicated host stack BEFORE CLGI/VMRUN so
    ; VM_HSAVE_PA.host_rsp saves a pointer into HV-owned memory. The
    ; caller's kernel stack is only safe while the caller's thread is
    ; executing in it; once DriverEntry's load thread returns it the OS
    ; reclaims the memory for other calls. The vmrun loop runs on the
    ; dedicated stack forever; host_done halts the CPU because the
    ; caller is in guest mode by then and cannot be returned to.
    ; Reserve a 16-byte ctx+scratch frame on the dedicated stack.
    sub rdx, 16                         ; rdx = host_stack_top - 16
    mov [rdx], rcx                      ; dedicated [rsp] = ctx
    mov qword ptr [rdx + 8], 0          ; dedicated scratch init
    mov rsp, rdx                        ; switch stacks

    ; Defensive LFENCE-serializing enablement.  DE_CFG (0xC0011029) bit 1
    ; makes LFENCE dispatch-serializing on AMD Zen; modern Windows sets
    ; this at boot, but re-setting it per-CPU here guarantees the TSC
    ; fences below actually serialize rather than silently permit OOO
    ; execution to straddle RDTSC.  Idempotent read-modify-write; preserved
    ; across the loop lifetime of this CPU.
    push rax
    push rcx
    push rdx
    mov ecx, 0C0011029h                 ; DE_CFG
    rdmsr
    or eax, 2                           ; set bit 1 (LFENCE serializing)
    wrmsr
    pop rdx
    pop rcx
    pop rax

    clgi

host_vmexit_loop:
    ; rsp = top of ctx frame on dedicated host stack.  rsp%16 == 0.
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
    ; LFENCE before AND after RDTSC: the pre-fence prevents older
    ; speculative work from retiring into the TSC sample; the post-fence
    ; prevents younger dispatch (shl/or/mov) from being reordered ahead of
    ; the TSC read and inflating the captured timestamp with instructions
    ; that haven't logically executed yet.  Both are needed to kill
    ; speculative jitter around the sample.
    push rax                            ; [rsp]=guest vmcb_pa; rsp%16=8
    lfence
    rdtsc
    lfence
    shl rdx, 32
    or rax, rdx
    mov [r15 + TIMING_HOST_INTERVAL_START], rax
    pop rax                             ; rsp%16=0; rax=guest vmcb_pa

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

    ; FXSAVE64 to the 16-byte-aligned per-CPU scratch area.  Sufficient
    ; for the integer-only vmexit_handler path.  If a future handler
    ; emits YMM via SIMD intrinsics, upgrade to xsave64 against XCR0
    ; and resize the save area per CPUID 0xD.0.
    lea rax, [r15 + FXSAVE_AREA]
    fxsave64 [rax]

    mov rcx, r15                        ; first arg = ctx
    sub rsp, 32                         ; shadow space (rsp%16 0->0 at CALL)
    call vmexit_handler
    add rsp, 32

    mov r15, [rsp]                      ; reload ctx

    mov eax, dword ptr [r15 + SHUTDOWN_REQ_OFFSET]
    test eax, eax
    jnz host_done

    ; FXRSTOR64 BEFORE the END capture: the restore latency varies with
    ; guest FPU state (empty FXSAVE area fast-pathed vs full 512-byte
    ; replay), and was previously outside the (END - START) bracket,
    ; leaking that variance to guest-visible RDTSC.  Doing the restore
    ; here folds the latency into the measured interval so timing_update
    ; sees it.  Guest GPRs are still in ctx->gpr_save; reload happens
    ; below.
    lea rax, [r15 + FXSAVE_AREA]
    fxrstor64 [rax]

    ; Capture END BEFORE timing_update so END and START are matched from
    ; the same iteration (if END followed timing_update, END would pair
    ; with the NEXT iteration's START and timing.c's END<START guard
    ; would fire every call).  timing_update's own cycles plus the GPR
    ; reload sled are charged to g_timing_tail_cycles in timing.c.
    ; Pre- AND post-RDTSC lfences bracket the sample to kill speculative
    ; jitter from either side.
    lfence
    rdtsc
    lfence
    shl rdx, 32
    or rax, rdx
    mov [r15 + TIMING_HOST_INTERVAL_END], rax

    mov rcx, r15                        ; first arg = ctx
    sub rsp, 32                         ; shadow space (rsp%16 0->0 at CALL)
    call timing_update
    add rsp, 32
    mov r15, [rsp]                      ; reload ctx after call

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
    ; Shutdown path. We are on the dedicated host stack; the caller is
    ; in guest mode on its own thread stack and cannot be returned to
    ; from here. Clear EFER.SVME on this CPU and halt. A proper clean
    ; unload would require a per-CPU HV thread that can rendezvous on
    ; a signal; that is a later phase. Shutdown today is one-way.
    stgi
    mov ecx, 0C0000080h                 ; EFER
    rdmsr
    btr eax, 12                         ; clear SVME bit
    wrmsr
    cli
host_halt_loop:
    hlt
    jmp host_halt_loop

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
