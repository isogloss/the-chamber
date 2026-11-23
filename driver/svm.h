/* svm.h -- AMD SVM structures + constants
 * References: AMD64 Architecture Programmer's Manual Vol 2 (System Programming),
 * Chapter 15 (Secure Virtual Machine).
 */
#pragma once
#include "the_chamber.h"

/* MSRs (AMD 15.3, 15.30, APM Vol 2 Appendix) */
#define SVM_MSR_EFER            0xC0000080ULL
#define EFER_SVME               (1ULL << 12)
#define SVM_MSR_VM_CR           0xC0010114ULL
#define VM_CR_SVMDIS            (1ULL << 4)
#define VM_CR_LOCK              (1ULL << 3)
#define SVM_MSR_VM_HSAVE_PA     0xC0010117ULL

/* CPUID (AMD 15.3) */
#define CPUID_EXT_FEATURES      0x80000001U
#define CPUID_SVM_BIT           (1U << 2)            /* ECX bit 2 */
#define CPUID_SVM_REVISION_LEAF 0x8000000AU
#define CPUID_HYPERV_VENDOR_LEAF 0x40000000U

/* VMEXIT codes (AMD 15.7) */
#define VMEXIT_CPUID            0x72ULL
#define VMEXIT_MSR              0x7CULL
#define VMEXIT_VMMCALL          0x81ULL
#define VMEXIT_VMRUN            0x80ULL
#define VMEXIT_NPF              0x400ULL
#define VMEXIT_INVALID          ((ULONGLONG)-1)

/* Intercept bit positions (AMD 15.9) */
/* intercept_vec3 at VMCB offset 0x014 */
#define IVEC3_INTR              (1U <<  0)
#define IVEC3_NMI               (1U <<  1)
#define IVEC3_SMI               (1U <<  2)
#define IVEC3_INIT              (1U <<  3)
#define IVEC3_VINTR             (1U <<  4)
#define IVEC3_CR0_SEL_WRITE     (1U <<  5)
#define IVEC3_IDTR_READ         (1U <<  6)
#define IVEC3_GDTR_READ         (1U <<  7)
#define IVEC3_LDTR_READ         (1U <<  8)
#define IVEC3_TR_READ           (1U <<  9)
#define IVEC3_IDTR_WRITE        (1U << 10)
#define IVEC3_GDTR_WRITE        (1U << 11)
#define IVEC3_LDTR_WRITE        (1U << 12)
#define IVEC3_TR_WRITE          (1U << 13)
#define IVEC3_RDTSC             (1U << 14)
#define IVEC3_RDPMC             (1U << 15)
#define IVEC3_PUSHF             (1U << 16)
#define IVEC3_POPF              (1U << 17)
#define IVEC3_CPUID             (1U << 18)
#define IVEC3_RSM               (1U << 19)
#define IVEC3_IRET              (1U << 20)
#define IVEC3_INTN              (1U << 21)
#define IVEC3_INVD              (1U << 22)
#define IVEC3_PAUSE             (1U << 23)
#define IVEC3_HLT               (1U << 24)
#define IVEC3_INVLPG            (1U << 25)
#define IVEC3_INVLPGA           (1U << 26)
#define IVEC3_IOIO              (1U << 27)
#define IVEC3_MSR               (1U << 28)
#define IVEC3_TASK_SWITCH       (1U << 29)
#define IVEC3_FERR_FREEZE       (1U << 30)
#define IVEC3_SHUTDOWN          (1U << 31)
/* intercept_vec4 at VMCB offset 0x018 */
#define IVEC4_VMRUN             (1U <<  0)
#define IVEC4_VMMCALL           (1U <<  1)
#define IVEC4_VMLOAD            (1U <<  2)
#define IVEC4_VMSAVE            (1U <<  3)
#define IVEC4_STGI              (1U <<  4)
#define IVEC4_CLGI              (1U <<  5)
#define IVEC4_SKINIT            (1U <<  6)
#define IVEC4_RDTSCP            (1U <<  7)
#define IVEC4_ICEBP             (1U <<  8)
#define IVEC4_WBINVD            (1U <<  9)
#define IVEC4_MONITOR           (1U << 10)
#define IVEC4_MWAIT             (1U << 11)
#define IVEC4_MWAIT_COND        (1U << 12)
#define IVEC4_XSETBV            (1U << 13)

/* NP_ENABLE register bits (VMCB offset 0x090, AMD 15.19) */
#define NP_ENABLE               (1ULL << 0)

#pragma pack(push, 1)

/* Segment selector attribute entry for state-save area (AMD Table 15-3). */
typedef struct _VMCB_SEG {
    USHORT      selector;
    USHORT      attrib;
    ULONG       limit;
    ULONGLONG   base;
} VMCB_SEG;

/* Control area -- 1024 bytes. AMD Table 15-1. */
typedef struct _VMCB_CONTROL_AREA {
    /* 0x000 */ ULONG       intercept_cr_read;
    /* 0x004 */ ULONG       intercept_cr_write;
    /* 0x008 */ ULONG       intercept_dr_read;
    /* 0x00C */ ULONG       intercept_dr_write;
    /* 0x010 */ ULONG       intercept_exceptions;
    /* 0x014 */ ULONG       intercept_vec3;
    /* 0x018 */ ULONG       intercept_vec4;
    /* 0x01C */ ULONG       intercept_vec5;
    /* 0x020 */ UCHAR       pad_020[0x03C - 0x020];
    /* 0x03C */ ULONGLONG   iopm_base_pa;
    /* 0x044 */ ULONG       pad_044;
    /* 0x048 */ ULONGLONG   msrpm_base_pa;
    /* 0x050 */ ULONGLONG   tsc_offset;
    /* 0x058 */ ULONG       guest_asid_tlb;
    /* 0x05C */ ULONG       pad_05c;
    /* 0x060 */ ULONGLONG   vintr;
    /* 0x068 */ ULONGLONG   interrupt_shadow;
    /* 0x070 */ ULONGLONG   exit_code;
    /* 0x078 */ ULONGLONG   exit_info_1;
    /* 0x080 */ ULONGLONG   exit_info_2;
    /* 0x088 */ ULONGLONG   exit_int_info;
    /* 0x090 */ ULONGLONG   np_enable;
    /* 0x098 */ UCHAR       pad_098[0x0A8 - 0x098];
    /* 0x0A8 */ ULONGLONG   event_inject;
    /* 0x0B0 */ ULONGLONG   n_cr3;
    /* 0x0B8 */ ULONGLONG   lbr_virtualization;
    /* 0x0C0 */ ULONG       vmcb_clean_bits;
    /* 0x0C4 */ ULONG       pad_0c4;
    /* 0x0C8 */ ULONGLONG   next_rip;
    /* 0x0D0 */ UCHAR       n_bytes_fetched;
    /* 0x0D1 */ UCHAR       guest_bytes[15];
    /* 0x0E0 */ UCHAR       pad_0e0[0x400 - 0x0E0];
} VMCB_CONTROL_AREA;

C_ASSERT(sizeof(VMCB_CONTROL_AREA) == 0x400);

/* State save area -- 1024 bytes at VMCB offset 0x400. AMD Table 15-3. */
typedef struct _VMCB_STATE_SAVE_AREA {
    /* 0x000 */ VMCB_SEG    es;
    /* 0x010 */ VMCB_SEG    cs;
    /* 0x020 */ VMCB_SEG    ss;
    /* 0x030 */ VMCB_SEG    ds;
    /* 0x040 */ VMCB_SEG    fs;
    /* 0x050 */ VMCB_SEG    gs;
    /* 0x060 */ VMCB_SEG    gdtr;
    /* 0x070 */ VMCB_SEG    ldtr;
    /* 0x080 */ VMCB_SEG    idtr;
    /* 0x090 */ VMCB_SEG    tr;
    /* 0x0A0 */ UCHAR       cpl;
    /* 0x0A1 */ UCHAR       pad_0a1[7];
    /* 0x0A8 */ ULONGLONG   efer;
    /* 0x0B0 */ UCHAR       pad_0b0[0x148 - 0x0B0];
    /* 0x148 */ ULONGLONG   cr4;
    /* 0x150 */ ULONGLONG   cr3;
    /* 0x158 */ ULONGLONG   cr0;
    /* 0x160 */ ULONGLONG   dr7;
    /* 0x168 */ ULONGLONG   dr6;
    /* 0x170 */ ULONGLONG   rflags;
    /* 0x178 */ ULONGLONG   rip;
    /* 0x180 */ UCHAR       pad_180[0x1D8 - 0x180];
    /* 0x1D8 */ ULONGLONG   rsp;
    /* 0x1E0 */ UCHAR       pad_1e0[0x1F8 - 0x1E0];
    /* 0x1F8 */ ULONGLONG   rax;
    /* 0x200 */ ULONGLONG   star;
    /* 0x208 */ ULONGLONG   lstar;
    /* 0x210 */ ULONGLONG   cstar;
    /* 0x218 */ ULONGLONG   sfmask;
    /* 0x220 */ ULONGLONG   kernel_gs_base;
    /* 0x228 */ ULONGLONG   sysenter_cs;
    /* 0x230 */ ULONGLONG   sysenter_esp;
    /* 0x238 */ ULONGLONG   sysenter_eip;
    /* 0x240 */ ULONGLONG   cr2;
    /* 0x248 */ UCHAR       pad_248[0x268 - 0x248];
    /* 0x268 */ ULONGLONG   g_pat;
    /* 0x270 */ ULONGLONG   dbgctl;
    /* 0x278 */ ULONGLONG   br_from;
    /* 0x280 */ ULONGLONG   br_to;
    /* 0x288 */ ULONGLONG   last_excp_from;
    /* 0x290 */ ULONGLONG   last_excp_to;
    /* 0x298 */ UCHAR       pad_298[0x400 - 0x298];
} VMCB_STATE_SAVE_AREA;

C_ASSERT(sizeof(VMCB_STATE_SAVE_AREA) == 0x400);

typedef struct _VMCB {
    VMCB_CONTROL_AREA ctl;
    VMCB_STATE_SAVE_AREA save;
} VMCB;

C_ASSERT(sizeof(VMCB) == 0x800);

#pragma pack(pop)

/* PER_CPU_CTX is defined in the_chamber.h and expects vmcb_va as PVOID.
 * We cast where needed inside the SVM/NPT/VMEXIT clusters. */

void     svm_build_vmcb(PER_CPU_CTX *ctx);
void     vmexit_handler(PER_CPU_CTX *ctx);
void     svm_launch(PER_CPU_CTX *ctx);  /* defined in vmrun.asm */
