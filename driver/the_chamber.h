/* the_chamber.h -- shared header for the THE_CHAMBER AMD SVM ring-0
 * instrumentation driver. Declares IOCTL codes, global state, and the
 * canonical structures the SVM/NPT/VMEXIT clusters fill in.
 *
 * All ring-0; must be built with WDK kernel headers only.
 */

#ifndef THE_CHAMBER_H
#define THE_CHAMBER_H

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>

#define THE_CHAMBER_POOL_TAG  'nMvH'   /* pool tag reads as "HvMn" in poolmon */
#define THE_CHAMBER_DEVICE_NAME  L"\\Device\\WinHvMon"
#define THE_CHAMBER_SYMLINK      L"\\DosDevices\\WinHvMon"
#define THE_CHAMBER_MARKER_PATH  L"\\??\\C:\\Windows\\System32\\config\\winhvmon.dat"

#define THE_CHAMBER_VERSION  0x00010000UL  /* 1.0.0 */
#define WATCHDOG_TIMEOUT_MS  60000

/* IOCTL control codes (device type 0x8000, method buffered, any access) */
#define IOCTL_THE_CHAMBER_STATUS    CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THE_CHAMBER_KICK      CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_THE_CHAMBER_SHUTDOWN  CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _CHAMBER_STATUS {
    ULONG   version;
    ULONG   cpu_count;
    ULONG   active_cpus;
    ULONG   reserved;
    ULONGLONG vmexit_count;
} CHAMBER_STATUS, *PCHAMBER_STATUS;

/* --- Canonical AMD SVM types --- */
/* The SVM cluster (svm.h) fills in the exact layouts per AMD manual Vol 2
 * Ch 15. We forward-declare them here so the_chamber.c and the IOCTL layer
 * can hold typed pointers without needing the full definitions. */

typedef struct _VMCB_CONTROL_AREA    VMCB_CONTROL_AREA;
typedef struct _VMCB_STATE_SAVE_AREA VMCB_STATE_SAVE_AREA;
typedef struct _VMCB                 VMCB;

#define CHAMBER_GPR_COUNT 16   /* rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8..r15 */

typedef struct _PER_CPU_CTX {
    PVOID       vmcb_va;
    ULONGLONG   vmcb_pa;
    PVOID       host_save_va;
    ULONGLONG   host_save_pa;
    PVOID       host_stack_va;
    SIZE_T      host_stack_size;
    ULONG       cpu_index;
    volatile LONG shutdown_requested;
    BOOLEAN     active;
    UCHAR       reserved[7];
    /* Shadow GPR save area, written by vmrun.asm after each VMEXIT and
     * consumed by handle_cpuid/handle_msr. Layout:
     *  0=rax, 1=rbx, 2=rcx, 3=rdx, 4=rsi, 5=rdi, 6=rbp, 7=rsp(unused),
     *  8=r8 ..15=r15.
     * Offset 64 (0x40); 16 x 8 = 128 bytes, ends at 192 (0xC0). */
    ULONGLONG   gpr_save[CHAMBER_GPR_COUNT];
    /* NEW in Phase 1.2: host-only interval TSC captures.
     * vmrun.asm writes host_interval_start right after `vmrun rax` returns
     * (before `vmsave`) and host_interval_end immediately before the next
     * `vmrun rax` (after the handler and any vmload). timing_update()
     * reads their difference, adds the calibrated fixed-vmexit microcode
     * cost, and refreshes the VMCB tsc_offset from the shared global
     * accumulator. Offsets 192/200 MUST match the TIMING_HOST_INTERVAL_START
     * / TIMING_HOST_INTERVAL_END EQUs in vmrun.asm. */
    ULONGLONG   host_interval_start;    /* offset 192 (0xC0) */
    ULONGLONG   host_interval_end;      /* offset 200 (0xC8) */
} PER_CPU_CTX, *PPER_CPU_CTX;

typedef struct _CHAMBER_GLOBALS {
    PDRIVER_OBJECT   driver_object;
    PDEVICE_OBJECT   device_object;
    KTIMER           watchdog_timer;
    KDPC             watchdog_dpc;
    KSPIN_LOCK       state_lock;
    volatile LONG    unload_requested;
    volatile LONG    kick_counter;
    LARGE_INTEGER    last_kick_time;
    BOOLEAN          svm_initialized;
    BOOLEAN          npt_initialized;
} CHAMBER_GLOBALS, *PCHAMBER_GLOBALS;

/* --- Externs implemented by the SVM/NPT/VMEXIT clusters --- */
extern PER_CPU_CTX *g_cpu_ctx;
extern ULONG        g_cpu_count;
extern volatile ULONGLONG g_vmexit_count;
extern ULONGLONG    g_npt_cr3_pa;

NTSTATUS svm_init_all_cpus(void);
NTSTATUS svm_shutdown_all_cpus(void);
BOOLEAN  svm_is_supported(void);

NTSTATUS npt_init(void);
void     npt_free_tables(void);

void     vmexit_cleanup(void);

/* Global driver state */
extern CHAMBER_GLOBALS g_chamber;

#endif /* THE_CHAMBER_H */
