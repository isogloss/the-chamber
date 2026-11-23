/* the_chamber.h -- shared header for the AMD SVM ring-0 instrumentation
 * driver. Declares IOCTL codes, global state, logging, pool tag, and the
 * canonical structures the SVM/NPT/VMEXIT clusters fill in.
 *
 * All ring-0; must be built with WDK kernel headers only.
 */

#ifndef THE_CHAMBER_H
#define THE_CHAMBER_H

#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>

/* -----------------------------------------------------------------------
 * Phase 1.7: debug-only logging.
 * CHAMBER_LOG expands to DbgPrintEx under CHAMBER_DEBUG; in release the
 * macro collapses to a no-op so the .rdata section carries no branded
 * strings. Replace every DbgPrintEx call with CHAMBER_LOG / _WARN / _ERR.
 * ----------------------------------------------------------------------- */
#ifdef CHAMBER_DEBUG
#define CHAMBER_LOG(...)      DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,    __VA_ARGS__)
#define CHAMBER_LOG_WARN(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL, __VA_ARGS__)
#define CHAMBER_LOG_ERR(...)  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,   __VA_ARGS__)
#else
#define CHAMBER_LOG(...)      ((void)0)
#define CHAMBER_LOG_WARN(...) ((void)0)
#define CHAMBER_LOG_ERR(...)  ((void)0)
#endif

/* -----------------------------------------------------------------------
 * Phase 1.7: compile-time pool tag.
 * Override by passing /D"CHAMBER_POOL_TAG=0x......" at the compile line.
 * Default is a neutral 4-byte alphanumeric that resembles common minifilter
 * tags in poolmon output (poolmon prints bytes in memory order, which is
 * the reverse of the multichar C literal under MSVC/x64 little-endian).
 * POOLTAG(x) ignores x but keeps it in source for human-readable context.
 * ----------------------------------------------------------------------- */
#ifndef CHAMBER_POOL_TAG
#define CHAMBER_POOL_TAG  'FsFl'
#endif
#define POOLTAG(x) ((ULONG)CHAMBER_POOL_TAG)

/* Backwards-compat shim: svm_bringup.c and other sites referenced the old
 * THE_CHAMBER_POOL_TAG name. Keep one indirection point so no site has to
 * change when the tag macro name itself changes. */
#define THE_CHAMBER_POOL_TAG CHAMBER_POOL_TAG

/* -----------------------------------------------------------------------
 * Phase 1.7: runtime-patchable config blob.
 *
 * Every string that would otherwise leak a brand name through the binary
 * (device path, DOS symlink, marker-file path) lives in this struct, which
 * the launcher patches with a per-install random name after a successful
 * build but before signing. The struct is placed in a dedicated writable
 * section (".cfg") so the launcher can locate it by section name and by
 * the magic signature.
 *
 * The defaults below look like a generic storage-filter driver; the
 * launcher overwrites them anyway. Nothing else in the driver should hold
 * device / symlink / marker strings.
 * ----------------------------------------------------------------------- */

#define CHAMBER_CFG_MAGIC_V1     0x5F474643UL   /* "CFG_" launcher marker */
#define CHAMBER_CFG_DEVICE_MAX   64
#define CHAMBER_CFG_SYMLINK_MAX  64
#define CHAMBER_CFG_MARKER_MAX   128

typedef struct _CHAMBER_CFG {
    ULONG magic;                                 /* CHAMBER_CFG_MAGIC_V1 */
    ULONG version;
    WCHAR device_path [CHAMBER_CFG_DEVICE_MAX];  /* L"\\Device\\<name>" */
    WCHAR symlink_path[CHAMBER_CFG_SYMLINK_MAX]; /* L"\\DosDevices\\<name>" */
    WCHAR marker_path [CHAMBER_CFG_MARKER_MAX];  /* L"\\??\\C:\\...\\<name>.dat" */
    ULONG pool_tag_override;                     /* 0 => use CHAMBER_POOL_TAG */
    ULONG reserved[16];
} CHAMBER_CFG;

extern CHAMBER_CFG g_chamber_cfg;

#define THE_CHAMBER_VERSION  0x00010000UL  /* 1.0.0 */
#define WATCHDOG_TIMEOUT_MS  60000

/* IOCTL control codes.  STATUS is read-only, KICK and SHUTDOWN mutate
 * device state and require FILE_WRITE_ACCESS so a plain-read open
 * cannot invoke them. */
#define IOCTL_THE_CHAMBER_STATUS    CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_THE_CHAMBER_KICK      CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_THE_CHAMBER_SHUTDOWN  CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_WRITE_ACCESS)

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
    UCHAR       pad_c8[256 - 208];       /* pad to 16-aligned FXSAVE at 256 */
    /* FXSAVE64 scratch area: 512 bytes, 16-byte aligned (offset 256 =
     * 16*16; pool base is 16-aligned on x64 so this is 16-aligned). The
     * vmrun.asm epilogue FXSAVE64 saves guest x87/SSE state here across
     * the C handler; AVX-512/XSAVE upgrades require 64-byte alignment and
     * a larger buffer. Offset 256 must match the FXSAVE_AREA EQU in
     * vmrun.asm. */
    UCHAR       fxsave_area[512];       /* offset 256 (0x100) */
    /* Phase 2.0: guest-entry latch. svm_launch_all_cpus sets this before
     * calling svm_launch() on this ctx and refuses to re-enter a ctx whose
     * latch is already TRUE. Prevents a stray second call from VMRUNing
     * into a CPU that is already serving guest VMEXITs. */
    BOOLEAN     guest_entered;          /* offset 768 (0x300) */
    /* Phase 2.1: per-CPU PMU shadow. guest_pmc_armed[i] is TRUE when the
     * guest has written PerfEvtSelCoreI (even MSR 0xC0010200 + 2*i) with
     * EN set and a non-zero event. On each VMEXIT, the handler saves the
     * current PerfCtrCoreI value into guest_pmc_snapshot[i] and restores
     * it before VMRUN so counts accrued inside the handler are hidden
     * from the guest. handle_rdpmc also serves reads from the snapshot. */
    BOOLEAN     guest_pmc_armed[6];
    ULONGLONG   guest_pmc_snapshot[6];
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
NTSTATUS svm_launch_all_cpus(void);
NTSTATUS svm_shutdown_all_cpus(void);
BOOLEAN  svm_is_supported(void);

NTSTATUS npt_init(void);
void     npt_free_tables(void);

void     vmexit_cleanup(void);

/* Global driver state */
extern CHAMBER_GLOBALS g_chamber;

/* Phase 1.5: single, process-lifetime spin lock guarding every
 * PsLoadedModuleList edit made by stealth.c. Initialized ONCE in
 * DriverEntry before stealth_apply() is called; stealth.c acquires and
 * releases without re-init. The old in-function
 * `static KSPIN_LOCK dummy; KeInitializeSpinLock(&dummy)` pattern reset the
 * lock on every entry, so a concurrent walker could observe the
 * mid-operation state. */
extern KSPIN_LOCK g_stealth_lock;

#endif /* THE_CHAMBER_H */
