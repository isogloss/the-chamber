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
#define CHAMBER_CFG_MAGIC_V2     0x32474643UL   /* "CFG2" launcher marker */
#define CHAMBER_CFG_DEVICE_MAX   64
#define CHAMBER_CFG_SYMLINK_MAX  64
#define CHAMBER_CFG_MARKER_MAX   128

/* v1 struct kept for name compatibility; the .cfg section now holds the
 * v2 blob and the v1 shape is no longer accepted at DriverEntry. */
typedef struct _CHAMBER_CFG {
    ULONG magic;
    ULONG version;
    WCHAR device_path [CHAMBER_CFG_DEVICE_MAX];
    WCHAR symlink_path[CHAMBER_CFG_SYMLINK_MAX];
    WCHAR marker_path [CHAMBER_CFG_MARKER_MAX];
    ULONG pool_tag_override;
    ULONG reserved[16];
} CHAMBER_CFG;

/* ---- Seed-derived machine-identity config (v2) -----------------------
 * Wire format is byte-exact: #pragma pack(1), little-endian, 632 bytes.
 * The installer locates this blob in the on-disk .sys by scanning for
 * (magic == 0x32474643 && version == 2 && total_length == 632) and
 * overwrites it with seed-expanded values before signing. Every
 * runtime-visible machine fingerprint comes from this blob or from
 * iterated SHA-256 of the seed. The signing identity (cert + the
 * embedded launcher cert) stays constant across reseeds. */

/* Toggle bit positions in CHAMBER_CFG_V2.toggles. */
#define CHAMBER_TOGGLE_CI_STATE_SPOOF         (1UL <<  0)
#define CHAMBER_TOGGLE_MACHINE_IDENTITY_SPOOF (1UL <<  1)
#define CHAMBER_TOGGLE_HV_INTROSPECTION_RESIST (1UL << 2)
#define CHAMBER_TOGGLE_POOL_TAG_RANDOMIZE_SVM       (1UL << 3)
#define CHAMBER_TOGGLE_POOL_TAG_RANDOMIZE_NPT       (1UL << 4)
#define CHAMBER_TOGGLE_POOL_TAG_RANDOMIZE_VMEXIT    (1UL << 5)
#define CHAMBER_TOGGLE_POOL_TAG_RANDOMIZE_DUMP      (1UL << 6)
#define CHAMBER_TOGGLE_POOL_TAG_RANDOMIZE_INTEGRITY (1UL << 7)
#define CHAMBER_TOGGLE_POOL_TAG_RANDOMIZE_DISPATCH  (1UL << 8)
#define CHAMBER_TOGGLE_TPM_ABSENT_SPOOF             (1UL << 9)

#define CHAMBER_CFG_V2_TOTAL_LENGTH  632

#pragma pack(push, 1)
typedef struct _CHAMBER_CFG_V2 {
    /* Header */
    ULONG     magic;                        /* off 0  */
    ULONG     version;                      /* off 4  */
    ULONG     total_length;                 /* off 8  */

    /* Master seed */
    UCHAR     seed[32];                     /* off 12 */

    /* Toggles (bit-packed) */
    ULONG     toggles;                      /* off 44 */

    /* HV identity */
    UCHAR     service_name[12];             /* off 48  */
    UCHAR     device_suffix[12];            /* off 60  */
    ULONG     pool_tag[6];                  /* off 72  : svm/npt/vmexit/dump/integrity/dispatch */
    ULONGLONG vmmcall_magic;                /* off 96  */
    ULONGLONG chamber_cfg_magic_override;   /* off 104 */
    UCHAR     rename_donor_index;           /* off 112 */
    UCHAR     _pad0[3];                     /* off 113 */
    ULONG     guest_asid;                   /* off 116 */
    ULONG     section_scramble_seed;        /* off 120 */
    ULONGLONG driver_nonce;                 /* off 124 */

    /* Machine identity */
    UCHAR     computer_name[16];            /* off 132 */
    UCHAR     machine_guid[16];             /* off 148 */
    ULONGLONG install_date_filetime;        /* off 164 */
    UCHAR     product_id[24];               /* off 172 */
    UCHAR     digital_product_id[164];      /* off 196 */
    UCHAR     cpu_brand_string[48];         /* off 360 */
    UCHAR     smbios_system_uuid[16];       /* off 408 */
    UCHAR     baseboard_serial[16];         /* off 424 */
    UCHAR     chassis_serial[16];           /* off 440 */
    UCHAR     bios_vendor[16];              /* off 456 */
    UCHAR     bios_version[16];             /* off 472 */
    UCHAR     mac_addrs[6][4];              /* off 488 */
    UCHAR     disk_serials[20][4];          /* off 512 */
    UCHAR     volume_serials[4][4];         /* off 592 */
    ULONG     gpu_ven_dev;                  /* off 608 */
    UCHAR     edid_nonce[16];               /* off 612 */

    /* Tail pad to 8-aligned total length */
    UCHAR     _tail_pad[4];                 /* off 628 */
} CHAMBER_CFG_V2;
#pragma pack(pop)
C_ASSERT(sizeof(CHAMBER_CFG_V2) == CHAMBER_CFG_V2_TOTAL_LENGTH);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, seed)                == 12);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, toggles)             == 44);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, pool_tag)            == 72);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, vmmcall_magic)       == 96);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, rename_donor_index)  == 112);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, guest_asid)          == 116);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, driver_nonce)        == 124);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, computer_name)       == 132);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, cpu_brand_string)    == 360);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, mac_addrs)           == 488);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, disk_serials)        == 512);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, volume_serials)      == 592);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, gpu_ven_dev)         == 608);
C_ASSERT(FIELD_OFFSET(CHAMBER_CFG_V2, edid_nonce)          == 612);

extern CHAMBER_CFG     g_chamber_cfg;         /* legacy wrapper; populated at init from v2 */
extern CHAMBER_CFG_V2  g_chamber_cfg_v2;      /* authoritative seed-derived blob */
extern BOOLEAN         g_chamber_cfg_v2_valid; /* TRUE after DriverEntry version probe */

/* Agent C's fingerprint driver reads its own copy of CHAMBER_CFG_V2 from
 * a service-parameters registry blob (see audit/wave4_design.md §7).
 * TODO (Agent C): if a shared-memory hook is needed for runtime coordination
 * between the HV driver and chamber_fingerprint.sys, declare it here and
 * wire the implementation in a dedicated file; the HV side exposes only
 * the v2 cfg through the launcher's patcher. */

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
    /* Phase 2.0: top-of-stack pointer (16-byte aligned) for the host
     * side of the vmrun loop. svm_launch switches rsp to this value
     * before CLGI so VM_HSAVE_PA.host_rsp saves a pointer into memory
     * the HV owns, not into the caller's kernel stack (which gets
     * reclaimed once DriverEntry's load thread finishes). Base of the
     * allocation is host_stack_va; size is host_stack_size. */
    PVOID       host_stack_top;
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
    /* Phase 7.3: consecutive-miss counter for the watchdog DPC. Every
     * miss increments; a successful IOCTL_THE_CHAMBER_KICK zeros it.
     * After WATCHDOG_MAX_MISSES consecutive misses the DPC queues a
     * PASSIVE_LEVEL work item that calls svm_shutdown_all_cpus to
     * clear EFER.SVME on every CPU (the AMD-SVM equivalent of VMXOFF).
     * Prevents the HV from running orphaned if the operator agent
     * crashes mid-session. */
    ULONG            miss_count;
    PIO_WORKITEM     shutdown_work_item;
} CHAMBER_GLOBALS, *PCHAMBER_GLOBALS;

/* Phase 7.3 threshold. 5 consecutive missed kicks at the watchdog
 * timeout interval triggers auto-unload. Each kick is nominally every
 * 60 s (WATCHDOG_TIMEOUT_MS); the DPC itself re-arms every 5 s so one
 * missed kick = one miss. */
#define WATCHDOG_MAX_MISSES 5

/* VMMCALL hypercall shared-secret magic. handle_vmmcall validates
 * RBX against this value before dispatching to any hcall. Referenced
 * by integrity.c, dump.c, and vmexit.c so hoisted here. */
#define THE_CHAMBER_HYPERCALL_MAGIC   0x5452484D4648434AULL

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
