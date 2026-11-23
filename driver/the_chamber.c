/* the_chamber.c -- driver skeleton for the AMD SVM ring-0
 * performance-instrumentation driver.
 *
 * Responsibilities handled here:
 *   - DriverEntry + unload
 *   - Device + symlink creation (names sourced from g_chamber_cfg)
 *   - IRP_MJ_CREATE / _CLOSE / _DEVICE_CONTROL dispatch
 *   - Crash-marker safety (refuse to load if previous session left marker)
 *   - Watchdog timer (auto-unload if user-mode stops kicking)
 *   - Phase 1.7 scrub of DriverExtension->ServiceKeyName
 *
 * SVM/NPT/VMEXIT cluster implementations live in separate .c files and are
 * called via the externs declared in the_chamber.h.
 *
 * --- \Driver directory discoverability note ----------------------------
 *
 * The \Driver\<name> object-directory entry that IoCreateDeviceSecure
 * registers is still reachable to anything walking \Driver with
 * ObjectDirectoryInformation. The master plan's "no \Driver entry at all"
 * alternative (VMMCALL-only interface) is not fully applicable here
 * because KICK / SHUTDOWN / STATUS must be reachable from user mode via
 * IOCTL, which requires a DEVICE_OBJECT.
 *
 * Instead:
 *   - DEVICE_TYPE is FILE_DEVICE_UNKNOWN (no device-type fingerprint).
 *   - No additional \GLOBAL?? symlinks are created at runtime beyond the
 *     one already produced from g_chamber_cfg.symlink_path. That single
 *     symlink's name is patched per install by the launcher to a random
 *     string, written to last_install.txt; nothing in the driver's
 *     release binary reveals it.
 *   - The device path itself (g_chamber_cfg.device_path) is likewise
 *     launcher-randomized.
 *
 * Discovery therefore requires enumerating \Driver (not grepping strings)
 * AND knowing which launcher-random \GLOBAL?? symlink maps to it. An
 * adversary with ring-0 code and a willingness to walk the object
 * namespace finds us; a surface scanner relying on brand strings or
 * known-device-names does not. */

#include "the_chamber.h"
#include "stealth.h"
#include "timing.h"
#include "npt.h"
#include "integrity.h"
#include "identity.h"
#include <wdmsec.h>   /* IoCreateDeviceSecure + SDDL_DEVOBJ_SYS_ALL_ADM_ALL */

CHAMBER_GLOBALS g_chamber;

/* Phase 1.5: process-lifetime spin lock for PsLoadedModuleList edits.
 * Initialized once in DriverEntry; declared extern in the_chamber.h. */
KSPIN_LOCK g_stealth_lock;

/* Seed-derived config blob. The launcher locates this section by name
 * (".cfg") and by (magic == CHAMBER_CFG_MAGIC_V2 && version == 2 &&
 * total_length == 632), overwriting it with the full 632-byte derived
 * blob before signing. The default blob below carries placeholder
 * values so the driver object code is self-consistent if a developer
 * loads an un-patched build locally; nothing here is meant to be used
 * on a release install. */
#pragma section(".cfg", read, write)
__declspec(allocate(".cfg"))
CHAMBER_CFG_V2 g_chamber_cfg_v2 = {
    CHAMBER_CFG_MAGIC_V2,
    2,
    CHAMBER_CFG_V2_TOTAL_LENGTH,
    { 0 },                                      /* seed */
    0,                                          /* toggles */
    { 's','v','c','_','p','l','c','h','d','r',0,0 },
    { 'p','l','c','h','d','r','d','e','v',0,0,0 },
    { 'FsFl','FsFl','FsFl','FsFl','FsFl','FsFl' },
    0x5452484D4648434AULL,                      /* vmmcall_magic placeholder */
    0,                                          /* cfg_magic_override placeholder */
    0, { 0, 0, 0 },                             /* rename_donor_index + pad */
    1,                                          /* guest_asid (overridden) */
    0, 0,                                       /* section_scramble, driver_nonce */
    { 'C','H','A','M','B','E','R','-','P','L','C','H','D','R','-',0 },
    { 0 },                                      /* machine_guid */
    0,                                          /* install_date */
    { 'X','X','X','X','X','-','X','X','X','X','X','-','X','X','X','X','X','-','X','X','X','X','X',0 },
    { 0 },                                      /* digital_product_id */
    { 'A','M','D',' ','R','y','z','e','n',' ','7',' ','7','7','0','0',
      'X',' ','8','-','C','o','r','e',' ','P','r','o','c','e','s','s',
      'o','r',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',0 },
    { 0 }, { 0 }, { 0 }, { 0 }, { 0 },           /* smbios uuid, serials, bios */
    { { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 } }, /* mac_addrs */
    { { 0 } },                                   /* disk_serials */
    { { 0 } },                                   /* volume_serials */
    0x10022208UL,                                /* gpu_ven_dev placeholder */
    { 0 },                                       /* edid_nonce */
    { 0 }                                        /* tail pad */
};

/* Runtime wrapper over CHAMBER_CFG_V2, populated at DriverEntry so
 * downstream call sites keep stable pointers to UNICODE_STRING buffers
 * that persist for the driver's lifetime. The v1 struct name is kept
 * purely so existing code paths compile; no v1 blob is read anywhere. */
CHAMBER_CFG g_chamber_cfg = {
    CHAMBER_CFG_MAGIC_V2,
    2,
    { 0 },
    { 0 },
    { 0 },
    0,
    { 0 }
};

BOOLEAN g_chamber_cfg_v2_valid = FALSE;

/* --- Forward decls --- */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     UnloadRoutine;
DRIVER_DISPATCH   IrpCreateClose;
DRIVER_DISPATCH   IrpDeviceControl;

static NTSTATUS crash_marker_present(BOOLEAN *out_present);
static NTSTATUS crash_marker_drop(void);
static NTSTATUS crash_marker_clear(void);

/* Expand the v2 blob into the legacy WCHAR buffers consumed below.
 * Called once in DriverEntry after the version/magic probe succeeds.
 * Returns FALSE if either suffix would exceed its buffer, so the
 * caller can refuse to load rather than truncate a path. */
static BOOLEAN expand_cfg_v2_to_wide(void)
{
    SIZE_T i;
    SIZE_T len;
    static const WCHAR DEV_PREFIX[]    = L"\\Device\\";
    static const WCHAR DOS_PREFIX[]    = L"\\DosDevices\\";
    static const WCHAR MARKER_PREFIX[] =
        L"\\??\\C:\\Windows\\System32\\config\\";
    static const WCHAR MARKER_SUFFIX[] = L".dat";

    /* device_path = L"\\Device\\" + suffix(ASCII). */
    for (i = 0; DEV_PREFIX[i]; i++) g_chamber_cfg.device_path[i] = DEV_PREFIX[i];
    len = i;
    for (i = 0; i < sizeof(g_chamber_cfg_v2.device_suffix); i++) {
        UCHAR b = g_chamber_cfg_v2.device_suffix[i];
        if (b == 0) break;
        if (len + 2 >= CHAMBER_CFG_DEVICE_MAX) return FALSE;
        g_chamber_cfg.device_path[len++] = (WCHAR)b;
    }
    g_chamber_cfg.device_path[len] = 0;

    /* symlink_path = L"\\DosDevices\\" + suffix. */
    for (i = 0; DOS_PREFIX[i]; i++) g_chamber_cfg.symlink_path[i] = DOS_PREFIX[i];
    len = i;
    for (i = 0; i < sizeof(g_chamber_cfg_v2.device_suffix); i++) {
        UCHAR b = g_chamber_cfg_v2.device_suffix[i];
        if (b == 0) break;
        if (len + 2 >= CHAMBER_CFG_SYMLINK_MAX) return FALSE;
        g_chamber_cfg.symlink_path[len++] = (WCHAR)b;
    }
    g_chamber_cfg.symlink_path[len] = 0;

    /* marker_path = L"\\??\\C:\\...\\" + service_name + L".dat". */
    for (i = 0; MARKER_PREFIX[i]; i++) g_chamber_cfg.marker_path[i] = MARKER_PREFIX[i];
    len = i;
    for (i = 0; i < sizeof(g_chamber_cfg_v2.service_name); i++) {
        UCHAR b = g_chamber_cfg_v2.service_name[i];
        if (b == 0) break;
        if (len + 6 >= CHAMBER_CFG_MARKER_MAX) return FALSE;
        g_chamber_cfg.marker_path[len++] = (WCHAR)b;
    }
    for (i = 0; MARKER_SUFFIX[i]; i++) {
        if (len + 2 >= CHAMBER_CFG_MARKER_MAX) return FALSE;
        g_chamber_cfg.marker_path[len++] = MARKER_SUFFIX[i];
    }
    g_chamber_cfg.marker_path[len] = 0;

    /* Pool-tag override: first subsystem tag (svm) carries the aggregate
     * override; subsystem-specific tags are consulted by pool-aware call
     * sites once the launcher populates them via the seed. */
    g_chamber_cfg.pool_tag_override = g_chamber_cfg_v2.pool_tag[0];
    return TRUE;
}

static void watchdog_dpc_routine(PKDPC Dpc, PVOID Ctx, PVOID Sa1, PVOID Sa2);
static void start_watchdog(void);
static void stop_watchdog(void);
static void reset_watchdog(void);

static void scrub_service_key_name(PDRIVER_OBJECT Driver);

/* --- Crash marker file ops (via ZwCreateFile / ZwWriteFile) --- */
static NTSTATUS crash_marker_present(BOOLEAN *out_present)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    NTSTATUS st;

    *out_present = FALSE;
    RtlInitUnicodeString(&path, g_chamber_cfg.marker_path);
    InitializeObjectAttributes(&oa, &path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    st = ZwOpenFile(&h, FILE_READ_ATTRIBUTES | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

    if (NT_SUCCESS(st)) {
        *out_present = TRUE;
        ZwClose(h);
        return STATUS_SUCCESS;
    }
    if (st == STATUS_OBJECT_NAME_NOT_FOUND ||
        st == STATUS_OBJECT_PATH_NOT_FOUND) {
        return STATUS_SUCCESS;
    }
    /* Any other status (SHARING_VIOLATION, ACCESS_DENIED, IO_DEVICE_ERROR)
     * is indeterminate: treat it as "present or unknown" so the load-time
     * safety gate refuses rather than quietly proceeds. */
    *out_present = TRUE;
    return st;
}

static NTSTATUS crash_marker_drop(void)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    NTSTATUS st;
    UCHAR marker_bytes[1] = { 0x01 };

    RtlInitUnicodeString(&path, g_chamber_cfg.marker_path);
    InitializeObjectAttributes(&oa, &path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    st = ZwCreateFile(&h, GENERIC_WRITE | SYNCHRONIZE, &oa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    st = ZwWriteFile(h, NULL, NULL, NULL, &iosb,
        marker_bytes, sizeof(marker_bytes), NULL, NULL);
    ZwClose(h);
    return st;
}

static NTSTATUS crash_marker_clear(void)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    NTSTATUS st;
    FILE_DISPOSITION_INFORMATION disp;

    RtlInitUnicodeString(&path, g_chamber_cfg.marker_path);
    InitializeObjectAttributes(&oa, &path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    st = ZwOpenFile(&h, DELETE | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE |
        FILE_DELETE_ON_CLOSE);
    if (st == STATUS_OBJECT_NAME_NOT_FOUND ||
        st == STATUS_OBJECT_PATH_NOT_FOUND) {
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(st)) return st;

    disp.DeleteFile = TRUE;
    ZwSetInformationFile(h, &iosb, &disp, sizeof(disp),
        FileDispositionInformation);
    ZwClose(h);
    return STATUS_SUCCESS;
}

/* --- Watchdog ---
 *
 * Phase 7.3 extends the watchdog with:
 *   - Consecutive-miss counter. A miss is one DPC fire that sees
 *     elapsed time since last_kick > WATCHDOG_TIMEOUT_MS; a KICK
 *     IOCTL resets the counter to 0.
 *   - Auto-unload path. After WATCHDOG_MAX_MISSES misses the DPC
 *     queues a PASSIVE_LEVEL work item that calls svm_shutdown_all_cpus.
 *     The work item is required because svm_shutdown_all_cpus uses
 *     affinity-switch logic that cannot run at DISPATCH_LEVEL (where
 *     the DPC fires).
 *
 * The AMD-SVM unload sequence is EFER.SVME-clear per CPU (see
 * svm_bringup.c svm_offline_cpu). There is no VMXOFF on AMD -- that's
 * Intel VT-x terminology.
 */

/* PASSIVE_LEVEL work-item callback. Called once when the watchdog
 * determines the operator agent is gone. Does the full SVM teardown
 * (EFER.SVME clear per CPU, free VMCB / MSRPM / IOPM / NPT / host-save).
 * Running IoAllocateWorkItem's callback at PASSIVE_LEVEL is documented;
 * the DPC that queued it has already returned. */
static IO_WORKITEM_ROUTINE watchdog_unload_worker;
static void watchdog_unload_worker(PDEVICE_OBJECT DevObj, PVOID Ctx)
{
    UNREFERENCED_PARAMETER(DevObj);
    UNREFERENCED_PARAMETER(Ctx);

    CHAMBER_LOG_WARN("watchdog auto-unload: clearing EFER.SVME on all CPUs\n");

    /* Stop the integrity DPC BEFORE clearing EFER.SVME. Otherwise the
     * next 5-second fire of integrity_dpc_routine would issue a VMMCALL
     * on a CPU with SVME=0, raising #UD inside the DPC (IRQL at
     * DISPATCH_LEVEL) which is a terminal bugcheck. Mirror the
     * UnloadRoutine ordering (integrity first, then SVM). */
    integrity_shutdown();

    /* Full SVM teardown. svm_shutdown_all_cpus sets per-CPU
     * shutdown_requested, broadcasts the offline IPI (which clears
     * EFER.SVME), frees per-CPU structures, and nulls g_cpu_ctx. */
    if (g_chamber.svm_initialized) {
        (void)svm_shutdown_all_cpus();
        g_chamber.svm_initialized = FALSE;
    }
    if (g_chamber.npt_initialized) {
        npt_free_tables();
        g_chamber.npt_initialized = FALSE;
    }
    identity_release();

    /* Free the work item itself. We stashed its pointer in globals so
     * the DPC could queue it exactly once; zero the pointer AFTER free
     * so a late second queue attempt sees NULL. */
    if (g_chamber.shutdown_work_item) {
        PIO_WORKITEM wi = g_chamber.shutdown_work_item;
        g_chamber.shutdown_work_item = NULL;
        IoFreeWorkItem(wi);
    }
}

static void watchdog_dpc_routine(PKDPC Dpc, PVOID Ctx, PVOID Sa1, PVOID Sa2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Sa1);
    UNREFERENCED_PARAMETER(Sa2);

    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);

    KIRQL irql;
    KeAcquireSpinLock(&g_chamber.state_lock, &irql);
    LARGE_INTEGER last = g_chamber.last_kick_time;
    KeReleaseSpinLock(&g_chamber.state_lock, irql);

    ULONGLONG delta_100ns = (ULONGLONG)(now.QuadPart - last.QuadPart);
    ULONGLONG delta_ms = delta_100ns / 10000ULL;

    if (delta_ms > WATCHDOG_TIMEOUT_MS) {
        ULONG miss;
        KeAcquireSpinLock(&g_chamber.state_lock, &irql);
        miss = ++g_chamber.miss_count;
        KeReleaseSpinLock(&g_chamber.state_lock, irql);

        CHAMBER_LOG_WARN("watchdog miss %u/%u (delta=%llu ms)\n",
                         miss, WATCHDOG_MAX_MISSES, delta_ms);

        if (miss >= WATCHDOG_MAX_MISSES) {
            /* Signal per-CPU shutdown flags so VMRUN loops exit at
             * their next VMEXIT. The work item below then does the
             * actual EFER.SVME-clear sequence at PASSIVE_LEVEL. */
            InterlockedExchange(&g_chamber.unload_requested, 1);
            if (g_cpu_ctx) {
                for (ULONG i = 0; i < g_cpu_count; i++) {
                    InterlockedExchange(
                        &g_cpu_ctx[i].shutdown_requested, 1);
                }
            }

            /* Queue the PASSIVE-level unload path exactly once. The
             * work item was allocated in DriverEntry. Null the pointer
             * under the lock to make this one-shot even if the DPC
             * refires. */
            PIO_WORKITEM wi = NULL;
            KeAcquireSpinLock(&g_chamber.state_lock, &irql);
            if (g_chamber.shutdown_work_item &&
                g_chamber.unload_requested) {
                wi = g_chamber.shutdown_work_item;
                /* Don't null here -- the worker frees it and nulls
                 * on completion. We mark the DPC's intent via a
                 * sentinel: raise miss_count beyond threshold so the
                 * check above stays true but we only queue once. */
                g_chamber.miss_count = WATCHDOG_MAX_MISSES + 1;
            }
            KeReleaseSpinLock(&g_chamber.state_lock, irql);

            if (wi && miss == WATCHDOG_MAX_MISSES) {
                IoQueueWorkItem(wi, watchdog_unload_worker,
                                DelayedWorkQueue, NULL);
            }
        }
    } else {
        /* Successful kick observed since the last DPC. Reset the
         * miss counter so a transient hiccup doesn't accumulate. */
        KeAcquireSpinLock(&g_chamber.state_lock, &irql);
        g_chamber.miss_count = 0;
        KeReleaseSpinLock(&g_chamber.state_lock, irql);
    }
}

static void start_watchdog(void)
{
    KeInitializeTimer(&g_chamber.watchdog_timer);
    KeInitializeDpc(&g_chamber.watchdog_dpc, watchdog_dpc_routine, NULL);

    /* Phase 7.3: pre-allocate the work item at PASSIVE_LEVEL so the
     * DPC can queue it without allocating. g_chamber.device_object is
     * required; it was created in DriverEntry before start_watchdog. */
    if (g_chamber.device_object) {
        g_chamber.shutdown_work_item =
            IoAllocateWorkItem(g_chamber.device_object);
    }

    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)(5000 * 10000);  /* first fire in 5 s */
    KeSetTimerEx(&g_chamber.watchdog_timer, due, 5000, &g_chamber.watchdog_dpc);
}

static void stop_watchdog(void)
{
    KeCancelTimer(&g_chamber.watchdog_timer);
    KeRemoveQueueDpc(&g_chamber.watchdog_dpc);
    /* If the auto-unload path never fired, free the work item here.
     * If it did fire, the worker already freed it and nulled the
     * pointer -- null-check before free. */
    if (g_chamber.shutdown_work_item) {
        IoFreeWorkItem(g_chamber.shutdown_work_item);
        g_chamber.shutdown_work_item = NULL;
    }
}

static void reset_watchdog(void)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);

    KIRQL irql;
    KeAcquireSpinLock(&g_chamber.state_lock, &irql);
    g_chamber.last_kick_time = now;
    /* Phase 7.3: a successful kick zeros the miss counter so a
     * transient agent stall does not accumulate toward the auto-
     * unload threshold. */
    g_chamber.miss_count = 0;
    KeReleaseSpinLock(&g_chamber.state_lock, irql);
    InterlockedIncrement(&g_chamber.kick_counter);
}

/* --- Phase 1.7: scrub DriverExtension->ServiceKeyName ---
 *
 * DriverExtension->ServiceKeyName is a kernel-owned UNICODE_STRING whose
 * Buffer holds the service registry sub-key name (e.g. "winhvmon"). It
 * survives any DriverObject-level rename done by stealth_apply, because
 * it lives on the DriverExtension, which we leave intact so the loader
 * can still find us during unload. An enumerator that grabs the Driver
 * object and reads ServiceKeyName reconstructs the original service name.
 *
 * Deleting the kernel registry key from user land doesn't help: the Buffer
 * is a kernel COPY captured at load time. We overwrite the buffer in place
 * with noise. Tread carefully -- a few paths (ObReferenceObjectByName of
 * the driver by its registry name) read it, but on a never-unload stealth
 * driver no legitimate consumer should care. */
static void scrub_service_key_name(PDRIVER_OBJECT Driver)
{
    UNICODE_STRING *skn;
    USHORT chars;
    USHORT i;
    ULONGLONG seed;

    /* On x64 Windows, DRIVER_OBJECT.DriverExtension is a pointer the loader
     * fills in; ntddk.h exposes the pointee as DRIVER_EXTENSION whose
     * first field is ServiceKeyName. We do NOT touch DriverExtension
     * itself -- only the string buffer it holds -- so the unload path
     * that walks DriverExtension continues to work. */
    if (!Driver || !Driver->DriverExtension) return;
    skn = &Driver->DriverExtension->ServiceKeyName;
    if (!skn->Buffer || !skn->MaximumLength) return;

    /* Overwrite the entire buffer with a rotating noise pattern, keeping
     * the UNICODE_STRING metadata (Length / MaximumLength) in sync so
     * downstream readers still see a well-formed, nul-terminated string
     * of the same length. Simple LCG seeded from TSC + address so each
     * load differs. */
    chars = skn->MaximumLength / sizeof(WCHAR);
    seed  = __rdtsc() ^ (ULONGLONG)(ULONG_PTR)skn;
    for (i = 0; i + 1 < chars; i++) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        /* Printable lowercase ASCII, kept inside WCHAR. */
        skn->Buffer[i] = (WCHAR)(L'a' + ((seed >> 33) % 26));
    }
    if (chars > 0) skn->Buffer[chars - 1] = L'\0';
    /* Recompute Length from the actual string we just wrote (chars - 1
     * WCHARs of noise plus the NUL terminator at index chars - 1).  The
     * previous blind `Length -= 2` mismatched readers that disagreed on
     * whether the original Length counted the NUL. */
    if (chars > 0) {
        skn->Length = (USHORT)((chars - 1) * sizeof(WCHAR));
    } else {
        skn->Length = 0;
    }
}

/* --- IRP handlers --- */
NTSTATUS IrpCreateClose(PDEVICE_OBJECT Device, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Device);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS IrpDeviceControl(PDEVICE_OBJECT Device, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Device);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG in_len = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_len = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(in_len);

    switch (code) {
    case IOCTL_THE_CHAMBER_STATUS: {
        if (out_len < sizeof(CHAMBER_STATUS)) {
            st = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        CHAMBER_STATUS s;
        RtlZeroMemory(&s, sizeof(s));
        s.version = THE_CHAMBER_VERSION;
        s.cpu_count = g_cpu_count;
        ULONG active = 0;
        if (g_cpu_ctx) {
            for (ULONG i = 0; i < g_cpu_count; i++) {
                if (g_cpu_ctx[i].active) active++;
            }
        }
        s.active_cpus = active;
        s.vmexit_count = g_vmexit_count;
        RtlCopyMemory(buf, &s, sizeof(s));
        info = sizeof(s);
        st = STATUS_SUCCESS;
        break;
    }
    case IOCTL_THE_CHAMBER_KICK:
        reset_watchdog();
        st = STATUS_SUCCESS;
        break;
    case IOCTL_THE_CHAMBER_SHUTDOWN:
        CHAMBER_LOG("shutdown IOCTL received\n");
        InterlockedExchange(&g_chamber.unload_requested, 1);
        if (g_cpu_ctx) {
            for (ULONG i = 0; i < g_cpu_count; i++) {
                InterlockedExchange(&g_cpu_ctx[i].shutdown_requested, 1);
            }
        }
        st = STATUS_SUCCESS;
        break;
    default:
        break;
    }

    Irp->IoStatus.Status = st;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

/* --- Unload --- */
VOID UnloadRoutine(PDRIVER_OBJECT Driver)
{
    CHAMBER_LOG("unload begin (vmexits=%llu, kicks=%ld)\n",
                g_vmexit_count, g_chamber.kick_counter);

    /* Phase 7.2: stop the integrity DPC first; it reads HV code via
     * either direct call or VMMCALL, both of which are unsafe after
     * we start tearing down. */
    integrity_shutdown();

    /* Restore ourselves to PsLoadedModuleList + DriverObject BEFORE any
     * of the IO-manager cleanup paths run. */
    (void)stealth_revert(Driver);

    stop_watchdog();
    /* KeRemoveQueueDpc does NOT wait for an in-flight DPC on another
     * CPU; without this flush, a pending watchdog_dpc_routine may race
     * svm_shutdown_all_cpus freeing g_cpu_ctx and write into freed
     * pool. */
    KeFlushQueuedDpcs();

    if (g_chamber.svm_initialized) {
        svm_shutdown_all_cpus();
        g_chamber.svm_initialized = FALSE;
    }
    if (g_chamber.npt_initialized) {
        npt_free_tables();
        g_chamber.npt_initialized = FALSE;
    }
    identity_release();
    vmexit_cleanup();

    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, g_chamber_cfg.symlink_path);
    IoDeleteSymbolicLink(&sym);

    if (Driver->DeviceObject) {
        IoDeleteDevice(Driver->DeviceObject);
    }

    crash_marker_clear();

    CHAMBER_LOG("unload complete\n");
}

/* --- Entry --- */
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(RegPath);
    NTSTATUS st;
    UNICODE_STRING dev, sym;
    PDEVICE_OBJECT device = NULL;
    BOOLEAN marker_present = FALSE;

    CHAMBER_LOG("DriverEntry (version 0x%08x)\n", THE_CHAMBER_VERSION);

    RtlZeroMemory(&g_chamber, sizeof(g_chamber));
    g_chamber.driver_object = Driver;
    KeInitializeSpinLock(&g_chamber.state_lock);
    /* Phase 1.5: initialize the stealth lock ONCE here. stealth.c now
     * acquires it without reinitializing. */
    KeInitializeSpinLock(&g_stealth_lock);
    KeQuerySystemTimePrecise(&g_chamber.last_kick_time);

    /* Phase 1.7: scrub the kernel-owned ServiceKeyName copy. Done early so
     * that even a concurrent enumerator racing with our bringup sees noise
     * instead of the registry subkey name. */
    scrub_service_key_name(Driver);

    /* Version dispatch on the seed-derived config blob. The wave-3 v1
     * shape is retired in place: the installer must have produced v2
     * (magic 'CFG2', version 2, total_length 632). Loading a v1 blob
     * is refused with a specific error so the installer path surfaces
     * the mismatch rather than silently running under stale values. */
    if (g_chamber_cfg_v2.magic == CHAMBER_CFG_MAGIC_V1 ||
        g_chamber_cfg_v2.version == 1) {
        CHAMBER_LOG_ERR("v1 config blob detected; v2 required\n");
        return STATUS_REVISION_MISMATCH;
    }
    if (g_chamber_cfg_v2.magic != CHAMBER_CFG_MAGIC_V2 ||
        g_chamber_cfg_v2.version != 2 ||
        g_chamber_cfg_v2.total_length != CHAMBER_CFG_V2_TOTAL_LENGTH) {
        CHAMBER_LOG_ERR("cfg blob mismatch magic=0x%08x ver=%u len=%u\n",
                        g_chamber_cfg_v2.magic,
                        g_chamber_cfg_v2.version,
                        g_chamber_cfg_v2.total_length);
        return STATUS_INVALID_PARAMETER;
    }
    if (!expand_cfg_v2_to_wide()) {
        CHAMBER_LOG_ERR("cfg suffix too long for legacy path buffers\n");
        return STATUS_INVALID_PARAMETER;
    }
    g_chamber_cfg_v2_valid = TRUE;

    /* Crash-marker safety: refuse to load if the previous session left
     * one, OR if the probe returned an indeterminate status (now
     * surfaced as marker_present=TRUE so the safety gate fails closed). */
    st = crash_marker_present(&marker_present);
    if (!NT_SUCCESS(st)) {
        CHAMBER_LOG_WARN("marker probe failed 0x%08x -- refusing\n", st);
    }
    if (marker_present) {
        CHAMBER_LOG_ERR("crash marker from previous session present -- "
                        "refusing to load\n");
        return STATUS_UNSUCCESSFUL;
    }

    /* SVM support probe */
    if (!svm_is_supported()) {
        CHAMBER_LOG_ERR("SVM not supported / disabled by firmware\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* Drop crash marker -- cleared again at end on success. If we
     * crash between here and the end of DriverEntry, the marker
     * survives and next boot refuses to load. */
    st = crash_marker_drop();
    if (!NT_SUCCESS(st)) {
        CHAMBER_LOG_ERR("crash_marker_drop failed 0x%08x -- refusing\n", st);
        return st;
    }

    /* Device + symlink, both sourced from the patchable config blob.
     * Use IoCreateDeviceSecure with SDDL_DEVOBJ_SYS_ALL_ADM_ALL so only
     * SYSTEM and the Administrators group can open the device.  Pass a
     * zero class GUID: the device class is driver-owned and the
     * randomized Phase 1.7 names mean we can't share a stable GUID
     * across installs. */
    RtlInitUnicodeString(&dev, g_chamber_cfg.device_path);
    RtlInitUnicodeString(&sym, g_chamber_cfg.symlink_path);

    {
        UNICODE_STRING sddl;
        RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        st = IoCreateDeviceSecure(Driver, 0, &dev, FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, NULL, &device);
    }
    if (!NT_SUCCESS(st)) {
        CHAMBER_LOG_ERR("IoCreateDeviceSecure failed 0x%08x\n", st);
        goto fail;
    }
    g_chamber.device_object = device;
    device->Flags |= DO_BUFFERED_IO;

    st = IoCreateSymbolicLink(&sym, &dev);
    if (!NT_SUCCESS(st)) {
        CHAMBER_LOG_ERR("IoCreateSymbolicLink failed 0x%08x\n", st);
        goto fail;
    }

    Driver->MajorFunction[IRP_MJ_CREATE]         = IrpCreateClose;
    Driver->MajorFunction[IRP_MJ_CLOSE]          = IrpCreateClose;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;
    Driver->DriverUnload = UnloadRoutine;

    /* NPT first (VMCB needs the n_cr3 PA) */
    st = npt_init();
    if (!NT_SUCCESS(st)) {
        CHAMBER_LOG_ERR("npt_init failed 0x%08x\n", st);
        goto fail;
    }
    g_chamber.npt_initialized = TRUE;

    /* SVM per-CPU bringup */
    st = svm_init_all_cpus();
    if (!NT_SUCCESS(st)) {
        CHAMBER_LOG_ERR("svm_init_all_cpus failed 0x%08x\n", st);
        goto fail;
    }
    g_chamber.svm_initialized = TRUE;

    /* Populate per-vCPU identity tables and single-valued derived state.
     * svm_online_cpu has already run on every CPU (KeIpiGenericCall at
     * the tail of svm_init_all_cpus), but the VMCB builder reads no
     * identity state at bringup; the identity lookup is consulted at
     * VMEXIT time by handle_cpuid and handle_msr. Applying the table
     * after bringup is therefore sufficient and avoids calling an
     * allocator from inside the IPI broadcast. */
    st = identity_apply(&g_chamber_cfg_v2);
    if (!NT_SUCCESS(st)) {
        CHAMBER_LOG_ERR("identity_apply failed 0x%08x\n", st);
        goto fail;
    }

    /* Phase 1.2: set the pessimistic default microcode round-trip cost that
     * timing_update() adds to every captured host interval. */
    timing_calibrate();

    start_watchdog();

    /* Phase 2.0: demote every active CPU to guest mode. Done after
     * svm_init_all_cpus (VMCB + EFER.SVME) and before stealth_apply so
     * the KLDR rename step and anything after runs with the HV already
     * live. svm_launch_all_cpus pins the thread to each CPU in turn and
     * calls svm_launch; on return that CPU is live in guest mode. */
    st = svm_launch_all_cpus();
    if (!NT_SUCCESS(st)) {
        CHAMBER_LOG_ERR("svm_launch_all_cpus failed 0x%08x\n", st);
        goto fail;
    }

    /* Phase 7.1: NPT-hide the HV's own image so guest reads of our
     * code / data return #PF (when CHAMBER_HV_INTROSPECTION_RESIST is
     * compiled in; no-op otherwise). Capture DllBase/SizeOfImage from
     * the live DRIVER_OBJECT BEFORE stealth_apply scrambles section
     * headers and zeros the PE prefix; DriverStart/DriverSize survive
     * stealth_apply, but doing this first keeps the hide pass agnostic
     * to stealth internals. */
    (void)npt_hide_hv_image(Driver->DriverStart, Driver->DriverSize);

    /* Phase 7.1 TLB flush: broadcast the ASID-flush request to every
     * per-CPU VMCB so stale (GVA, HPA) translations from before the
     * hide do not keep serving HV bytes to the guest. Each CPU picks
     * it up on its next VMRUN. This write races a running guest but
     * the mutated field is a one-byte control (TLB_CONTROL at 0x05C),
     * single-byte writes are atomic on x86_64, and worst case a CPU
     * flushes twice across adjacent VMEXITs. */
    {
        ULONG i;
        for (i = 0; i < g_cpu_count; i++) {
            VMCB *v = (VMCB *)g_cpu_ctx[i].vmcb_va;
            if (v) npt_tlb_flush(v);
        }
    }

    /* Phase 7.2: arm the integrity self-check DPC. Non-fatal on
     * failure -- operator can disable integrity by removing this call
     * without breaking the rest of the HV. Must come AFTER
     * npt_hide_hv_image so that, when §7.1 is enabled, the DPC's
     * compile-time branch sees the correct state. */
    (void)integrity_init(Driver);

    /* Self-hide: rename our KLDR entry + null driver name.  Keep the
     * crash marker set across stealth_apply so a bugcheck from the
     * KLDR walk leaves a next-boot refuse-to-load gate. */
    (void)stealth_apply(Driver);

    crash_marker_clear();  /* init complete -- next boot can load again */

    CHAMBER_LOG("ready (cpus=%u)\n", g_cpu_count);
    return STATUS_SUCCESS;

fail:
    if (g_chamber.svm_initialized)  { svm_shutdown_all_cpus(); }
    if (g_chamber.npt_initialized)  { npt_free_tables(); }
    if (device) {
        IoDeleteSymbolicLink(&sym);
        IoDeleteDevice(device);
    }
    /* Leave marker so next boot refuses -- user clears it manually */
    return st;
}
