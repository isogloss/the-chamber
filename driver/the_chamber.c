/* the_chamber.c -- driver skeleton for THE_CHAMBER AMD SVM ring-0
 * performance-instrumentation driver.
 *
 * Responsibilities handled here:
 *   - DriverEntry + unload
 *   - Device + symlink creation
 *   - IRP_MJ_CREATE / _CLOSE / _DEVICE_CONTROL dispatch
 *   - Crash-marker safety (refuse to load if previous session left marker)
 *   - Watchdog timer (auto-unload if user-mode stops kicking)
 *
 * SVM/NPT/VMEXIT cluster implementations live in separate .c files and are
 * called via the externs declared in the_chamber.h.
 */

#include "the_chamber.h"
#include "stealth.h"
#include "timing.h"

CHAMBER_GLOBALS g_chamber;

/* Phase 1.5: process-lifetime spin lock for PsLoadedModuleList edits.
 * Initialized once in DriverEntry; declared extern in the_chamber.h. */
KSPIN_LOCK g_stealth_lock;

/* --- Forward decls --- */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     UnloadRoutine;
DRIVER_DISPATCH   IrpCreateClose;
DRIVER_DISPATCH   IrpDeviceControl;

static NTSTATUS crash_marker_present(BOOLEAN *out_present);
static NTSTATUS crash_marker_drop(void);
static NTSTATUS crash_marker_clear(void);

static void watchdog_dpc_routine(PKDPC Dpc, PVOID Ctx, PVOID Sa1, PVOID Sa2);
static void start_watchdog(void);
static void stop_watchdog(void);
static void reset_watchdog(void);

/* --- Crash marker file ops (via ZwCreateFile / ZwWriteFile) --- */
static NTSTATUS crash_marker_present(BOOLEAN *out_present)
{
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    NTSTATUS st;

    *out_present = FALSE;
    RtlInitUnicodeString(&path, THE_CHAMBER_MARKER_PATH);
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

    RtlInitUnicodeString(&path, THE_CHAMBER_MARKER_PATH);
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

    RtlInitUnicodeString(&path, THE_CHAMBER_MARKER_PATH);
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

/* --- Watchdog --- */
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
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "WinHvMon: watchdog timeout (%llu ms) -- requesting unload\n",
            delta_ms);
        InterlockedExchange(&g_chamber.unload_requested, 1);
        /* Signal any per-CPU shutdown flags so VMRUN loops exit */
        if (g_cpu_ctx) {
            for (ULONG i = 0; i < g_cpu_count; i++) {
                InterlockedExchange(&g_cpu_ctx[i].shutdown_requested, 1);
            }
        }
    }
}

static void start_watchdog(void)
{
    KeInitializeTimer(&g_chamber.watchdog_timer);
    KeInitializeDpc(&g_chamber.watchdog_dpc, watchdog_dpc_routine, NULL);

    LARGE_INTEGER due;
    due.QuadPart = -(LONGLONG)(5000 * 10000);  /* first fire in 5 s */
    KeSetTimerEx(&g_chamber.watchdog_timer, due, 5000, &g_chamber.watchdog_dpc);
}

static void stop_watchdog(void)
{
    KeCancelTimer(&g_chamber.watchdog_timer);
    KeRemoveQueueDpc(&g_chamber.watchdog_dpc);
}

static void reset_watchdog(void)
{
    LARGE_INTEGER now;
    KeQuerySystemTimePrecise(&now);

    KIRQL irql;
    KeAcquireSpinLock(&g_chamber.state_lock, &irql);
    g_chamber.last_kick_time = now;
    KeReleaseSpinLock(&g_chamber.state_lock, irql);
    InterlockedIncrement(&g_chamber.kick_counter);
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
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
            "WinHvMon: shutdown IOCTL received\n");
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
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "WinHvMon: unload begin (vmexits=%llu, kicks=%ld)\n",
        g_vmexit_count, g_chamber.kick_counter);

    /* Restore ourselves to PsLoadedModuleList + DriverObject BEFORE any
     * of the IO-manager cleanup paths run. */
    (void)stealth_revert(Driver);

    stop_watchdog();

    if (g_chamber.svm_initialized) {
        svm_shutdown_all_cpus();
        g_chamber.svm_initialized = FALSE;
    }
    if (g_chamber.npt_initialized) {
        npt_free_tables();
        g_chamber.npt_initialized = FALSE;
    }
    vmexit_cleanup();

    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, THE_CHAMBER_SYMLINK);
    IoDeleteSymbolicLink(&sym);

    if (Driver->DeviceObject) {
        IoDeleteDevice(Driver->DeviceObject);
    }

    crash_marker_clear();

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "WinHvMon: unload complete\n");
}

/* --- Entry --- */
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegPath)
{
    UNREFERENCED_PARAMETER(RegPath);
    NTSTATUS st;
    UNICODE_STRING dev, sym;
    PDEVICE_OBJECT device = NULL;
    BOOLEAN marker_present = FALSE;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "WinHvMon: DriverEntry (version 0x%08x)\n", THE_CHAMBER_VERSION);

    RtlZeroMemory(&g_chamber, sizeof(g_chamber));
    g_chamber.driver_object = Driver;
    KeInitializeSpinLock(&g_chamber.state_lock);
    /* Phase 1.5: initialize the stealth lock ONCE here. stealth.c now
     * acquires it without reinitializing. */
    KeInitializeSpinLock(&g_stealth_lock);
    KeQuerySystemTimePrecise(&g_chamber.last_kick_time);

    /* Crash-marker safety: refuse to load if the previous session left one */
    st = crash_marker_present(&marker_present);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_WARNING_LEVEL,
            "WinHvMon: marker probe failed 0x%08x -- continuing\n", st);
    }
    if (marker_present) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "WinHvMon: crash marker from previous session present -- "
            "refusing to load. Delete C:\\Windows\\System32\\config\\winhvmon.dat "
            "manually once you have verified the system.\n");
        return STATUS_UNSUCCESSFUL;
    }

    /* SVM support probe */
    if (!svm_is_supported()) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "WinHvMon: SVM not supported / disabled by firmware\n");
        return STATUS_NOT_SUPPORTED;
    }

    /* Drop crash marker -- cleared again at end on success. If we crash
     * between here and the end of DriverEntry, the marker survives and
     * next boot refuses to load. */
    (void)crash_marker_drop();

    /* Device + symlink */
    RtlInitUnicodeString(&dev, THE_CHAMBER_DEVICE_NAME);
    RtlInitUnicodeString(&sym, THE_CHAMBER_SYMLINK);

    st = IoCreateDevice(Driver, 0, &dev, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "WinHvMon: IoCreateDevice failed 0x%08x\n", st);
        goto fail;
    }
    g_chamber.device_object = device;
    device->Flags |= DO_BUFFERED_IO;

    st = IoCreateSymbolicLink(&sym, &dev);
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "WinHvMon: IoCreateSymbolicLink failed 0x%08x\n", st);
        goto fail;
    }

    Driver->MajorFunction[IRP_MJ_CREATE]         = IrpCreateClose;
    Driver->MajorFunction[IRP_MJ_CLOSE]          = IrpCreateClose;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControl;
    Driver->DriverUnload = UnloadRoutine;

    /* NPT first (VMCB needs the n_cr3 PA) */
    st = npt_init();
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "WinHvMon: npt_init failed 0x%08x\n", st);
        goto fail;
    }
    g_chamber.npt_initialized = TRUE;

    /* SVM per-CPU bringup */
    st = svm_init_all_cpus();
    if (!NT_SUCCESS(st)) {
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            "WinHvMon: svm_init_all_cpus failed 0x%08x\n", st);
        goto fail;
    }
    g_chamber.svm_initialized = TRUE;

    /* Phase 1.2: set the pessimistic default microcode round-trip cost that
     * timing_update() adds to every captured host interval. A proper
     * guest-side synthetic-VMMCALL calibration pass can refine this value
     * later; the Phase 1 bringup path has no running guest in which to
     * execute it, so timing_calibrate() picks a conservative Zen 4
     * constant. See timing.c for the measurement protocol. */
    timing_calibrate();

    start_watchdog();
    crash_marker_clear();  /* init complete -- next boot can load again */

    /* Self-hide: remove from PsLoadedModuleList + null driver name. */
    (void)stealth_apply(Driver);

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
        "WinHvMon: ready (cpus=%u)\n", g_cpu_count);
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
