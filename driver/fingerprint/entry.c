/* entry.c -- DriverEntry for chamber_fingerprint.sys.
 *
 * Orchestration only. Each subsystem lives in its own translation unit;
 * this file wires them together in the required order and provides the
 * control device + dispatch table.
 *
 * Boot sequence:
 *   1. cfp_cfg_load   : pull CHAMBER_CFG_V2 from Services\<svc>\Parameters\CfgBlob
 *   2. cfp_target_init: spoof-list spin lock
 *   3. cfp_instr_init : IC arm table
 *   4. Create control device + symlink (launcher opens this for IOCTLs)
 *   5. cfp_cm_register: CmRegisterCallbackEx for registry surfaces
 *   6. cfp_flt_register: no-op since Wave 8.5 — FLT was the wrong
 *      framework for NDIS IOCTLs (IRP_MJ_DEVICE_CONTROL against
 *      \Device\Ndis never traverses a mounted FS volume's filter
 *      stack, so FltMgr never dispatches); the call remains in the
 *      sequence so the register/unregister pair stays symmetric and
 *      a later wave can put real file-system work behind the same
 *      handle if ever needed. See flt_filter.c for the rationale.
 *   7. cfp_instr_register: PsSetCreateProcessNotifyRoutineEx +
 *      PsSetLoadImageNotifyRoutine for per-PID arming and shim
 *      injection on first qualifying image load.
 *
 * Any step failing tears down the earlier ones in reverse order and
 * returns the failure. A partial teardown never leaks a registered
 * callback.
 *
 * Device and symlink names are CFG-derived (see build_cfg_name
 * below): the launcher writes CHAMBER_CFG_V2.device_suffix at
 * CFG-derive time, this driver reads it back from its own
 * Services\<svc>\Parameters\CfgBlob, and both sides agree on the
 * same \Device\<suffix> / \DosDevices\<suffix> without needing a
 * runtime return channel. If CFG has not loaded (cfp_cfg_load
 * failed) we fall back to a per-boot random suffix the launcher
 * cannot predict — the driver still loads but the launcher cannot
 * reach the control device until the next session. After the first
 * IOCTL handshake (IOCTL_CFP_ARM_PID landing with a valid
 * ARM_REQUEST) the DOS symlink is torn down so the launcher's held
 * kernel handle is the only remaining way in.
 */

#include "fingerprint_cfg.h"
#include <wdmsec.h>     /* IoCreateDeviceSecure + SDDL_* constants */
#include <ntimage.h>    /* PE image types (PIMAGE_DOS_HEADER / NT_HEADERS / SECTION_HEADER) */

/* Pool tag resolves through the shared symbol in cfg_shared.c so this
 * TU does not bake 'cFPC' into .rdata and every allocation here wears
 * the same per-install identity the CFG swap assigns. */
#define CFP_TAG         (g_cfp_pool_tag)

/* -----------------------------------------------------------------------
 * Local stealth implementation.
 *
 * The HV driver has stealth.c in the parent directory; its build does not
 * pull that file into chamber_fingerprint.sys (separate linker set), so
 * the equivalent logic lives here. The scheme mirrors the HV side exactly:
 *   - locate our own KLDR entry by DllBase matching DriverStart,
 *   - rename BaseDllName AND FullDllName to a donor driver's strings,
 *   - scramble PE section names with random alphabetic bytes,
 *   - zero the DOS + PE header prefix (0x400 bytes),
 *   - scrub DriverName / DriverSection on the DriverObject,
 *   - revert BaseDllName / FullDllName / DriverName / DriverSection on
 *     unload (section-name scramble and header zero are NOT restored —
 *     the driver image is about to be freed).
 * See driver/stealth.c for the full rationale against unlinking
 * PsLoadedModuleList (bugcheck 0x109) and the partial-swap tells.
 * ----------------------------------------------------------------------- */

typedef struct _CFP_KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
    LIST_ENTRY     HashLinks;
} CFP_KLDR_DATA_TABLE_ENTRY, *PCFP_KLDR_DATA_TABLE_ENTRY;

extern LIST_ENTRY PsLoadedModuleList;

static KSPIN_LOCK             g_cfp_stealth_lock;
static PCFP_KLDR_DATA_TABLE_ENTRY g_cfp_saved_entry      = NULL;
static UNICODE_STRING         g_cfp_saved_base          = {0};
static UNICODE_STRING         g_cfp_saved_full          = {0};
static UNICODE_STRING         g_cfp_saved_driver_name   = {0};
static PVOID                  g_cfp_saved_driver_section = NULL;
static BOOLEAN                g_cfp_stealth_driver_saved = FALSE;

static const WCHAR *const CFP_DONOR_POOL[] = {
    L"pci.sys",   L"acpi.sys", L"msrpc.sys", L"storport.sys",
    L"tcpip.sys", L"ndis.sys", L"disk.sys",  L"partmgr.sys"
};
#define CFP_DONOR_POOL_COUNT  (sizeof(CFP_DONOR_POOL)/sizeof(CFP_DONOR_POOL[0]))

static BOOLEAN
cfp_name_matches(PCFP_KLDR_DATA_TABLE_ENTRY e, const WCHAR *want)
{
    if (!e || !want || !e->BaseDllName.Buffer) return FALSE;
    USHORT have = e->BaseDllName.Length / sizeof(WCHAR);
    USHORT w = 0;
    while (want[w]) ++w;
    if (have != w) return FALSE;
    for (USHORT j = 0; j < w; ++j) {
        WCHAR a = e->BaseDllName.Buffer[j];
        WCHAR b = want[j];
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
        if (a != b) return FALSE;
    }
    return TRUE;
}

static BOOLEAN
cfp_is_donor(PCFP_KLDR_DATA_TABLE_ENTRY e)
{
    for (SIZE_T i = 0; i < CFP_DONOR_POOL_COUNT; ++i) {
        if (cfp_name_matches(e, CFP_DONOR_POOL[i])) return TRUE;
    }
    return FALSE;
}

static void
cfp_scramble_sections(PVOID image_base)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;
    LARGE_INTEGER tc;
    ULONG seed;
    USHORT n;

    if (!image_base) return;
    dos = (PIMAGE_DOS_HEADER)image_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)image_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    KeQueryTickCount(&tc);
    seed = tc.LowPart ^ (ULONG)(ULONG_PTR)image_base;

    n   = nt->FileHeader.NumberOfSections;
    sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < n; ++i) {
        for (int j = 0; j < IMAGE_SIZEOF_SHORT_NAME; ++j) {
            ULONG v = RtlRandomEx(&seed) % 52U;
            sec[i].Name[j] = (UCHAR)((v < 26U) ? ('A' + v) : ('a' + (v - 26U)));
        }
    }
}

static NTSTATUS
cfp_stealth_apply(PDRIVER_OBJECT drv)
{
    PLIST_ENTRY head, cur;
    KIRQL irql;
    PCFP_KLDR_DATA_TABLE_ENTRY our_entry = NULL, donor = NULL;
    PVOID our_base = NULL;

    if (!drv) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_cfp_stealth_lock, &irql);
    head = &PsLoadedModuleList;
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        PCFP_KLDR_DATA_TABLE_ENTRY e =
            CONTAINING_RECORD(cur, CFP_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (e->DllBase == drv->DriverStart) { our_entry = e; break; }
    }
    if (!our_entry) {
        KeReleaseSpinLock(&g_cfp_stealth_lock, irql);
        return STATUS_NOT_FOUND;
    }
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        PCFP_KLDR_DATA_TABLE_ENTRY e =
            CONTAINING_RECORD(cur, CFP_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (e == our_entry) continue;
        if (cfp_is_donor(e)) { donor = e; break; }
    }
    if (!donor) {
        KeReleaseSpinLock(&g_cfp_stealth_lock, irql);
        return STATUS_NOT_FOUND;
    }

    /* Atomic rename: Buffer + Length + MaximumLength must move together.
     * Half-swaps trip the loader's RtlEqualUnicodeString integrity check
     * and are a stronger tell than the original branded name. */
    g_cfp_saved_entry = our_entry;
    g_cfp_saved_base  = our_entry->BaseDllName;
    g_cfp_saved_full  = our_entry->FullDllName;
    our_entry->BaseDllName = donor->BaseDllName;
    our_entry->FullDllName = donor->FullDllName;

    our_base = our_entry->DllBase;
    KeReleaseSpinLock(&g_cfp_stealth_lock, irql);

    /* Pool-scanner evasion: section-name scramble BEFORE DOS/PE header
     * zero (IMAGE_FIRST_SECTION dereferences e_lfanew which the zero
     * clobbers). Writes target our own image, outside the shared KLDR
     * walk, so no lock here. */
    if (our_base) {
        cfp_scramble_sections(our_base);
        RtlZeroMemory(our_base, 0x400);
    }

    /* DriverObject fields. Clearing DriverSection breaks the unload
     * path's KLDR lookup; cfp_stealth_revert restores it before
     * MmUnloadSystemImage needs it (see cfp_unload). */
    g_cfp_saved_driver_name    = drv->DriverName;
    g_cfp_saved_driver_section = drv->DriverSection;
    g_cfp_stealth_driver_saved = TRUE;
    drv->DriverName.Length         = 0;
    drv->DriverName.MaximumLength  = 0;
    drv->DriverName.Buffer         = NULL;
    drv->DriverSection             = NULL;

    return STATUS_SUCCESS;
}

static void
cfp_stealth_revert(PDRIVER_OBJECT drv)
{
    KIRQL irql;
    BOOLEAN restore_drv;

    KeAcquireSpinLock(&g_cfp_stealth_lock, &irql);
    if (g_cfp_saved_entry) {
        g_cfp_saved_entry->BaseDllName = g_cfp_saved_base;
        g_cfp_saved_entry->FullDllName = g_cfp_saved_full;
        g_cfp_saved_entry = NULL;
    }
    restore_drv = g_cfp_stealth_driver_saved;
    g_cfp_stealth_driver_saved = FALSE;
    KeReleaseSpinLock(&g_cfp_stealth_lock, irql);

    if (drv && restore_drv) {
        drv->DriverName    = g_cfp_saved_driver_name;
        drv->DriverSection = g_cfp_saved_driver_section;
    }
    /* Section-name scramble and PE-header zero are not undone: the
     * image is being released. The loader's unload path uses the
     * restored DriverSection, not the section headers, to locate the
     * KLDR entry. */
}

/* Per-install suffix for the control device name and its DOS symbolic
 * link. Fixed names (\Device\CFPControl + \DosDevices\CFPControl) were
 * a static string any sample could enumerate; a per-boot random suffix
 * fixed the string-leak but left the launcher unable to find the
 * device (there is no return channel from kernel to launcher for the
 * generated name).
 *
 * The suffix comes from CHAMBER_CFG_V2.device_suffix[12], which the
 * launcher derives from the seed at CFG-blob-build time and writes
 * into both this driver's Services\<svc>\Parameters\CfgBlob and its
 * own compiled-in copy. Both sides derive the same ASCII suffix, so
 * the launcher opens \DosDevices\<suffix> directly without needing to
 * read anything back. A separate reboot regenerates the seed (if the
 * installer opts into reseeds) and therefore the suffix.
 *
 * If CFG has not loaded (cfp_cfg_load failed), we fall back to a
 * per-boot random suffix — the fp driver then runs in a degraded
 * state where only the HV side is reachable, and cfp_cfg_load's
 * failure is the primary error surface. */
#define CFP_DEV_NAME_BASE   L"\\Device\\"
#define CFP_DOS_NAME_BASE   L"\\DosDevices\\"
#define CFP_NAME_SUFFIX_LEN 16
#define CFP_NAME_MAX_CHARS  64

/* --- forwarded from other TUs --- */
NTSTATUS cfp_cfg_load(PUNICODE_STRING registry_path);
void     cfp_cfg_unload(void);

void     cfp_target_init(void);
void     cfp_target_cleanup(void);
NTSTATUS cfp_target_handle_ioctl(PIRP irp, PIO_STACK_LOCATION iosp, PULONG_PTR info);

void     cfp_instr_init(void);
NTSTATUS cfp_instr_register(PDEVICE_OBJECT control_device);
void     cfp_instr_unregister(void);
NTSTATUS cfp_instr_pend(HANDLE pid, PVOID user_trampoline);

NTSTATUS cfp_cm_register(PDRIVER_OBJECT drv);
void     cfp_cm_unregister(void);

NTSTATUS cfp_flt_register(PDRIVER_OBJECT drv);
void     cfp_flt_unregister_now(void);

/* --- state --- */

static PDEVICE_OBJECT g_device        = NULL;
static UNICODE_STRING g_dev_name      = {0};
static WCHAR          g_dev_name_buf [CFP_NAME_MAX_CHARS];
static UNICODE_STRING g_symlink_name  = {0};
static WCHAR          g_symlink_buf  [CFP_NAME_MAX_CHARS];
static BOOLEAN        g_symlink_made  = FALSE;
/* Ephemeral symlink: torn down after the first successful launcher
 * handshake (IOCTL_CFP_ARM_PID landing with a valid ARM_REQUEST), so
 * subsequent IOCTLs ride the raw device handle the launcher already
 * holds. Keeps the link out of the public DOS namespace for the
 * lifetime of the driver. */
static volatile LONG  g_first_handshake_done = 0;

/* Build a random 16-char hex suffix and append it to `base` into `dst`.
 * The suffix seed mixes KeQueryTickCount with the driver image base so a
 * reboot picks fresh bytes even without CFG access yet. Reserved for the
 * degraded (no CFG) fallback — a random suffix the launcher cannot
 * predict; the fp driver still loads, cm_filter / IC still run, but the
 * launcher cannot open the control device. */
static void
build_random_name(const WCHAR *base, WCHAR *dst, USHORT cap_chars,
                  PUNICODE_STRING out)
{
    static const WCHAR hex[] = L"0123456789abcdef";
    LARGE_INTEGER tc;
    KeQueryTickCount(&tc);
    ULONG seed = tc.LowPart ^ (ULONG)(ULONG_PTR)&dst;

    USHORT bi = 0;
    while (base[bi] && bi + 1 < cap_chars) {
        dst[bi] = base[bi];
        ++bi;
    }
    for (int i = 0; i < CFP_NAME_SUFFIX_LEN && bi + 1 < cap_chars; ++i) {
        seed = RtlRandomEx(&seed);
        dst[bi++] = hex[(seed >> 4) & 0xF];
    }
    dst[bi] = 0;

    out->Buffer        = dst;
    out->Length        = (USHORT)(bi * sizeof(WCHAR));
    out->MaximumLength = (USHORT)(cap_chars * sizeof(WCHAR));
}

/* Build the device / symlink name from the CFG-supplied 12-byte ASCII
 * suffix (NUL-terminated or fully filled). Returns TRUE on success
 * with `out` pointing into `dst`. The launcher derives the same suffix
 * from the seed so it can open \DosDevices\<suffix> directly — no
 * runtime channel is required to communicate the name back to user
 * mode. A zero-length / all-NUL suffix is treated as "CFG absent" and
 * the caller falls back to the random path. */
static BOOLEAN
build_cfg_name(const WCHAR *base, WCHAR *dst, USHORT cap_chars,
               PUNICODE_STRING out)
{
    UCHAR suffix[12];
    if (!cfp_cfg_get(CFP_FID_DEVICE_SUFFIX, suffix, sizeof(suffix))) {
        return FALSE;
    }

    /* Treat an all-zero suffix (or a leading NUL) as unset: the
     * launcher writes a non-empty suffix on every real install, so a
     * zero here means the compile-time placeholder was never patched.
     * Validate every byte lives in [A-Za-z0-9_-]; a byte outside that
     * range would make the ObCreateObject name parser reject the open
     * and is almost certainly a stale / corrupt CFG — fall back
     * instead of emitting a device name that cannot be opened. */
    BOOLEAN all_zero = TRUE;
    for (SIZE_T j = 0; j < sizeof(suffix); ++j) {
        UCHAR b = suffix[j];
        if (b == 0) break;
        all_zero = FALSE;
        BOOLEAN ok = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
                     (b >= '0' && b <= '9') || b == '_' || b == '-';
        if (!ok) return FALSE;
    }
    if (all_zero) return FALSE;

    USHORT bi = 0;
    while (base[bi] && bi + 1 < cap_chars) {
        dst[bi] = base[bi];
        ++bi;
    }
    for (SIZE_T j = 0; j < sizeof(suffix) && bi + 1 < cap_chars; ++j) {
        UCHAR b = suffix[j];
        if (b == 0) break;
        dst[bi++] = (WCHAR)b;
    }
    dst[bi] = 0;

    if (bi == 0 || bi * sizeof(WCHAR) > (SIZE_T)(cap_chars * sizeof(WCHAR))) {
        return FALSE;
    }

    out->Buffer        = dst;
    out->Length        = (USHORT)(bi * sizeof(WCHAR));
    out->MaximumLength = (USHORT)(cap_chars * sizeof(WCHAR));
    return TRUE;
}

/* Extended arm IOCTL carries both PID and user-mode trampoline VA.
 * FILE_DEVICE_UNKNOWN (not 0x8001) — the earlier device-type literal
 * was one nibble from the HV driver's 0x8000 and allowed a cross-driver
 * correlator to pair the two images by IOCTL space alone. */
#define IOCTL_CFP_ARM_PID    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _CFP_ARM_REQUEST {
    ULONG pid;
    ULONG reserved;
    ULONGLONG user_trampoline;
} CFP_ARM_REQUEST;

/* --- dispatch --- */

static NTSTATUS
cfp_create_close(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
cfp_devctl(PDEVICE_OBJECT dev, PIRP irp)
{
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION iosp = IoGetCurrentIrpStackLocation(irp);
    ULONG     code = iosp->Parameters.DeviceIoControl.IoControlCode;
    ULONG_PTR info = 0;
    NTSTATUS  status;

    if (code == IOCTL_CFP_ARM_PID) {
        ULONG in_len = iosp->Parameters.DeviceIoControl.InputBufferLength;
        if (in_len < sizeof(CFP_ARM_REQUEST)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            CFP_ARM_REQUEST *req = (CFP_ARM_REQUEST *)irp->AssociatedIrp.SystemBuffer;
            status = cfp_instr_pend((HANDLE)(ULONG_PTR)req->pid,
                                    (PVOID)(ULONG_PTR)req->user_trampoline);
            /* First valid handshake retires the symlink: the launcher
             * now holds a kernel handle to the device and does not need
             * the DOS namespace entry to remain. A sample that later
             * attempts to open the link by name gets STATUS_OBJECT_
             * NAME_NOT_FOUND. */
            if (NT_SUCCESS(status) &&
                InterlockedCompareExchange(&g_first_handshake_done,
                                           1, 0) == 0 &&
                g_symlink_made) {
                IoDeleteSymbolicLink(&g_symlink_name);
                g_symlink_made = FALSE;
            }
        }
    } else {
        status = cfp_target_handle_ioctl(irp, iosp, &info);
    }

    irp->IoStatus.Status      = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* --- unload --- */

static VOID
cfp_unload(PDRIVER_OBJECT drv)
{
    /* Deregister in reverse order of registration. Pending callbacks
     * drain before each API returns. */
    cfp_instr_unregister();
    cfp_flt_unregister_now();
    cfp_cm_unregister();

    if (g_symlink_made) {
        IoDeleteSymbolicLink(&g_symlink_name);
        g_symlink_made = FALSE;
    }
    if (g_device) {
        IoDeleteDevice(g_device);
        g_device = NULL;
    }

    cfp_target_cleanup();
    cfp_cfg_unload();

    /* Restore DriverName / DriverSection / KLDR BaseDllName so the
     * loader's unload path sees the real names. Must run after the
     * callback deregistration above so no in-flight callback resolves
     * against an unexpected module state. */
    cfp_stealth_revert(drv);
}

/* --- DriverEntry --- */

NTSTATUS
DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg_path)
{
    NTSTATUS status;

    /* 0. Module self-concealment MUST run first, before any callback
     *    registers or any device object gets created. The three
     *    callbacks we register below (PsSetCreateProcessNotifyRoutineEx,
     *    CmRegisterCallbackEx, FltRegisterFilter) each take an internal
     *    VA-to-module reference on the caller — a tool reading the
     *    SystemModuleInformation list against those addresses lands on
     *    chamber_fingerprint.sys unless the KLDR entry has already been
     *    renamed to the donor. Rename, scrub DriverName / DriverSection,
     *    and scramble section names + zero the DOS/PE header, same as
     *    the HV driver's stealth_apply. A revert happens on unload. */
    KeInitializeSpinLock(&g_cfp_stealth_lock);
    (void)cfp_stealth_apply(drv);

    /* 1. Load CFG v2. Without a valid blob we cannot spoof consistently
     *    with the HV side, so a failure here must stop the load. */
    status = cfp_cfg_load(reg_path);
    if (!NT_SUCCESS(status)) {
        CHAMBER_LOG_ERR("cfp: cfg load failed 0x%08x\n", status);
        cfp_stealth_revert(drv);
        return status;
    }

    /* 2 + 3. Per-subsystem init that cannot fail. */
    cfp_target_init();
    cfp_instr_init();

    /* 4. Control device. The name's suffix comes from CHAMBER_CFG_V2
     *    .device_suffix (launcher-written, byte-for-byte reproducible
     *    on the launcher side); if that is unavailable the fp driver
     *    falls back to a per-boot random suffix the launcher cannot
     *    open — degraded but not unsafe.
     *
     *    SDDL on the fallback (non-rewritten) path grants only SYSTEM
     *    access (SDDL_DEVOBJ_SYS_ALL = "D:P(A;;GA;;;SY)"); the launcher
     *    runs elevated under LocalSystem (service identity the
     *    installer created), so a non-SYSTEM admin or non-launcher
     *    SYSTEM-level sample cannot open the device at all. A later
     *    installer wave rewrites this field to the launcher-service
     *    SID (S-1-5-80-<hash>) before signing for the full
     *    "launcher-only" posture. */
    if (!build_cfg_name(CFP_DEV_NAME_BASE, g_dev_name_buf,
                        CFP_NAME_MAX_CHARS, &g_dev_name)) {
        build_random_name(CFP_DEV_NAME_BASE, g_dev_name_buf,
                          CFP_NAME_MAX_CHARS, &g_dev_name);
    }
    status = IoCreateDeviceSecure(
        drv, 0, &g_dev_name, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE,
        &SDDL_DEVOBJ_SYS_ALL,
        NULL, &g_device);
    if (!NT_SUCCESS(status)) {
        cfp_cfg_unload();
        cfp_stealth_revert(drv);
        return status;
    }
    g_device->Flags |= DO_BUFFERED_IO;
    g_device->Flags &= ~DO_DEVICE_INITIALIZING;

    if (!build_cfg_name(CFP_DOS_NAME_BASE, g_symlink_buf,
                        CFP_NAME_MAX_CHARS, &g_symlink_name)) {
        build_random_name(CFP_DOS_NAME_BASE, g_symlink_buf,
                          CFP_NAME_MAX_CHARS, &g_symlink_name);
    }
    status = IoCreateSymbolicLink(&g_symlink_name, &g_dev_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device);
        g_device = NULL;
        cfp_cfg_unload();
        cfp_stealth_revert(drv);
        return status;
    }
    g_symlink_made = TRUE;

    drv->MajorFunction[IRP_MJ_CREATE]         = cfp_create_close;
    drv->MajorFunction[IRP_MJ_CLOSE]          = cfp_create_close;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = cfp_devctl;
    drv->DriverUnload                          = cfp_unload;

    /* The DriverName / DriverSection / ServiceKeyName scrub the
     * HV-side stealth_apply performs is already in place from step 0
     * above; the three callbacks registered below record their
     * DriverObject-backed VA references against the scrubbed
     * (donor-shaped) image, not against chamber_fingerprint.sys. */

    /* 5. Registry callback. Passes drv so Cm holds a lifetime ref. */
    status = cfp_cm_register(drv);
    if (!NT_SUCCESS(status)) {
        CHAMBER_LOG_ERR("cfp: cm register failed 0x%08x\n", status);
        goto bail_after_device;
    }

    /* 6. Minifilter. Not fatal if Fltmgr is unavailable in the pre-boot
     *    phase this driver happened to be loaded during — cm + IC cover
     *    the primary adapter path. */
    NTSTATUS flt_s = cfp_flt_register(drv);
    if (!NT_SUCCESS(flt_s)) {
        CHAMBER_LOG_WARN("cfp: flt register failed 0x%08x; continuing\n", flt_s);
    }

    /* 7. Process-create notify (installs IC per-PID). */
    status = cfp_instr_register(g_device);
    if (!NT_SUCCESS(status)) {
        CHAMBER_LOG_ERR("cfp: instr register failed 0x%08x\n", status);
        goto bail_after_flt;
    }

    return STATUS_SUCCESS;

bail_after_flt:
    cfp_flt_unregister_now();
    cfp_cm_unregister();
bail_after_device:
    if (g_symlink_made) {
        IoDeleteSymbolicLink(&g_symlink_name);
        g_symlink_made = FALSE;
    }
    IoDeleteDevice(g_device);
    g_device = NULL;
    cfp_target_cleanup();
    cfp_cfg_unload();
    cfp_stealth_revert(drv);
    return status;
}
