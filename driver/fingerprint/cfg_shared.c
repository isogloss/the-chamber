/* cfg_shared.c -- loads the 632-byte CHAMBER_CFG_V2 blob the launcher wrote
 * under Services\<svc>\Parameters\CfgBlob and exposes a byte-accurate
 * get_override() to the other translation units in this driver.
 *
 * The HV driver (the_chamber.sys) reads the same blob out of its own .cfg
 * section. The launcher produces both copies from the same derive() output
 * so a field queried via CPUID (HV path) and via NtQuerySystemInformation
 * (IC path) returns identical bytes.
 *
 * All functions here are PASSIVE_LEVEL only.
 */

#include "fingerprint_cfg.h"

#define CFP_TAG         'cFPC'  /* appears as 'CPFc' in poolmon */
#define CFG_BLOB_SIZE   632

/* Local cached copy. Allocated at cfp_cfg_load, freed at cfp_cfg_unload.
 * Reads are lock-free: the blob is only replaced on explicit reload, which
 * callers must sequence so no IC/CM handler is mid-read. We do not
 * support hot-reload; reload = driver restart via launcher.
 */
static PUCHAR   g_cfg_blob    = NULL;
static ULONG    g_cfg_len     = 0;
static BOOLEAN  g_cfg_loaded  = FALSE;

/* -------- offset table (byte-exact against CFG v2 wire format) ----- */

#define OFF_MAGIC                   0
#define OFF_VERSION                 4
#define OFF_TOTAL_LENGTH            8
#define OFF_SEED                   12
#define OFF_TOGGLES                44
#define OFF_SERVICE_NAME           48
#define OFF_DEVICE_SUFFIX          60
#define OFF_POOL_TAG                72    /* 6 tags, 4 bytes each */
#define OFF_VMMCALL_MAGIC          96
#define OFF_CFG_MAGIC_OVERRIDE    104
#define OFF_RENAME_DONOR          112
#define OFF_GUEST_ASID            116
#define OFF_SECTION_SCRAMBLE      120
#define OFF_DRIVER_NONCE          124
#define OFF_COMPUTER_NAME         132
#define OFF_MACHINE_GUID          148
#define OFF_INSTALL_DATE          164
#define OFF_PRODUCT_ID            172
#define OFF_DIGITAL_PRODUCT_ID    196
#define OFF_CPU_BRAND             360
#define OFF_SMBIOS_UUID           408
#define OFF_BASEBOARD_SERIAL      424
#define OFF_CHASSIS_SERIAL        440
#define OFF_BIOS_VENDOR           456
#define OFF_BIOS_VERSION          472
#define OFF_MAC_ADDRS             488    /* 6 adapters, 4 bytes each: [OUI_idx, nic0, nic1, nic2] */
#define OFF_DISK_SERIALS          512    /* 20 slots, 4 bytes seed-tag each */
#define OFF_VOLUME_SERIALS        592    /* 4 vols, 4 bytes each */
#define OFF_GPU_VEN_DEV           608
#define OFF_EDID_NONCE            612

/* OUI pool for MAC byte 0..2. Design Section 4.3. */
static const UCHAR g_oui_pool[8][3] = {
    { 0x24, 0x4b, 0xfe },  /* ASUSTeK  */
    { 0xb0, 0x25, 0xaa },  /* Dell     */
    { 0x00, 0x25, 0xb3 },  /* HPE      */
    { 0x18, 0xc0, 0x4d },  /* Intel    */
    { 0x50, 0xeb, 0x71 },  /* Realtek  */
    { 0x74, 0xd4, 0x35 },  /* Gigabyte */
    { 0x28, 0x80, 0x88 },  /* Lenovo   */
    { 0xa4, 0x1f, 0x72 }   /* MSI      */
};

/* ---------------- registry read ---------------- */

static NTSTATUS
cfp_read_cfgblob(_In_  PUNICODE_STRING service_key,
                 _Out_ PUCHAR         *out_buf,
                 _Out_ PULONG          out_len)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING    params_rel;
    HANDLE            key_handle = NULL;
    NTSTATUS          status;

    *out_buf = NULL;
    *out_len = 0;

    /* The service key is \Registry\Machine\...\Services\<svc>. Open
     * Parameters below it. */
    RtlInitUnicodeString(&params_rel, L"Parameters");

    HANDLE svc_handle;
    InitializeObjectAttributes(&oa, service_key,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&svc_handle, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(&oa, &params_rel,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               svc_handle, NULL);
    status = ZwOpenKey(&key_handle, KEY_READ, &oa);
    ZwClose(svc_handle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Query CfgBlob value. */
    UNICODE_STRING value_name;
    RtlInitUnicodeString(&value_name, L"CfgBlob");

    UCHAR stack_info[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 8];
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)stack_info;
    ULONG needed = 0;

    status = ZwQueryValueKey(key_handle, &value_name,
                             KeyValuePartialInformation,
                             kvpi, sizeof(stack_info), &needed);
    if (status != STATUS_BUFFER_OVERFLOW && status != STATUS_BUFFER_TOO_SMALL) {
        ZwClose(key_handle);
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }

    PKEY_VALUE_PARTIAL_INFORMATION full =
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, needed, CFP_TAG);
    if (!full) {
        ZwClose(key_handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryValueKey(key_handle, &value_name,
                             KeyValuePartialInformation,
                             full, needed, &needed);
    ZwClose(key_handle);

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(full, CFP_TAG);
        return status;
    }

    if (full->Type != REG_BINARY || full->DataLength != CFG_BLOB_SIZE) {
        ExFreePoolWithTag(full, CFP_TAG);
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR blob = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, CFG_BLOB_SIZE, CFP_TAG);
    if (!blob) {
        ExFreePoolWithTag(full, CFP_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(blob, full->Data, CFG_BLOB_SIZE);
    ExFreePoolWithTag(full, CFP_TAG);

    /* Validate magic + version + length. Launcher writes magic=0x32474643
     * ('CFG2'), version=2, total_length=632. If any of those do not match
     * we reject — falling back to defaults would make the two drivers
     * disagree about identity, which defeats the whole wave. */
    ULONG magic   = *(PULONG)(blob + OFF_MAGIC);
    ULONG version = *(PULONG)(blob + OFF_VERSION);
    ULONG tlen    = *(PULONG)(blob + OFF_TOTAL_LENGTH);

    if (magic != 0x32474643UL || version != 2 || tlen != CFG_BLOB_SIZE) {
        ExFreePoolWithTag(blob, CFP_TAG);
        return STATUS_REVISION_MISMATCH;
    }

    *out_buf = blob;
    *out_len = CFG_BLOB_SIZE;
    return STATUS_SUCCESS;
}

NTSTATUS
cfp_cfg_load(PUNICODE_STRING registry_path)
{
    PAGED_CODE();

    if (g_cfg_loaded) {
        return STATUS_SUCCESS;   /* idempotent */
    }

    PUCHAR blob = NULL;
    ULONG  len  = 0;
    NTSTATUS status = cfp_read_cfgblob(registry_path, &blob, &len);
    if (!NT_SUCCESS(status)) {
        CHAMBER_LOG_ERR("cfp_cfg_load: read failed 0x%08x\n", status);
        return status;
    }

    g_cfg_blob   = blob;
    g_cfg_len    = len;
    g_cfg_loaded = TRUE;
    return STATUS_SUCCESS;
}

void
cfp_cfg_unload(void)
{
    if (g_cfg_blob) {
        RtlSecureZeroMemory(g_cfg_blob, g_cfg_len);
        ExFreePoolWithTag(g_cfg_blob, CFP_TAG);
        g_cfg_blob = NULL;
    }
    g_cfg_len    = 0;
    g_cfg_loaded = FALSE;
}

/* ---------------- accessor ---------------- */

static BOOLEAN
cfp_copy_field(ULONG offset, ULONG field_len, PVOID out, ULONG out_len)
{
    if (!g_cfg_loaded || !g_cfg_blob) return FALSE;
    if (out_len != field_len)         return FALSE;
    if ((ULONGLONG)offset + field_len > (ULONGLONG)g_cfg_len) return FALSE;
    RtlCopyMemory(out, g_cfg_blob + offset, field_len);
    return TRUE;
}

BOOLEAN
cfp_cfg_get(_In_ ULONG field_id,
            _Out_writes_bytes_(len) PVOID out,
            _In_ ULONG len)
{
    if (!out) return FALSE;

    /* MAC adapters: CFP_FID_MAC_ADDR_0 + N, N in 0..5. Spliced OUI + NIC id. */
    if (field_id >= CFP_FID_MAC_ADDR_0 && field_id <= CFP_FID_MAC_ADDR_0 + 5) {
        if (len != 6) return FALSE;
        if (!g_cfg_loaded || !g_cfg_blob) return FALSE;
        ULONG slot = field_id - CFP_FID_MAC_ADDR_0;
        PUCHAR row = g_cfg_blob + OFF_MAC_ADDRS + slot * 4;
        UCHAR oui_idx = row[0] % (UCHAR)(sizeof(g_oui_pool) / sizeof(g_oui_pool[0]));
        PUCHAR o = (PUCHAR)out;
        o[0] = g_oui_pool[oui_idx][0];
        o[1] = g_oui_pool[oui_idx][1];
        o[2] = g_oui_pool[oui_idx][2];
        o[3] = row[1];
        o[4] = row[2];
        o[5] = row[3];
        return TRUE;
    }

    /* Disk serials: returns the stored 4-byte seed tag. The DMI/IC rewrite
     * path expands this tag to a 20-char ASCII serial by chained derive at
     * read time (keeps CFG to 632 bytes). */
    if (field_id >= CFP_FID_DISK_SERIAL_0 && field_id <= CFP_FID_DISK_SERIAL_0 + 19) {
        ULONG slot = field_id - CFP_FID_DISK_SERIAL_0;
        return cfp_copy_field(OFF_DISK_SERIALS + slot * 4, 4, out, len);
    }

    /* Volume serials: 4 bytes per letter C:/D:/E:/F:. */
    if (field_id >= CFP_FID_VOLUME_SERIAL_0 && field_id <= CFP_FID_VOLUME_SERIAL_0 + 3) {
        ULONG slot = field_id - CFP_FID_VOLUME_SERIAL_0;
        return cfp_copy_field(OFF_VOLUME_SERIALS + slot * 4, 4, out, len);
    }

    switch (field_id) {
    case CFP_FID_COMPUTER_NAME:       return cfp_copy_field(OFF_COMPUTER_NAME,       16,  out, len);
    case CFP_FID_MACHINE_GUID:        return cfp_copy_field(OFF_MACHINE_GUID,        16,  out, len);
    case CFP_FID_INSTALL_DATE:        return cfp_copy_field(OFF_INSTALL_DATE,         8,  out, len);
    case CFP_FID_PRODUCT_ID:          return cfp_copy_field(OFF_PRODUCT_ID,          24,  out, len);
    case CFP_FID_DIGITAL_PRODUCT_ID:  return cfp_copy_field(OFF_DIGITAL_PRODUCT_ID, 164,  out, len);
    case CFP_FID_CPU_BRAND:           return cfp_copy_field(OFF_CPU_BRAND,           48,  out, len);
    case CFP_FID_SMBIOS_UUID:         return cfp_copy_field(OFF_SMBIOS_UUID,         16,  out, len);
    case CFP_FID_BASEBOARD_SERIAL:    return cfp_copy_field(OFF_BASEBOARD_SERIAL,    16,  out, len);
    case CFP_FID_CHASSIS_SERIAL:      return cfp_copy_field(OFF_CHASSIS_SERIAL,      16,  out, len);
    case CFP_FID_BIOS_VENDOR:         return cfp_copy_field(OFF_BIOS_VENDOR,         16,  out, len);
    case CFP_FID_BIOS_VERSION:        return cfp_copy_field(OFF_BIOS_VERSION,        16,  out, len);
    case CFP_FID_GPU_VEN_DEV:         return cfp_copy_field(OFF_GPU_VEN_DEV,          4,  out, len);
    case CFP_FID_EDID_NONCE:          return cfp_copy_field(OFF_EDID_NONCE,          16,  out, len);
    case CFP_FID_TOGGLES:             return cfp_copy_field(OFF_TOGGLES,              4,  out, len);
    }
    return FALSE;
}
