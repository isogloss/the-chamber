/* dmi_rewrite.c -- SMBIOS/DMI blob walker.
 *
 * NtQuerySystemInformation(SystemFirmwareTableInformation=76) returns the
 * raw SMBIOS table the firmware published at boot. GetSystemFirmwareTable
 * ('RSMB', 0, ...) is a thin wrapper around the same syscall. Both yield
 * the same byte blob. Samples parse this blob directly looking for fields
 * that uniquely identify the machine.
 *
 * Wire format: a sequence of structures, each with:
 *   UCHAR  Type        offset 0
 *   UCHAR  Length      offset 1 (length of the formatted fixed-size area)
 *   USHORT Handle      offset 2
 *   UCHAR  FixedArea[Length - 4]
 *   UCHAR  Strings[]   (variable, NUL-terminated string pool after fixed area,
 *                       terminated by double-NUL)
 *
 * We walk the table, locate Type 0 / 1 / 2 / 3, and rewrite:
 *   Type 0 (BIOS Information)       offset 0x04 Vendor string
 *                                   offset 0x05 Version string
 *   Type 1 (System Information)     offset 0x04 Manufacturer
 *                                   offset 0x05 Product Name
 *                                   offset 0x06 Version
 *                                   offset 0x07 Serial Number
 *                                   offset 0x08 UUID (16 raw bytes, not a string ref)
 *                                   offset 0x19 Family
 *                                   offset 0x1A SKUNumber
 *   Type 2 (Baseboard Information)  offset 0x04 Manufacturer
 *                                   offset 0x07 Serial Number
 *   Type 3 (Chassis Information)    offset 0x04 Manufacturer
 *                                   offset 0x07 Serial Number
 *
 * String-field offsets store a 1-based index into the structure's string
 * pool. We never resize the pool: we overwrite the pointed-at string in
 * place if the override fits, otherwise we truncate. This keeps every
 * subsequent structure at the same offset and avoids a full repack.
 *
 * Special case: Type 1 UUID at offset 0x08 is 16 raw bytes, not a string
 * reference. We overwrite it directly with the CFG smbios_system_uuid.
 */

#include "fingerprint_cfg.h"

/* Replace the Nth string in the pool that starts at `pool` within `end`
 * with `new_val` (len bytes, no NUL). The pool strings are
 * NUL-terminated; we overwrite up to the old length, pad with spaces if
 * the new string is shorter, and never grow. index is 1-based. */
static void
replace_pool_string(PUCHAR pool, PUCHAR end, UCHAR index1,
                    const char *new_val, ULONG new_len)
{
    if (!pool || !end || index1 == 0 || pool >= end) return;

    PUCHAR p = pool;
    UCHAR  cur = 1;
    while (p < end) {
        PUCHAR start = p;
        /* find NUL */
        while (p < end && *p != 0) ++p;
        if (p >= end) return;

        if (cur == index1) {
            ULONG have = (ULONG)(p - start);
            ULONG copy = new_len < have ? new_len : have;
            RtlCopyMemory(start, new_val, copy);
            if (copy < have) {
                /* pad with spaces to keep subsequent offsets intact */
                RtlFillMemory(start + copy, have - copy, ' ');
            }
            return;
        }

        /* move past the NUL to the next string. Double-NUL terminates
         * the pool. */
        ++p;
        if (p < end && *p == 0) return;
        ++cur;
    }
}

/* Convert a NUL- or space-terminated 16-byte override into a C-string of
 * `maxlen` chars (no NUL). Returns the string length. */
static ULONG
flatten_override(const UCHAR *src, ULONG srclen, char *dst, ULONG maxlen)
{
    ULONG n = 0;
    for (ULONG i = 0; i < srclen && n < maxlen; ++i) {
        if (src[i] == 0) break;
        dst[n++] = (char)src[i];
    }
    return n;
}

static void
patch_type0(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    if (fixed_len < 0x12) return;
    UCHAR vendor_idx  = fixed[0x04];
    UCHAR version_idx = fixed[0x05];

    UCHAR ov[16];
    char  flat[16];
    ULONG fl;

    if (cfp_cfg_get(CFP_FID_BIOS_VENDOR, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, vendor_idx, flat, fl);
    }
    if (cfp_cfg_get(CFP_FID_BIOS_VERSION, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, version_idx, flat, fl);
    }
}

static void
patch_type1(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    if (fixed_len < 0x19) return;

    /* UUID at offset 0x08 is 16 raw bytes inside the fixed area. */
    UCHAR uuid[16];
    if (cfp_cfg_get(CFP_FID_SMBIOS_UUID, uuid, sizeof(uuid))) {
        RtlCopyMemory(fixed + 0x08, uuid, 16);
    }

    UCHAR mfr_idx  = fixed[0x04];
    UCHAR prd_idx  = fixed[0x05];
    UCHAR ver_idx  = fixed[0x06];
    UCHAR ser_idx  = fixed[0x07];

    UCHAR ov[16];
    char  flat[16];
    ULONG fl;

    /* We treat system manufacturer and product as mirrors of BIOS vendor
     * and product — most laptops really do have the same string here, so
     * this stays plausible. */
    if (cfp_cfg_get(CFP_FID_BIOS_VENDOR, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) {
            replace_pool_string(pool, end, mfr_idx, flat, fl);
            replace_pool_string(pool, end, prd_idx, flat, fl);
        }
    }
    if (cfp_cfg_get(CFP_FID_BIOS_VERSION, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, ver_idx, flat, fl);
    }
    /* The system serial reuses the chassis serial — identical on most
     * real OEM machines. */
    if (cfp_cfg_get(CFP_FID_CHASSIS_SERIAL, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, ser_idx, flat, fl);
    }
}

static void
patch_type2(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    if (fixed_len < 0x08) return;
    UCHAR mfr_idx = fixed[0x04];
    UCHAR ser_idx = fixed[0x07];

    UCHAR ov[16];
    char  flat[16];
    ULONG fl;

    if (cfp_cfg_get(CFP_FID_BIOS_VENDOR, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, mfr_idx, flat, fl);
    }
    if (cfp_cfg_get(CFP_FID_BASEBOARD_SERIAL, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, ser_idx, flat, fl);
    }
}

static void
patch_type3(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    if (fixed_len < 0x08) return;
    UCHAR mfr_idx = fixed[0x04];
    UCHAR ser_idx = fixed[0x07];

    UCHAR ov[16];
    char  flat[16];
    ULONG fl;

    if (cfp_cfg_get(CFP_FID_BIOS_VENDOR, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, mfr_idx, flat, fl);
    }
    if (cfp_cfg_get(CFP_FID_CHASSIS_SERIAL, ov, sizeof(ov))) {
        fl = flatten_override(ov, sizeof(ov), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, ser_idx, flat, fl);
    }
}

/* Top-level walker. `blob`/`len` points at the raw DMI stream (after the
 * SMBIOS header the firmware stripped — this is the "DMI only" view that
 * NtQuerySystemInformation returns inside SYSTEM_FIRMWARE_TABLE_INFORMATION.
 */
void
cfp_dmi_patch_blob(PUCHAR blob, ULONG len)
{
    if (!blob || len < 4) return;

    PUCHAR p   = blob;
    PUCHAR end = blob + len;

    while (p + 4 <= end) {
        UCHAR  type       = p[0];
        UCHAR  fixed_len  = p[1];
        if (fixed_len < 4 || p + fixed_len > end) break;

        PUCHAR pool_start = p + fixed_len;
        /* Scan for double-NUL that terminates the string pool. */
        PUCHAR pool_scan  = pool_start;
        while (pool_scan + 1 < end) {
            if (pool_scan[0] == 0 && pool_scan[1] == 0) break;
            ++pool_scan;
        }
        PUCHAR pool_end = pool_scan + 2;
        if (pool_end > end) pool_end = end;

        switch (type) {
        case 0:  patch_type0(p, fixed_len, pool_start, pool_end); break;
        case 1:  patch_type1(p, fixed_len, pool_start, pool_end); break;
        case 2:  patch_type2(p, fixed_len, pool_start, pool_end); break;
        case 3:  patch_type3(p, fixed_len, pool_start, pool_end); break;
        case 127: return;   /* end of table */
        default: break;
        }

        p = pool_end;
    }
}
