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
 * We walk the table, locate Type 0 / 1 / 2 / 3 / 4 / 7 / 11 / 16 / 17 / 19 / 32
 * and rewrite:
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
 *   Type 4 (Processor)              offset 0x04 Socket Designation
 *                                   offset 0x07 Manufacturer
 *                                   offset 0x10 Version (full brand string)
 *                                   offset 0x20 Serial Number
 *                                   offset 0x21 Asset Tag
 *                                   offset 0x22 Part Number
 *                                   Processor ID at 0x08 preserved — on a
 *                                   real Zen 4 host this is already a
 *                                   family-0x19 shape coherent with the
 *                                   vmexit.c leaf-1 rewrite (same ext_fam
 *                                   / fam bits). The per-install stepping
 *                                   /model low bits in g_identity_cpu_signature
 *                                   live in the HV driver TU and are not
 *                                   reachable from this driver; fabricating
 *                                   a different value here would risk
 *                                   drifting out of lockstep. Family byte
 *                                   (0x06) and Family 2 (0x28) are host
 *                                   passthrough — on real Zen 4 these are
 *                                   0xFE / 0x0140 which match the brand.
 *   Type 7 (Cache)                  size fields rewritten to Zen 4-shape
 *                                   based on the Cache Configuration level
 *                                   bits (L1 64 KB, L2 1 MB, L3 32 MB,
 *                                   bumped to 64 MB when the launcher
 *                                   chose a Ryzen 9 brand slot)
 *   Type 11 (OEM Strings)           any pool string carrying a VM token
 *                                   (QEMU/OVMF/VBox/innotek/VMware/Xen/
 *                                   Bochs/EDK II/TianoCore/KVM/Parallels/
 *                                   virtio) is overwritten with a short
 *                                   retail-sounding placeholder and the
 *                                   remainder space-padded in place
 *   Type 16 (Memory Array)          Location=motherboard, Use=system
 *                                   memory, ECC=None (desktop), Maximum
 *                                   Capacity=128 GB, 4 DIMM slots
 *   Type 17 (Memory Device)         Manufacturer / Serial Number /
 *                                   Asset Tag / Part Number re-derived
 *                                   from the SMBIOS UUID + per-DIMM
 *                                   Handle so they vary across DIMMs
 *                                   while staying stable per install
 *   Type 19 (Memory Mapped Addr)    Partition Width normalized to a
 *                                   plausible desktop dual-channel value
 *                                   when the firmware left it 0/0xFF;
 *                                   addresses kept at host passthrough
 *                                   (already <= Type 16 Maximum Capacity
 *                                   on any Zen 4 host)
 *   Type 32 (System Boot Info)      Reserved bytes zeroed, Boot Status
 *                                   forced to 0 ("no errors detected")
 *                                   so no VM firmware boot-status bits
 *                                   survive
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

/* ------------------------------------------------------------------
 * Shared helpers for the broader-type handlers below (Type 4 / 7 /
 * 11 / 16 / 17 / 19 / 32). Kept local to this translation unit; the
 * fingerprint driver has no seed access of its own and these are
 * deterministic hashes over CFG bytes we are allowed to read.
 * ------------------------------------------------------------------ */

/* FNV-1a 32-bit over `bytes[0..len-1]` with `mix` folded into the IV.
 * Used only as a stable per-install salt for synthetic SMBIOS strings
 * (DIMM manufacturer / serial / part number). Not security critical. */
static ULONG
dmi_fnv32(const UCHAR *bytes, ULONG len, ULONG mix)
{
    ULONG h = 0x811C9DC5UL ^ mix;
    ULONG i;
    for (i = 0; i < len; i++) {
        h ^= (ULONG)bytes[i];
        h *= 0x01000193UL;
    }
    /* Final avalanche so adjacent mix values produce well-separated
     * hashes even when `bytes` is identical across calls. */
    h ^= h >> 16;
    h *= 0x85EBCA6BUL;
    h ^= h >> 13;
    h *= 0xC2B2AE35UL;
    h ^= h >> 16;
    return h;
}

/* Fill `n` chars of dst with uppercase alnum deterministically from
 * `seed`. dst is NOT NUL-terminated by this helper. */
static void
dmi_fill_alnum(char *dst, ULONG n, ULONG seed)
{
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    ULONG h = seed;
    ULONG i;
    for (i = 0; i < n; i++) {
        /* Simple xorshift step keeps per-char entropy without pulling
         * in a PRNG; each step mutates every output char. */
        h ^= h << 13;
        h ^= h >> 17;
        h ^= h <<  5;
        dst[i] = A[((h >> 8) ^ (h >> 20)) % 36u];
    }
}

/* Populate a 16-byte per-install scratch from the CFG. Prefers the
 * SMBIOS UUID (16 raw bytes, always derived) and falls back to the
 * baseboard serial, then zeros. The caller treats this as an opaque
 * salt — not displayed to users. */
static void
dmi_get_scratch(UCHAR out[16])
{
    if (cfp_cfg_get(CFP_FID_SMBIOS_UUID, out, 16)) return;
    if (cfp_cfg_get(CFP_FID_BASEBOARD_SERIAL, out, 16)) return;
    RtlZeroMemory(out, 16);
}

/* ASCII case-insensitive substring search. Returns TRUE if `needle`
 * (length `nlen`, no NUL requirement) occurs anywhere in `haystack`
 * (length `hlen`). Used by the VM-token scrubber and the brand-slot
 * detector. */
static BOOLEAN
dmi_contains_ci(const UCHAR *haystack, ULONG hlen,
                const char *needle, ULONG nlen)
{
    if (nlen == 0 || hlen < nlen) return FALSE;
    ULONG i, j;
    for (i = 0; i + nlen <= hlen; i++) {
        BOOLEAN hit = TRUE;
        for (j = 0; j < nlen; j++) {
            UCHAR a = haystack[i + j];
            UCHAR b = (UCHAR)needle[j];
            if (a >= 'a' && a <= 'z') a = (UCHAR)(a - 32);
            if (b >= 'a' && b <= 'z') b = (UCHAR)(b - 32);
            if (a != b) { hit = FALSE; break; }
        }
        if (hit) return TRUE;
    }
    return FALSE;
}

/* VM-authored-firmware token table used for Type 11 (OEM strings) and
 * also consulted by patch_type4 before overwriting the socket string.
 * Case-insensitive. The retail SMBIOS surface has no reason to carry
 * any of these. */
static const char *const DMI_VM_TOKENS[] = {
    "QEMU", "OVMF", "TianoCore", "EDK II", "VBox",
    "VirtualBox", "innotek", "VMware", "Xen", "Bochs",
    "KVM", "Parallels", "virtio", "S3 Corp", "VS2005R2"
};

static BOOLEAN
dmi_string_has_vm_token(const UCHAR *s, ULONG slen)
{
    ULONG t;
    for (t = 0; t < sizeof(DMI_VM_TOKENS) / sizeof(DMI_VM_TOKENS[0]); t++) {
        const char *tok = DMI_VM_TOKENS[t];
        ULONG tl = 0;
        while (tok[tl]) ++tl;
        if (dmi_contains_ci(s, slen, tok, tl)) return TRUE;
    }
    return FALSE;
}

/* ------------------------------------------------------------------
 * Type 4 — Processor Information
 *
 * Fixed-area offsets referenced:
 *   0x04 Socket Designation (string)
 *   0x05 Processor Type     (byte, 0x03 = Central Processor)
 *   0x06 Processor Family   (byte)
 *   0x07 Processor Manufacturer (string)
 *   0x08 Processor ID       (8 raw bytes)                    [preserved]
 *   0x10 Processor Version  (string)
 *   0x11 Voltage, 0x12 Ext Clock, 0x14 Max, 0x16 Current, 0x18 Status
 *   0x19 Upgrade
 *   0x20 Serial Number (string)
 *   0x21 Asset Tag     (string)
 *   0x22 Part Number   (string)
 * ------------------------------------------------------------------ */
static void
patch_type4(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    if (fixed_len < 0x1A) return;

    UCHAR socket_idx = fixed[0x04];
    UCHAR mfr_idx    = fixed[0x07];
    UCHAR ver_idx    = (fixed_len > 0x10) ? fixed[0x10] : 0;
    UCHAR ser_idx    = (fixed_len > 0x20) ? fixed[0x20] : 0;
    UCHAR asset_idx  = (fixed_len > 0x21) ? fixed[0x21] : 0;
    UCHAR part_idx   = (fixed_len > 0x22) ? fixed[0x22] : 0;

    UCHAR brand[48];
    BOOLEAN have_brand = cfp_cfg_get(CFP_FID_CPU_BRAND, brand, sizeof(brand));

    /* Processor Family byte (0x06) and Processor Family 2 (0x28, SMBIOS
     * 2.6+) are left at host passthrough. On a real Zen 4 host the
     * firmware fills Family=0xFE and Family 2=0x0140 (Ryzen 7) or
     * similar, which matches the brand string the launcher chose from
     * its AMD-only subset. Normalizing them here would risk writing
     * an out-of-list code point whose meaning drifts across SMBIOS
     * spec revisions. */

    /* Socket Designation. The brand pool mixes Zen 3 (AM4) and Zen 4
     * (AM5) parts; a hardcoded "AM5" produces a cross-leaf inconsistency
     * whenever a 5600X/5800X slot is picked. Stamp the socket to match
     * the family of the chosen brand so Type 4 stays coherent with both
     * the brand pool and the vmexit.c leaf-1 rewrite. We always stamp
     * (not only on VM-token hits) because the firmware's socket may be
     * correct for the host board yet wrong for the spoofed brand. */
    if (socket_idx != 0) {
        const char *sock = "AM5";
        ULONG sl = 3;
        if (have_brand && (brand[0] == 'I' || brand[0] == 'i')) {
            sock = "LGA1700"; sl = 7;
        } else if (have_brand) {
            /* Detect Zen 3 (AM4) by the family-leading digit immediately
             * after "Ryzen N ": "Ryzen 5 5600X", "Ryzen 9 5950X3D", any
             * future 5xxx addition to the pool. The earlier exact
             * 5800X/5600X substring match would silently stamp AM5 on a
             * freshly added 5900X/5700X/5950X. Scan for the first ASCII
             * digit after a space; '5' => AM4, '7'/'8'/'9' => AM5. */
            BOOLEAN is_zen3 = FALSE;
            BOOLEAN saw_space = FALSE;
            ULONG i;
            for (i = 0; i < sizeof(brand); i++) {
                UCHAR c = brand[i];
                if (c == 0) break;
                if (c == ' ') { saw_space = TRUE; continue; }
                if (saw_space && c >= '0' && c <= '9') {
                    is_zen3 = (c == '5');
                    break;
                }
            }
            if (is_zen3) { sock = "AM4"; sl = 3; }
        }
        replace_pool_string(pool, end, socket_idx, sock, sl);
    }

    /* Manufacturer: first ASCII letter run of the seed-selected brand
     * string. The literal "AMD" or "Intel" we end up writing came from
     * the installer's brand pool, not a hardcoded impersonation here. */
    if (have_brand && mfr_idx) {
        char flat[16];
        ULONG fl = 0;
        ULONG i;
        for (i = 0; i < sizeof(brand) && fl < sizeof(flat); i++) {
            UCHAR c = brand[i];
            if (c == 0) break;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9')) {
                flat[fl++] = (char)c;
                continue;
            }
            if (fl > 0) break;   /* stop at first non-alnum after run */
        }
        if (fl) replace_pool_string(pool, end, mfr_idx, flat, fl);
    }

    /* Version: full 48-byte brand string (trailing spaces/NUL trimmed
     * by flatten_override). */
    if (have_brand && ver_idx) {
        char flat[48];
        ULONG fl = flatten_override(brand, sizeof(brand), flat, sizeof(flat));
        if (fl) replace_pool_string(pool, end, ver_idx, flat, fl);
    }

    /* Serial / Asset / Part: seed-local alphanumeric. Most retail AM5
     * / LGA1700 boards leave the processor serial blank or "To Be
     * Filled By O.E.M.", but neither reads cleanly through a sample's
     * string-match pass — a stable 10-char alnum avoids both the blank-
     * field and the "To Be Filled" tells. */
    UCHAR scr[16];
    dmi_get_scratch(scr);

    if (ser_idx) {
        char flat[10];
        dmi_fill_alnum(flat, sizeof(flat), dmi_fnv32(scr, 16, 0x7041u));
        replace_pool_string(pool, end, ser_idx, flat, sizeof(flat));
    }
    if (asset_idx) {
        char flat[10];
        dmi_fill_alnum(flat, sizeof(flat), dmi_fnv32(scr, 16, 0x7042u));
        replace_pool_string(pool, end, asset_idx, flat, sizeof(flat));
    }
    if (part_idx) {
        char flat[10];
        dmi_fill_alnum(flat, sizeof(flat), dmi_fnv32(scr, 16, 0x7043u));
        replace_pool_string(pool, end, part_idx, flat, sizeof(flat));
    }
}

/* ------------------------------------------------------------------
 * Type 7 — Cache Information
 *
 * Fixed-area offsets referenced:
 *   0x04 Socket Designation (string)
 *   0x05 Cache Configuration (2 bytes; bits [2:0] = level, 0=L1 1=L2 2=L3)
 *   0x07 Maximum Cache Size (2 bytes; MSB=1 means 64 KB granularity)
 *   0x09 Installed Size (2 bytes; same encoding)
 *   0x11 System Cache Type (byte; 0x03 Instruction, 0x04 Data, 0x05 Unified)
 *   0x13 Maximum Cache Size 2 (4 bytes, SMBIOS 3.1+; MSB=1 => 64 KB gran)
 *   0x17 Installed Cache Size 2 (4 bytes)
 *
 * Zen 4 canonical sizes we stamp:
 *   L1 = 64 KB   (32 KB I + 32 KB D per core; firmware typically
 *                 reports one 64 KB unified entry per core cluster)
 *   L2 = 1 MB
 *   L3 = 32 MB   (or 64 MB when the brand slot is Ryzen 9 7900X/7950X)
 * ------------------------------------------------------------------ */
static void
patch_type7(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    if (fixed_len < 0x0B) return;

    ULONG cfg_word = (ULONG)fixed[0x05] | ((ULONG)fixed[0x06] << 8);
    ULONG level0   = cfg_word & 0x7u;   /* 0 = L1 */

    /* Decide L3 variant from the chosen brand. The installer BRAND_POOL
     * is a static table; Ryzen 9 entries have 64 MB L3, everything else
     * in the pool has 32 MB. We inspect the brand string we were given
     * rather than hardcoding by index so a future pool rotation keeps
     * working. */
    BOOLEAN ryzen9 = FALSE;
    {
        UCHAR brand[48];
        if (cfp_cfg_get(CFP_FID_CPU_BRAND, brand, sizeof(brand))) {
            if (dmi_contains_ci(brand, sizeof(brand), "7900X", 5) ||
                dmi_contains_ci(brand, sizeof(brand), "7950X", 5) ||
                dmi_contains_ci(brand, sizeof(brand), "Ryzen 9", 7)) {
                ryzen9 = TRUE;
            }
        }
    }

    /* Size-16 encoding at offsets 0x07 / 0x09:
     *   bit 15 = 0 -> value in 1-KB units
     *   bit 15 = 1 -> value in 64-KB units */
    USHORT sz16 = 0;
    ULONG  sz32 = 0;
    UCHAR  cache_type = 0x05;   /* Unified */

    switch (level0) {
    case 0:  /* L1 */
        /* Zen 4 runs a split L1: 32 KB I$ + 32 KB D$ per core. Honor the
         * firmware's System Cache Type at 0x11 so a separate Instruction
         * (0x03) or Data (0x04) structure gets 32 KB, while a single
         * Unified (0x05) per-core-cluster entry keeps the combined 64 KB
         * shape. A one-size-fits-all 64 KB stamp drifts from Zen 4's
         * actual micro-architecture whenever firmware chose split
         * reporting. */
        if (fixed_len > 0x11 &&
            (fixed[0x11] == 0x03 || fixed[0x11] == 0x04)) {
            sz16 = 0x0020;      /* 32 KB, 1-KB granularity */
            sz32 = 32;
            cache_type = fixed[0x11];   /* preserve I$ / D$ marker */
        } else {
            sz16 = 0x0040;      /* 64 KB combined (Unified reporting) */
            sz32 = 64;
            cache_type = 0x05;
        }
        break;
    case 1:  /* L2 */
        sz16 = 0x0400;          /* 1024 KB, 1-KB granularity */
        sz32 = 1024;
        cache_type = 0x05;
        break;
    case 2:  /* L3 */
        if (ryzen9) {
            /* 64 MB = 1024 * 64 KB; MSB=1 -> encoded 0x8400. */
            sz16 = (USHORT)(0x8000u | 1024u);
            sz32 = 0x80000000u | 1024u;   /* 1024 * 64 KB */
        } else {
            /* 32 MB = 512 * 64 KB; MSB=1 -> encoded 0x8200. */
            sz16 = (USHORT)(0x8000u | 512u);
            sz32 = 0x80000000u | 512u;
        }
        cache_type = 0x05;
        break;
    default:
        /* L4+ structures (level 3..7 in the Configuration encoding) do
         * not exist on Zen 4; leave the firmware shape as-is rather
         * than stamp an L3 size onto a level we don't model. */
        return;
    }

    fixed[0x07] = (UCHAR)(sz16 & 0xFFu);
    fixed[0x08] = (UCHAR)((sz16 >> 8) & 0xFFu);
    if (fixed_len >= 0x0B) {
        fixed[0x09] = (UCHAR)(sz16 & 0xFFu);
        fixed[0x0A] = (UCHAR)((sz16 >> 8) & 0xFFu);
    }

    /* System Cache Type: only touch if firmware left it Unknown (0x02) or
     * Other (0x01). Real per-core-cluster reports can distinguish I$/D$
     * at L1; leave those alone. */
    if (fixed_len > 0x11 && (fixed[0x11] == 0x01 || fixed[0x11] == 0x02)) {
        fixed[0x11] = cache_type;
    }

    /* Extended size fields (SMBIOS 3.1+). Only write when the fixed area
     * is long enough to hold them. */
    if (fixed_len >= 0x1B) {
        fixed[0x13] = (UCHAR)(sz32 & 0xFFu);
        fixed[0x14] = (UCHAR)((sz32 >>  8) & 0xFFu);
        fixed[0x15] = (UCHAR)((sz32 >> 16) & 0xFFu);
        fixed[0x16] = (UCHAR)((sz32 >> 24) & 0xFFu);
        fixed[0x17] = (UCHAR)(sz32 & 0xFFu);
        fixed[0x18] = (UCHAR)((sz32 >>  8) & 0xFFu);
        fixed[0x19] = (UCHAR)((sz32 >> 16) & 0xFFu);
        fixed[0x1A] = (UCHAR)((sz32 >> 24) & 0xFFu);
    }

    /* Socket Designation: scrub if it carries a VM token. Typical retail
     * values are "L1-Cache" / "L2 Cache" / "L3 Cache" which we leave
     * intact. */
    UCHAR socket_idx = fixed[0x04];
    if (socket_idx != 0) {
        PUCHAR p = pool;
        UCHAR cur = 1;
        while (p < end) {
            PUCHAR start = p;
            while (p < end && *p != 0) ++p;
            if (p >= end) break;
            if (cur == socket_idx) {
                if (dmi_string_has_vm_token(start, (ULONG)(p - start))) {
                    static const char *const LBL[] = {
                        "L1-Cache", "L2-Cache", "L3-Cache"
                    };
                    ULONG li = (level0 < 3) ? level0 : 2;
                    const char *s = LBL[li];
                    ULONG sl = 0; while (s[sl]) ++sl;
                    replace_pool_string(pool, end, socket_idx, s, sl);
                }
                break;
            }
            ++p;
            if (p < end && *p == 0) break;
            ++cur;
        }
    }
}

/* ------------------------------------------------------------------
 * Type 11 — OEM Strings
 *
 * Fixed-area offsets referenced:
 *   0x04 Count (byte) — number of strings in the pool
 *
 * No string indices in the fixed area; every string 1..Count lives in
 * the pool. We walk the pool directly and overwrite any string that
 * carries a VM-firmware token with a short retail-sounding placeholder
 * ("OEM") and space-pad the remainder so every subsequent structure
 * stays at its original byte offset.
 * ------------------------------------------------------------------ */
static void
patch_type11(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    if (fixed_len < 0x05) return;
    (void)fixed_len;

    PUCHAR p = pool;
    while (p < end) {
        PUCHAR start = p;
        while (p < end && *p != 0) ++p;
        if (p >= end) return;

        ULONG slen = (ULONG)(p - start);
        if (slen > 0 && dmi_string_has_vm_token(start, slen)) {
            static const char REPL[] = "OEM";
            ULONG rl = sizeof(REPL) - 1;
            ULONG copy = rl < slen ? rl : slen;
            RtlCopyMemory(start, REPL, copy);
            if (copy < slen) {
                RtlFillMemory(start + copy, slen - copy, ' ');
            }
        }

        ++p;
        if (p < end && *p == 0) return;   /* double-NUL = pool end */
    }
}

/* ------------------------------------------------------------------
 * Pre-walk facts that Type 16 and Type 17 patchers need before their
 * single-pass rewrite. Populated once by dmi_prewalk() so the main
 * walker can run forward without a second scan.
 *
 * type17_count / type17_total_mb cover EVERY Type 17 in the blob
 * (not only those whose current Physical Memory Array Handle matches
 * the first Type 16): patch_type17 re-anchors each DIMM to the first
 * Type 16, so the Type 16 count field must reflect that post-rewrite
 * state rather than the firmware's pre-rewrite reference pattern.
 * ------------------------------------------------------------------ */
struct dmi_prewalk_info {
    USHORT    type16_handle;
    BOOLEAN   have_type16_handle;
    ULONG     type17_count;
    ULONGLONG type17_total_mb;
};

static void
dmi_prewalk(PUCHAR blob, ULONG len, struct dmi_prewalk_info *info)
{
    RtlZeroMemory(info, sizeof(*info));
    if (!blob || len < 4) return;

    PUCHAR p   = blob;
    PUCHAR end = blob + len;

    while (p + 4 <= end) {
        UCHAR type = p[0];
        UCHAR flen = p[1];
        if (flen < 4 || p + flen > end) return;

        if (type == 16 && !info->have_type16_handle) {
            info->type16_handle = (USHORT)p[0x02] | ((USHORT)p[0x03] << 8);
            info->have_type16_handle = TRUE;
        } else if (type == 17 && flen >= 0x0E) {
            info->type17_count++;

            /* Decode Size at 0x0C (2 bytes) into MB.
             *   0x0000 => no module installed      (contributes 0)
             *   0xFFFF => unknown                  (contributes 0)
             *   0x7FFF => use Extended Size at 0x1C (MB, bit 31 reserved)
             *   bit 15 set => kB granularity in bits [14:0]
             *   bit 15 clear => MB granularity in bits [14:0]
             */
            USHORT sz = (USHORT)p[0x0C] | ((USHORT)p[0x0D] << 8);
            ULONGLONG mb = 0;
            if (sz == 0 || sz == 0xFFFF) {
                mb = 0;
            } else if (sz == 0x7FFF) {
                if (flen >= 0x20) {
                    ULONG esz = (ULONG)p[0x1C]
                              | ((ULONG)p[0x1D] <<  8)
                              | ((ULONG)p[0x1E] << 16)
                              | ((ULONG)p[0x1F] << 24);
                    mb = (ULONGLONG)(esz & 0x7FFFFFFFul);
                }
            } else if (sz & 0x8000u) {
                /* kB; round up to MB so we never undercount capacity. */
                ULONG kb = sz & 0x7FFFu;
                mb = (ULONGLONG)((kb + 1023u) / 1024u);
            } else {
                mb = (ULONGLONG)(sz & 0x7FFFu);
            }
            info->type17_total_mb += mb;
        }

        if (type == 127) return;   /* end-of-table */

        /* Skip past the string pool (double-NUL terminates). */
        PUCHAR pool = p + flen;
        while (pool + 1 < end) {
            if (pool[0] == 0 && pool[1] == 0) break;
            ++pool;
        }
        p = pool + 2;
        if (p > end) return;
    }
}

/* ------------------------------------------------------------------
 * Type 16 — Physical Memory Array
 *
 * Fixed-area offsets referenced:
 *   0x04 Location (byte)                     0x03 = System board
 *   0x05 Use (byte)                          0x03 = System memory
 *   0x06 Memory Error Correction (byte)      0x03 = None (desktop)
 *   0x07 Maximum Capacity (4 bytes, KB)      sum(Type 17 sizes) * 2 or
 *                                            32 GB floor, whichever is
 *                                            larger (escape to Extended
 *                                            Max Capacity if > 2 TB)
 *   0x0B Memory Error Information Handle     0xFFFE = not provided
 *   0x0D Number of Memory Devices (2 bytes)  actual count from prewalk
 *   0x0F Extended Maximum Capacity (8 bytes, SMBIOS 2.7+)
 *
 * No strings in this structure. Maximum Capacity and Number of Memory
 * Devices are both derived from the Type 17 instances in the blob so
 * the "sum of Type 17 <= Max Capacity" / "Max Devices >= actual count"
 * spec invariants hold across arbitrary firmware DIMM topologies.
 * ------------------------------------------------------------------ */
static void
patch_type16(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end,
             const struct dmi_prewalk_info *info)
{
    (void)pool; (void)end;
    if (fixed_len < 0x0F) return;

    fixed[0x04] = 0x03;         /* System board or motherboard */
    fixed[0x05] = 0x03;         /* System memory */
    fixed[0x06] = 0x03;         /* No error correction (desktop) */

    /* Maximum capacity: round sum_of_Type17_sizes up to the next
     * populated-slot step so Max Capacity == N * per-slot-step, which
     * matches how retail firmware reports a board with empty slots.
     * Falling back to the sum as a floor keeps the SMBIOS invariant
     * (sum of Type 17 <= Max Capacity) exact when every slot is filled.
     * When the blob has no Type 17s at all, set Max Capacity to the
     * declared slot count * a plausible per-slot step (default 32 GB
     * per slot on AM5 boards). */
    ULONGLONG total_mb = info ? info->type17_total_mb : 0ull;
    ULONG     count    = info ? info->type17_count : 0;
    /* Per-slot step: 32 GB covers the common AM5 ceiling (DDR5 32 GB
     * UDIMMs). For zero-DIMM blobs, assume 4 slots * 32 GB = 128 GB. */
    ULONGLONG per_slot_mb = 32ull * 1024ull;
    ULONGLONG slots       = count > 0 ? (ULONGLONG)count : 4ull;
    ULONGLONG capacity_mb = slots * per_slot_mb;
    /* If Type 17 sum already exceeds the slot-step estimate, use the
     * sum itself (saturates upward; keeps the invariant). */
    if (total_mb > capacity_mb) capacity_mb = total_mb;
    ULONGLONG max_kb64 = capacity_mb * 1024ull;

    if (max_kb64 >= 0x80000000ull && fixed_len >= 0x17) {
        /* Stamp the escape sentinel in the 32-bit field and put the
         * actual capacity (in BYTES) in Extended Maximum Capacity. */
        ULONG escape = 0x80000000u;
        fixed[0x07] = (UCHAR)(escape         & 0xFFu);
        fixed[0x08] = (UCHAR)((escape >>  8) & 0xFFu);
        fixed[0x09] = (UCHAR)((escape >> 16) & 0xFFu);
        fixed[0x0A] = (UCHAR)((escape >> 24) & 0xFFu);

        ULONGLONG max_bytes = max_kb64 * 1024ull;
        fixed[0x0F] = (UCHAR)(max_bytes         & 0xFFull);
        fixed[0x10] = (UCHAR)((max_bytes >>  8) & 0xFFull);
        fixed[0x11] = (UCHAR)((max_bytes >> 16) & 0xFFull);
        fixed[0x12] = (UCHAR)((max_bytes >> 24) & 0xFFull);
        fixed[0x13] = (UCHAR)((max_bytes >> 32) & 0xFFull);
        fixed[0x14] = (UCHAR)((max_bytes >> 40) & 0xFFull);
        fixed[0x15] = (UCHAR)((max_bytes >> 48) & 0xFFull);
        fixed[0x16] = (UCHAR)((max_bytes >> 56) & 0xFFull);
    } else {
        /* Plain 32-bit field in KB. Saturate at 0x7FFFFFFF (just under
         * the 0x80000000 escape sentinel) on an old SMBIOS 2.6 blob
         * that cannot carry Extended Maximum Capacity. */
        ULONG max_kb = max_kb64 > 0x7FFFFFFFull
                           ? 0x7FFFFFFFul
                           : (ULONG)max_kb64;
        fixed[0x07] = (UCHAR)(max_kb         & 0xFFu);
        fixed[0x08] = (UCHAR)((max_kb >>  8) & 0xFFu);
        fixed[0x09] = (UCHAR)((max_kb >> 16) & 0xFFu);
        fixed[0x0A] = (UCHAR)((max_kb >> 24) & 0xFFu);

        /* Extended Maximum Capacity: zero when the plain field is used. */
        if (fixed_len >= 0x17) {
            RtlZeroMemory(fixed + 0x0F, 8);
        }
    }

    /* Error-info handle = 0xFFFE (no information) when the firmware left
     * it pointing at a VM-authored error-info structure. */
    fixed[0x0B] = 0xFE;
    fixed[0x0C] = 0xFF;

    /* Number of Memory Devices: count from the prewalk. patch_type17
     * re-anchors every DIMM to this Type 16, so the count mirrors the
     * post-rewrite reality. When the firmware produced no Type 17s at
     * all, reporting "0 devices" against a non-zero Maximum Capacity is
     * itself a tell — but so is synthesising a DIMM count the blob
     * cannot back up with Type 17 records. In that case leave the
     * firmware-written field alone and let the sample draw its own
     * (benign) conclusion that the DIMM population is unknown; do NOT
     * overwrite 0 with 1 because that stamps a device count the
     * downstream Type 17 walker cannot corroborate. */
    ULONG count = info ? info->type17_count : 0;
    if (count > 0) {
        if (count > 0xFFFFu) count = 0xFFFFu;
        fixed[0x0D] = (UCHAR)(count         & 0xFFu);
        fixed[0x0E] = (UCHAR)((count >> 8)  & 0xFFu);
    }
}

/* ------------------------------------------------------------------
 * Type 17 — Memory Device
 *
 * Fixed-area offsets referenced:
 *   0x04 Physical Memory Array Handle (2 bytes)
 *   0x06 Memory Error Information Handle (2 bytes)
 *   0x08 Total Width (2 bytes)
 *   0x0A Data Width (2 bytes)
 *   0x0C Size (2 bytes; MB; 0x7FFF => use Extended Size at 0x1C)
 *   0x0E Form Factor (byte; 0x09 = DIMM)
 *   0x10 Device Locator (string)
 *   0x11 Bank Locator (string)
 *   0x12 Memory Type (byte; 0x22 = DDR5, 0x1A = DDR4)
 *   0x15 Speed (2 bytes, MT/s)
 *   0x17 Manufacturer (string)   <-- scrub
 *   0x18 Serial Number (string)  <-- scrub
 *   0x19 Asset Tag (string)      <-- scrub
 *   0x1A Part Number (string)    <-- scrub
 * ------------------------------------------------------------------ */
static void
patch_type17(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end,
             const struct dmi_prewalk_info *info)
{
    if (fixed_len < 0x1B) return;

    /* Re-anchor the Physical Memory Array Handle at 0x04..0x05 to the
     * Type 16 we normalized — otherwise firmware that pointed Type 17s
     * at a different (VM-era) Memory Array handle keeps a dangling
     * reference after patch_type16. When the blob has no Type 16 at
     * all (edge case: hostile firmware), stamp the "no such handle"
     * sentinel 0xFFFE so the sample sees a clean no-array shape rather
     * than a dangling VM-era handle. */
    if (info && info->have_type16_handle) {
        fixed[0x04] = (UCHAR)(info->type16_handle        & 0xFFu);
        fixed[0x05] = (UCHAR)((info->type16_handle >> 8) & 0xFFu);
    } else {
        fixed[0x04] = 0xFE;
        fixed[0x05] = 0xFF;
    }

    /* Fetch the launcher-chosen CPU brand so Form Factor / Memory Type /
     * Speed stay coherent with the Type 4 socket (AM4 / AM5). Previous
     * guard-to-preserve pattern let QEMU/Zen-3-era shapes survive next
     * to a Zen 4 brand — a DDR4 DIMM at 2400 MT/s on an AM5 socket is
     * itself a tell. Pool decision rule mirrors patch_type4. */
    UCHAR brand17[48];
    BOOLEAN have_brand17 = cfp_cfg_get(CFP_FID_CPU_BRAND, brand17, sizeof(brand17));
    BOOLEAN brand_is_zen3 = FALSE;
    if (have_brand17) {
        /* Same family-digit scan as patch_type4 so Type 17 stays aligned
         * with Type 4's socket decision for any pool rotation. */
        BOOLEAN saw_space = FALSE;
        ULONG i;
        for (i = 0; i < sizeof(brand17); i++) {
            UCHAR c = brand17[i];
            if (c == 0) break;
            if (c == ' ') { saw_space = TRUE; continue; }
            if (saw_space && c >= '0' && c <= '9') {
                brand_is_zen3 = (c == '5');
                break;
            }
        }
    }

    /* Form Factor at 0x0E: DIMM (0x09) is the only desktop form factor
     * that stays coherent with our Type 16 / Type 7 shape. SODIMM,
     * FB-DIMM, RIMM etc. would advertise a laptop / server / legacy
     * packaging next to a desktop socket. Stamp unconditionally. */
    fixed[0x0E] = 0x09u;

    /* Memory Type at 0x12: DDR5 (0x22) for Zen 4 (AM5), DDR4 (0x1A) for
     * Zen 3 (AM4). Stamp unconditionally — firmware-reported values
     * like QEMU's 0x18 (DDR) or a Zen-3 host's 0x1A on a Zen-4 brand
     * are themselves cross-leaf tells. */
    fixed[0x12] = brand_is_zen3 ? 0x1Au : 0x22u;

    /* Size at 0x0C (2 bytes): 16 GB expressed as 0x4000 MB (bit 15
     * clear => MB units). Only stamp when firmware left it 0 (no
     * module reported) or 0xFFFF (unknown) — a plausible non-zero
     * value is preserved along with its Extended Size escape. */
    {
        USHORT sz = (USHORT)fixed[0x0C] | ((USHORT)fixed[0x0D] << 8);
        if (sz == 0 || sz == 0xFFFF) {
            fixed[0x0C] = (UCHAR)(0x4000u & 0xFFu);
            fixed[0x0D] = (UCHAR)((0x4000u >> 8) & 0xFFu);
        }
    }

    /* Speed at 0x15 (2 bytes, MT/s): 5200 for Zen 4 DDR5, 3200 for Zen 3
     * DDR4. Stamp unconditionally — QEMU/VM firmware values at
     * 2133/2400/2666 would survive a preserve-if-plausible guard and
     * mismatch the DDR5 / DDR4 Memory Type stamped above. */
    if (fixed_len > 0x16) {
        USHORT target_sp = brand_is_zen3 ? 0x0C80u : 0x1450u;
        fixed[0x15] = (UCHAR)(target_sp & 0xFFu);
        fixed[0x16] = (UCHAR)((target_sp >> 8) & 0xFFu);
    }

    /* Total Width at 0x08 and Data Width at 0x0A (2 bytes each): 64
     * bits each (non-ECC desktop DDR5). Only stamp when 0 or 0xFFFF. */
    {
        USHORT tw = (USHORT)fixed[0x08] | ((USHORT)fixed[0x09] << 8);
        if (tw == 0 || tw == 0xFFFF) {
            fixed[0x08] = 64;
            fixed[0x09] = 0;
        }
        USHORT dw = (USHORT)fixed[0x0A] | ((USHORT)fixed[0x0B] << 8);
        if (dw == 0 || dw == 0xFFFF) {
            fixed[0x0A] = 64;
            fixed[0x0B] = 0;
        }
    }

    /* The per-DIMM salt is the structure's Handle (fixed_len includes
     * bytes 0..3; fixed pointer starts at the Type byte). Using the
     * handle keeps each DIMM's synthetic identity distinct while being
     * stable within a boot. */
    ULONG handle = (ULONG)fixed[0x02] | ((ULONG)fixed[0x03] << 8);

    UCHAR mfr_idx   = fixed[0x17];
    UCHAR ser_idx   = fixed[0x18];
    UCHAR asset_idx = fixed[0x19];
    UCHAR part_idx  = fixed[0x1A];

    UCHAR scr[16];
    dmi_get_scratch(scr);

    /* Manufacturer: 6-char alnum. Real DDR DIMM manufacturer strings
     * are typically a short vendor name or a 4-digit JEDEC code; a
     * 6-char synthetic alnum reads as a vendor-neutral manufacturer
     * ID without impersonating any specific DDR vendor. */
    if (mfr_idx) {
        char flat[6];
        dmi_fill_alnum(flat, sizeof(flat),
                       dmi_fnv32(scr, 16, 0x1700u ^ handle));
        replace_pool_string(pool, end, mfr_idx, flat, sizeof(flat));
    }
    /* Serial Number: 8-char alnum (standard DIMM serial shape). */
    if (ser_idx) {
        char flat[8];
        dmi_fill_alnum(flat, sizeof(flat),
                       dmi_fnv32(scr, 16, 0x1701u ^ handle));
        replace_pool_string(pool, end, ser_idx, flat, sizeof(flat));
    }
    /* Asset Tag. */
    if (asset_idx) {
        char flat[10];
        dmi_fill_alnum(flat, sizeof(flat),
                       dmi_fnv32(scr, 16, 0x1702u ^ handle));
        replace_pool_string(pool, end, asset_idx, flat, sizeof(flat));
    }
    /* Part Number: 14-char alnum (fits the typical DDR5 OEM part-number
     * shape with margin). */
    if (part_idx) {
        char flat[14];
        dmi_fill_alnum(flat, sizeof(flat),
                       dmi_fnv32(scr, 16, 0x1703u ^ handle));
        replace_pool_string(pool, end, part_idx, flat, sizeof(flat));
    }

    /* Device Locator / Bank Locator: scrub if they carry a VM token
     * ("DIMM 0 (Hyper-V)" etc.), otherwise leave alone — real board
     * firmware fills these with silkscreen labels we should preserve. */
    UCHAR dev_idx  = fixed[0x10];
    UCHAR bank_idx = fixed[0x11];
    for (ULONG k = 0; k < 2; k++) {
        UCHAR idx = (k == 0) ? dev_idx : bank_idx;
        if (idx == 0) continue;
        PUCHAR p = pool;
        UCHAR cur = 1;
        while (p < end) {
            PUCHAR start = p;
            while (p < end && *p != 0) ++p;
            if (p >= end) break;
            if (cur == idx) {
                if (dmi_string_has_vm_token(start, (ULONG)(p - start))) {
                    /* Overwrite with blank-padding; the field becomes
                     * an empty label, which is benign on retail boards
                     * where unused slots carry whitespace. */
                    replace_pool_string(pool, end, idx, "", 0);
                }
                break;
            }
            ++p;
            if (p < end && *p == 0) break;
            ++cur;
        }
    }
}

/* ------------------------------------------------------------------
 * Type 19 — Memory Array Mapped Address
 *
 * Fixed-area offsets referenced:
 *   0x04 Starting Address (4 bytes KB)       passthrough
 *   0x08 Ending Address   (4 bytes KB)       passthrough
 *   0x0C Memory Array Handle (2 bytes)       passthrough
 *   0x0E Partition Width (byte)              normalize 0/0xFF -> 2
 *   0x0F Extended Starting Address (8 bytes) passthrough
 *   0x17 Extended Ending Address   (8 bytes) passthrough
 *
 * No strings. The host's start/end are already <= the 128 GB maximum
 * we stamp in Type 16 on any Zen 4 desktop, so we leave the address
 * fields alone and only normalize the Partition Width byte when the
 * firmware left it unspecified.
 * ------------------------------------------------------------------ */
static void
patch_type19(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    (void)pool; (void)end;
    if (fixed_len < 0x0F) return;

    if (fixed[0x0E] == 0x00 || fixed[0x0E] == 0xFF) {
        fixed[0x0E] = 0x02;    /* dual-channel desktop */
    }
}

/* ------------------------------------------------------------------
 * Type 32 — System Boot Information
 *
 * Fixed-area offsets referenced:
 *   0x04 Reserved (6 bytes, must be 0 per DMTF SMBIOS spec)
 *   0x0A Boot Status (byte 0 of the boot status array; 0 = no errors)
 *
 * No strings. Any value other than 0 in Boot Status reports a boot
 * warning / error / vendor-specific condition, several of which are
 * emitted by VM firmware when the guest boots in nonstandard modes.
 * ------------------------------------------------------------------ */
static void
patch_type32(PUCHAR fixed, UCHAR fixed_len, PUCHAR pool, PUCHAR end)
{
    (void)pool; (void)end;
    if (fixed_len < 0x0B) return;

    RtlZeroMemory(fixed + 0x04, 6);

    /* Boot Status: first byte is the standard status code; any trailing
     * bytes carry vendor/product-specific data. Clear the standard byte;
     * zero any trailing bytes the firmware filled in (they are only
     * defined when byte 0 is >= 0x80, which no longer applies). */
    fixed[0x0A] = 0x00;
    if (fixed_len > 0x0B) {
        RtlZeroMemory(fixed + 0x0B, (SIZE_T)fixed_len - 0x0B);
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

    /* Pre-walk: patch_type16 needs the DIMM count and total MB and
     * patch_type17 needs the Type 16 handle; both must be known before
     * either structure is rewritten. The main pass runs forward once. */
    struct dmi_prewalk_info info;
    dmi_prewalk(blob, len, &info);

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
        case 0:   patch_type0 (p, fixed_len, pool_start, pool_end); break;
        case 1:   patch_type1 (p, fixed_len, pool_start, pool_end); break;
        case 2:   patch_type2 (p, fixed_len, pool_start, pool_end); break;
        case 3:   patch_type3 (p, fixed_len, pool_start, pool_end); break;
        case 4:   patch_type4 (p, fixed_len, pool_start, pool_end); break;
        case 7:   patch_type7 (p, fixed_len, pool_start, pool_end); break;
        case 11:  patch_type11(p, fixed_len, pool_start, pool_end); break;
        case 16:  patch_type16(p, fixed_len, pool_start, pool_end, &info); break;
        case 17:  patch_type17(p, fixed_len, pool_start, pool_end, &info); break;
        case 19:  patch_type19(p, fixed_len, pool_start, pool_end); break;
        case 32:  patch_type32(p, fixed_len, pool_start, pool_end); break;
        case 127: return;   /* end of table */
        default: break;
        }

        p = pool_end;
    }
}
