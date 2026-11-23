/* identity.c -- seed-derived field expansion and per-vCPU identity table.
 *
 * Two entry points:
 *
 *   identity_compute_all(seed, cfg)
 *       Full installer-side expansion. Fills every seed-controlled field
 *       of CHAMBER_CFG_V2 (machine identity + HV identity, excluding
 *       magic/version/total_length/toggles which the installer owns).
 *       Driver code never calls this; the driver reads the already-
 *       expanded blob written by patcher.exe. Lives here so that a
 *       shared build (patcher includes driver/identity.c directly) sees
 *       the same bytes as the kernel-side code.
 *
 *   identity_apply(cfg)
 *       Driver-side runtime. Allocates g_cpu_identity (one entry per
 *       vCPU), derives single-valued state (microcode rev, platform ID,
 *       CPU signature, TSC/frequency fields) from cfg->seed, and seeds
 *       per-vCPU APIC IDs and TSC_AUX latches. VMEXIT handlers call the
 *       getters below to rewrite guest CPUID / RDMSR returns.
 *
 * Every byte that enters g_cpu_identity or g_identity_* comes from
 * chamber_derive(seed, field, ...). No host-side fallbacks, no live
 * CPUID reads: a reseed must change every process-observable
 * fingerprint.
 *
 * ASCII only. No branded identifiers. */

#include "identity.h"

/* --- Single-valued derived state ------------------------------------ */
CHAMBER_CPU_IDENTITY *g_cpu_identity = NULL;
ULONGLONG g_identity_microcode_rev   = 0;
ULONGLONG g_identity_platform_id     = 0;
ULONG     g_identity_cpu_signature   = 0;
ULONG     g_identity_cpu_ext_feat_ecx = 0;
ULONG     g_identity_cpu_ext_feat_edx = 0;
ULONG     g_identity_tsc_denom       = 0;
ULONG     g_identity_tsc_numer       = 0;
ULONG     g_identity_tsc_crystal     = 0;
ULONG     g_identity_cpu_base_mhz    = 0;
ULONG     g_identity_cpu_max_mhz     = 0;
ULONG     g_identity_cpu_bus_mhz     = 0;
BOOLEAN   g_identity_valid           = FALSE;

/* ------------------------------------------------------------------- */
/* Format helpers for identity_compute_all.                            */
/* ------------------------------------------------------------------- */

static void fmt_alphanum_upper(UCHAR *buf, UCHAR *scratch, SIZE_T n)
{
    static const char ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    SIZE_T i;
    for (i = 0; i < n; i++) {
        buf[i] = (UCHAR)ALPHA[scratch[i] % 36];
    }
}

static void fmt_alphanum_mixed_lead_lower(UCHAR *buf, UCHAR *scratch, SIZE_T n)
{
    /* First char from [a-z]; remainder from [a-z0-9]. Service name shape. */
    static const char LOWER[] = "abcdefghijklmnopqrstuvwxyz";
    static const char LOWNUM[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    SIZE_T i;
    if (n == 0) return;
    buf[0] = (UCHAR)LOWER[scratch[0] % 26];
    for (i = 1; i < n; i++) {
        buf[i] = (UCHAR)LOWNUM[scratch[i] % 36];
    }
}

static const char *const BRAND_POOL[] = {
    "AMD Ryzen 7 7700X 8-Core Processor",
    "AMD Ryzen 9 7900X 12-Core Processor",
    "AMD Ryzen 9 7950X 16-Core Processor",
    "AMD Ryzen 7 5800X 8-Core Processor",
    "AMD Ryzen 5 5600X 6-Core Processor",
    "Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz",
    "Intel(R) Core(TM) i9-13900K CPU @ 3.00GHz",
    "Intel(R) Core(TM) i5-12400 CPU @ 2.50GHz"
};

/* Zen 4 host: default to the AMD-only subset so family/model/stepping
 * stays consistent across intercepted and non-intercepted CPUID leaves. */
#define BRAND_POOL_AMD_COUNT   5
#define BRAND_POOL_TOTAL_COUNT (sizeof(BRAND_POOL)/sizeof(BRAND_POOL[0]))

static SIZE_T ascii_len(const char *s) {
    SIZE_T n = 0;
    while (s[n]) n++;
    return n;
}

static void brand_to_48(const char *brand, UCHAR out[48])
{
    SIZE_T n = ascii_len(brand);
    SIZE_T i;
    if (n > 47) n = 47;
    for (i = 0; i < n; i++)  out[i] = (UCHAR)brand[i];
    for (i = n; i < 47; i++) out[i] = ' ';
    out[47] = 0;
}

static const UCHAR OUI_POOL[8][3] = {
    { 0x24, 0x4b, 0xfe }, /* ASUSTeK */
    { 0xb0, 0x25, 0xaa }, /* Dell    */
    { 0x00, 0x25, 0xb3 }, /* HPE     */
    { 0x18, 0xc0, 0x4d }, /* Intel   */
    { 0x50, 0xeb, 0x71 }, /* Realtek */
    { 0x74, 0xd4, 0x35 }, /* Gigabyte */
    { 0x28, 0x80, 0x88 }, /* Lenovo  */
    { 0xa4, 0x1f, 0x72 }  /* MSI     */
};

static const char *const BIOS_VENDOR_POOL[] = {
    "American Megatrends",
    "Phoenix Technologies",
    "Insyde Corp.",
    "AMI",
    "Award Software Intl"
};

static const char *const BIOS_VERSION_POOL[] = {
    "F.27", "2.A1", "1801", "P3.80", "5.17", "F.14"
};

static const ULONG GPU_VEN_DEV_POOL[] = {
    0x10DE2684UL,  /* RTX 4090      */
    0x10DE2782UL,  /* RTX 4070      */
    0x10DE1E07UL,  /* RTX 2080 Ti   */
    0x10022208UL,  /* RX 7900 XTX   */
    0x1002731FUL,  /* RX 5700 XT    */
    0x86415690UL   /* Intel UHD 630 */
};

/* CRC-32 (IEEE 802.3, poly 0xEDB88320) used to stamp a plausible trailer
 * on the DigitalProductId blob. Not security critical; just enough so a
 * sample that CRC-checks the trailer sees a self-consistent value. */
static ULONG crc32_ieee(const UCHAR *data, SIZE_T len)
{
    static const ULONG P = 0xEDB88320UL;
    ULONG c = 0xFFFFFFFFUL;
    SIZE_T i;
    ULONG b;
    for (i = 0; i < len; i++) {
        c ^= (ULONG)data[i];
        for (b = 0; b < 8; b++) {
            c = (c & 1u) ? (c >> 1) ^ P : (c >> 1);
        }
    }
    return c ^ 0xFFFFFFFFUL;
}

/* Scratch buffer sized to the largest single derivation (digital_product_id
 * at 164 bytes). Reused across fields; allocated on stack. */
#define DERIVE_SCRATCH_MAX 192

NTSTATUS identity_compute_all(const UCHAR seed[32], CHAMBER_CFG_V2 *cfg)
{
    UCHAR scratch[DERIVE_SCRATCH_MAX];
    ULONG u32;
    ULONGLONG u64;
    SIZE_T i;

    if (!seed || !cfg) return STATUS_INVALID_PARAMETER;

    /* ---- HV identity --------------------------------------------- */

    chamber_derive(seed, "service_name", scratch, 12);
    fmt_alphanum_mixed_lead_lower(cfg->service_name, scratch, 11);
    cfg->service_name[11] = 0;

    chamber_derive(seed, "device_suffix", scratch, 12);
    fmt_alphanum_mixed_lead_lower(cfg->device_suffix, scratch, 11);
    cfg->device_suffix[11] = 0;

    {
        static const char *const POOL_FIELD[] = {
            "pool_tag_svm",      "pool_tag_npt",
            "pool_tag_vmexit",   "pool_tag_dump",
            "pool_tag_integrity","pool_tag_dispatch"
        };
        static const char LETTERS[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        for (i = 0; i < 6; i++) {
            UCHAR tag_bytes[4];
            SIZE_T j;
            chamber_derive(seed, POOL_FIELD[i], scratch, 4);
            for (j = 0; j < 4; j++) {
                tag_bytes[j] = (UCHAR)LETTERS[scratch[j] % 52];
            }
            cfg->pool_tag[i] = ((ULONG)tag_bytes[0])       |
                               ((ULONG)tag_bytes[1] <<  8) |
                               ((ULONG)tag_bytes[2] << 16) |
                               ((ULONG)tag_bytes[3] << 24);
        }
    }

    chamber_derive(seed, "vmmcall_magic", scratch, 8);
    u64 = 0;
    for (i = 0; i < 8; i++) u64 |= ((ULONGLONG)scratch[i]) << (i * 8);
    cfg->vmmcall_magic = u64;

    chamber_derive(seed, "cfg_magic_override", scratch, 8);
    u64 = 0;
    for (i = 0; i < 8; i++) u64 |= ((ULONGLONG)scratch[i]) << (i * 8);
    cfg->chamber_cfg_magic_override = u64;

    chamber_derive(seed, "rename_donor", scratch, 1);
    cfg->rename_donor_index = scratch[0];
    cfg->_pad0[0] = 0; cfg->_pad0[1] = 0; cfg->_pad0[2] = 0;

    chamber_derive(seed, "guest_asid", scratch, 4);
    u32 = ((ULONG)scratch[0]) | ((ULONG)scratch[1] << 8) |
          ((ULONG)scratch[2] << 16) | ((ULONG)scratch[3] << 24);
    /* Fit into [0x1000, 0x7FFF]. */
    cfg->guest_asid = 0x1000u + (u32 & 0x6FFFu);

    chamber_derive(seed, "section_scramble", scratch, 4);
    cfg->section_scramble_seed = ((ULONG)scratch[0]) |
                                 ((ULONG)scratch[1] <<  8) |
                                 ((ULONG)scratch[2] << 16) |
                                 ((ULONG)scratch[3] << 24);

    chamber_derive(seed, "driver_nonce", scratch, 8);
    u64 = 0;
    for (i = 0; i < 8; i++) u64 |= ((ULONGLONG)scratch[i]) << (i * 8);
    cfg->driver_nonce = u64;

    /* ---- Machine identity ---------------------------------------- */

    chamber_derive(seed, "computer_name", scratch, 16);
    fmt_alphanum_upper(cfg->computer_name, scratch, 15);
    cfg->computer_name[15] = 0;

    chamber_derive(seed, "machine_guid", scratch, 16);
    for (i = 0; i < 16; i++) cfg->machine_guid[i] = scratch[i];
    cfg->machine_guid[6] = (UCHAR)(0x40u | (cfg->machine_guid[6] & 0x0Fu));
    cfg->machine_guid[8] = (UCHAR)(0x80u | (cfg->machine_guid[8] & 0x3Fu));

    chamber_derive(seed, "install_date", scratch, 8);
    u64 = 0;
    for (i = 0; i < 8; i++) u64 |= ((ULONGLONG)scratch[i]) << (i * 8);
    /* FILETIME window [2019-01-01, 2024-01-01). Pre-computed 100-ns units. */
    {
        const ULONGLONG LO = 132223104000000000ULL; /* 2019-01-01 UTC */
        const ULONGLONG HI = 133800768000000000ULL; /* 2024-01-01 UTC */
        const ULONGLONG RANGE = HI - LO;
        cfg->install_date_filetime = LO + (u64 % RANGE);
    }

    chamber_derive(seed, "product_id", scratch, 32);
    {
        static const char ALNUM[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        UCHAR chars[20];
        SIZE_T src = 0;
        for (i = 0; i < 20; i++) chars[i] = (UCHAR)ALNUM[scratch[src++] % 36];
        cfg->product_id[0]  = chars[0]; cfg->product_id[1]  = chars[1];
        cfg->product_id[2]  = chars[2]; cfg->product_id[3]  = chars[3];
        cfg->product_id[4]  = chars[4]; cfg->product_id[5]  = '-';
        cfg->product_id[6]  = chars[5]; cfg->product_id[7]  = chars[6];
        cfg->product_id[8]  = chars[7]; cfg->product_id[9]  = chars[8];
        cfg->product_id[10] = chars[9]; cfg->product_id[11] = '-';
        cfg->product_id[12] = chars[10]; cfg->product_id[13] = chars[11];
        cfg->product_id[14] = chars[12]; cfg->product_id[15] = chars[13];
        cfg->product_id[16] = chars[14]; cfg->product_id[17] = '-';
        cfg->product_id[18] = chars[15]; cfg->product_id[19] = chars[16];
        cfg->product_id[20] = chars[17]; cfg->product_id[21] = chars[18];
        cfg->product_id[22] = chars[19]; cfg->product_id[23] = 0;
    }

    /* DigitalProductId: 164 bytes, last 4 bytes = CRC32 of first 160. */
    {
        UCHAR dpid_scratch[164];
        chamber_derive(seed, "digital_product_id", dpid_scratch, 164);
        for (i = 0; i < 164; i++) cfg->digital_product_id[i] = dpid_scratch[i];
        {
            ULONG crc = crc32_ieee(cfg->digital_product_id, 160);
            cfg->digital_product_id[160] = (UCHAR)(crc      );
            cfg->digital_product_id[161] = (UCHAR)(crc >>  8);
            cfg->digital_product_id[162] = (UCHAR)(crc >> 16);
            cfg->digital_product_id[163] = (UCHAR)(crc >> 24);
        }
    }

    chamber_derive(seed, "cpu_brand", scratch, 4);
    {
        SIZE_T idx = scratch[0] % BRAND_POOL_AMD_COUNT;
        brand_to_48(BRAND_POOL[idx], cfg->cpu_brand_string);
    }

    chamber_derive(seed, "smbios_uuid", scratch, 16);
    for (i = 0; i < 16; i++) cfg->smbios_system_uuid[i] = scratch[i];
    cfg->smbios_system_uuid[6] = (UCHAR)(0x40u | (cfg->smbios_system_uuid[6] & 0x0Fu));
    cfg->smbios_system_uuid[8] = (UCHAR)(0x80u | (cfg->smbios_system_uuid[8] & 0x3Fu));

    chamber_derive(seed, "baseboard_serial", scratch, 16);
    fmt_alphanum_upper(cfg->baseboard_serial, scratch, 12);
    for (i = 12; i < 16; i++) cfg->baseboard_serial[i] = 0;

    chamber_derive(seed, "chassis_serial", scratch, 16);
    fmt_alphanum_upper(cfg->chassis_serial, scratch, 12);
    for (i = 12; i < 16; i++) cfg->chassis_serial[i] = 0;

    chamber_derive(seed, "bios_vendor", scratch, 4);
    {
        const char *v = BIOS_VENDOR_POOL[scratch[0] % (sizeof(BIOS_VENDOR_POOL)/sizeof(BIOS_VENDOR_POOL[0]))];
        SIZE_T vlen = ascii_len(v);
        if (vlen > 15) vlen = 15;
        for (i = 0; i < vlen; i++) cfg->bios_vendor[i] = (UCHAR)v[i];
        for (i = vlen; i < 16; i++) cfg->bios_vendor[i] = 0;
    }

    chamber_derive(seed, "bios_version", scratch, 4);
    {
        const char *v = BIOS_VERSION_POOL[scratch[0] % (sizeof(BIOS_VERSION_POOL)/sizeof(BIOS_VERSION_POOL[0]))];
        SIZE_T vlen = ascii_len(v);
        SIZE_T out  = 0;
        static const char HEX[] = "0123456789ABCDEF";
        if (vlen > 13) vlen = 13;
        for (i = 0; i < vlen; i++) cfg->bios_version[out++] = (UCHAR)v[i];
        cfg->bios_version[out++] = (UCHAR)HEX[scratch[1] & 0x0Fu];
        cfg->bios_version[out++] = (UCHAR)HEX[scratch[2] & 0x0Fu];
        for (i = out; i < 16; i++) cfg->bios_version[i] = 0;
    }

    for (i = 0; i < 6; i++) {
        static const char *const MAC_FIELD[] = {
            "mac_addr_0", "mac_addr_1", "mac_addr_2",
            "mac_addr_3", "mac_addr_4", "mac_addr_5"
        };
        chamber_derive(seed, MAC_FIELD[i], scratch, 4);
        cfg->mac_addrs[i][0] = (UCHAR)(scratch[0] % 8U); /* OUI pool index */
        cfg->mac_addrs[i][1] = scratch[1];
        cfg->mac_addrs[i][2] = scratch[2];
        cfg->mac_addrs[i][3] = scratch[3];
    }

    for (i = 0; i < 20; i++) {
        /* Per-slot tag; interceptor re-derives the full 20-char serial
         * at return-rewrite time using "disk_serial_<i>". */
        char fn[16];
        SIZE_T k = 0; SIZE_T idx = i;
        fn[k++] = 'd'; fn[k++] = 'i'; fn[k++] = 's'; fn[k++] = 'k';
        fn[k++] = '_'; fn[k++] = 's'; fn[k++] = 'l'; fn[k++] = 'o';
        fn[k++] = 't'; fn[k++] = '_';
        if (idx >= 10) { fn[k++] = (char)('0' + (idx / 10)); idx %= 10; }
        fn[k++] = (char)('0' + idx);
        fn[k] = 0;
        chamber_derive(seed, fn, scratch, 4);
        cfg->disk_serials[i][0] = scratch[0];
        cfg->disk_serials[i][1] = scratch[1];
        cfg->disk_serials[i][2] = scratch[2];
        cfg->disk_serials[i][3] = scratch[3];
    }

    for (i = 0; i < 4; i++) {
        static const char *const VOL_FIELD[] = {
            "volume_serial_0", "volume_serial_1",
            "volume_serial_2", "volume_serial_3"
        };
        chamber_derive(seed, VOL_FIELD[i], scratch, 4);
        cfg->volume_serials[i][0] = scratch[0];
        cfg->volume_serials[i][1] = scratch[1];
        cfg->volume_serials[i][2] = scratch[2];
        cfg->volume_serials[i][3] = scratch[3];
    }

    chamber_derive(seed, "gpu_ven_dev", scratch, 4);
    cfg->gpu_ven_dev = GPU_VEN_DEV_POOL[scratch[0] %
        (sizeof(GPU_VEN_DEV_POOL)/sizeof(GPU_VEN_DEV_POOL[0]))];

    chamber_derive(seed, "edid_nonce", scratch, 16);
    for (i = 0; i < 16; i++) cfg->edid_nonce[i] = scratch[i];

    /* Silence unused warnings for the OUI table when identity_compute_all
     * is the only user in this TU and later per-adapter lookups live
     * inside the interceptor driver. */
    (void)OUI_POOL;
    (void)BRAND_POOL_TOTAL_COUNT;

    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------- */
/* Driver-side apply + getters.                                        */
/* ------------------------------------------------------------------- */

static ULONG derive_u32(const UCHAR seed[32], const char *field)
{
    UCHAR s[4];
    chamber_derive(seed, field, s, 4);
    return ((ULONG)s[0]) |
           ((ULONG)s[1] <<  8) |
           ((ULONG)s[2] << 16) |
           ((ULONG)s[3] << 24);
}

static ULONGLONG derive_u64(const UCHAR seed[32], const char *field)
{
    UCHAR s[8];
    SIZE_T i;
    ULONGLONG v = 0;
    chamber_derive(seed, field, s, 8);
    for (i = 0; i < 8; i++) v |= ((ULONGLONG)s[i]) << (i * 8);
    return v;
}

NTSTATUS identity_apply(const CHAMBER_CFG_V2 *cfg)
{
    SIZE_T i;

    if (!cfg) return STATUS_INVALID_PARAMETER;
    if (g_cpu_count == 0) return STATUS_UNSUCCESSFUL;

    /* ---- Single-valued derived state ----------------------------- */

    /* CPU signature (CPUID 0x1 EAX). Zen 4 family 0x19, model mask set
     * so a Ryzen 7700X-shaped signature stays plausible even when the
     * launcher later lets the pool widen. */
    {
        ULONG raw = derive_u32(cfg->seed, "cpu_signature");
        /* Family 0x19 = 25. Extended family = 0x19 - 0xF = 0x0A.
         * Bits 27:20 extended family, 19:16 extended model,
         * 11:8 family (0xF), 7:4 model, 3:0 stepping. */
        ULONG stepping = raw & 0x0Fu;
        ULONG model    = (raw >>  4) & 0x0Fu;
        ULONG ext_mod  = (raw >>  8) & 0x0Fu;
        g_identity_cpu_signature =
            (0x0AU << 20) | (ext_mod << 16) | (0x0FU << 8) | (model << 4) | stepping;
    }

    g_identity_cpu_ext_feat_ecx = derive_u32(cfg->seed, "cpu_ext_feat_ecx");
    g_identity_cpu_ext_feat_edx = derive_u32(cfg->seed, "cpu_ext_feat_edx");

    /* MSR 0x8B upper 32 bits hold the microcode patch level; low 32 are
     * cleared by RDMSR before IA32_BIOS_SIGN_ID is read, but when read
     * via the "patch_level" alias on AMD both halves can be meaningful.
     * Emit a 64-bit derived value with the upper 32 bits reserved for
     * the patch level and the lower 32 bits left zero. */
    g_identity_microcode_rev = (ULONGLONG)derive_u32(cfg->seed, "microcode_rev") << 32;

    g_identity_platform_id   = derive_u64(cfg->seed, "platform_id");

    /* CPUID 0x15 TSC/crystal ratio. Choose a 24 MHz crystal and a
     * 100:1-ish ratio so the computed base frequency lands in a
     * believable range. The seed shifts both the ratio and the crystal
     * within narrow bands. */
    {
        ULONG r = derive_u32(cfg->seed, "tsc_ratio");
        g_identity_tsc_denom   = 1 + (r & 0x3u);         /* 1..4 */
        g_identity_tsc_numer   = 100 + (ULONG)((r >> 2) % 60u); /* 100..159 */
        g_identity_tsc_crystal = 24000000U + (ULONG)((r >> 8) % 1000000u); /* ~24 MHz */
    }

    /* CPUID 0x16 base/max/bus frequency in MHz. */
    {
        ULONG f = derive_u32(cfg->seed, "cpu_freq_mhz");
        g_identity_cpu_base_mhz = 2400U + (ULONG)((f      ) % 3000u); /* 2.4..5.4 GHz */
        g_identity_cpu_max_mhz  = g_identity_cpu_base_mhz +
                                  (ULONG)((f >>  8) % 1000u);
        g_identity_cpu_bus_mhz  = 100U;
    }

    /* ---- Per-vCPU table ----------------------------------------- */

    if (g_cpu_identity) {
        ExFreePoolWithTag(g_cpu_identity, POOLTAG("per_cpu_identity"));
        g_cpu_identity = NULL;
    }
    g_cpu_identity = (CHAMBER_CPU_IDENTITY *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(CHAMBER_CPU_IDENTITY) * g_cpu_count,
        POOLTAG("per_cpu_identity"));
    if (!g_cpu_identity) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_cpu_identity,
                  sizeof(CHAMBER_CPU_IDENTITY) * g_cpu_count);

    {
        ULONG apic_base = derive_u32(cfg->seed, "apic_id_base") & 0xFFu;
        for (i = 0; i < g_cpu_count; i++) {
            char fn[24];
            SIZE_T k = 0; SIZE_T idx = i;
            fn[k++] = 't'; fn[k++] = 's'; fn[k++] = 'c';
            fn[k++] = '_'; fn[k++] = 'a'; fn[k++] = 'u'; fn[k++] = 'x';
            fn[k++] = '_';
            if (idx >= 10) { fn[k++] = (char)('0' + (idx / 10)); idx %= 10; }
            fn[k++] = (char)('0' + idx);
            fn[k] = 0;

            g_cpu_identity[i].apic_id =
                (apic_base + (ULONG)i) & 0xFFu;
            g_cpu_identity[i].x2apic_id =
                apic_base + (ULONG)i;
            g_cpu_identity[i].tsc_aux_latched = derive_u64(cfg->seed, fn);
            g_cpu_identity[i].tsc_aux_latched_valid = FALSE;
        }
    }

    g_identity_valid = TRUE;
    return STATUS_SUCCESS;
}

void identity_release(void)
{
    g_identity_valid = FALSE;
    if (g_cpu_identity) {
        ExFreePoolWithTag(g_cpu_identity, POOLTAG("per_cpu_identity"));
        g_cpu_identity = NULL;
    }
}

ULONG identity_get_apic_id(ULONG vcpu)
{
    if (!g_cpu_identity || vcpu >= g_cpu_count) return 0;
    return g_cpu_identity[vcpu].apic_id;
}

ULONG identity_get_x2apic_id(ULONG vcpu)
{
    if (!g_cpu_identity || vcpu >= g_cpu_count) return 0;
    return g_cpu_identity[vcpu].x2apic_id;
}

ULONGLONG identity_get_tsc_aux(ULONG vcpu)
{
    if (!g_cpu_identity || vcpu >= g_cpu_count) return 0;
    return g_cpu_identity[vcpu].tsc_aux_latched;
}

void identity_set_tsc_aux(ULONG vcpu, ULONGLONG value)
{
    if (!g_cpu_identity || vcpu >= g_cpu_count) return;
    g_cpu_identity[vcpu].tsc_aux_latched = value;
    g_cpu_identity[vcpu].tsc_aux_latched_valid = TRUE;
}
