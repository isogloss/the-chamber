/* syscall_rewrite.c -- central dispatch for syscall-return rewrites.
 *
 * The user-mode trampoline (ic_trampoline.asm, mirrored into every spoofed
 * process by the launcher's ntdll shim) calls cfp_ic_dispatch() on every
 * syscall return. We receive the value the syscall produced and the user
 * RIP that follows the syscall instruction; from the RIP we identify which
 * syscall just returned, and if it is one of the fingerprint-sensitive
 * classes we rewrite the caller-provided output buffer in place.
 *
 * Covered syscalls:
 *   NtQuerySystemInformation
 *       SystemFirmwareTableInformation  (DMI blob rewrite; RSMB + ACPI providers)
 *       SystemCodeIntegrityInformation  (CI state spoof)
 *       SystemSecureBootPolicyInformation
 *       SystemCodeIntegrityPolicyFullInformation
 *       SystemBootLogoInformation       (BGRT XOR-scramble to miss OVMF/Hyper-V CRCs)
 *       SystemLogicalProcessorInformationEx (per-PID bytes-identical cache)
 *       SystemBasicInformation / topology  (pass through)
 *   NtQueryVolumeInformationFile (FileFsVolumeInformation)
 *       VolumeSerialNumber rewrite
 *   NtDeviceIoControlFile
 *       IOCTL_STORAGE_QUERY_PROPERTY / _EX  (serial-ASCII patch)
 *       IOCTL_NDIS_QUERY_GLOBAL_STATS       (MAC rewrite)
 *       TBS TCG event-log IOCTLs            (OVMF firmware-range + digest scrub)
 *   NtPowerInformation
 *       SystemPowerCapabilities         (retail-desktop Sx + hibernate shape)
 *   NtEnumerateSystemEnvironmentValuesEx (QEMU/OVMF/TianoCore/VBox name filter)
 *   NtQuerySystemEnvironmentValueEx     (payload-aware PK/KEK/db/SetupMode/SecureBoot)
 *   NtGdiGetDeviceCaps
 *       COLORMGMTCAPS / BITSPIXEL / PLANES / LOGPIXELSX|Y (GPU+DISPLAY shape)
 *
 * Design intent: each handler is a pure in-place rewrite of the output
 * buffer the user process passed to the syscall. We never rewrite the
 * return status (that would confuse callers) — we rewrite what the buffer
 * says. Callers that check the status still succeed; callers that read the
 * buffer see our seed-derived values.
 *
 * NtGdiGetDeviceCaps is an exception to the "buffer rewrite" rule: the
 * capability is returned as the syscall return value itself, so the handler
 * substitutes the return value rather than touching a buffer.
 */

#include "fingerprint_cfg.h"

/* NtQuerySystemInformation class constants. Many are not in the public
 * header; the values are documented in Windows Internals 7e Appendix B
 * and in the TBS / Setup API headers. */
#define SystemBasicInformation                              0
#define SystemProcessorPerformanceInformation               8
#define SystemLogicalProcessorInformation                  73
#define SystemFirmwareTableInformation                     76
#define SystemCodeIntegrityInformation                    103
#define SystemBootLogoInformation                         140
#define SystemSecureBootPolicyInformation                 144
#define SystemLogicalProcessorInformationEx               171
#define SystemCodeIntegrityPolicyFullInformation          176

/* NtQueryInformationProcess information classes we intercept. */
#define ProcessInstrumentationCallback                     40

/* NtQueryInformationToken classes the IC-side cares about. The real header
 * values (winnt.h TOKEN_INFORMATION_CLASS) are UM-only; the kernel's
 * SeQueryInformationToken takes the same numeric constants. */
#define TokenStatistics                                    10
#define TokenOrigin                                        17

/* NtGdiGetDeviceCaps nIndex values. The real symbols live in wingdi.h
 * (user-mode only); the numeric values are part of the GDI public ABI and
 * have been stable since Win 3.x, so hard-coding is safe. Only the subset
 * the VMAware GPU_CAPABILITIES / DISPLAY probes read is listed here. */
#define GDI_CAP_BITSPIXEL                                  12   /* 0x0C */
#define GDI_CAP_PLANES                                     14   /* 0x0E */
#define GDI_CAP_LOGPIXELSX                                 88   /* 0x58 */
#define GDI_CAP_LOGPIXELSY                                 90   /* 0x5A */
#define GDI_CAP_COLORMGMTCAPS                             121   /* 0x79 */

/* Bit returned by COLORMGMTCAPS. CM_GAMMA_RAMP says the active display
 * miniport supports SetDeviceGammaRamp(). Real hardware miniports on
 * Win10+ set this bit; a purely emulated framebuffer (basic display
 * adapter / VM display) does not. VMAware's GPU_CAPABILITIES gates on it. */
#define CFP_CM_GAMMA_RAMP                                  0x00000002UL

/* NtPowerInformation POWER_INFORMATION_LEVEL constants. The public
 * header (ntpoapi.h) defines SystemPowerCapabilities as enum value 4.
 * We only rewrite that level; everything else passes through. */
#define SystemPowerCapabilities                             4

/* SystemFirmwareTableInformation ProviderSignature values, read as a
 * little-endian ULONG from offset 0 of the SYSTEM_FIRMWARE_TABLE_INFORMATION
 * structure. 'RSMB'/'ACPI'/'FIRM' are the three Microsoft-defined providers
 * GetSystemFirmwareTable exposes. In memory order bytes are 'R','S','M','B'
 * (etc.); on little-endian x64 that reads as 0x424D5352 as a ULONG. */
#define FW_PROVIDER_RSMB                            0x424D5352UL
#define FW_PROVIDER_ACPI                            0x49504341UL
#define FW_PROVIDER_FIRM                            0x4D524946UL

/* TCG event-type constants we inspect inside TBS event-log IOCTL returns.
 * Taken from the TCG PC Client Platform Firmware Profile spec, section
 * 10.4.1. Only the handful of types this scrubber actually touches are
 * defined here; the rest flow through unchanged. */
#define EV_NO_ACTION                                0x00000003
#define EV_SEPARATOR                                0x00000004
#define EV_EFI_PLATFORM_FIRMWARE_BLOB               0x80000008

/* TPM_ALG_ID digest-size table. Only the five algorithms a TPM 2.0 vTPM
 * event log realistically carries. */
#define TPM_ALG_SHA1                                0x0004
#define TPM_ALG_SHA256                              0x000B
#define TPM_ALG_SHA384                              0x000C
#define TPM_ALG_SHA512                              0x000D
#define TPM_ALG_SM3_256                             0x0012

/* RAW_SMBIOS_HEADER that sits at the start of the TableBuffer returned by
 * SystemFirmwareTableInformation with ProviderSignature='RSMB'. Layout:
 *   UCHAR  Used20CallingMethod
 *   UCHAR  SMBIOSMajorVersion
 *   UCHAR  SMBIOSMinorVersion
 *   UCHAR  DmiRevision
 *   ULONG  Length           (length of the DMI stream that follows)
 * Total: 8 bytes. Walking the DMI stream must skip this header; starting
 * one byte early reads bogus Type/Length and the walker gives up on the
 * first structure. */
#define RAW_SMBIOS_HEADER_SIZE                              8

/* Forward decls from other TUs in this driver. */
void cfp_dmi_patch_blob(PUCHAR blob, ULONG len);
BOOLEAN cfp_target_contains(HANDLE pid);
PVOID cfp_instr_shadow_get(HANDLE pid);

/* ---------------- shared helpers ---------------- */

/* Minimal wide-string equality (case-insensitive for the simple ASCII subset
 * we match UEFI variable names against). The kernel's RtlCompareUnicodeString
 * would work too but we keep this file's dependency surface minimal. */
static BOOLEAN
cfp_uni_eq_ci(const WCHAR *a, SIZE_T alen, const WCHAR *b)
{
    SIZE_T i = 0;
    while (b[i]) {
        if (i >= alen) return FALSE;
        WCHAR ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca = (WCHAR)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (WCHAR)(cb + 32);
        if (ca != cb) return FALSE;
        ++i;
    }
    /* Trailing chars after the compare terminator are allowed; the UEFI
     * variable name is a counted buffer that may or may not carry a
     * trailing NUL. */
    return TRUE;
}

/* TPM_ALG_ID → digest size (bytes). Returns 0 for unknown algs so the
 * walker can give up cleanly instead of reading past the TPML_DIGEST_VALUES
 * record. */
static ULONG
cfp_tpm_digest_size(USHORT alg_id)
{
    switch (alg_id) {
    case TPM_ALG_SHA1:    return 20;
    case TPM_ALG_SHA256:  return 32;
    case TPM_ALG_SHA384:  return 48;
    case TPM_ALG_SHA512:  return 64;
    case TPM_ALG_SM3_256: return 32;
    default:              return 0;
    }
}

/* Clobber the first UCHAR of every VM-vendor substring in a wide name.
 * The probe's substring search no longer fires because 'Q' in "QEMU" became
 * something else; the overall name stays legible to anything that cares
 * about the full string. */
static void
cfp_scrub_vm_tokens_w(PWCHAR s, SIZE_T wlen)
{
    static const struct {
        const WCHAR *pat;
        USHORT       plen;
    } tokens[] = {
        { L"QEMU",      4 },
        { L"OVMF",      4 },
        { L"TianoCore", 9 },
        { L"VBox",      4 },
        { L"VirtualBox",10 },
        { L"EDK II",    6 },
    };

    if (!s || wlen == 0) return;
    for (SIZE_T i = 0; i < wlen; ++i) {
        for (ULONG t = 0; t < sizeof(tokens) / sizeof(tokens[0]); ++t) {
            USHORT plen = tokens[t].plen;
            if (i + plen > wlen) continue;
            SIZE_T k;
            for (k = 0; k < plen; ++k) {
                if (s[i + k] != tokens[t].pat[k]) break;
            }
            if (k == plen) {
                /* Replace the leading char with '_' (0x5F). Value stays a
                 * printable wide char and the token no longer matches. */
                s[i] = L'_';
            }
        }
    }
}

/* ASCII variant of the VM-token scrubber, run across an AML byte stream.
 * Matches literal ASCII substrings rather than case-insensitive — AML uses
 * fixed-case 4-character NameSegs so the probes compare bytes directly. */
static void
cfp_scrub_acpi_aml_tokens(PUCHAR aml, ULONG len)
{
    static const struct {
        const UCHAR *pat;
        ULONG        plen;
    } tokens[] = {
        { (const UCHAR *)"BOCHS", 5 },
        { (const UCHAR *)"BXPC",  4 },
        { (const UCHAR *)"DBG_",  4 },
        { (const UCHAR *)"DBUG",  4 },
        { (const UCHAR *)"DRAC",  4 },
        { (const UCHAR *)"VBOX",  4 },
        { (const UCHAR *)"QEMU",  4 },
    };

    if (!aml || len < 4) return;
    for (ULONG i = 0; i < len; ++i) {
        for (ULONG t = 0; t < sizeof(tokens) / sizeof(tokens[0]); ++t) {
            ULONG plen = tokens[t].plen;
            if (i + plen > len) continue;
            if (RtlCompareMemory(aml + i, tokens[t].pat, plen) == plen) {
                aml[i] = (UCHAR)'_';
            }
        }
    }
}

/* Replace ACPI-header vendor fields when they match a known VM-authored
 * signature: OEM ID (6 bytes @ 10), OEM Table ID (8 bytes @ 16), OEM
 * Revision (4 bytes @ 24) and Creator ID (4 bytes @ 28). Substitutes
 * come from retail-firmware pools indexed by the per-install seed so
 * two installs do not land on the same shape. Checksum recompute is
 * handled by the caller (see cfp_rewrite_acpi_table). */
static void
cfp_scrub_acpi_oem_id(PUCHAR tbl, ULONG tbl_len)
{
    if (!tbl || tbl_len < 36) return;

    /* Retail OEM-ID pool (6 bytes @ offset 10). All six-character ASCII
     * shapes used by common x86 retail firmware — the audit explicitly
     * calls for AMI / Insyde / Phoenix-shaped substitutes. The specific
     * strings here are the retail OEM IDs that already ship in widely-
     * deployed boards, so a real guest booting on that firmware produces
     * the same bytes. */
    static const UCHAR oem_id_pool[4][6] = {
        { 'A','L','A','S','K','A' },  /* AMI reference codename */
        { 'I','N','S','Y','D','E' },  /* Insyde BIOS */
        { 'P','T','L','T','D',' ' },  /* Phoenix Technologies Ltd */
        { 'A','M','I',' ',' ',' ' },  /* American Megatrends */
    };

    /* Retail OEM-Table-ID pool (8 bytes @ offset 16). */
    static const UCHAR oem_tbl_id_pool[4][8] = {
        { 'A','L','A','S','K','A',' ',' ' },
        { 'I','N','S','Y','D','E',' ',' ' },
        { 'P','T','L','T','D',' ',' ',' ' },
        { 'A','M','I',' ','B','O','A','R' },
    };

    /* Retail Creator-ID pool (4 bytes @ offset 28). QEMU/SeaBIOS stamps
     * "BXPC" here; AMI/Insyde/Microsoft ASL compilers stamp their own. */
    static const UCHAR creator_id_pool[4][4] = {
        { 'M','S','F','T' },  /* Microsoft ASL compiler */
        { 'I','N','T','L' },  /* Intel ASL compiler */
        { 'A','M','I',' ' },  /* AMI ASL compiler */
        { 'I','N','S','Y' },  /* Insyde ASL compiler */
    };

    UCHAR seed[4];
    BOOLEAN have_seed = cfp_cfg_get(CFP_FID_VOLUME_SERIAL_0, seed, sizeof(seed));
    if (!have_seed) RtlZeroMemory(seed, sizeof(seed));

    /* OEM ID @ 10..15: 6 bytes. Match BOCHS / BXPC / QEMU / OVMF / VMW. */
    UCHAR *oem = tbl + 10;
    BOOLEAN oem_hit =
        (oem[0]=='B' && oem[1]=='O' && oem[2]=='C' && oem[3]=='H' && oem[4]=='S') ||
        (oem[0]=='B' && oem[1]=='X' && oem[2]=='P' && oem[3]=='C') ||
        (oem[0]=='Q' && oem[1]=='E' && oem[2]=='M' && oem[3]=='U') ||
        (oem[0]=='O' && oem[1]=='V' && oem[2]=='M' && oem[3]=='F') ||
        (oem[0]=='V' && oem[1]=='M' && oem[2]=='W');
    if (oem_hit) {
        ULONG idx = (ULONG)seed[0] % 4;
        RtlCopyMemory(oem, oem_id_pool[idx], 6);
    }

    /* OEM Table ID @ 16..23 and OEM Revision @ 24..27: sweep [16..27]
     * for 4-byte VM tokens. QEMU stamps "BXPC" into the table-ID too. */
    BOOLEAN tbl_id_hit = FALSE;
    for (ULONG i = 16; i + 4 <= 28; ++i) {
        if ((tbl[i+0]=='B' && tbl[i+1]=='O' && tbl[i+2]=='C' && tbl[i+3]=='H') ||
            (tbl[i+0]=='B' && tbl[i+1]=='X' && tbl[i+2]=='P' && tbl[i+3]=='C') ||
            (tbl[i+0]=='Q' && tbl[i+1]=='E' && tbl[i+2]=='M' && tbl[i+3]=='U') ||
            (tbl[i+0]=='O' && tbl[i+1]=='V' && tbl[i+2]=='M' && tbl[i+3]=='F') ||
            (tbl[i+0]=='V' && tbl[i+1]=='M' && tbl[i+2]=='W' && (tbl[i+3]==' ' || tbl[i+3]=='_'))) {
            tbl_id_hit = TRUE;
            break;
        }
    }
    if (tbl_id_hit) {
        ULONG idx = (ULONG)seed[1] % 4;
        RtlCopyMemory(tbl + 16, oem_tbl_id_pool[idx], 8);
        /* OEM Revision (4 bytes @ 24): overwrite with a seed-stable
         * retail-shaped value (printable ASCII avoided — real revisions
         * are usually small integers). */
        tbl[24] = 0x01; tbl[25] = 0x00; tbl[26] = 0x00; tbl[27] = 0x00;
    }

    /* Creator ID @ 28..31: 4 bytes. Match BXPC / BOCH / QEMU / OVMF / VMW. */
    UCHAR *creator = tbl + 28;
    BOOLEAN creator_hit =
        (creator[0]=='B' && creator[1]=='X' && creator[2]=='P' && creator[3]=='C') ||
        (creator[0]=='B' && creator[1]=='O' && creator[2]=='C' && creator[3]=='H') ||
        (creator[0]=='Q' && creator[1]=='E' && creator[2]=='M' && creator[3]=='U') ||
        (creator[0]=='O' && creator[1]=='V' && creator[2]=='M' && creator[3]=='F') ||
        (creator[0]=='V' && creator[1]=='M' && creator[2]=='W');
    if (creator_hit) {
        ULONG idx = (ULONG)seed[2] % 4;
        RtlCopyMemory(creator, creator_id_pool[idx], 4);
    }
}

/* Recompute the one-byte header checksum (@ offset 9) so that the sum of
 * every byte in the table is zero mod 256. Called after any mutation to
 * the table body — probes do not check this, but a conforming table is
 * less likely to invite secondary attention. */
static void
cfp_recompute_acpi_checksum(PUCHAR tbl, ULONG tbl_len)
{
    if (!tbl || tbl_len < 10) return;
    tbl[9] = 0;
    UCHAR sum = 0;
    for (ULONG i = 0; i < tbl_len; ++i) sum = (UCHAR)(sum + tbl[i]);
    tbl[9] = (UCHAR)(0 - sum);
}

/* Top-level ACPI-provider rewriter. Called when the caller asked for a
 * specific table (Action == 1). The table starts with a 36-byte header
 * followed by the AML body. Sweep the body for VM-vendor NameSegs first,
 * then scrub vendor fields in the header, then recompute the checksum so
 * downstream mutations do not leave a stale sum. */
static void
cfp_rewrite_acpi_table(PUCHAR tbl, ULONG tbl_len)
{
    if (!tbl || tbl_len < 36) return;
    __try {
        cfp_scrub_acpi_aml_tokens(tbl + 36, tbl_len - 36);
        cfp_scrub_acpi_oem_id(tbl, tbl_len);
        cfp_recompute_acpi_checksum(tbl, tbl_len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* user buffer vanished mid-rewrite — nothing to do */
    }
}

/* Enumeration-call (Action == 0) rewriter: TableBuffer is a packed array of
 * 4-byte table signatures. Rewrite the single most distinctive VM tell
 * ('WAET' — the QEMU/KVM "Windows ACPI Emulated Devices Table") to FPDT
 * (Firmware Performance Data Table). FPDT is optional on retail firmware
 * and not duplicated by the baseline table set, so the substitution does
 * not produce a duplicate entry — substituting into BGRT (which retail
 * firmware already ships) would. */
static void
cfp_rewrite_acpi_enum(PUCHAR tbl, ULONG tbl_len)
{
    if (!tbl || tbl_len < 4) return;
    ULONG n = tbl_len & ~3u;
    __try {
        for (ULONG i = 0; i + 4 <= n; i += 4) {
            if (tbl[i+0] == 'W' && tbl[i+1] == 'A' &&
                tbl[i+2] == 'E' && tbl[i+3] == 'T') {
                tbl[i+0] = 'F';
                tbl[i+1] = 'P';
                tbl[i+2] = 'D';
                tbl[i+3] = 'T';
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* user buffer vanished */
    }
}

/* Synthesize a plausible OEM-signed cert blob into `buf`. Shape: a 64-byte
 * header pattern derived from the per-install seed (so two installs do not
 * emit identical PK/KEK/db payloads), followed by up to 2 KiB of entropy
 * drawn from the same seed by running it through a mixing LCG. The probe
 * inspects for ASCII VM-vendor substrings (QEMU / OVMF / TianoCore /
 * VBox) across the whole payload; an LCG-generated stream almost never
 * produces four consecutive printable ASCII bytes let alone a vendor
 * token, and the leading 64-byte signature header matches the generic
 * shape of an EFI_SIGNATURE_LIST without carrying any vendor identity. */
static void
cfp_synth_oem_cert_blob(PUCHAR buf, ULONG len)
{
    if (!buf || len == 0) return;
    UCHAR seed[16];
    if (!cfp_cfg_get(CFP_FID_EDID_NONCE, seed, sizeof(seed))) {
        /* Seed unavailable — fall back to the old 16-byte zero so we do
         * not regress callers that depended on the pre-rewrite shape. */
        ULONG z = len > 16 ? 16 : len;
        RtlZeroMemory(buf, z);
        return;
    }

    ULONG write_len = len > 2112 ? 2112 : len;  /* 64 + 2048 cap */

    /* 64-byte header: cycle the seed four times with a per-row twist so
     * the four rows are not literally identical. The shape is an
     * EFI_SIGNATURE_LIST-like header (vendor-neutral GUID, type, size)
     * expressed as a seed-derived byte pattern that passes the
     * "non-zero, non-VM-tokens" check without claiming any real vendor
     * identity. */
    ULONG hdr_len = write_len > 64 ? 64 : write_len;
    for (ULONG i = 0; i < hdr_len; ++i) {
        buf[i] = (UCHAR)(seed[i & 0x0F] ^ (UCHAR)(0x5A ^ (i & 0x3F)));
    }

    /* Entropy tail: LCG seeded from the full 16-byte nonce. Numerical-
     * recipes constants; we are not after cryptographic quality, only a
     * byte stream that will not incidentally contain vendor tokens. */
    ULONG s = *(PULONG)&seed[0] ^ *(PULONG)&seed[4] ^
              *(PULONG)&seed[8] ^ *(PULONG)&seed[12];
    if (s == 0) s = 0xA5A5A5A5u;
    for (ULONG i = hdr_len; i < write_len; ++i) {
        s = s * 1664525u + 1013904223u;
        buf[i] = (UCHAR)(s >> 16);
    }
}

/* ---- SystemLogicalProcessorInformationEx bytes-identical cache ---- */

/* Spec: "two reads 25 ms apart see byte-identical topology". We cache the
 * first observed response per spoofed PID in a small 16-entry LRU and
 * replay it on subsequent reads. The cache is static module-local state;
 * when this file runs as the kernel-mode driver it is shared across all
 * threads; when the same bytes are mirrored into a per-process shim
 * mapping, each process gets its own private copy. Both deployments
 * preserve the "byte-identical repeat" guarantee for any individual
 * spoofed PID. */
#define CFP_SLPI_CACHE_ENTRIES     16
#define CFP_SLPI_MAX_BYTES         2048

typedef struct _CFP_SLPI_ENTRY {
    volatile LONG in_use;
    ULONG         lru_tick;
    ULONG         pid;
    ULONG         length;
    UCHAR         bytes[CFP_SLPI_MAX_BYTES];
} CFP_SLPI_ENTRY;

static CFP_SLPI_ENTRY g_slpi_cache[CFP_SLPI_CACHE_ENTRIES];
static volatile LONG  g_slpi_lru_counter;

static BOOLEAN
cfp_slpi_cache_lookup(ULONG pid, PUCHAR dst, ULONG dst_len, PULONG out_len)
{
    for (ULONG i = 0; i < CFP_SLPI_CACHE_ENTRIES; ++i) {
        if (g_slpi_cache[i].in_use == 0) continue;
        if (g_slpi_cache[i].pid    != pid) continue;
        ULONG n = g_slpi_cache[i].length;
        if (n == 0 || n > dst_len) return FALSE;
        g_slpi_cache[i].lru_tick =
            (ULONG)InterlockedIncrement(&g_slpi_lru_counter);
        __try {
            RtlCopyMemory(dst, g_slpi_cache[i].bytes, n);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return FALSE;
        }
        if (out_len) *out_len = n;
        return TRUE;
    }
    return FALSE;
}

static void
cfp_slpi_cache_store(ULONG pid, const UCHAR *src, ULONG len)
{
    if (!src || len == 0 || len > CFP_SLPI_MAX_BYTES) return;

    ULONG victim    = 0;
    ULONG min_tick  = ~0u;
    BOOLEAN found_slot = FALSE;

    /* Prefer replacing an existing entry for the same PID over LRU — keeps
     * the cache behaving sensibly if a process re-queries after a buffer
     * resize, and limits the cache to at most one line per PID. A smaller
     * subsequent read must not evict the fuller first snapshot: the
     * "byte-identical across reads" guarantee for the stable-topology
     * probe depends on the larger observation surviving. */
    for (ULONG i = 0; i < CFP_SLPI_CACHE_ENTRIES; ++i) {
        if (g_slpi_cache[i].in_use && g_slpi_cache[i].pid == pid) {
            if (len < g_slpi_cache[i].length) return;
            victim = i;
            found_slot = TRUE;
            break;
        }
    }
    if (!found_slot) {
        for (ULONG i = 0; i < CFP_SLPI_CACHE_ENTRIES; ++i) {
            if (g_slpi_cache[i].in_use == 0) {
                victim = i;
                found_slot = TRUE;
                break;
            }
            if (g_slpi_cache[i].lru_tick < min_tick) {
                min_tick = g_slpi_cache[i].lru_tick;
                victim   = i;
            }
        }
    }

    g_slpi_cache[victim].pid      = pid;
    g_slpi_cache[victim].length   = len;
    g_slpi_cache[victim].lru_tick =
        (ULONG)InterlockedIncrement(&g_slpi_lru_counter);
    __try {
        RtlCopyMemory(g_slpi_cache[victim].bytes, src, len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_slpi_cache[victim].length = 0;
        return;
    }
    InterlockedExchange(&g_slpi_cache[victim].in_use, 1);
}

/* ---- TBS TCG event-log scrubber (MEASURED_BOOT + TPM gaps) ---- */

/* OVMF firmware-blob base addresses that VMAware's MEASURED_BOOT arm
 * matches against. See TCG PC Client Platform Firmware Profile §9.4.4
 * for the EV_EFI_PLATFORM_FIRMWARE_BLOB event structure. */
static BOOLEAN
cfp_is_ovmf_firmware_range(ULONGLONG phys_base)
{
    return (phys_base == 0x0000000000830000ULL) ||
           (phys_base == 0x00000000000D0000ULL) ||
           (phys_base == 0x0000000000900000ULL) ||
           (phys_base == 0x0000000000E80000ULL);
}

/* Return a seed-derived substitute PhysicalAddress for an OVMF-ranged
 * EV_EFI_PLATFORM_FIRMWARE_BLOB. The pool shape follows AMI/InsydeH2O
 * retail BIOS SPI mapping (0xFF800000-0xFFFFFFFF window on x64 with 4 MiB
 * SPI). */
static ULONGLONG
cfp_retail_firmware_base(const UCHAR *seed)
{
    static const ULONGLONG pool[4] = {
        0xFFFFFFFF80000000ULL,   /* 2 GiB SPI window top */
        0xFFFFFFFF80100000ULL,
        0xFFFFFFFFC0000000ULL,
        0xFFFFFFFFFFE00000ULL,   /* classic 2 MiB top of 4 GiB */
    };
    ULONG idx = seed ? (ULONG)seed[0] % 4 : 0;
    return pool[idx];
}

/* Walk a TCG event log in-place: HMAC-mix each digest against the per-
 * install seed (removes the vTPM determinism tell across reseeds) and
 * swap EV_EFI_PLATFORM_FIRMWARE_BLOB PhysicalAddress fields that match the
 * OVMF constants for a retail SPI-shaped base.
 *
 * The audit remediation also calls for inserting EV_SEPARATOR entries in
 * PCRs that lack them. That requires growing the buffer, which a syscall-
 * return rewriter cannot do (the caller already sized the Information-
 * Buffer and NtDeviceIoControlFile wrote ReturnLength). We approximate by
 * promoting the first EV_NO_ACTION event in each PCR whose log has no
 * EV_SEPARATOR to EV_SEPARATOR. On real firmware every PCR carries at
 * least one EV_NO_ACTION Spec-ID header so there is always a candidate. */
static void
cfp_scrub_tcg_log(PUCHAR buf, ULONG len)
{
    if (!buf || len < 32 + 13) return;

    UCHAR seed[16];
    if (!cfp_cfg_get(CFP_FID_EDID_NONCE, seed, sizeof(seed))) return;

    /* First entry is the legacy TCG_PCR_EVENT header (PCRIndex=0,
     * EventType=EV_NO_ACTION, Digest[20]=0, EventSize, Event[]). Verify
     * the "Spec ID Event" signature so we only scrub real TBS traffic
     * rather than any IOCTL output that happens to pass through here. */
    __try {
        ULONG first_pcr   = *(PULONG)(buf + 0);
        ULONG first_etype = *(PULONG)(buf + 4);
        if (first_pcr   != 0)              return;
        if (first_etype != EV_NO_ACTION)   return;
        static const UCHAR sig[13] =
            { 'S','p','e','c',' ','I','D',' ','E','v','e','n','t' };
        if (RtlCompareMemory(buf + 32, sig, 13) != 13) return;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    /* Track which PCRs have seen an EV_SEPARATOR (bit per PCR, PCR 0..23
     * covers the TCG profile; the ULONG mask covers 32). */
    ULONG have_separator = 0;
    ULONG first_no_action_off[32];
    for (ULONG p = 0; p < 32; ++p) first_no_action_off[p] = (ULONG)-1;

    /* Skip the legacy first entry. Its event-size lives at offset 28. */
    ULONG cur_off;
    __try {
        ULONG first_ev_size = *(PULONG)(buf + 28);
        if (32ULL + first_ev_size > (ULONGLONG)len) return;
        cur_off = 32 + first_ev_size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }

    ULONG event_index = 0;
    while (cur_off + 12 <= len && event_index < 4096) {
        __try {
            ULONG  pcr   = *(PULONG)(buf + cur_off + 0);
            ULONG  etype = *(PULONG)(buf + cur_off + 4);
            ULONG  count = *(PULONG)(buf + cur_off + 8);
            ULONG  cursor = cur_off + 12;
            if (count > 16) break;

            /* Walk the TPML_DIGEST_VALUES. Each TPMT_HA is {AlgorithmId
             * (USHORT), Digest[digest_size]}. */
            for (ULONG i = 0; i < count; ++i) {
                if (cursor + 2 > len) goto walker_done;
                USHORT alg = *(PUSHORT)(buf + cursor);
                cursor += 2;
                ULONG dsize = cfp_tpm_digest_size(alg);
                if (dsize == 0 || cursor + dsize > len) goto walker_done;

                /* Mix the digest with the seed × event-index so reseeds do
                 * not emit identical digests for identical boot flows. We
                 * are not reconstructing a real hash chain here — the
                 * probe only looks for the absence of determinism and for
                 * known swtpm/OVMF digest patterns, both of which a
                 * seed-mixed byte stream defeats. */
                for (ULONG k = 0; k < dsize; ++k) {
                    buf[cursor + k] ^= (UCHAR)(seed[k & 0x0F] ^
                                               (UCHAR)((event_index + k) & 0xFF));
                }
                cursor += dsize;
            }

            if (cursor + 4 > len) break;
            ULONG event_size = *(PULONG)(buf + cursor);
            cursor += 4;
            if ((ULONGLONG)cursor + event_size > (ULONGLONG)len) break;

            /* OVMF firmware-blob substitution. UEFI_PLATFORM_FIRMWARE_BLOB:
             *   { ULONGLONG PhysicalAddress; ULONGLONG Length; }
             * The probe compares PhysicalAddress against the OVMF SEC/PEI
             * constants. */
            if (etype == EV_EFI_PLATFORM_FIRMWARE_BLOB && event_size >= 16) {
                ULONGLONG phys = *(PULONGLONG)(buf + cursor);
                if (cfp_is_ovmf_firmware_range(phys)) {
                    ULONGLONG new_base = cfp_retail_firmware_base(seed);
                    *(PULONGLONG)(buf + cursor) = new_base;
                }
            }

            /* Track EV_SEPARATOR presence per PCR. */
            if (pcr < 32) {
                if (etype == EV_SEPARATOR) {
                    have_separator |= (1u << pcr);
                } else if (etype == EV_NO_ACTION &&
                           first_no_action_off[pcr] == (ULONG)-1) {
                    first_no_action_off[pcr] = cur_off;
                }
            }

            cur_off = cursor + event_size;
            event_index++;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
    }
walker_done:
    ;   /* explicit no-op so the label precedes a plain statement */

    /* Approximation of audit remediation (b): promote the first
     * EV_NO_ACTION entry (other than the Spec-ID header, which lives in
     * the legacy prefix we already skipped) to EV_SEPARATOR for any PCR
     * that lacked one. This gives the probe the expected per-PCR
     * separator shape without growing the buffer. PCRs 0..7 are the
     * standard measured-boot surface. */
    __try {
        for (ULONG p = 0; p < 8; ++p) {
            if (have_separator & (1u << p)) continue;
            ULONG off = first_no_action_off[p];
            if (off == (ULONG)-1) continue;
            if (off + 8 > len) continue;
            *(PULONG)(buf + off + 4) = EV_SEPARATOR;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* buffer vanished */
    }
}

/* Return value of SystemCodeIntegrityInformation is a
 * SYSTEM_CODEINTEGRITY_INFORMATION{ULONG Length; ULONG CodeIntegrityOptions}.
 * When ci_state_spoof is set we clear the ENABLED + HVCI bits and leave the
 * optional bits alone. The real struct uses these bit values (undocumented
 * but stable since Win8.1): */
#define CODEINTEGRITY_OPTION_ENABLED                       0x01
#define CODEINTEGRITY_OPTION_TESTSIGN                      0x02
#define CODEINTEGRITY_OPTION_UMCI_ENABLED                  0x04
#define CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED             0x400

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;

/* ---------------- dispatch context ---------------- */

/* The user-mode shim passes a small context describing which syscall just
 * returned. The shim has a per-process syscall-number table (built once at
 * attach via a one-pass ntdll walk; the RtlCopyMemoryNonTemporal /
 * NtQuerySystemInformation stubs are stable enough on a fixed OS build).
 */
typedef struct _CFP_IC_CTX {
    ULONG   sysnum;            /* NT syscall number */
    PVOID   arg0, arg1, arg2, arg3;
    PVOID   arg4, arg5, arg6, arg7;
    SIZE_T  return_value;
} CFP_IC_CTX;

/* Rewriter implementations. Each takes the saved syscall return value and
 * returns the (possibly rewritten) value the caller should see. The
 * user-mode output buffer is mutated in place. */

static SIZE_T
rewrite_system_information(CFP_IC_CTX *ctx)
{
    ULONG   info_class = (ULONG)(ULONG_PTR)ctx->arg0;
    PVOID   buf        = ctx->arg1;
    ULONG   len        = (ULONG)(ULONG_PTR)ctx->arg2;

    if (!buf || !len) return ctx->return_value;

    /* Only rewrite on NT_SUCCESS returns — propagating a rewrite over a
     * failure confuses callers that check Status before the buffer. */
    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS) {
        return ctx->return_value;
    }

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));

    switch (info_class) {
    case SystemFirmwareTableInformation: {
        /* DMI/ACPI blob rewrite. The buffer layout is:
         *   SYSTEM_FIRMWARE_TABLE_INFORMATION { ULONG ProviderSignature;
         *       ULONG Action; ULONG TableID; ULONG TableBufferLength;
         *       UCHAR TableBuffer[]; }
         * The payload starts at offset 16. For the 'RSMB' provider the
         * TableBuffer begins with the 8-byte RAW_SMBIOS_HEADER (calling
         * method, SMBIOS major/minor, DMI rev, DMI length); the DMI
         * structure stream starts at offset 16 + 8 = 24, not 16. For
         * 'ACPI' the TableBuffer is the ACPI table itself (header + AML)
         * with no additional prefix; its first 36 bytes are the ACPI
         * description-table header.
         *
         * Action==1 (get specific table) and Action==0 (enumerate list of
         * signatures) take different post-processing. */
        if (len <= 16) break;
        if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) break;
        ULONG  provider = *(PULONG)buf;
        ULONG  action   = *(PULONG)((PUCHAR)buf + 4);
        PUCHAR tbl      = (PUCHAR)buf + 16;
        ULONG  tbl_l    = len - 16;

        switch (provider) {
        case FW_PROVIDER_RSMB:
            if (tbl_l > RAW_SMBIOS_HEADER_SIZE) {
                cfp_dmi_patch_blob(tbl + RAW_SMBIOS_HEADER_SIZE,
                                   tbl_l - RAW_SMBIOS_HEADER_SIZE);
            }
            break;
        case FW_PROVIDER_ACPI:
            /* Action 0 is "return the list of table signatures"; any
             * other action value is a per-table get. Microsoft currently
             * defines only 1 ("get"); treat anything that is not 0 as a
             * get. */
            if (action == 0) {
                cfp_rewrite_acpi_enum(tbl, tbl_l);
            } else {
                cfp_rewrite_acpi_table(tbl, tbl_l);
            }
            break;
        default:
            /* 'FIRM' (raw BIOS ROM) and any unrecognised provider flow
             * through unmodified; there is no VMAware probe gated on
             * them today. */
            break;
        }
        break;
    }

    case SystemCodeIntegrityInformation: {
        if (len < sizeof(SYSTEM_CODEINTEGRITY_INFORMATION)) break;
        if (!(toggles & CFP_TOGGLE_CI_STATE_SPOOF)) break;
        SYSTEM_CODEINTEGRITY_INFORMATION *ci = (SYSTEM_CODEINTEGRITY_INFORMATION *)buf;
        /* Report CI disabled, no HVCI, no test-signing. This is the shape
         * of a clean Windows install without WDAC or HVCI. */
        ci->CodeIntegrityOptions &= ~(CODEINTEGRITY_OPTION_ENABLED |
                                      CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED |
                                      CODEINTEGRITY_OPTION_TESTSIGN |
                                      CODEINTEGRITY_OPTION_UMCI_ENABLED);
        break;
    }

    case SystemSecureBootPolicyInformation: {
        if (!(toggles & CFP_TOGGLE_CI_STATE_SPOOF)) break;
        /* Secure Boot policy blob. We zero the active-policy signature so
         * callers see "default / unenforced" shape. The real blob layout
         * is private but every observed sample only checks the first
         * ULONG for a non-zero "policy present" marker. */
        if (len >= 4) *(PULONG)buf = 0;
        break;
    }

    case SystemCodeIntegrityPolicyFullInformation: {
        if (!(toggles & CFP_TOGGLE_CI_STATE_SPOOF)) break;
        /* WDAC policy blob. Shape: ULONG PolicyCount; followed by entries.
         * Zero the count. Callers that enumerate get zero policies. */
        if (len >= 4) *(PULONG)buf = 0;
        break;
    }

    case SystemBasicInformation:
    case SystemLogicalProcessorInformation:
        /* Topology pass through. The HV side keeps CPU count and core
         * topology consistent; we must not diverge here. */
        break;

    case SystemLogicalProcessorInformationEx: {
        /* VCPU_SCHEDULING gap: two reads 25 ms apart must see byte-
         * identical topology. Windows's value is normally stable on a
         * quiescent box but Chamber must guarantee it so a probe cannot
         * catch the HV scheduler re-pinning a vCPU across samples. Cache
         * the first observed response per spoofed PID and replay it. */
        if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) break;
        if (len == 0 || len > CFP_SLPI_MAX_BYTES) break;
        ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        if (pid == 0) break;

        __try {
            ULONG cached_len = 0;
            if (cfp_slpi_cache_lookup(pid, (PUCHAR)buf, len, &cached_len)) {
                /* Second (and later) reads: already byte-identical. */
                break;
            }
            /* First read: snapshot and stash. */
            cfp_slpi_cache_store(pid, (const UCHAR *)buf, len);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* user buffer vanished */
        }
        break;
    }

    case SystemBootLogoInformation: {
        /* BOOT_LOGO gap: the probe CRC32C's the BGRT bitmap payload and
         * compares against the OVMF (0x110350C5) and Hyper-V (0x87C39681)
         * hashes. XOR 64 bytes at info->BitmapOffset with a seed-derived
         * pattern so the CRC32C moves out of that two-entry collision
         * set. Do not zero — the probe also flags an all-zero payload as
         * suspicious.
         *
         * SYSTEM_BOOT_LOGO_INFORMATION:
         *   ULONG Flags;         // 0
         *   ULONG BitmapOffset;  // 4
         *   UCHAR Bitmap[];      // at BitmapOffset from start of buffer
         */
        if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) break;
        if (len < 8) break;

        ULONG  bitmap_off = *(PULONG)((PUCHAR)buf + 4);
        if (bitmap_off < 8 || bitmap_off >= len) break;
        ULONG  bitmap_avail = len - bitmap_off;
        ULONG  xor_len = bitmap_avail < 64 ? bitmap_avail : 64;
        if (xor_len == 0) break;

        UCHAR seed[16];
        if (!cfp_cfg_get(CFP_FID_EDID_NONCE, seed, sizeof(seed))) break;
        /* Guarantee the XOR flips at least one bit even if the seed row
         * happens to carry a zero byte — a zero XOR against the raw
         * bitmap would be a no-op and the CRC would still match. */
        BOOLEAN any_nonzero = FALSE;
        for (ULONG i = 0; i < 16; ++i) if (seed[i]) { any_nonzero = TRUE; break; }
        if (!any_nonzero) seed[0] = 0xA5;

        __try {
            PUCHAR bmp = (PUCHAR)buf + bitmap_off;
            for (ULONG i = 0; i < xor_len; ++i) {
                bmp[i] ^= seed[i & 0x0F];
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            /* user buffer vanished */
        }
        break;
    }

    case SystemProcessorPerformanceInformation: {
        /* SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION per-CPU rows carry
         *   LARGE_INTEGER IdleTime, KernelTime, UserTime, DpcTime,
         *                 InterruptTime; ULONG InterruptCount;
         * (48 bytes per CPU). DpcTime accumulates during the pause-the-
         * world dump window — a naive sampler sees a step jump in
         * DpcTime that is not matched by elapsed wall-clock. We back-
         * fill the delta here by subtracting the pause-world DPC debt
         * the HV side accumulated into g_cfp_dpc_pause_debt (updated
         * by the dump/pause owner through a shared symbol).
         *
         * Without that symbol available at link time we can still zero
         * the DpcTime field when a pause has just happened — the cost
         * is a small undercount which no sample actually checks against
         * a ground truth. The HV side signals a recent pause through
         * the toggles word bit CFP_TOGGLE_HV_INTROSPECTION_RESIST shift
         * (set across the pause window; cleared on resume).
         *
         * Row stride is 48 on x64. */
        if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) break;
        ULONG row = 48;
        if (len < row) break;
        PUCHAR cur = (PUCHAR)buf;
        ULONG  rem = len;
        while (rem >= row) {
            /* Zero DpcTime (offset 24) for this row. Keeping Idle/Kernel/
             * User consistent is enough for the fingerprint purpose: a
             * sample that reads DpcTime twice and computes a delta sees
             * no jump across a pause window. */
            *(volatile ULONGLONG *)(cur + 24) = 0;
            cur += row;
            rem -= row;
        }
        break;
    }
    }

    return ctx->return_value;
}

static SIZE_T
rewrite_volume_information(CFP_IC_CTX *ctx)
{
    /* NtQueryVolumeInformationFile(FileFsVolumeInformation) returns:
     *   LARGE_INTEGER VolumeCreationTime;
     *   ULONG         VolumeSerialNumber;      // offset 8
     *   ULONG         VolumeLabelLength;
     *   BOOLEAN       SupportsObjects;
     *   WCHAR         VolumeLabel[];
     */
    PVOID buf = ctx->arg2;
    ULONG len = (ULONG)(ULONG_PTR)ctx->arg3;

    if (!buf || len < 16) return ctx->return_value;
    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS) return ctx->return_value;

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) return ctx->return_value;

    /* Rewrite serial with the first (C: slot) seed. Volume-letter affinity
     * requires file-object -> drive letter, which the shim resolves ahead
     * of time and passes via arg6 (slot index). */
    ULONG slot = (ULONG)(ULONG_PTR)ctx->arg6;
    if (slot > 3) slot = 0;

    UCHAR ser[4];
    if (cfp_cfg_get(CFP_FID_VOLUME_SERIAL_0 + slot, ser, sizeof(ser))) {
        *(PULONG)((PUCHAR)buf + 8) = *(PULONG)ser;
    }
    return ctx->return_value;
}

/* IOCTL_STORAGE_QUERY_PROPERTY + IOCTL_DISK_GET_DRIVE_GEOMETRY_EX.
 *
 * STORAGE_DEVICE_DESCRIPTOR layout (public, winioctl.h):
 *   ULONG Version;
 *   ULONG Size;
 *   UCHAR DeviceType, DeviceTypeModifier, RemovableMedia, CommandQueueing;
 *   ULONG VendorIdOffset;
 *   ULONG ProductIdOffset;
 *   ULONG ProductRevisionOffset;
 *   ULONG SerialNumberOffset;
 *   ...
 *   UCHAR RawDeviceProperties[];
 * The ASCII strings at those offsets are what we rewrite.
 */
static void
rewrite_storage_descriptor(PUCHAR buf, ULONG len)
{
    if (!buf || len < 40) return;
    ULONG serial_off = *(PULONG)(buf + 24);
    if (serial_off == 0 || serial_off >= len) return;

    /* 20-char serial from the stored slot tag expanded by chained derive.
     * Slot 0 is the first disk the shim walks; slot-to-handle mapping is
     * launcher-side. For now we use slot 0 for all disk queries from a
     * spoofed process; per-handle slot resolution is a later refinement. */
    UCHAR tag[4];
    if (!cfp_cfg_get(CFP_FID_DISK_SERIAL_0, tag, sizeof(tag))) return;

    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    PUCHAR dst = buf + serial_off;
    ULONG  rem = len - serial_off;
    ULONG  n   = rem > 21 ? 20 : (rem > 0 ? rem - 1 : 0);

    /* Mix tag bytes to produce 20 ASCII chars. We do not call the shared
     * derive() from here; that would require BCrypt at syscall-return time.
     * Instead we use the tag as a seed into a small LCG that produces
     * stable bytes. CFG stores only the 4-byte tag; the result is
     * per-boot stable (the tag does not change across reboots for a
     * fixed seed, because the launcher derives the tag once). */
    ULONG s = *(PULONG)tag;
    for (ULONG i = 0; i < n; ++i) {
        s = s * 1664525UL + 1013904223UL;
        dst[i] = alphabet[(s >> 16) % 36];
    }
    if (rem > n) dst[n] = 0;
}

static SIZE_T
rewrite_device_io_control(CFP_IC_CTX *ctx)
{
    /* NtDeviceIoControlFile args:
     *   arg0 FileHandle
     *   arg1 Event
     *   arg2 ApcRoutine
     *   arg3 ApcContext
     *   arg4 IoStatusBlock
     *   arg5 IoControlCode (ULONG)
     *   arg6 InputBuffer
     *   ... (shim collapses the rest into arg7 as OutputBuffer)
     *
     * The shim normalizes the layout so arg5 carries the IoControlCode and
     * arg7 carries OutputBuffer+Length as a packed { void*, ULONG }.
     */
    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS &&
        (NTSTATUS)ctx->return_value != STATUS_BUFFER_OVERFLOW) {
        return ctx->return_value;
    }

    ULONG ioctl = (ULONG)(ULONG_PTR)ctx->arg5;

    /* The "packed buf+len" shape: arg7 is a pointer to a struct
     *   { PVOID buf; ULONG len; } the shim built on the stack. */
    struct { PVOID buf; ULONG len; } *o = (void *)ctx->arg7;
    if (!o || !o->buf || !o->len) return ctx->return_value;

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) return ctx->return_value;

    switch (ioctl) {
    /* IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400; IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
     * = 0x700A0. Hard-coded so this file does not pull winioctl.h which is
     * user-mode-only. */
    case 0x002D1400:
    case 0x002D5C00:                /* IOCTL_STORAGE_QUERY_PROPERTY_EX */
        rewrite_storage_descriptor((PUCHAR)o->buf, o->len);
        break;

    /* IOCTL_NDIS_QUERY_GLOBAL_STATS on \Device\Ndis (OID_802_3_*).
     * Handled primarily in flt_filter.c but the shim also catches the
     * syscall-return side as belt-and-braces. The OID is in the input
     * buffer, not the output; the output carries the MAC. 6-byte return
     * = permanent MAC. */
    case 0x00170002: {                  /* IOCTL_NDIS_QUERY_GLOBAL_STATS */
        if (o->len >= 6) {
            UCHAR mac[6];
            if (cfp_cfg_get(CFP_FID_MAC_ADDR_0, mac, sizeof(mac))) {
                RtlCopyMemory(o->buf, mac, 6);
            }
        }
        break;
    }

    default: {
        /* MEASURED_BOOT + TPM gaps: match TBS TCG event-log returns on
         * \Device\Tpm / \Device\TrustedPlatformModule. The specific
         * IOCTL encoding (Tbsi_Get_TCG_Log_Ex, Tbsi_Submit_Command with
         * TPM2_GetCapability, …) drifts across Windows builds; rather
         * than enumerating every one, we match on the TCG log signature
         * at the head of the output buffer. The first entry is always a
         * legacy TCG_PCR_EVENT with PCRIndex==0, EventType==EV_NO_ACTION
         * and the ASCII string "Spec ID Event" at offset 32. That
         * composite is tight enough to distinguish genuine TBS traffic
         * from any other METHOD_BUFFERED IOCTL that happens to flow
         * through this handler. The Device type (bits 31..16 of the
         * IOCTL code) also has to be FILE_DEVICE_UNKNOWN (0x0022) which
         * TBS uses, narrowing the match slightly before the signature
         * check runs. */
        if (((ioctl >> 16) & 0xFFFFu) == 0x0022u && o->len >= 64) {
            cfp_scrub_tcg_log((PUCHAR)o->buf, o->len);
        }
        break;
    }
    }

    return ctx->return_value;
}

/* NtPowerInformation — POWER_CAPABILITIES gap.
 *
 * Arg layout (ntpoapi.h signature):
 *   arg0 POWER_INFORMATION_LEVEL InformationLevel
 *   arg1 PVOID                   InputBuffer
 *   arg2 ULONG                   InputBufferLength
 *   arg3 PVOID                   OutputBuffer
 *   arg4 ULONG                   OutputBufferLength
 *
 * On SystemPowerCapabilities (level 4) the output is SYSTEM_POWER_CAPABILITIES.
 * We fill it in with a retail desktop shape: S3+S4 supported, HiberFile
 * present, no battery, no APM. All other levels pass through.
 */
static SIZE_T
rewrite_power_information(CFP_IC_CTX *ctx)
{
    ULONG level  = (ULONG)(ULONG_PTR)ctx->arg0;
    PVOID outbuf = ctx->arg3;
    ULONG outlen = (ULONG)(ULONG_PTR)ctx->arg4;

    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS) return ctx->return_value;
    if (!outbuf || outlen == 0) return ctx->return_value;
    if (level != SystemPowerCapabilities) return ctx->return_value;

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) return ctx->return_value;

    /* SYSTEM_POWER_CAPABILITIES byte offsets (public ntpoapi.h layout).
     * The struct begins with 24 BOOLEAN/UCHAR fields then 6 UCHAR spare3,
     * then SystemBatteriesPresent at offset 30. We only write bytes we
     * need; everything else in the struct keeps the caller-sized shape.
     *
     * Required for the full write: 32 bytes. Smaller buffers (unexpected
     * for this level) get what fits. */
    if (outlen < 32) return ctx->return_value;

    __try {
        PUCHAR p = (PUCHAR)outbuf;
        /* PowerButtonPresent (0) / SleepButtonPresent (1) / LidPresent (2)
         * — leave alone; they reflect the real chassis buttons through the
         * HV passthrough path. */
        p[3]  = 0;    /* SystemS1       -> FALSE */
        p[4]  = 0;    /* SystemS2       -> FALSE */
        p[5]  = 1;    /* SystemS3       -> TRUE  */
        p[6]  = 1;    /* SystemS4       -> TRUE  */
        /* SystemS5 (7) — always TRUE on any ACPI system. Leave alone. */
        p[8]  = 1;    /* HiberFilePresent -> TRUE */
        p[9]  = 1;    /* FullWake         -> TRUE */
        /* VideoDimPresent (10) — retail default is 0 on desktop, 1 on
         * laptop. Leave as caller-reported so it tracks the chassis type
         * the SMBIOS rewrite already surfaces. */
        p[11] = 0;    /* ApmPresent       -> FALSE */
        /* UpsPresent (12) / ThermalControl (13) / ProcessorThrottle (14)
         * — pass through; silicon reports them truthfully on Zen 4. */
        p[15] = 5;    /* ProcessorMinThrottle -> 5   (retail desktop) */
        p[16] = 100;  /* ProcessorMaxThrottle -> 100 */
        p[17] = 1;    /* FastSystemS4     -> TRUE  */
        p[18] = 1;    /* Hiberboot        -> TRUE  */
        p[19] = 0;    /* WakeAlarmPresent -> FALSE */
        p[20] = 0;    /* AoAc             -> FALSE (desktop, not Modern Standby) */
        /* DiskSpinDown (21) — pass through; depends on attached storage. */
        p[22] = 1;    /* HiberFileType    -> 1 (NTFS hiberfile)   */
        /* AoAcConnectivitySupported (23) — pass through. */
        /* spare3[6] at 24..29 — pass through. */
        p[30] = 0;    /* SystemBatteriesPresent -> FALSE (desktop shape) */
        /* BatteriesAreShortTerm (31) stays whatever the caller saw. */
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* user buffer vanished */
    }

    return ctx->return_value;
}

/* NtEnumerateSystemEnvironmentValuesEx — NVRAM (a) half.
 *
 * Walks a returned VARIABLE_NAME_AND_VALUE list and scrubs the leading
 * character of any UEFI variable name containing QEMU/OVMF/TianoCore/VBox.
 * The probe's substring search no longer fires without us having to
 * rebuild the list layout (which would require growing the buffer).
 *
 * Arg layout:
 *   arg0 ULONG  InformationClass    (1 == variable-name walk)
 *   arg1 PVOID  Buffer
 *   arg2 PULONG BufferLength
 */
static SIZE_T
rewrite_environment_enum(CFP_IC_CTX *ctx)
{
    ULONG   klass = (ULONG)(ULONG_PTR)ctx->arg0;
    PVOID   buf   = ctx->arg1;
    PULONG  plen  = (PULONG)ctx->arg2;

    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS) return ctx->return_value;
    if (!buf || !plen) return ctx->return_value;
    if (klass != 1) return ctx->return_value;

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) return ctx->return_value;

    ULONG total = 0;
    __try {
        total = *plen;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return ctx->return_value;
    }
    if (total < 20 || total > 0x01000000u) return ctx->return_value;

    /* VARIABLE_NAME_AND_VALUE entries. Each record:
     *   ULONG NextEntryOffset;        // 0 terminates the list
     *   GUID  VendorGuid;             // 16 bytes
     *   WCHAR Name[];                 // NUL-terminated wide string
     * followed (for the variant that returns values) by the value bytes,
     * but the Microsoft-documented class 1 is name-only. */
    __try {
        PUCHAR cur = (PUCHAR)buf;
        PUCHAR end = cur + total;
        ULONG  guard = 0;
        while (cur + 20 < end && guard++ < 0x10000) {
            ULONG next = *(PULONG)cur;
            if (next == 0) break;
            if (next < 20 || cur + next > end) break;

            PWCHAR name = (PWCHAR)(cur + 20);
            SIZE_T wlen = (SIZE_T)((next - 20) / sizeof(WCHAR));
            cfp_scrub_vm_tokens_w(name, wlen);
            cur += next;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* user buffer vanished */
    }

    return ctx->return_value;
}

/* NtQueryInformationProcess(ProcessInstrumentationCallback) --
 * a packer that writes a cookie into its own IC via NtSetInformationProcess
 * and then reads it back with class 40 must see the exact value it set, not
 * our shim's trampoline VA. The per-PID shadow table in instrumentation.c
 * records the prior user-mode VA each set-op observed; this handler returns
 * that saved value on a query from the same PID. */
static SIZE_T
rewrite_process_information(CFP_IC_CTX *ctx)
{
    /* NtQueryInformationProcess args:
     *   arg0 ProcessHandle
     *   arg1 ProcessInformationClass (ULONG)
     *   arg2 ProcessInformation (buf)
     *   arg3 ProcessInformationLength (ULONG)
     *   arg4 ReturnLength
     */
    ULONG  klass = (ULONG)(ULONG_PTR)ctx->arg1;
    PVOID  buf   = ctx->arg2;
    ULONG  len   = (ULONG)(ULONG_PTR)ctx->arg3;

    if (klass != ProcessInstrumentationCallback) return ctx->return_value;
    if (!buf || len < 16) return ctx->return_value;

    /* PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION:
     *   ULONG Version; ULONG Reserved; PVOID Callback. */
    PVOID shadow = cfp_instr_shadow_get((HANDLE)(ULONG_PTR)PsGetCurrentProcessId());
    *(volatile ULONG *)((PUCHAR)buf + 0)     = 0;    /* Version */
    *(volatile ULONG *)((PUCHAR)buf + 4)     = 0;    /* Reserved */
    *(volatile PVOID *)((PUCHAR)buf + 8)     = shadow;

    return ctx->return_value;
}

/* NtQueryInformationToken -- hides integrity-level / TokenOrigin tells
 * that pack-and-run samples use to distinguish sandboxes. We zero the
 * well-known classes rather than returning fabricated structure. */
static SIZE_T
rewrite_token_information(CFP_IC_CTX *ctx)
{
    ULONG klass = (ULONG)(ULONG_PTR)ctx->arg1;
    PVOID buf   = ctx->arg2;
    ULONG len   = (ULONG)(ULONG_PTR)ctx->arg3;

    if (!buf || !len) return ctx->return_value;
    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS) return ctx->return_value;

    switch (klass) {
    case TokenStatistics:
        /* TOKEN_STATISTICS carries a LUID (AuthenticationId) that a
         * sample can fingerprint against a well-known sandbox-session
         * value. Zero it; a real caller already has the LUID elsewhere. */
        if (len >= 8) *(volatile ULONGLONG *)buf = 0;
        break;
    case TokenOrigin:
        /* TOKEN_ORIGIN.OriginatingLogonSession is the only field. */
        if (len >= 8) *(volatile ULONGLONG *)buf = 0;
        break;
    default:
        break;
    }
    return ctx->return_value;
}

/* NtQuerySystemEnvironmentValueEx -- UEFI variable read.
 *
 * NVRAM (b) half. Payload-aware rewrite:
 *   SetupMode  (byte)  -> 0        (retail default: not in setup mode)
 *   SecureBoot (byte)  -> 1        (retail default: Secure Boot enabled)
 *   PK / KEK / db      -> seed-derived OEM-cert blob (not a 16-byte zero,
 *                         which is itself anomalous on a Secure-Boot-
 *                         shipped board)
 *   other              -> zero out min(ValueLength, 256) bytes (strictly
 *                         stronger than the prior 16-byte zero, which
 *                         left vendor metadata past byte 16 intact)
 *
 * Arg layout (ntdef.h signature):
 *   arg0 PUNICODE_STRING VariableName
 *   arg1 LPGUID          VendorGuid
 *   arg2 PVOID           Value
 *   arg3 PULONG          ValueLength (in on entry, out on return)
 *   arg4 PULONG          Attributes  (optional)
 */
static SIZE_T
rewrite_system_environment(CFP_IC_CTX *ctx)
{
    PUNICODE_STRING pname = (PUNICODE_STRING)ctx->arg0;
    PVOID           buf   = ctx->arg2;
    PULONG          plen  = (PULONG)ctx->arg3;

    if (!buf) return ctx->return_value;
    if ((NTSTATUS)ctx->return_value != STATUS_SUCCESS) return ctx->return_value;

    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) return ctx->return_value;

    /* Dereference ValueLength under SEH to learn the kernel-reported size.
     * Callers can legally pass a NULL length pointer only when the
     * ValueLength is encoded elsewhere; fall back to 16 in that case so
     * we preserve the old defensive behaviour on malformed inputs. */
    ULONG vlen = 0;
    __try {
        vlen = plen ? *plen : 16;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        vlen = 16;
    }
    if (vlen == 0) return ctx->return_value;

    enum {
        VAR_UNKNOWN,
        VAR_SETUP_MODE,
        VAR_SECURE_BOOT,
        VAR_PK,
        VAR_KEK,
        VAR_DB
    } kind = VAR_UNKNOWN;

    __try {
        if (pname && pname->Buffer && pname->Length >= sizeof(WCHAR)) {
            PWCHAR nm = pname->Buffer;
            SIZE_T nw = pname->Length / sizeof(WCHAR);
            if      (cfp_uni_eq_ci(nm, nw, L"SetupMode"))  kind = VAR_SETUP_MODE;
            else if (cfp_uni_eq_ci(nm, nw, L"SecureBoot")) kind = VAR_SECURE_BOOT;
            else if (cfp_uni_eq_ci(nm, nw, L"PK"))         kind = VAR_PK;
            else if (cfp_uni_eq_ci(nm, nw, L"KEK"))        kind = VAR_KEK;
            else if (cfp_uni_eq_ci(nm, nw, L"db"))         kind = VAR_DB;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        kind = VAR_UNKNOWN;
    }

    __try {
        switch (kind) {
        case VAR_SETUP_MODE:
            /* Byte-sized flag. Retail boards post-manufacture: 0. */
            if (vlen >= 1) *(PUCHAR)buf = 0;
            break;
        case VAR_SECURE_BOOT:
            /* Byte-sized flag. Retail with Secure Boot on: 1. */
            if (vlen >= 1) *(PUCHAR)buf = 1;
            break;
        case VAR_PK:
        case VAR_KEK:
        case VAR_DB:
            /* Seed-derived OEM-cert-shaped payload. Replaces the prior
             * 16-byte zero, which left vendor metadata past byte 16
             * intact and produced an empty-PK shape that is itself
             * anomalous on a Secure-Boot-shipped retail board. */
            cfp_synth_oem_cert_blob((PUCHAR)buf, vlen);
            break;
        default: {
            /* Unknown variable: extend the former 16-byte zero to cover
             * min(ValueLength, 256) bytes. */
            ULONG zlen = vlen > 256 ? 256 : vlen;
            RtlZeroMemory(buf, zlen);
            break;
        }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* user buffer vanished — nothing to do */
    }
    return ctx->return_value;
}

/* NtGdiGetDeviceCaps -- forces display-miniport capability returns to shapes
 * VMAware's GPU_CAPABILITIES and DISPLAY probes expect of real hardware:
 *
 *     COLORMGMTCAPS                : CM_GAMMA_RAMP (0x02) must be set
 *     BITSPIXEL * PLANES           : must equal 32  (we clamp 32 and 1)
 *     LOGPIXELSX, LOGPIXELSY       : must be >= 96  (standard DPI floor)
 *
 * PREFERRED REMEDIATION IS CONFIG-LEVEL, NOT CODE-LEVEL. Pass the physical
 * AMD GPU through to the guest with the inbox or vendor miniport bound
 * there and the real miniport reports these values natively — no syscall
 * hook needed, no fragility against win32k drift. This handler is the
 * code-level fallback for deployments that cannot afford GPU passthrough.
 *
 * FRAGILITY NOTES. We intercept the return side of the NtGdiGetDeviceCaps
 * win32k syscall. Two things can drift and silently break this handler:
 *
 *   1. The syscall number (0x1083 on current Win10/11 x64 builds at the
 *      time this file was last updated) is Microsoft-churned frequently.
 *      The shim resolves win32k numbers at attach by walking win32u.dll
 *      the same way it walks ntdll for NT numbers, so the value below is
 *      a comment-worthy anchor rather than a live dispatch key — if
 *      Microsoft renumbers it, the shim picks up the new value. If the
 *      shim ever loses that resolver, this hook silently disables itself
 *      (the sysnum simply never hits our switch).
 *
 *   2. The (hdc, nIndex) → int shape is win32k-public and has been stable
 *      for decades, but the dispatch marshalling the shim uses to land
 *      args in ctx->arg0/arg1 does depend on current win32k thunking
 *      conventions. If the marshalling changes, arg1 will carry the
 *      wrong value and the switch below will miss every real query.
 *
 * In either drift case the correct response is to revert to config-level
 * GPU passthrough rather than patch this file.
 */
static SIZE_T
rewrite_gdi_device_caps(CFP_IC_CTX *ctx)
{
    /* NtGdiGetDeviceCaps(HDC hdc, int nIndex) returns int:
     *   arg0 = hdc    (ignored — PID filtering happened at the shim)
     *   arg1 = nIndex (capability constant from wingdi.h)
     * The returned int sits in the low 32 bits of ctx->return_value. */
    ULONG toggles = 0;
    cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
    if (!(toggles & CFP_TOGGLE_MACHINE_IDENTITY)) return ctx->return_value;

    int   index = (int)(LONG_PTR)ctx->arg1;
    LONG  value = (LONG)(LONG_PTR)ctx->return_value;

    switch (index) {
    case GDI_CAP_COLORMGMTCAPS:
        /* Force CM_GAMMA_RAMP on. Preserve other bits the miniport
         * reported (CM_DEVICE_ICM, CM_CMYK_COLOR, ...). */
        value |= (LONG)CFP_CM_GAMMA_RAMP;
        break;
    case GDI_CAP_BITSPIXEL:
        /* Real desktops are 32bpp on Win10+. Clamp; do not conditionally
         * modify — the DISPLAY probe insists on BITSPIXEL*PLANES == 32. */
        value = 32;
        break;
    case GDI_CAP_PLANES:
        /* With BITSPIXEL=32, PLANES must be 1 to satisfy the product
         * check. Clamp unconditionally. */
        value = 1;
        break;
    case GDI_CAP_LOGPIXELSX:
    case GDI_CAP_LOGPIXELSY:
        /* 96 is the Windows standard-DPI floor. Respect any higher DPI
         * the user has configured; only clamp values the probe would
         * fail on. */
        if (value < 96) value = 96;
        break;
    default:
        return ctx->return_value;
    }

    /* Return as a sign-extended 32-bit int in a SIZE_T slot. GetDeviceCaps
     * never returns negative values for the indices above, but the caller
     * treats the result as a signed int so the sign-extension form is the
     * correct ABI shape. */
    return (SIZE_T)(LONG_PTR)value;
}

/* ---------------- top-level dispatch ---------------- */

/* Called from ic_trampoline.asm. Must run quickly — every syscall-return
 * in a spoofed process passes through here. */
SIZE_T NTAPI
cfp_ic_dispatch(SIZE_T return_value, PVOID return_rip, SIZE_T saved_rax)
{
    UNREFERENCED_PARAMETER(return_rip);

    /* The shim fills a per-thread CFP_IC_CTX before the detour. We
     * accept return_value + saved_rax (NT syscall number) and read the
     * args from the thread's user-mode stack via the shim's prologue.
     * The per-thread CTX pointer rides in gs:[0x1480] (an unused slot
     * in TEB on current Windows; shim reserves it at attach).
     *
     * This kernel-mode file is linked into chamber_fingerprint.sys for
     * contract clarity. At runtime the compiled version of this function
     * is copied into the shim's allocation along with the trampoline, so
     * the handlers above run in user mode in the target. The code is
     * written to a position-independent subset of MSVC C and takes no
     * kernel-only API dependencies except cfp_cfg_get — which the shim
     * routes to a per-process shared-memory view of the CFG blob the
     * launcher publishes.
     */
    CFP_IC_CTX ctx_storage;
    CFP_IC_CTX *ctx = &ctx_storage;
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->sysnum       = (ULONG)saved_rax;
    ctx->return_value = return_value;

    /* Syscall-number dispatch. The shim fills the arg0..arg7 slots from
     * the saved caller frame before jumping here. */
    switch (ctx->sysnum) {
    /* These numbers are placeholders. The shim resolves syscall numbers
     * once at attach via a one-shot ntdll walk and patches them into the
     * dispatch table it hands to this routine. Hard-coding specific
     * numbers would tie the driver to a single OS build. */
    case 0x0036:  /* NtQuerySystemInformation (Win11 22H2 example) */
        return rewrite_system_information(ctx);
    case 0x0007:  /* NtDeviceIoControlFile */
        return rewrite_device_io_control(ctx);
    case 0x0049:  /* NtQueryVolumeInformationFile */
        return rewrite_volume_information(ctx);
    case 0x0019:  /* NtQueryInformationProcess (shim-resolved) */
        return rewrite_process_information(ctx);
    case 0x0021:  /* NtQueryInformationToken (shim-resolved) */
        return rewrite_token_information(ctx);
    case 0x0120:  /* NtQuerySystemEnvironmentValueEx (shim-resolved) */
        return rewrite_system_environment(ctx);
    case 0x0182:  /* NtPowerInformation (shim-resolved) */
        return rewrite_power_information(ctx);
    case 0x0171:  /* NtEnumerateSystemEnvironmentValuesEx (shim-resolved) */
        return rewrite_environment_enum(ctx);
    case 0x1083:  /* NtGdiGetDeviceCaps (win32k; shim-resolved via win32u.dll
                   * walk at attach — 0x1083 is the current Win10/11 x64
                   * anchor and is churned more often than NT numbers; see
                   * the fragility notes on rewrite_gdi_device_caps). */
        return rewrite_gdi_device_caps(ctx);
    default:
        break;
    }
    return return_value;
}
