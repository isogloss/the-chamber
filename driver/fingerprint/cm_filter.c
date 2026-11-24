/* cm_filter.c -- CmRegisterCallbackEx handler.
 *
 * Covers every registry identity value a packed sample reads to
 * fingerprint the host: MachineGuid, ProductId, InstallDate,
 * DigitalProductId, EDID blob, BitLocker status, NtpServer, the
 * HARDWARE\\DESCRIPTION\\System\\BIOS mirror, and the PCI / USB
 * HardwareID / CompatibleIDs multi-strings under
 * SYSTEM\\CurrentControlSet\\Enum\\ (SetupDi device enumeration).
 *
 * The registered callback fires pre-op and post-op on every registry
 * operation in the kernel. We intercept RegNtPostQueryValueKey only,
 * PID-filter against the spoof list, and for matched paths and value
 * names we supply a seed-derived override.
 *
 * Why we patch on *post*-op rather than *pre*: returning
 * STATUS_CALLBACK_BYPASS from pre-op with a synthesized buffer works
 * but forces us to allocate and lifetime-manage every buffer. The
 * cleaner path is to let the real read happen, then overwrite the
 * returned buffer in place at post-op. Registry values are usually
 * small (REG_SZ / REG_DWORD / short REG_BINARY) and the kernel copied
 * them into the caller's KVPI buffer, which we can edit before
 * returning.
 *
 * One exception: EDID is where we really do want to synthesize the
 * whole 128-byte blob, because the real value may not exist at all on
 * a VM or the real monitor may differ from the shape we claim. For
 * that one path we rewrite the blob in post-op to our EDID template,
 * truncating if the caller's buffer is shorter.
 *
 * The REG_MULTI_SZ rewrite for \Enum\PCI\ and \Enum\USB\ HardwareID /
 * CompatibleIDs values is also strictly in-place: VEN:DEV and VID:PID
 * tokens are always four hex digits so the overwrite preserves the
 * per-string NUL framing and the REG_MULTI_SZ trailing double-NUL
 * without touching DataLength.
 */

#include "fingerprint_cfg.h"

#define CFP_TAG  'cFPC'

/* --- forward decls from other TUs --- */
BOOLEAN cfp_target_contains(HANDLE pid);
BOOLEAN cfp_edid_build(UCHAR out_128[128]);

/* --- state --- */

static LARGE_INTEGER   g_cookie    = {0};
static BOOLEAN         g_registered = FALSE;
static PDRIVER_OBJECT  g_driver    = NULL;

/* --- helpers --- */

static BOOLEAN
unicode_contains_i(PCUNICODE_STRING hay, PCWSTR needle)
{
    if (!hay || !hay->Buffer || !needle) return FALSE;
    USHORT nlen = 0;
    while (needle[nlen]) ++nlen;
    if (hay->Length < (USHORT)(nlen * sizeof(WCHAR))) return FALSE;

    ULONG hw = hay->Length / sizeof(WCHAR);
    for (ULONG i = 0; i + nlen <= hw; ++i) {
        BOOLEAN ok = TRUE;
        for (USHORT j = 0; j < nlen; ++j) {
            WCHAR a = hay->Buffer[i + j];
            WCHAR b = needle[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
            if (a != b) { ok = FALSE; break; }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
unicode_equals_i(PCUNICODE_STRING hay, PCWSTR needle)
{
    if (!hay || !hay->Buffer || !needle) return FALSE;
    USHORT nlen = 0;
    while (needle[nlen]) ++nlen;
    if (hay->Length != (USHORT)(nlen * sizeof(WCHAR))) return FALSE;
    for (USHORT j = 0; j < nlen; ++j) {
        WCHAR a = hay->Buffer[j];
        WCHAR b = needle[j];
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* Convert a 16-byte raw GUID into "{XXXXXXXX-XXXX-XXXXX-XXXX-XXXXXXXXXXXX}"
 * at `out` (expects at least 78 WCHARs). Returns the character count
 * written (not including a trailing NUL, which we also write). */
static ULONG
guid_to_wstring(const UCHAR *g, WCHAR *out)
{
    static const WCHAR hex[] = L"0123456789ABCDEF";
    WCHAR *p = out;
    *p++ = L'{';
    /* 4 bytes little-endian group: bytes 3,2,1,0 */
    static const int order[16] = { 3,2,1,0, 5,4, 7,6, 8,9, 10,11,12,13,14,15 };
    for (ULONG i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) *p++ = L'-';
        UCHAR b = g[order[i]];
        *p++ = hex[b >> 4];
        *p++ = hex[b & 0x0F];
    }
    *p++ = L'}';
    *p = 0;
    return (ULONG)(p - out);
}

/* Converts an override byte buffer to a wide string. Treats input as
 * ASCII, stops at NUL, writes at most `max_chars` WCHARs, terminates. */
static ULONG
bytes_to_wstring(const UCHAR *src, ULONG srclen, WCHAR *dst, ULONG max_chars)
{
    ULONG n = 0;
    for (ULONG i = 0; i < srclen && n + 1 < max_chars; ++i) {
        if (src[i] == 0) break;
        dst[n++] = (WCHAR)src[i];
    }
    if (max_chars) dst[n] = 0;
    return n;
}

/* ---------------- PCI / USB enum VEN:DEV pools ----------------
 *
 * Seed-derived canonical VEN:DEV pairs we substitute into the four-hex
 * tokens inside HardwareID / CompatibleIDs multi-strings under
 *   \Registry\Machine\System\CurrentControlSet\Enum\PCI\...
 *   \Registry\Machine\System\CurrentControlSet\Enum\USB\...
 *
 * VMAware's DEVICES probe walks those multi-strings via
 * SetupDiGetDeviceRegistryPropertyW(SPDRP_HARDWAREID) and matches each
 * VEN:DEV (or VID:PID) token against a VM-vendor blacklist:
 *     virtio        0x1AF4
 *     VMware        0x15AD
 *     QEMU/Red Hat  0x1B36
 *     VirtualBox    0x80EE
 *     Parallels     0x1AB8
 *     Xen           0x5853
 * The pools below are constructed to exclude every entry on that list;
 * each pair is a real retail-silicon identity so the probe parses it
 * as bare metal. If a pool entry is ever rotated at reseed, verify it
 * is not in the blacklist above before shipping.
 *
 * PCI and USB vendor IDs live in separate namespaces (PCI-SIG vs USB-IF):
 * an Intel PCI VID like 0x8086 is NOT a valid USB-IF VID, so pairing it
 * with a VID_ token under Enum\USB is a tell in itself. The two pools
 * below segregate the namespaces — PCI entries only appear on Enum\PCI
 * HardwareIDs, USB-IF entries only on Enum\USB (and Enum\USBSTOR) ones.
 */
typedef struct _cfp_vendev_pair {
    USHORT ven;
    USHORT dev;
} CFP_VENDEV_PAIR;

static const CFP_VENDEV_PAIR g_cfp_pci_vendev_pool[] = {
    { 0x1002, 0x7480 },   /* AMD/ATI RDNA 2 (Navi 24) */
    { 0x10EC, 0x8168 },   /* Realtek RTL8111/8168 GbE */
    { 0x8086, 0x08D8 }    /* Intel chipset */
};
#define CFP_PCI_VENDEV_POOL_N \
    (sizeof(g_cfp_pci_vendev_pool) / sizeof(g_cfp_pci_vendev_pool[0]))

static const CFP_VENDEV_PAIR g_cfp_usb_vendev_pool[] = {
    { 0x0781, 0x5581 },   /* SanDisk Ultra USB 3.0        */
    { 0x090C, 0x1000 },   /* Silicon Motion flash drive   */
    { 0x0930, 0x6545 },   /* Toshiba TransMemory          */
    { 0x054C, 0x09A4 },   /* Sony Storage Media           */
    { 0x04E8, 0x61F5 },   /* Samsung Portable SSD T5      */
    { 0x0BDA, 0x0316 }    /* Realtek USB audio/storage    */
};
#define CFP_USB_VENDEV_POOL_N \
    (sizeof(g_cfp_usb_vendev_pool) / sizeof(g_cfp_usb_vendev_pool[0]))

/* Parse four wide-char hex digits at `p` into a USHORT (big-endian in
 * reading order, matching "VEN_xxxx" = v[0]<<12 | v[1]<<8 | ...).
 * Returns FALSE if any digit is non-hex. */
static BOOLEAN
cfp_parse_hex4_w(const WCHAR *p, USHORT *out)
{
    USHORT v = 0;
    for (int i = 0; i < 4; ++i) {
        WCHAR c = p[i];
        UCHAR d;
        if      (c >= L'0' && c <= L'9') d = (UCHAR)(c - L'0');
        else if (c >= L'a' && c <= L'f') d = (UCHAR)(c - L'a' + 10);
        else if (c >= L'A' && c <= L'F') d = (UCHAR)(c - L'A' + 10);
        else return FALSE;
        v = (USHORT)((v << 4) | d);
    }
    *out = v;
    return TRUE;
}

/* Write a four-digit uppercase hex representation of `v` into `p[0..3]`.
 * Matches the casing PnP normally stores (upper-case VEN/DEV tokens). */
static void
cfp_write_hex4_w(WCHAR *p, USHORT v)
{
    static const WCHAR hex[] = L"0123456789ABCDEF";
    p[0] = hex[(v >> 12) & 0xF];
    p[1] = hex[(v >>  8) & 0xF];
    p[2] = hex[(v >>  4) & 0xF];
    p[3] = hex[ v        & 0xF];
}

/* Case-insensitive four-WCHAR match: compares buf[0..3] against a
 * literal 4-char tag (ASCII, either upper or lower on both sides).
 * Short-circuits on any mismatch. */
static BOOLEAN
cfp_match4_i(const WCHAR *buf, const WCHAR *tag)
{
    for (int k = 0; k < 4; ++k) {
        WCHAR a = buf[k];
        WCHAR b = tag[k];
        if (a >= L'a' && a <= L'z') a = (WCHAR)(a - L'a' + L'A');
        if (b >= L'a' && b <= L'z') b = (WCHAR)(b - L'a' + L'A');
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* Rewrite the VEN:DEV (PCI) or VID:PID (USB) tokens inside a single
 * REG_MULTI_SZ wide-char buffer in place. `cwchars` is the buffer
 * length in WCHARs, inclusive of the trailing double-NUL. The rewrite
 * is strictly same-length (4 hex digits for 4 hex digits) so NUL
 * framing and REG_MULTI_SZ DataLength are preserved — no caller-side
 * buffer resize is required.
 *
 * The pool entry is selected via a modulo on the original VEN value;
 * this keeps the mapping deterministic per original device so repeated
 * reads of the same HardwareID produce the same rewritten bytes, and a
 * DEV_ token in the same substring pairs to the same pool entry as its
 * VEN_ prefix. */
static void
cfp_rewrite_hwid_vendev(WCHAR *buf, ULONG cwchars, BOOLEAN is_usb)
{
    if (!buf || cwchars < 8) return;

    const WCHAR *ven_tag = is_usb ? L"VID_" : L"VEN_";
    const WCHAR *dev_tag = is_usb ? L"PID_" : L"DEV_";

    /* Pick the namespace-correct pool: USB-IF VIDs under Enum\USB,
     * PCI-SIG VIDs under Enum\PCI. A cross-namespace reuse would itself
     * be the tell we are trying to erase. */
    const CFP_VENDEV_PAIR *pool;
    ULONG pool_n;
    if (is_usb) {
        pool   = g_cfp_usb_vendev_pool;
        pool_n = CFP_USB_VENDEV_POOL_N;
    } else {
        pool   = g_cfp_pci_vendev_pool;
        pool_n = CFP_PCI_VENDEV_POOL_N;
    }

    /* A full "VEN_xxxx&DEV_xxxx" token occupies 17 WCHARs:
     *   VEN_xxxx = 8    &  = 1    DEV_xxxx = 8
     * The VEN_-only read only needs 8 WCHARs, so the outer bound is 8. */
    ULONG i = 0;
    while (i + 8 <= cwchars) {
        if (!cfp_match4_i(&buf[i], ven_tag)) {
            ++i;
            continue;
        }
        USHORT old_ven;
        if (!cfp_parse_hex4_w(&buf[i + 4], &old_ven)) {
            ++i;
            continue;
        }
        ULONG slot = (ULONG)old_ven % pool_n;
        cfp_write_hex4_w(&buf[i + 4], pool[slot].ven);

        /* Paired DEV_/PID_ tag sits at i+9 when preceded by '&':
         *   VEN_xxxx & DEV_xxxx
         *   0  4   8 9 13   17
         * so the DEV_ hex digits start at i+13 and end at i+16. */
        if (i + 17 <= cwchars &&
            buf[i + 8] == L'&' &&
            cfp_match4_i(&buf[i + 9], dev_tag))
        {
            USHORT old_dev;
            if (cfp_parse_hex4_w(&buf[i + 13], &old_dev)) {
                cfp_write_hex4_w(&buf[i + 13], pool[slot].dev);
            }
        }

        /* Skip past the VEN_xxxx we just wrote so the next iteration
         * cannot re-match on the four digits we installed. */
        i += 8;
    }
}

/* ---------------- USBSTOR / sibling-value textual tells ----------------
 *
 * Enum\USBSTOR subkeys store HardwareID / CompatibleIDs as textual
 * REG_MULTI_SZ: the shape is "USBSTOR\DiskVendor__Product_________Rev"
 * where Vendor is 8 chars, Product is 16, Revision is 4, each padded
 * with underscores. A VirtualBox host yields "VBOX" / "VBOX_HARDDISK",
 * a QEMU host "QEMU" / "QEMU_HARDDISK", a VMware host "VMware" /
 * "VMware_Virtual_S", a virtio-blk host "Virtio". Those textual tokens
 * are what the audit's Setup* / WMIC USBSTOR probes grep for; the
 * numeric VID:PID rewrite at Enum\USB does not reach them.
 *
 * The pools below carry plausible retail USB-storage product names in
 * fixed lengths (4 / 6 / 7 / 13 WCHARs) so each matched tell can be
 * substituted in place without shifting the surrounding bytes. The same
 * pools feed the sibling-value rewrites (Service, Mfg) on PCI/USB/USBSTOR
 * subkeys so vboxguest / Innotek / Red Hat strings on Service and Mfg
 * do not survive after the HardwareID has been scrubbed. */
static const WCHAR *const g_cfp_usbstor_pool_13[] = {
    L"SanDisk Ultra",
    L"Crucial MX500",
    L"WDBlue_SN570U",
    L"ADATA SU650 P"
};
static const WCHAR *const g_cfp_usbstor_pool_7[] = {
    L"SanDisk",
    L"Samsung",
    L"Crucial",
    L"ADATAUS"
};
static const WCHAR *const g_cfp_usbstor_pool_6[] = {
    L"SanDsk",
    L"SmsngT",
    L"CrclMX",
    L"WDBlue"
};
static const WCHAR *const g_cfp_usbstor_pool_4[] = {
    L"SNDK",
    L"SMSG",
    L"CRCL",
    L"WDCB"
};

/* Table of VM-vendor tells to erase. Longer tells come first so a
 * "VMwareVirtual" occurrence is consumed before the shorter "VMware"
 * pass could half-replace it and leave trailing "Virtual" bytes. Each
 * substitute pool carries no VM-vendor token so a later pass over the
 * same buffer finds nothing to re-rewrite. */
static const struct {
    const WCHAR         *tell;
    USHORT               len;
    const WCHAR *const  *pool;
    ULONG                pool_n;
} g_cfp_usbstor_tells[] = {
    { L"VMwareVirtual", 13, g_cfp_usbstor_pool_13, 4 },
    { L"VirtualBox",    10, g_cfp_usbstor_pool_7,  4 },  /* 10 trunc -> 7 + 3 pad */
    { L"Parallels",      9, g_cfp_usbstor_pool_7,  4 },  /* 9 trunc -> 7 + 2 pad */
    { L"vboxguest",      9, g_cfp_usbstor_pool_7,  4 },
    { L"Innotek",        7, g_cfp_usbstor_pool_7,  4 },
    { L"Red Hat",        7, g_cfp_usbstor_pool_7,  4 },
    { L"VMware",         6, g_cfp_usbstor_pool_6,  4 },
    { L"Virtio",         6, g_cfp_usbstor_pool_6,  4 },
    { L"Oracle",         6, g_cfp_usbstor_pool_6,  4 },
    { L"VBOX",           4, g_cfp_usbstor_pool_4,  4 },
    { L"QEMU",           4, g_cfp_usbstor_pool_4,  4 },
    { L"Xen_",           4, g_cfp_usbstor_pool_4,  4 }
};
#define CFP_USBSTOR_TELLS_N \
    (sizeof(g_cfp_usbstor_tells) / sizeof(g_cfp_usbstor_tells[0]))

/* Case-insensitive match of a run of WCHARs. */
static BOOLEAN
cfp_match_ci_run(const WCHAR *hay, const WCHAR *needle, USHORT nlen)
{
    for (USHORT k = 0; k < nlen; ++k) {
        WCHAR a = hay[k];
        WCHAR b = needle[k];
        if (a >= L'a' && a <= L'z') a = (WCHAR)(a - L'a' + L'A');
        if (b >= L'a' && b <= L'z') b = (WCHAR)(b - L'a' + L'A');
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* Replace every VM-vendor tell in `buf` (length `cwchars` WCHARs) with
 * a same-length retail token. Pool selection is seed-derived from the
 * token's buffer offset so repeated reads of the same key yield the
 * same substitute. If a tell length exceeds the chosen pool's entry
 * length, the pool entry is written at the head of the tell and the
 * remainder is zero-padded (still ASCII-safe inside REG_MULTI_SZ). */
static void
cfp_rewrite_textual_tells(WCHAR *buf, ULONG cwchars)
{
    if (!buf || cwchars < 4) return;

    for (ULONG t = 0; t < CFP_USBSTOR_TELLS_N; ++t) {
        const WCHAR *tell  = g_cfp_usbstor_tells[t].tell;
        USHORT       nlen  = g_cfp_usbstor_tells[t].len;
        const WCHAR *const *pool = g_cfp_usbstor_tells[t].pool;
        ULONG        pool_n = g_cfp_usbstor_tells[t].pool_n;
        if (nlen == 0 || pool_n == 0 || cwchars < (ULONG)nlen) continue;

        ULONG i = 0;
        while (i + nlen <= cwchars) {
            if (!cfp_match_ci_run(&buf[i], tell, nlen)) {
                ++i;
                continue;
            }
            ULONG slot = (ULONG)i % pool_n;
            const WCHAR *sub = pool[slot];
            USHORT sub_len = 0;
            while (sub[sub_len]) ++sub_len;
            USHORT k = 0;
            while (k < nlen && k < sub_len) {
                buf[i + k] = sub[k];
                ++k;
            }
            /* Underscore-pad any residual: keeps the fixed-width
             * USBSTOR Vendor/Product column shape intact. */
            while (k < nlen) {
                buf[i + k] = L'_';
                ++k;
            }
            i += nlen;
        }
    }
}

/* Seed-derived GUID string (with braces) -> out (needs 39 WCHARs incl.
 * NUL). `salt` perturbs the seed so Driver and ContainerID derive to
 * different GUIDs under the same key path. */
static void
cfp_derive_guid_wstr(ULONG salt, WCHAR out[39])
{
    UCHAR seed[16] = { 0 };
    (void)cfp_cfg_get(CFP_FID_MACHINE_GUID, seed, 16);
    UCHAR g[16];
    for (int i = 0; i < 16; ++i) {
        g[i] = (UCHAR)(seed[i] ^ (UCHAR)((salt >> ((i & 3) * 8)) & 0xFF));
    }
    /* RFC 4122 version 4 / variant-10 nibbles so the shape passes the
     * usual {GUID} parsers. */
    g[7] = (UCHAR)((g[7] & 0x0F) | 0x40);
    g[8] = (UCHAR)((g[8] & 0x3F) | 0x80);
    (void)guid_to_wstring(g, out);
}

/* Overwrite the first `cap_chars` of `buf` with a seed-derived braced
 * GUID; writes 38 chars plus a trailing NUL, zero-fills any residual
 * up to cap_chars so the REG_SZ length the kernel copied in remains
 * consistent. Returns TRUE on success. */
static BOOLEAN
cfp_write_guid_in_place(WCHAR *buf, ULONG cap_chars, ULONG salt)
{
    if (cap_chars < 39) return FALSE;    /* 38 + NUL */
    WCHAR tmp[80];
    cfp_derive_guid_wstr(salt, tmp);
    for (ULONG i = 0; i < 38; ++i) buf[i] = tmp[i];
    for (ULONG i = 38; i < cap_chars; ++i) buf[i] = 0;
    return TRUE;
}

/* Cheap hash over a UNICODE_STRING, used to salt per-key GUID derivation
 * so sibling values at the same subkey agree on their identity but
 * sibling values at a different subkey derive distinct GUIDs. */
static ULONG
cfp_key_salt(PCUNICODE_STRING s)
{
    ULONG h = 0x811C9DC5UL;    /* FNV-1a 32-bit basis */
    if (!s || !s->Buffer) return h;
    ULONG cw = s->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < cw; ++i) {
        WCHAR c = s->Buffer[i];
        if (c >= L'a' && c <= L'z') c = (WCHAR)(c - L'a' + L'A');
        h = (h ^ (ULONG)(c & 0xFF)) * 0x01000193UL;
    }
    return h;
}

/* Rewrite Service / Mfg / Driver / ContainerID at an Enum\{PCI,USB,
 * USBSTOR}\... subkey in place. ClassGUID is intentionally left alone
 * (it names the device class — Disk / USBDevice / Net — not the vendor,
 * so a packed sample's consistency check wants the real class GUID).
 *
 * Service and Mfg are REG_SZ textual strings that often carry VM tells
 * (vboxguest, Oracle Corporation, Red Hat Inc.) — we run the same
 * tell-substitution as USBSTOR hardware IDs. Driver and ContainerID are
 * REG_SZ GUID strings we regenerate from the MachineGuid seed plus a
 * per-key / per-value salt, so repeat reads under the same subkey
 * return the same bytes. */
static void
cfp_rewrite_enum_sibling_sz(PKEY_VALUE_PARTIAL_INFORMATION kvpi,
                            PCUNICODE_STRING key_path,
                            PCUNICODE_STRING value_name)
{
    if (!kvpi || kvpi->DataLength < sizeof(WCHAR)) return;

    BOOLEAN is_enum =
        unicode_contains_i(key_path, L"\\Enum\\PCI\\") ||
        unicode_contains_i(key_path, L"\\Enum\\USB\\") ||
        unicode_contains_i(key_path, L"\\Enum\\USBSTOR\\");
    if (!is_enum) return;

    ULONG cwchars = kvpi->DataLength / sizeof(WCHAR);
    WCHAR *buf = (WCHAR *)kvpi->Data;

    if (unicode_equals_i(value_name, L"Service") ||
        unicode_equals_i(value_name, L"Mfg")) {
        cfp_rewrite_textual_tells(buf, cwchars);
        return;
    }
    if (unicode_equals_i(value_name, L"ContainerID")) {
        (void)cfp_write_guid_in_place(buf, cwchars, cfp_key_salt(key_path));
        return;
    }
    if (unicode_equals_i(value_name, L"Driver")) {
        /* Driver values are typically "{classGUID}\NNNN" where NNNN is
         * the per-instance decimal index. Write the GUID (0..37), then
         * '\', then four decimal digits derived from the same salt,
         * then NUL. A probe scanning for the \NNNN shape sees the right
         * framing; same-key / same-boot reads are stable because the
         * suffix comes from the key salt, not from a random. */
        ULONG salt = cfp_key_salt(key_path) ^ 0xD71C3A5EUL;
        if (cwchars < 44) {
            (void)cfp_write_guid_in_place(buf, cwchars, salt);
            return;
        }
        (void)cfp_write_guid_in_place(buf, 39, salt);  /* 38 GUID + implicit NUL at 38 inside the helper */
        /* Overwrite indices 38..43 with "\NNNN" + NUL. */
        buf[38] = L'\\';
        ULONG n = salt;
        for (ULONG d = 0; d < 4; ++d) {
            buf[42 - d] = (WCHAR)(L'0' + (n % 10));
            n /= 10;
        }
        buf[43] = 0;
        for (ULONG i = 44; i < cwchars; ++i) buf[i] = 0;
        return;
    }
    /* ClassGUID: pass through. The real class GUID (Disk, USBDevice,
     * HIDClass, Net) is exactly what a probe wants to see. */
}

/* ---------------- per-path rewriters ---------------- */

/* Compute the override wide-string for a given key path + value name.
 * Returns the number of BYTES placed in out_buf, or 0 if no rewrite. */
static ULONG
compute_wsz_override(PCUNICODE_STRING key_path, PCUNICODE_STRING value_name,
                     WCHAR *out_buf, ULONG out_chars)
{
    UCHAR ov[32];
    ULONG wchars;

    /* --- Cryptography\MachineGuid --- */
    if (unicode_contains_i(key_path, L"Microsoft\\Cryptography") &&
        unicode_equals_i(value_name, L"MachineGuid")) {
        if (cfp_cfg_get(CFP_FID_MACHINE_GUID, ov, 16)) {
            /* MachineGuid stores the GUID without braces, lowercase, 36 chars. */
            WCHAR full[80];
            guid_to_wstring(ov, full);
            /* Strip the braces and lowercase. full = "{AABBCC..}\0" */
            ULONG n = 0;
            for (ULONG i = 1; full[i] != L'}' && n + 1 < out_chars; ++i) {
                WCHAR c = full[i];
                if (c >= L'A' && c <= L'Z') c = (WCHAR)(c - L'A' + L'a');
                out_buf[n++] = c;
            }
            if (out_chars) out_buf[n] = 0;
            return (n + 1) * sizeof(WCHAR);
        }
    }

    /* --- Windows NT CurrentVersion\ProductId --- */
    if (unicode_contains_i(key_path, L"Windows NT\\CurrentVersion") &&
        unicode_equals_i(value_name, L"ProductId")) {
        if (cfp_cfg_get(CFP_FID_PRODUCT_ID, ov, 24)) {
            wchars = bytes_to_wstring(ov, 24, out_buf, out_chars);
            return (wchars + 1) * sizeof(WCHAR);
        }
    }

    /* --- HKLM\SYSTEM\HardwareConfig\{GUID}\LastConfig ---
     * Early-boot code paths (and some driver installers) read the
     * machine-identity SMBIOS blob from this value verbatim. The
     * launcher's offline rewrite does not cover it because the GUID
     * subkey is created per-boot by HAL. Treat the value as a REG_SZ
     * HardwareConfig identifier; rewrite to the MachineGuid shape so
     * a later code path that joins this against the Cryptography key
     * sees a consistent pair. */
    if (unicode_contains_i(key_path, L"SYSTEM\\HardwareConfig") &&
        unicode_equals_i(value_name, L"LastConfig")) {
        if (cfp_cfg_get(CFP_FID_MACHINE_GUID, ov, 16)) {
            WCHAR full[80];
            guid_to_wstring(ov, full);
            ULONG n = 0;
            for (ULONG i = 0; full[i] && n + 1 < out_chars; ++i) {
                out_buf[n++] = full[i];
            }
            if (out_chars) out_buf[n] = 0;
            return (n + 1) * sizeof(WCHAR);
        }
    }

    /* --- HARDWARE\DESCRIPTION\System\BIOS values --- */
    if (unicode_contains_i(key_path, L"HARDWARE\\DESCRIPTION\\System\\BIOS")) {
        if (unicode_equals_i(value_name, L"BIOSVendor") ||
            unicode_equals_i(value_name, L"SystemManufacturer")) {
            if (cfp_cfg_get(CFP_FID_BIOS_VENDOR, ov, 16)) {
                wchars = bytes_to_wstring(ov, 16, out_buf, out_chars);
                return (wchars + 1) * sizeof(WCHAR);
            }
        }
        if (unicode_equals_i(value_name, L"BIOSVersion") ||
            unicode_equals_i(value_name, L"SystemProductName") ||
            unicode_equals_i(value_name, L"SystemFamily")) {
            if (cfp_cfg_get(CFP_FID_BIOS_VERSION, ov, 16)) {
                wchars = bytes_to_wstring(ov, 16, out_buf, out_chars);
                return (wchars + 1) * sizeof(WCHAR);
            }
        }
        if (unicode_equals_i(value_name, L"SystemSKU")) {
            if (cfp_cfg_get(CFP_FID_CHASSIS_SERIAL, ov, 16)) {
                wchars = bytes_to_wstring(ov, 16, out_buf, out_chars);
                return (wchars + 1) * sizeof(WCHAR);
            }
        }
    }

    /* --- W32Time NtpServer --- */
    if (unicode_contains_i(key_path, L"Services\\W32Time\\Parameters") &&
        unicode_equals_i(value_name, L"NtpServer")) {
        static const WCHAR npool[] = L"time.windows.com,0x9";
        ULONG n = 0;
        while (npool[n] && n + 1 < out_chars) { out_buf[n] = npool[n]; ++n; }
        if (out_chars) out_buf[n] = 0;
        return (n + 1) * sizeof(WCHAR);
    }

    return 0;
}

/* InstallDate is REG_DWORD (seconds since 1970). CFG carries a FILETIME
 * in 100-ns since 1601, so we convert before writing. */
static BOOLEAN
compute_dword_override(PCUNICODE_STRING key_path, PCUNICODE_STRING value_name,
                      PULONG out)
{
    if (unicode_contains_i(key_path, L"Windows NT\\CurrentVersion") &&
        unicode_equals_i(value_name, L"InstallDate")) {
        ULONGLONG ft;
        if (cfp_cfg_get(CFP_FID_INSTALL_DATE, &ft, sizeof(ft))) {
            /* FILETIME -> Unix epoch: subtract 116444736000000000 (100-ns
             * ticks between 1601 and 1970), divide by 10^7. */
            ULONGLONG unix_100ns = ft - 116444736000000000ULL;
            *out = (ULONG)(unix_100ns / 10000000ULL);
            return TRUE;
        }
    }
    /* BitLocker reports off under machine-identity spoof. */
    if (unicode_contains_i(key_path, L"Control\\BitLockerStatus")) {
        ULONG toggles = 0;
        cfp_cfg_get(CFP_FID_TOGGLES, &toggles, sizeof(toggles));
        if (toggles & CFP_TOGGLE_MACHINE_IDENTITY) {
            *out = 0;
            return TRUE;
        }
    }
    return FALSE;
}

/* ---------------- post-op patcher ---------------- */

/* Apply the rewrite to a caller-provided KeyValuePartialInformation /
 * KeyValueFullInformation buffer in place. We only ever shrink or
 * equal-size-rewrite inside the DataLength the kernel already computed —
 * growing would require reallocating the caller's buffer. */
static void
patch_kvpi(PKEY_VALUE_PARTIAL_INFORMATION kvpi,
           PCUNICODE_STRING key_path,
           PCUNICODE_STRING value_name)
{
    if (!kvpi) return;

    switch (kvpi->Type) {
    case REG_SZ:
    case REG_EXPAND_SZ: {
        if (kvpi->DataLength < sizeof(WCHAR)) return;
        ULONG cap_chars = kvpi->DataLength / sizeof(WCHAR);
        WCHAR *dst = (WCHAR *)kvpi->Data;
        ULONG w_bytes = compute_wsz_override(key_path, value_name, dst, cap_chars);
        if (w_bytes > 0 && w_bytes <= kvpi->DataLength) {
            kvpi->DataLength = w_bytes;
        }
        /* Enum\{PCI,USB,USBSTOR}\... sibling values: Service /
         * Driver / ContainerID / Mfg carry the same vendor identity
         * as HardwareID and must be rewritten in sync. Always call
         * the helper (not only on compute_wsz_override miss) so a
         * future Enum-subpath entry added to compute_wsz_override
         * does not silently skip sibling rewrites at that value. The
         * helper is a no-op for value names it does not match and
         * for all values outside the Enum tree. */
        cfp_rewrite_enum_sibling_sz(kvpi, key_path, value_name);
        break;
    }

    case REG_DWORD:
        if (kvpi->DataLength == sizeof(ULONG)) {
            ULONG new_v;
            if (compute_dword_override(key_path, value_name, &new_v)) {
                *(PULONG)kvpi->Data = new_v;
            }
        }
        break;

    case REG_MULTI_SZ: {
        /* SetupDi device enumeration: HardwareID / CompatibleIDs under
         *   \Registry\Machine\System\CurrentControlSet\Enum\PCI\...
         *   \Registry\Machine\System\CurrentControlSet\Enum\USB\...
         *   \Registry\Machine\System\CurrentControlSet\Enum\USBSTOR\...
         * are REG_MULTI_SZ. PCI / USB carry VEN_/DEV_ or VID_/PID_ four-
         * hex-digit tokens we substitute from the namespace-correct
         * vendev pool. USBSTOR carries textual Vendor__Product_____Rev
         * strings we substitute against a retail-product tell table.
         * Both rewrites are same-length so DataLength and the
         * REG_MULTI_SZ double-NUL frame carry through unchanged. */
        BOOLEAN is_usbstor = unicode_contains_i(key_path, L"\\Enum\\USBSTOR\\");
        BOOLEAN is_pci = !is_usbstor &&
                         unicode_contains_i(key_path, L"\\Enum\\PCI\\");
        BOOLEAN is_usb = !is_usbstor && !is_pci &&
                         unicode_contains_i(key_path, L"\\Enum\\USB\\");
        if (!is_pci && !is_usb && !is_usbstor) break;
        if (!unicode_equals_i(value_name, L"HardwareID") &&
            !unicode_equals_i(value_name, L"CompatibleIDs") &&
            !unicode_equals_i(value_name, L"CompatibleID")) {
            break;
        }
        if (kvpi->DataLength < 4 * sizeof(WCHAR)) break;
        if (is_usbstor) {
            cfp_rewrite_textual_tells((WCHAR *)kvpi->Data,
                                      kvpi->DataLength / sizeof(WCHAR));
        } else {
            if (kvpi->DataLength < 8 * sizeof(WCHAR)) break;
            cfp_rewrite_hwid_vendev((WCHAR *)kvpi->Data,
                                    kvpi->DataLength / sizeof(WCHAR),
                                    is_usb);
        }
        break;
    }

    case REG_BINARY: {
        /* Surfaces 29, 30, 48: DigitalProductId, DigitalProductId4, EDID. */
        if (unicode_contains_i(key_path, L"Windows NT\\CurrentVersion") &&
            unicode_equals_i(value_name, L"DigitalProductId")) {
            if (kvpi->DataLength == 164) {
                UCHAR ov[164];
                if (cfp_cfg_get(CFP_FID_DIGITAL_PRODUCT_ID, ov, sizeof(ov))) {
                    RtlCopyMemory(kvpi->Data, ov, 164);
                }
            }
            break;
        }
        if (unicode_contains_i(key_path, L"Enum\\DISPLAY") &&
            unicode_equals_i(value_name, L"EDID")) {
            UCHAR edid[128];
            if (cfp_edid_build(edid) && kvpi->DataLength >= 128) {
                RtlCopyMemory(kvpi->Data, edid, 128);
                kvpi->DataLength = 128;
            }
            break;
        }
        /* HardwareConfig\{GUID}\LastConfig in its REG_BINARY shape: the
         * real bare-metal SMBIOS blob (or a short identifier under a
         * HAL-written GUID subkey). If the value is at least 16 bytes
         * we overwrite the first 16 with the SMBIOS UUID so a sample
         * that hashes the blob picks up our seed-derived identity
         * rather than the host's. */
        if (unicode_contains_i(key_path, L"SYSTEM\\HardwareConfig") &&
            unicode_equals_i(value_name, L"LastConfig")) {
            if (kvpi->DataLength >= 16) {
                UCHAR uuid[16];
                if (cfp_cfg_get(CFP_FID_SMBIOS_UUID, uuid, sizeof(uuid))) {
                    RtlCopyMemory(kvpi->Data, uuid, 16);
                }
            }
            break;
        }
        break;
    }

    default:
        break;
    }
}

/* ---------------- callback ---------------- */

static NTSTATUS
cfp_cm_callback(PVOID ctx, PVOID arg1, PVOID arg2)
{
    UNREFERENCED_PARAMETER(ctx);

    REG_NOTIFY_CLASS klass = (REG_NOTIFY_CLASS)(ULONG_PTR)arg1;
    if (klass != RegNtPostQueryValueKey) {
        return STATUS_SUCCESS;
    }

    PREG_POST_OPERATION_INFORMATION post = (PREG_POST_OPERATION_INFORMATION)arg2;
    if (!post || !NT_SUCCESS(post->Status)) {
        return STATUS_SUCCESS;
    }

    /* PID filter. */
    HANDLE pid = PsGetCurrentProcessId();
    if (!cfp_target_contains(pid)) {
        return STATUS_SUCCESS;
    }

    /* Resolve the key-object name. CmCallbackGetKeyObjectIDEx gives us
     * the full registry path.
     *
     * Documented limit (subkey-name rewrite): this post-op path sees the
     * key_path and value_name the kernel resolved against the existing
     * key tree, and can only mutate value DATA inside the caller's KVPI
     * buffer. It cannot rename the subkeys themselves — so subkey names
     * that still spell out VEN_80EE / PID_CAFE / VBOX_HARDDISK inside
     *   \Enum\PCI\VEN_80EE&DEV_CAFE\...
     *   \Enum\USB\VID_80EE&PID_CAFE\...
     *   \Enum\USBSTOR\DiskVBOX_HARDDISK_1.0\...
     * are returned unchanged to a caller that walks RegEnumKey /
     * NtEnumerateKey directly against the Enum tree. Rewriting a subkey
     * NAME requires a pre-op intercept on RegOpenKey/RegCreateKey with
     * caller-side allocation of a synthesized returned name, or a
     * syscall-layer intercept on NtEnumerateKey returns; both are
     * intrusive enough to move the rewrite out of this file. Setup*
     * device-enumeration APIs read the VALUES (HardwareID / Service /
     * ContainerID / Mfg) rather than parse the subkey name, so the
     * value-level rewrites below still defeat the audit's documented
     * probe surface — this is a known gap against a probe that reads
     * the subkey name directly, not against SetupDiEnumDevices +
     * SetupDiGetDeviceRegistryProperty. */
    PCUNICODE_STRING key_path = NULL;
    NTSTATUS s = CmCallbackGetKeyObjectIDEx(&g_cookie, post->Object,
                                            NULL, &key_path, 0);
    if (!NT_SUCCESS(s) || !key_path) {
        return STATUS_SUCCESS;
    }

    PREG_QUERY_VALUE_KEY_INFORMATION pre =
        (PREG_QUERY_VALUE_KEY_INFORMATION)post->PreInformation;

    if (pre && pre->ValueName && pre->KeyValueInformation &&
        pre->KeyValueInformationClass == KeyValuePartialInformation) {
        PKEY_VALUE_PARTIAL_INFORMATION kvpi =
            (PKEY_VALUE_PARTIAL_INFORMATION)pre->KeyValueInformation;
        patch_kvpi(kvpi, key_path, pre->ValueName);
    }

    CmCallbackReleaseKeyObjectIDEx(key_path);
    return STATUS_SUCCESS;
}

NTSTATUS
cfp_cm_register(PDRIVER_OBJECT drv)
{
    UNICODE_STRING alt;
    /* Microsoft-registered Security Enhancer altitude range is
     * 330000-339998. Picking 331457.0 (just above the FsFilter Security
     * Enhancer minimum) keeps us inside an allocated range so a reseed
     * does not collide with an in-tree filter the launcher can observe;
     * the real per-install allocation is a build-time swap target.
     * 331456.1.0.0 (the previous literal) is not in the allocation table
     * and a strict Windows build (one with cmchkr enabled) refuses to
     * register against it. */
    RtlInitUnicodeString(&alt, L"331457.0");
    /* Pass the real DriverObject (not NULL) so the Cm manager holds a
     * lifetime reference on the driver image; an unload race (where the
     * image is about to leave while a post-op callback is in flight)
     * then blocks on the Cm reference instead of racing on NULL. */
    g_driver = drv;
    NTSTATUS s = CmRegisterCallbackEx(cfp_cm_callback, &alt, drv, NULL,
                                      &g_cookie, NULL);
    if (NT_SUCCESS(s)) g_registered = TRUE;
    return s;
}

void
cfp_cm_unregister(void)
{
    if (g_registered) {
        CmUnRegisterCallback(g_cookie);
        g_registered = FALSE;
        g_cookie.QuadPart = 0;
    }
}
