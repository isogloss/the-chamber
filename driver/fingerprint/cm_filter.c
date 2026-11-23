/* cm_filter.c -- CmRegisterCallbackEx handler.
 *
 * Covers wave 4 design surfaces 24-34, 48, 56-58, 61 — every registry
 * value a packed sample reads to fingerprint the host.
 *
 * The registered callback fires pre-op and post-op on every registry
 * operation in the kernel. We intercept RegNtPreQueryValueKey and
 * RegNtPostQueryValueKey only, PID-filter against the spoof list, and
 * for matched paths and value names we supply a seed-derived override.
 *
 * Why we patch on *post*-op (for most paths) rather than *pre*:
 * returning STATUS_CALLBACK_BYPASS from pre-op with a synthesized buffer
 * works but forces us to allocate and lifetime-manage every buffer. The
 * cleaner path is to let the real read happen, then overwrite the
 * returned buffer in place at post-op. Registry values are usually small
 * (REG_SZ / REG_DWORD / short REG_BINARY) and the kernel copied them into
 * the caller's KVPI buffer, which we can edit before returning.
 *
 * One exception: surface 48 (EDID) is where we really do want to
 * synthesize the whole 128-byte blob, because the real value may not
 * exist at all on a VM or the real monitor may differ from the shape we
 * claim. For that one path we rewrite the blob in post-op to our EDID
 * template, truncating if the caller's buffer is shorter.
 */

#include "fingerprint_cfg.h"

#define CFP_TAG  'cFPC'

/* --- forward decls from other TUs --- */
BOOLEAN cfp_target_contains(HANDLE pid);
BOOLEAN cfp_edid_build(UCHAR out_128[128]);

/* --- state --- */

static LARGE_INTEGER   g_cookie    = {0};
static BOOLEAN         g_registered = FALSE;

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

/* ---------------- per-path rewriters ---------------- */

/* Compute the override wide-string for a given key path + value name.
 * Returns the number of BYTES placed in out_buf, or 0 if no rewrite. */
static ULONG
compute_wsz_override(PCUNICODE_STRING key_path, PCUNICODE_STRING value_name,
                     WCHAR *out_buf, ULONG out_chars)
{
    UCHAR ov[32];
    WCHAR wtmp[80];
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
    /* BitLocker off — surface 61. */
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
     * the full registry path. */
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
cfp_cm_register(void)
{
    UNICODE_STRING alt;
    RtlInitUnicodeString(&alt, L"331456.1.0.0");
    NTSTATUS s = CmRegisterCallbackEx(cfp_cm_callback, &alt, NULL, NULL,
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
