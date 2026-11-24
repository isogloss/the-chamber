/* edid_template.c -- 128-byte EDID template with seed-spliced identity.
 *
 * A sample reads the monitor EDID from
 * HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\<mfr>\<serial>\Device
 * Parameters\EDID. Our CmRegisterCallbackEx handler supplies a synthetic
 * 128-byte blob whenever a spoofed PID reads that value.
 *
 * EDID 1.3 structure (relevant offsets only):
 *   0x00-0x07  Fixed header: 00 FF FF FF FF FF FF 00
 *   0x08-0x09  Manufacturer ID (3-char PnP ID, 15-bit big-endian packed)
 *   0x0A-0x0B  Product code (16-bit LE)
 *   0x0C-0x0F  Serial number (32-bit LE)
 *   0x10       Week of manufacture
 *   0x11       Year of manufacture (offset 1990)
 *   0x12       EDID version
 *   0x13       EDID revision
 *   0x14-0x17  Video input / size / gamma (left static — real displays
 *              published by one vendor share these across SKUs)
 *   ...
 *   0x7F       Checksum. Sum of bytes 0..127 mod 256 must equal 0.
 *
 * The CFG v2 edid_nonce field is 16 bytes. We splice bytes 0..7 into the
 * manufacturer / product / serial / date fields (keeping the manufacturer
 * ID in the printable A-Z range so the resulting 3-letter PnP code is
 * valid) and bytes 8..15 into the preferred-timing descriptor's serial
 * string. Everything else stays at a plausible 1920x1080 LCD shape.
 */

#include "fingerprint_cfg.h"

/* Pool of plausible panel-model strings used to fill the monitor-name
 * detailed descriptor (descriptor 1). Each entry is up to 12 ASCII chars;
 * the writer pads with spaces and terminates with 0x0A at offset 0x59. The
 * index is seed-derived so cross-boot EDID reads differ in the model name
 * as well as the manufacturer / product / serial fields. No real-vendor
 * marketing names: generic panel-code shapes only. */
static const char * const g_edid_model_pool[] = {
    "LP270Q7HM",
    "LM250WR3 ",
    "M270QAN02",
    "LM340UW1 ",
    "LTN156HL02",
    "N133HCE-E",
    "B140HAN06",
    "UW344FHD",
    "QX270 M01",
    "WQ320 D4",
    "IPS QHD",
    "IPS 4K",
    "VA 1440P",
    "OLED FHD",
    "HVA 165HZ",
    "FHD GAME",
};

/* 128-byte canonical EDID for a 1920x1080@60Hz LCD, with manufacturer /
 * product / serial fields we overwrite from the seed. The remaining bytes
 * encode a reasonable set of standard + detailed timing blocks and base
 * display parameters; the checksum at byte 127 is recomputed. */
static const UCHAR g_edid_base[128] = {
    /* Fixed header */
    0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
    /* Manufacturer ID (DELL = 0x10, 0xAC placeholder; overwritten) */
    0x10, 0xAC,
    /* Product code (LE, overwritten) */
    0x12, 0x34,
    /* Serial number (LE, overwritten) */
    0x00, 0x00, 0x00, 0x00,
    /* Week + year (overwritten) */
    0x15, 0x1F,                            /* week 21, year 2021 */
    /* EDID 1.3 */
    0x01, 0x03,
    /* Video input: digital, 8-bit, DisplayPort */
    0x80,
    /* Max image size (cm): 53 x 30 */
    0x35, 0x1E,
    /* Gamma 2.2 */
    0x78,
    /* Features: RGB 4:4:4 + sRGB */
    0x2A,
    /* Chromaticity coordinates (sRGB) */
    0xEE, 0x95, 0xA3, 0x54, 0x4C, 0x99, 0x26, 0x0F, 0x50, 0x54,
    /* Established timings (640x480@60, 720x400@70, 1024x768@60) */
    0xA5, 0x4B, 0x00,
    /* Standard timing block (8 slots) */
    0xB3, 0x00, 0xD1, 0xC0, 0x81, 0xC0, 0x81, 0x00,
    0x81, 0x80, 0xA9, 0xC0, 0xB3, 0x00, 0x01, 0x01,
    /* Detailed timing block 1: 1920x1080@60Hz, 148.5 MHz pixel clock */
    0x02, 0x3A, 0x80, 0x18, 0x71, 0x38, 0x2D, 0x40, 0x58, 0x2C,
    0x45, 0x00, 0x0F, 0x28, 0x21, 0x00, 0x00, 0x1E,
    /* Detailed descriptor 2: display name "GENERIC LCD" */
    0x00, 0x00, 0x00, 0xFC, 0x00,
    'G', 'E', 'N', 'E', 'R', 'I', 'C', ' ', 'L', 'C', 'D', ' ', 0x0A,
    /* Detailed descriptor 3: serial number (ASCII, overwritten) */
    0x00, 0x00, 0x00, 0xFF, 0x00,
    'S', 'E', 'R', 'I', 'A', 'L', 'N', 'O', ' ', ' ', ' ', ' ', 0x0A,
    /* Detailed descriptor 4: range limits */
    0x00, 0x00, 0x00, 0xFD, 0x00,
    0x32, 0x4C, 0x1E, 0x50, 0x11, 0x00, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    /* Extensions, checksum */
    0x00, 0x00
};

/* Fills `out_128` with a seed-spliced EDID. Returns FALSE if the CFG does
 * not carry an edid_nonce (shouldn't happen post-DriverEntry). */
BOOLEAN
cfp_edid_build(UCHAR out_128[128])
{
    UCHAR nonce[16];
    if (!cfp_cfg_get(CFP_FID_EDID_NONCE, nonce, sizeof(nonce))) {
        return FALSE;
    }

    RtlCopyMemory(out_128, g_edid_base, sizeof(g_edid_base));

    /* Manufacturer ID (3-letter PnP code packed into 2 bytes, 5 bits each,
     * big-endian). Each 5-bit field holds (letter - 'A' + 1), range 1-26.
     * We derive the three letter indices from nonce[0..2] and repack. */
    UCHAR L1 = 1 + (nonce[0] % 26);
    UCHAR L2 = 1 + (nonce[1] % 26);
    UCHAR L3 = 1 + (nonce[2] % 26);
    out_128[0x08] = (UCHAR)((L1 << 2) | (L2 >> 3));
    out_128[0x09] = (UCHAR)(((L2 & 0x07) << 5) | L3);

    /* Product code (LE) */
    out_128[0x0A] = nonce[3];
    out_128[0x0B] = nonce[4];

    /* Serial number (LE) */
    out_128[0x0C] = nonce[5];
    out_128[0x0D] = nonce[6];
    out_128[0x0E] = nonce[7];
    out_128[0x0F] = nonce[8];

    /* Week of manufacture 1..52; year 2015..2023 (offset 1990 -> 25..33) */
    out_128[0x10] = 1 + (nonce[9] % 52);
    out_128[0x11] = 25 + (nonce[10] % 9);

    /* Monitor-name descriptor (descriptor 1) payload at
     * 0x36 + 18*1 + 5 = 0x4D..0x58, terminator 0x0A at 0x59. Pick a
     * model string from the pool via the seed, pad to 12 chars. */
    {
        ULONG pool_n = sizeof(g_edid_model_pool) / sizeof(g_edid_model_pool[0]);
        ULONG idx = ((ULONG)nonce[0] + (ULONG)nonce[1] + (ULONG)nonce[2]) % pool_n;
        const char *model = g_edid_model_pool[idx];
        ULONG len = 0;
        while (len < 12 && model[len] != '\0') {
            out_128[0x4D + len] = (UCHAR)model[len];
            ++len;
        }
        for (; len < 12; ++len) {
            out_128[0x4D + len] = ' ';
        }
        out_128[0x59] = 0x0A;
    }

    /* Serial-string descriptor (descriptor 2) payload at
     * 0x36 + 18*2 + 5 = 0x5F..0x6A, terminator 0x0A at 0x6B. The earlier
     * revision targeted 0x71, which lands inside descriptor 3 (the Range
     * Limits block) and produced a structurally invalid EDID. Overwrite
     * 12 ASCII chars from nonce[11..14] via a small LCG so each boot
     * yields a distinct string while leaving the range limits intact. */
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    ULONG s = ((ULONG)nonce[11] << 24) | ((ULONG)nonce[12] << 16) |
              ((ULONG)nonce[13] <<  8) | ((ULONG)nonce[14]      );
    for (ULONG i = 0; i < 12; ++i) {
        s = s * 1664525UL + 1013904223UL;
        out_128[0x5F + i] = (UCHAR)alphabet[(s >> 16) % 36];
    }

    /* Checksum: sum of bytes 0..127 must be 0 mod 256. */
    UCHAR sum = 0;
    for (ULONG i = 0; i < 127; ++i) sum = (UCHAR)(sum + out_128[i]);
    out_128[127] = (UCHAR)(0 - sum);

    return TRUE;
}
