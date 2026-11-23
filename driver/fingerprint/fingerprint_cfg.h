/* fingerprint_cfg.h -- thin wrapper. CHAMBER_CFG_V2 lives in ../the_chamber.h
 * (added by Agent B in the merge order). Consumers in this directory include
 * this file instead so a later relocation of the authoritative struct does
 * not require a sweep of every .c file here.
 */

#ifndef CHAMBER_FINGERPRINT_CFG_H
#define CHAMBER_FINGERPRINT_CFG_H

#include "../the_chamber.h"

/* TODO(merge): CHAMBER_CFG_V2 and its magic constant are provided by
 * driver/the_chamber.h after the HV-side agent's merge. Before that
 * merge lands this directory does not compile standalone — expected;
 * see the merge order in the identity design doc under audit/.
 */

/* Read-only accessor the local .c files use; defined in cfg_shared.c. */
struct _CHAMBER_CFG_V2;

NTSTATUS cfp_cfg_load(PUNICODE_STRING registry_path);
void     cfp_cfg_unload(void);

/* Copies `len` bytes of the override identified by `field` into `out`.
 * Returns FALSE if the field is unknown or the length does not match.
 * Safe to call at PASSIVE / APC_LEVEL; callers in DISPATCH_LEVEL paths must
 * stage data in advance.
 */
BOOLEAN  cfp_cfg_get(_In_ ULONG field_id,
                     _Out_writes_bytes_(len) PVOID out,
                     _In_ ULONG len);

/* Field identifiers for cfp_cfg_get. Independent of the installer's
 * field-ID numbering so this directory does not have to depend on an
 * installer header.
 */
enum cfp_field_id {
    CFP_FID_COMPUTER_NAME = 1,      /* 16 bytes ASCII (15 chars + NUL) */
    CFP_FID_MACHINE_GUID,           /* 16 raw bytes */
    CFP_FID_INSTALL_DATE,           /* 8 bytes FILETIME */
    CFP_FID_PRODUCT_ID,             /* 24 bytes ASCII */
    CFP_FID_DIGITAL_PRODUCT_ID,     /* 164 bytes */
    CFP_FID_CPU_BRAND,              /* 48 bytes ASCII (brand string) */
    CFP_FID_SMBIOS_UUID,            /* 16 raw bytes */
    CFP_FID_BASEBOARD_SERIAL,       /* 16 bytes ASCII */
    CFP_FID_CHASSIS_SERIAL,         /* 16 bytes ASCII */
    CFP_FID_BIOS_VENDOR,            /* 16 bytes ASCII */
    CFP_FID_BIOS_VERSION,           /* 16 bytes ASCII */
    CFP_FID_MAC_ADDR_0,             /* 6 bytes MAC; +N for adapter N (0..5) */
    CFP_FID_DISK_SERIAL_0 = 100,    /* 20 bytes ASCII per slot; +N for slot N (0..19) */
    CFP_FID_VOLUME_SERIAL_0 = 200,  /* 4 bytes per volume; +N for volume N (0..3) */
    CFP_FID_GPU_VEN_DEV,            /* 4 bytes: (VEN<<16)|DEV */
    CFP_FID_EDID_NONCE,             /* 16 raw bytes */
    CFP_FID_TOGGLES                 /* 4 bytes (bit-packed; see CFG v2 offset 44) */
};

/* Toggle bit indices (match CFG v2 toggles field). */
#define CFP_TOGGLE_CI_STATE_SPOOF        0x00000001UL
#define CFP_TOGGLE_MACHINE_IDENTITY      0x00000002UL
#define CFP_TOGGLE_TPM_ABSENT            0x00000200UL

#endif /* CHAMBER_FINGERPRINT_CFG_H */
