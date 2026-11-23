# Wave 4 Design — Persistent-Seed Machine Identity

**Status**: design-locked. Three parallel implementation agents (A/B/C) start from
this doc. No agent asks for clarification; every answer is below.

**Core requirement** (verbatim from the request): the seed makes the computer look
**totally different** on every bootup, but does **not** randomize on every bootup —
only when the user clicks "Randomize Seed" in the launcher. Every process-observable
fingerprint changes under a new seed. The Chamber retains its signing identity
(cert, driver file hash, embedded cert in the launcher) — only the runtime-visible
machine identity is seed-controlled.

**Posture**: passive-dump sandbox. The target is a packed Windows user-mode sample
running its anti-sandbox payload in-process. The sample queries APIs; we rewrite
the returns. No packet spoofing, no on-disk mutation, no PG-unsafe hooking.

---

## Section 1 — Fingerprint surface enumeration

Grouped by access mechanism (mechanism assignment is in Section 2). Each entry is
the API / syscall / MSR / registry path a target process can query.

### 1.a — CPU identity (CPUID + MSR; HV-interceptable)

| # | Surface | Field read |
|---|---|---|
| 1 | `CPUID 0x1 EAX` | Processor signature (family/model/stepping) |
| 2 | `CPUID 0x1 EBX[31:24]` | Initial APIC ID |
| 3 | `CPUID 0x1 EBX[23:16]` / `EBX[15:8]` | Max logical procs per pkg / CLFLUSH size |
| 4 | `CPUID 0x1 ECX / EDX` | Feature flags (ECX[31] hypervisor-present already handled) |
| 5 | `CPUID 0x7 subleaf 0 EBX/ECX/EDX` | Structured extended feature flags |
| 6 | `CPUID 0xB` / `CPUID 0x1F` | Extended topology enumeration |
| 7 | `CPUID 0x15 EAX/EBX/ECX` | TSC / core crystal clock ratio |
| 8 | `CPUID 0x16 EAX/EBX/ECX` | Processor base / max / bus frequency |
| 9 | `CPUID 0x80000001 ECX/EDX` | Extended feature flags |
| 10 | `CPUID 0x80000002-0x80000004` | 48-byte brand string |
| 11 | `CPUID 0x80000008 EAX/ECX` | Virt/phys address bits; physical core count |
| 12 | `CPUID 0x8000001D` / `CPUID 0x8000001E` | Cache / core topology extended |
| 13 | `CPUID 0x8000001F` | SEV / SME capability (must read as "SEV off") |
| 14 | `RDMSR 0x8B` (`IA32_BIOS_SIGN_ID`) | Microcode revision (top 32 bits) |
| 15 | `RDMSR 0x17` (`IA32_PLATFORM_ID`) | Platform-ID |
| 16 | `RDMSR 0xC0000103` (`TSC_AUX`) | Per-CPU logical ID tag |
| 17 | `RDMSR 0xC0010015` (`HWCR`) | AMD HWCR config bits |

### 1.b — SMBIOS / firmware (user-mode system call; interceptable per-process)

| # | Surface | Field read |
|---|---|---|
| 18 | `GetSystemFirmwareTable('RSMB', 0, …)` | DMI table blob |
| 19 | `NtQuerySystemInformation(SystemFirmwareTableInformation=76)` | Same blob via Nt-API |
| 20 | DMI Type 0 (BIOS) offset 0x04/0x05/0x08 | BIOS vendor, BIOS version, release date |
| 21 | DMI Type 1 (System) offset 0x04/0x05/0x07/0x08 | Manufacturer, product, serial, UUID |
| 22 | DMI Type 2 (Baseboard) offset 0x04/0x05/0x07 | Mfr, product, serial |
| 23 | DMI Type 3 (Chassis) offset 0x04/0x06/0x07 | Mfr, type, serial |
| 24 | `HKLM\SYSTEM\HardwareConfig\{GUID}\LastConfig` + `BIOSVendor`/`BIOSVersion` | Reg mirror of DMI |
| 25 | `HKLM\HARDWARE\DESCRIPTION\System\BIOS\*` | `BIOSVendor`, `BIOSVersion`, `SystemManufacturer`, `SystemProductName`, `SystemFamily`, `SystemSKU` |

### 1.c — Registry identity (per-process registry filter rewrite)

| # | Surface | Value |
|---|---|---|
| 26 | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | GUID string |
| 27 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate` | REG_DWORD Unix time |
| 28 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId` | "XXXXX-XXXXX-XXXXX-XXXXX" |
| 29 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId` | 164-byte blob |
| 30 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId4` | ~1272-byte blob |
| 31 | `HKLM\SYSTEM\Setup\OOBE\*` | `MediaBootInstall`, `OOBEInProgress` |
| 32 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate` | `SusClientId`, `SusClientIdValidation` |
| 33 | `HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\{GUID}` | Per-profile GUID |
| 34 | `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\NtpServer` | NTP peer |

### 1.d — OS-reported CI / Secure Boot state (NtQuerySystemInformation)

| # | Surface | Class |
|---|---|---|
| 35 | `NtQuerySystemInformation(SystemCodeIntegrityInformation=103)` | `SYSTEM_CODEINTEGRITY_INFORMATION.CodeIntegrityOptions` |
| 36 | `NtQuerySystemInformation(SystemSecureBootPolicyInformation=144)` | Secure Boot policy blob |
| 37 | `NtQuerySystemInformation(SystemCodeIntegrityPolicyFullInformation=176)` | WDAC policy blob |

### 1.e — Storage (per-process syscall + IOCTL rewrite)

| # | Surface | Mechanism |
|---|---|---|
| 38 | `IOCTL_STORAGE_QUERY_PROPERTY(StorageDeviceProperty)` | Serial, model, firmware, vendor |
| 39 | `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` | Geometry + size |
| 40 | `GetVolumeInformationW` / `NtQueryVolumeInformationFile(FileFsVolumeInformation)` | Volume label, serial, FS type |
| 41 | `IOCTL_STORAGE_QUERY_PROPERTY(StorageAdapterProperty)` | Adapter vendor/model |

### 1.f — Network adapters, identity only (no packet spoof)

| # | Surface | Mechanism |
|---|---|---|
| 42 | `GetAdaptersAddresses` (Iphlpapi) | MAC, adapter GUID, FriendlyName, Description |
| 43 | `GetAdaptersInfo` | Older MAC/desc enum |
| 44 | NSI (`NsiAllocateAndGetTable`, `NsiGetAllParameters`) | Underlying kernel table |
| 45 | `IOCTL_NDIS_QUERY_GLOBAL_STATS(OID_802_3_PERMANENT_ADDRESS / OID_802_3_CURRENT_ADDRESS)` | Hardware MAC via `\Device\Ndis` |

### 1.g — Display / GPU

| # | Surface | Mechanism |
|---|---|---|
| 46 | `EnumDisplayDevicesW` | `DeviceID` = `PCI\VEN_xxxx&DEV_xxxx&…` |
| 47 | `SetupDiEnumDeviceInterfaces` + `SetupDiGetDeviceRegistryPropertyW(SPDRP_HARDWAREID)` | PCI VEN/DEV |
| 48 | `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\<mfr>\<serial>\Device Parameters\EDID` | 128-byte EDID blob |
| 49 | `D3DKMTEnumAdapters2` + `D3DKMTQueryAdapterInfo(KMTQAITYPE_ADAPTERTYPE / UMD_DRIVERNAME)` | Adapter name, LUID, driver name |

### 1.h — Machine topology

| # | Surface | Mechanism |
|---|---|---|
| 50 | `GetLogicalProcessorInformationEx` / `NtQuerySystemInformation(SystemLogicalProcessorInformation=73)` | Cores / NUMA layout |
| 51 | `GlobalMemoryStatusEx` / `NtQuerySystemInformation(SystemBasicInformation=0)` | Phys memory total + page size |
| 52 | `GetSystemInfo` | Processor count, page size, min/max app addr |
| 53 | `NtQuerySystemInformation(SystemProcessorPerformanceInformation=8)` | Per-CPU idle/kernel/user counters |

### 1.i — OS install identity

| # | Surface | Mechanism |
|---|---|---|
| 54 | `GetComputerNameExW(ComputerNameNetBIOS / DnsHostname / PhysicalNetBIOS)` | Computer name |
| 55 | `GetUserNameW` / `NtQueryInformationToken(TokenUser)` | Interactive-user name + SID |
| 56 | `HKU\<SID>` enumeration | Per-user SID string |
| 57 | `GetLocaleInfoEx` / `GetSystemDefaultLCID` | Locale |
| 58 | `GetTimeZoneInformation` / `GetDynamicTimeZoneInformation` | TZ bias, `StandardName` |

### 1.j — TPM + security

| # | Surface | Mechanism |
|---|---|---|
| 59 | `NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER)` + export EK | TPM Endorsement Key public |
| 60 | `Tbsi_GetDeviceInfo` / `Tbsip_Context_Create` + PCR read | PCR banks |
| 61 | `HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus` | BitLocker on/off / recovery-ID tag |
| 62 | `GetFirmwareEnvironmentVariable("SecureBoot", "{8be4df61-…}")` | Secure Boot variable |

### 1.k — HV self-fingerprint (the 11 Wave-3 items)

| # | Surface | Where |
|---|---|---|
| 63 | Service name | `HKLM\…\Services\<rand>` (installer-written) |
| 64 | Device symlink | `\DosDevices\<rand>` (`g_chamber_cfg.symlink_path`) |
| 65 | Per-subsystem pool tags (6: `svm/npt/vmexit/dump/integrity/dispatch`) | `POOLTAG` macro + 6 overrides in CFG |
| 66 | `CHAMBER_CFG_MAGIC` | `CHAMBER_CFG_MAGIC_V1` default; CFG v2 carries a seed-derived override |
| 67 | VMMCALL magic | `THE_CHAMBER_HYPERCALL_MAGIC` — seeded in CFG v2 |
| 68 | Rename donor | `stealth.c` cover-module name — seed picks from a donor pool |
| 69 | Driver on-disk filename | `%ProgramFiles%\The Chamber\<rand>.sys` |
| 70 | PE padding scramble | Already in Wave 3 (R8 broadened alphabet); seed selects the padding bytes |
| 71 | Section-scramble seed | `.cfg` section post-sign re-order salt |
| 72 | Guest ASID | VMCB `GuestASID` — seed picks from a sane range (0x1000–0x7FFF) |
| 73 | Driver image VA nonce | Base-reloc jitter + unique `.rdata` nonce used to break import-hash static fingerprints |

**Total distinct surfaces: 73.**

---

## Section 2 — Intercept mechanism assignment

Each surface is covered by exactly one of six mechanisms. No inline hooks, no SSDT
patches. `CmRegisterCallback`, `FltRegisterFilter`, `ProcessInstrumentationCallback`
are all production-EDR APIs documented in Windows Internals 7e.

**Legend**
- **HV** = AMD-SVM VMEXIT handler in `driver/vmexit.c` (CPUID / MSR intercept)
- **CM** = `CmRegisterCallbackEx` filter callback, scoped to `g_target_pid`
- **FLT** = `FltRegisterFilter` minifilter, scoped to `g_target_pid`
- **IC** = instrumentation callback (`NtSetInformationProcess(ProcessInstrumentationCallback)` on `g_target_pid`), rewrites syscall returns before user-mode RIP resumes
- **WFP** = Windows Filtering Platform (NSI callout path) — scoped by process
- **CFG** = read directly out of CHAMBER_CFG v2 by the HV itself (self-fingerprint)
- **GAP** = accepted uncovered gap, with reason

| # | Mechanism | Rationale |
|---|---|---|
| 1-13 | HV | CPUID is already intercepted; brand string / topology / feature leaves are rewritten in `handle_cpuid` from `g_chamber_cfg_v2`. `0x8000001F` must zero the SEV bit under all seeds. |
| 14-17 | HV | MSR intercept is wired; adds `0x8B`, `0x17`, `0xC0000103`, `0xC0010015` to the rewrite table. |
| 18-19 | IC | `NtQuerySystemInformation(SystemFirmwareTableInformation)` and `GetSystemFirmwareTable` both bottom out in a single syscall; the IC catches the return, rewrites the DMI structured blob in place with SMBIOS values from CHAMBER_CFG v2. |
| 20-23 | IC | Same syscall, same return rewrite — the DMI blob is parsed and patched Type 0/1/2/3. |
| 24-25 | CM | Registry reads of the HKLM reg-mirror. |
| 26-34 | CM | All registry identity values. CM filter is pre-op `RegNtPreQueryValueKey`; supplies rewritten value when path matches. |
| 35-37 | IC | `NtQuerySystemInformation` classes 103 / 144 / 176: IC catches return, writes a "CI off, Secure Boot default, no WDAC policy" view when `ci_state_spoof` toggle is set. |
| 38-39 | IC | `NtDeviceIoControlFile` with storage IOCTLs — IC catches the return path, rewrites the `STORAGE_DEVICE_DESCRIPTOR` / `DISK_GEOMETRY_EX` payload. |
| 40 | IC | `NtQueryVolumeInformationFile(FileFsVolumeInformation)` — IC rewrites `VolumeSerialNumber` and `VolumeLabel`. |
| 41 | IC | Storage adapter IOCTL — same path as 38/39. |
| 42-43 | IC | `GetAdaptersAddresses` → `NtDeviceIoControlFile` to `\Device\Nsi`; IC rewrites the returned adapter table. |
| 44 | WFP | NSI get-all-parameters path: a WFP callout at `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4` is too high; the clean path is a dedicated NSI module provider shim in `chamber_fingerprint.sys` that registers at `NsiInitializeModule` for the TCP/IP provider's module GUID. In practice this is also wrapped by the IC rewrite of 42/43, and surface 44 is **only reachable from a sample that calls NSI directly**. Treated by IC (same rewrite data) and WFP left as belt-and-braces. |
| 45 | FLT | `\Device\Ndis` is a filesystem-adjacent device; FLT pre-op `IRP_MJ_DEVICE_CONTROL` on `\Device\Ndis` (or an IRP-redirect through the minifilter instance). Returns the override MAC on `OID_802_3_PERMANENT_ADDRESS`. |
| 46-47 | IC + CM | `EnumDisplayDevices` reads `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\…\HardwareID` via Cm; IC also catches the `NtOpenKey` + `NtQueryValueKey` lower path. |
| 48 | CM | EDID is a registry value; CM supplies a seed-derived 128-byte EDID blob (valid checksum). |
| 49 | GAP (D3DKMT) | `D3DKMT*` calls go through `dxgkrnl`, which is not directly interceptable at IC level without touching DXGK (PG-hostile). Accepted gap — mitigation is to rewrite the preceding `EnumDisplayDevices` so a sample that only trusts `D3DKMT` still sees a believable adapter name via Setup API chain (which is CM-covered). |
| 50-53 | IC | `NtQuerySystemInformation` classes 73 / 0 / 8: IC passes through CPU topology (it must match HV-visible CPU count) but can rewrite `NUMAnode` layout if needed. By default, class 73 is passed through unchanged — the seed does not vary core count, only identity. |
| 54 | IC | `NtQueryInformationProcess(ProcessImageFileName)` and `GetComputerNameExW` go through `NtQuerySystemInformation` for computer-name queries; IC rewrites. |
| 55 | IC | `NtQueryInformationToken(TokenUser)` rewrite — supplies a seed-derived SID. **Only applied under `machine_identity_spoof` toggle because changing TokenUser mid-process can confuse CRT init.** |
| 56 | CM | Enumerating HKU shows SIDs — CM filters the enumeration to the spoofed SID. |
| 57-58 | CM + IC | Locale / TZ reads go through both Cm (reg) and Nt (`NtQuerySystemInformation(SystemTimeOfDayInformation)`); both are covered. |
| 59-60 | GAP (TPM) | TPM EK read goes through `tbs.dll` → `\Device\Tbs` → ACPI TPM device. Spoofing a believable EK (signed by a cert chain) is architecturally impossible — any genuine EK is attested, any fake fails verification. Accepted gap. Mitigation: `machine_identity_spoof` optionally rewrites `Tbsi_GetDeviceInfo` returns to "TPM not present" via IC — which is a believable state for many bare-metal machines without TPM 2.0 firmware. |
| 61 | CM | BitLocker reg path — CM supplies "off". |
| 62 | IC | `NtQuerySystemEnvironmentValueEx` for Secure Boot variable — IC rewrites return. |
| 63-73 | CFG | HV self-fingerprint: the HV driver reads these directly from `g_chamber_cfg_v2` at `DriverEntry`. Installer patches them in place before `NtLoadDriver`. |

**Mechanisms actually used**: `hv_cpuid_msr_intercept`, `cm_register_callback`,
`flt_register_filter`, `instrumentation_callback`, `wfp_nsi`, `self_cfg_read`.
Gaps: D3DKMT adapter path (surface 49), TPM EK (surfaces 59-60). Both documented.

**PG safety**: every mechanism above is a documented Windows kernel API. CM, FLT,
WFP, and process-instrumentation callbacks are what every production EDR uses; PG
hashes code pages, not callback tables, and these APIs are on the sanctioned list.
The HV layer is already PG-safe per Wave 1/3 analysis (no SSDT/IDT/GDT edits).

---

## Section 3 — CHAMBER_CFG v2 wire format

`#pragma pack(push, 1)`; little-endian; total size **632 bytes**; placed in a
writable `.cfg` section the launcher locates by magic + version.

```c
typedef struct _CHAMBER_CFG_V2 {
    /* ---- Header (12 bytes) ---- */
    ULONG     magic;                        /* off 0:  seedable — see 66 */
    ULONG     version;                      /* off 4:  2 */
    ULONG     total_length;                 /* off 8:  632 */

    /* ---- Master seed (32 bytes) ---- */
    UCHAR     seed[32];                     /* off 12: raw master seed */

    /* ---- Toggles (4 bytes, bit-packed) ---- */
    ULONG     toggles;                      /* off 44:
       bit  0:  ci_state_spoof              (surfaces 35-37)
       bit  1:  machine_identity_spoof      (surfaces 18-62 except gaps)
       bit  2:  hv_introspection_resist     (CHAMBER_HV_INTROSPECTION_RESIST)
       bit  3:  pool_tag_randomize_svm
       bit  4:  pool_tag_randomize_npt
       bit  5:  pool_tag_randomize_vmexit
       bit  6:  pool_tag_randomize_dump
       bit  7:  pool_tag_randomize_integrity
       bit  8:  pool_tag_randomize_dispatch
       bit  9:  tpm_absent_spoof            (gap 59-60 mitigation)
       bits 10-31: reserved (must be 0) */

    /* ---- HV identity fields (84 bytes) ---- */
    UCHAR     service_name[12];             /* off 48:  ASCII [a-z][a-z0-9]{3,9} + NUL pad */
    UCHAR     device_suffix[12];            /* off 60:  ASCII, appended to "\\Device\\" */
    ULONG     pool_tag[6];                  /* off 72:  svm/npt/vmexit/dump/integrity/dispatch */
    ULONGLONG vmmcall_magic;                /* off 96:  overrides THE_CHAMBER_HYPERCALL_MAGIC */
    ULONGLONG chamber_cfg_magic_override;   /* off 104: not used at boot (chicken/egg); stored for the uninstaller's registry sweep */
    UCHAR     rename_donor_index;           /* off 112: index into donor pool (see Section 4) */
    UCHAR     _pad0[3];                     /* off 113 */
    ULONG     guest_asid;                   /* off 116: VMCB GuestASID (0x1000-0x7FFF) */
    ULONG     section_scramble_seed;        /* off 120: .cfg post-sign reorder salt */
    ULONGLONG driver_nonce;                 /* off 124: .rdata nonce for import-hash break */

    /* ---- Machine identity fields (496 bytes) ---- */
    UCHAR     computer_name[16];            /* off 132: upper-case 15 chars + NUL, [A-Z0-9-]{8,15} */
    UCHAR     machine_guid[16];             /* off 148: raw GUID bytes */
    ULONGLONG install_date_filetime;        /* off 164: FILETIME (100-ns since 1601) */
    UCHAR     product_id[24];               /* off 172: "XXXXX-XXXXX-XXXXX-XXXXX" + NUL */
    UCHAR     digital_product_id[164];      /* off 196: raw DigitalProductId binary */
    UCHAR     cpu_brand_string[48];         /* off 360: 48-byte CPUID 0x80000002-4 return */
    UCHAR     smbios_system_uuid[16];       /* off 408: DMI type 1 offset 0x08 */
    UCHAR     baseboard_serial[16];         /* off 424: DMI type 2 serial (ASCII padded) */
    UCHAR     chassis_serial[16];           /* off 440: DMI type 3 serial */
    UCHAR     bios_vendor[16];              /* off 456: DMI type 0 vendor */
    UCHAR     bios_version[16];             /* off 472: DMI type 0 version */
    UCHAR     mac_addrs[6][4];              /* off 488: 6 adapters; byte 0 = OUI pool index, bytes 1-3 = NIC-ID */
    UCHAR     disk_serials[20][4];          /* off 512: 20 disk-slot seed tags */
    UCHAR     volume_serials[4][4];         /* off 592: 4 volume-letter seed tags */
    ULONG     gpu_ven_dev;                  /* off 608: (VEN<<16) | DEV */
    UCHAR     edid_nonce[16];               /* off 612: blended into 128-byte EDID at CM-read time */

    /* ---- Tail pad to 8-aligned (4 bytes) ---- */
    UCHAR     _tail_pad[4];                 /* off 628 */
} CHAMBER_CFG_V2;                           /* sizeof = 632 */
#pragma pack(pop)
_STATIC_ASSERT(sizeof(CHAMBER_CFG_V2) == 632);
```

**Offset table summary**: header 0-11, seed 12-43, toggles 44-47, HV identity 48-131,
machine identity 132-627, pad 628-631. All offsets are byte-exact and are to be
quoted literally in launcher patch code and driver `identity.c`.

**Magic**: the installer writes `CHAMBER_CFG_MAGIC_V2 = 0x32474643` ('CFG2') at
offset 0 by default. Offset 0's value is used by the installer for linear-scan
location ONLY; the driver reads `version==2` at offset 4 to confirm. The field
`chamber_cfg_magic_override` at offset 104 is stored for the uninstaller's registry
sweep (see UNINSTALL.ps1 — the uninstaller currently scans for "CFG_"; v2 scan is
for 'CFG2' primarily, 'CFG_' fallback).

**Version-1 compatibility**: a v1 blob (`magic==0x5F474643`, `version==1`) is
rejected at driver init with a clear error; the installer must have produced v2.
The Wave-3 struct is retired in-place (not aliased).

---

## Section 4 — Seed → derived-values function

### 4.1 `derive()` — universal field expander

Portable C, usable from both installer (user-mode EXE linked against `bcrypt.dll`)
and driver (kernel-mode, uses `BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM)`
at init). A pure C SHA-256 is **also** supplied in `crypt.c` so the installer's
build is self-contained and not blocked on CryptoAPI linkage.

```c
/* crypt.h */
#ifndef CHAMBER_CRYPT_H
#define CHAMBER_CRYPT_H
#include <stdint.h>
#include <stddef.h>

void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void sha256_hmac_like(const uint8_t *k, size_t kl, const uint8_t *m, size_t ml, uint8_t out[32]);

/*
 * derive(seed, field, outbuf, outlen):
 *   Expand (seed || field) into `outlen` bytes using iterated SHA-256.
 *   For outlen <= 32:  outbuf = SHA256(seed || field)[0:outlen]
 *   For outlen  > 32:  chain h0 = SHA256(seed || field);
 *                      h_{i+1} = SHA256(h_i || "continue");
 *                      outbuf = h0 || h1 || ... truncated to outlen
 *   field is the ASCII field name (not NUL-terminated in the hash input).
 */
void derive(const uint8_t seed[32],
            const char   *field,
            uint8_t      *outbuf,
            size_t        outlen);
#endif
```

### 4.2 `identity.c` — format-aware wrappers

For every CHAMBER_CFG v2 field, a formatter calls `derive()` and shapes the output
to the field's wire format. Field-name strings are fixed ASCII constants:

```c
/* identity.h */
enum chamber_field_id {
    FID_SERVICE_NAME,           /* "service_name" — 12 bytes, [a-z][a-z0-9]{7} + NUL */
    FID_DEVICE_SUFFIX,          /* "device_suffix" — same alphabet */
    FID_POOL_TAG_SVM,           /* "pool_tag_svm" — 4 ASCII [A-Za-z] bytes */
    FID_POOL_TAG_NPT,           /* "pool_tag_npt" */
    FID_POOL_TAG_VMEXIT,        /* "pool_tag_vmexit" */
    FID_POOL_TAG_DUMP,          /* "pool_tag_dump" */
    FID_POOL_TAG_INTEGRITY,     /* "pool_tag_integrity" */
    FID_POOL_TAG_DISPATCH,      /* "pool_tag_dispatch" */
    FID_VMMCALL_MAGIC,          /* "vmmcall_magic" — 8 random bytes */
    FID_CFG_MAGIC_OVERRIDE,     /* "cfg_magic_override" — 8 bytes */
    FID_RENAME_DONOR,           /* "rename_donor" — 1 byte mod len(donor_pool) */
    FID_GUEST_ASID,             /* "guest_asid" — 4 bytes, masked to [0x1000,0x7FFF] */
    FID_SECTION_SCRAMBLE,       /* "section_scramble" — 4 bytes */
    FID_DRIVER_NONCE,           /* "driver_nonce" — 8 bytes */
    FID_COMPUTER_NAME,          /* "computer_name" — 15 char upper */
    FID_MACHINE_GUID,           /* "machine_guid" — 16 raw bytes, printed GUID */
    FID_INSTALL_DATE,           /* "install_date" — FILETIME in 2019-01..2024-01 window */
    FID_PRODUCT_ID,             /* "product_id" — 23-char formatted */
    FID_DIGITAL_PRODUCT_ID,     /* "digital_product_id" — 164 bytes with valid CRC region */
    FID_CPU_BRAND,              /* "cpu_brand" — 48 ASCII, from brand pool */
    FID_SMBIOS_UUID,            /* "smbios_uuid" — 16 bytes */
    FID_BASEBOARD_SERIAL,       /* "baseboard_serial" — 15 ASCII + NUL */
    FID_CHASSIS_SERIAL,         /* "chassis_serial" */
    FID_BIOS_VENDOR,            /* "bios_vendor" — 15 ASCII from vendor pool */
    FID_BIOS_VERSION,           /* "bios_version" */
    FID_MAC_ADDR_BASE,          /* "mac_addr_0" .. "mac_addr_5" */
    FID_DISK_SERIAL_BASE,       /* "disk_serial_0" .. "disk_serial_19" */
    FID_VOLUME_SERIAL_BASE,     /* "volume_serial_0" .. "volume_serial_3" */
    FID_GPU_VEN_DEV,            /* "gpu_ven_dev" — 4 bytes; VEN picked from pool */
    FID_EDID_NONCE,             /* "edid_nonce" */
};

NTSTATUS identity_compute_all(const uint8_t seed[32], CHAMBER_CFG_V2 *out);
```

### 4.3 Format rules — each field

- **computer_name**: `derive(..., "computer_name", buf, 16)`; map 15 bytes to
  `[A-Z0-9]` by `buf[i] = alphabet[buf[i] % 36]` (`alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"`); byte 15 = NUL.
- **machine_guid**: 16 raw bytes; byte 6 masked to `0x40 | (b6 & 0x0F)` (version 4),
  byte 8 masked to `0x80 | (b8 & 0x3F)` (variant 1).
- **install_date_filetime**: lift 8 bytes from `derive`, mod into FILETIME range
  `[2019-01-01, 2024-01-01]`.
- **product_id**: `derive(..., 32 bytes)`, map each of 20 ASCII chars to
  `[A-Z0-9]`, insert dashes at positions 5/11/17 → "XXXXX-XXXXX-XXXXX-XXXXX" + NUL.
- **digital_product_id**: 164 bytes from chained derive; last 4 bytes rewritten as
  the CRC32 of the preceding 160 bytes so the blob verifies as a plausible DPID
  (Windows itself does not fully validate but malware occasionally does).
- **cpu_brand_string**: index `derive[0] % len(brand_pool)` picks from
  `{"AMD Ryzen 7 7700X 8-Core Processor", "AMD Ryzen 9 7900X 12-Core Processor",
    "AMD Ryzen 9 7950X 16-Core Processor", "AMD Ryzen 7 5800X 8-Core Processor",
    "AMD Ryzen 5 5600X 6-Core Processor", "Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz",
    "Intel(R) Core(TM) i9-13900K CPU @ 3.00GHz", "Intel(R) Core(TM) i5-12400 CPU @ 2.50GHz"}`.
  Padded with spaces to 47 chars + NUL; **constrained so the selected brand matches
  the HV-visible family/model** (CPUID 0x1 EAX) — for an AMD Zen 4 host we only pick
  AMD brands unless the full feature-flag spoof is enabled.
- **smbios_system_uuid**: raw 16 bytes, UUID v4 shaping as for machine_guid.
- **baseboard_serial / chassis_serial**: 12 chars `[0-9A-Z]` + NUL + 3 pad.
- **bios_vendor**: picked from `{"American Megatrends Inc.", "Phoenix Technologies Ltd.",
  "Insyde Corp.", "AMI", "Award Software International"}`.
- **bios_version**: picked from `{"F.27", "2.A1", "1801", "P3.80", "5.17", "F.14"}` + random 2-char suffix.
- **mac_addrs[6][4]**: byte 0 = `derive[i*4] % len(OUI_POOL)`; bytes 1-3 = seed-derived
  NIC ID. OUI pool:
    `{ {0x24,0x4b,0xfe,"ASUSTeK"}, {0xb0,0x25,0xaa,"Dell"}, {0x00,0x25,0xb3,"HPE"},
      {0x18,0xc0,0x4d,"Intel"}, {0x50,0xeb,0x71,"Realtek"},
      {0x74,0xd4,0x35,"Gigabyte"}, {0x28,0x80,0x88,"Lenovo"},
      {0xa4,0x1f,0x72,"MSI"} }`.
  Final MAC = `OUI[idx] || NIC_ID[3]`.
- **disk_serials[20][4]**: for slot i, a 20-char ASCII serial is produced by
  `derive(seed, "disk_serial_<i>", 20)` mapped to `[A-Z0-9]`. The 4-byte entry in
  CHAMBER_CFG v2 is just a seed-stable index; the full 20-byte serial is re-derived
  in the interceptor at return-rewrite time.
- **volume_serials[4][4]**: 4-byte serial per volume letter C:/D:/E:/F:; derived
  directly.
- **gpu_ven_dev**: pick from pool `{0x10DE0x2684 (RTX 4090), 0x10DE0x2782 (RTX 4070),
  0x10DE0x1E07 (RTX 2080 Ti), 0x10022208 (Radeon RX 7900 XTX),
  0x1002731F (Radeon RX 5700 XT), 0x86415690 (Intel UHD 630)}`.
- **edid_nonce**: 16 raw bytes; the CM callback splices these into byte offsets
  8-23 (manufacturer/product/serial) of a canonical 128-byte EDID template at read
  time and recomputes the EDID checksum at byte 127.

### 4.4 Per-group re-derivation

Each UI group (Machine identity / HV identity / Toggles) gets a per-group salt
counter stored in the launcher's `%APPDATA%\The Chamber\seed_state.json`:

```json
{ "seed_hex": "...", "group_salt": { "identity": 0, "hv": 0 } }
```

The derive-with-group function is:
```c
derive_g(seed, group, group_salt, field, out, outlen) =
    derive(seed, "g1:<group>.<group_salt>:<field>", out, outlen)
    /* exactly: field_name_ascii passed to derive() becomes
       "g1:identity.3:computer_name" when identity_salt=3 */
```

"Randomize all" regenerates `seed_hex` from CSPRNG and resets both salts to 0.
"Randomize group: Machine identity" increments `identity_salt`. "Randomize group:
HV identity" increments `hv_salt`. CHAMBER_CFG v2 always carries the *computed*
final values; the group salts are **launcher state**, not CHAMBER_CFG state — this
is deliberate so the driver never has to recompute.

---

## Section 5 — UI field groupings (launcher modal)

Technology: C# WPF, .NET 8. Window `RandomizeSeedWindow.xaml`. Three tabs.

### Tab 1 — Machine identity
- Computer name (TextBlock, read-only) + `[refresh]` button (re-derive this field only)
- CPU brand string
- SMBIOS system UUID (formatted GUID)
- Baseboard serial
- Chassis serial
- BIOS vendor + version
- MachineGuid
- Install date
- Product ID
- DigitalProductId summary (first 32 bytes hex, with "...")
- MAC addresses table (6 rows: OUI vendor name, full MAC)
- Disk serials table (20 rows: slot index, serial)
- Volume serials (4 rows: C:/D:/E:/F:, hex)
- GPU VEN/DEV (vendor name, device ID)
- EDID nonce (16-byte hex)

`[Randomize group]` button at the bottom: increments `identity_salt`, re-renders every field in this tab.

### Tab 2 — HV identity
- Service name
- Device suffix (full path `\Device\<suffix>`)
- Per-subsystem pool tags (6 rows: subsystem, tag ASCII)
- CHAMBER_CFG magic (hex)
- VMMCALL magic (hex)
- Rename donor (dropdown, pre-selected to current index)
- Guest ASID (hex)
- Section scramble seed (hex)
- Driver nonce (hex)

`[Randomize group]` → increments `hv_salt`, re-renders.

### Tab 3 — Toggles
- Per-process CI state spoofing — switch
- Machine identity spoofing — switch (master gate for Tab 1)
- HV introspection resistance — switch (`CHAMBER_HV_INTROSPECTION_RESIST`)
- TPM-absent spoof — switch
- Per-subsystem pool tag randomize — 6 switches

### Bottom pane (always visible)
- **Seed preview**: `[XX XX XX XX XX XX XX XX ...]` 64 hex chars across two lines
  + `[Copy]` + `[Paste]` + `[Randomize all]` button (CSPRNG regenerate seed, reset salts).
- **Apply** and **Cancel** buttons. Apply writes `seed_state.json` and triggers the
  installer patcher to overwrite CHAMBER_CFG v2 in the on-disk `.sys`, then schedules
  the next driver reload (unload + reload on next launcher start, or immediate if
  the user confirms a reboot).

---

## Section 6 — Build and packaging

### Launcher (`launcher/ui/`)
- Project: `launcher/ui/TheChamber.csproj`
  - `<TargetFramework>net8.0-windows</TargetFramework>`
  - `<UseWPF>true</UseWPF>`
  - `<PublishSingleFile>true</PublishSingleFile>`
  - `<SelfContained>true</SelfContained>`
  - `<IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>`
  - `<RuntimeIdentifier>win-x64</RuntimeIdentifier>`
- Embedded resources (MSBuild `<EmbeddedResource>`):
  - `assets/chamber.png` ← copy of `/root/.claude/uploads/.../6ca1da63-image.png`
  - `drivers/the_chamber.sys` (signed)
  - `drivers/chamber_fingerprint.sys` (signed)
  - `drivers/integrity.sys` (optional, signed)
  - `certs/the_chamber.cer` (public cert for CI/TrustedPublisher import)
  - `launcher/patcher/patcher.exe` (native C user-mode patcher; see below)
- Target size: ~75 MB (SelfContained .NET 8 WPF runtime + embedded drivers).
- Output: `thechamber.exe` single-file.

### Installer / patcher flow
1. On first launch, `thechamber.exe` unpacks embedded resources to
   `%ProgramFiles%\The Chamber\` (requires UAC elevation).
2. If `%APPDATA%\The Chamber\seed_state.json` does not exist, CSPRNG-generate a seed
   and persist. UI opens on the Randomize-Seed modal.
3. Upon **Apply**, launcher calls `patcher.exe` to:
   - Locate the 632-byte `CHAMBER_CFG_V2` in `%ProgramFiles%\The Chamber\the_chamber.sys` by linear scan for `(magic==0x32474643) && (version==2) && (total_length==632)`.
   - Overwrite with the computed 632-byte blob.
   - Recompute the PE checksum (`ImageHlp!CheckSumMappedFile`).
   - **Re-sign** the driver with the embedded `the_chamber.pfx` (Subject `CN=The Chamber`).
4. Launcher ensures BCD state:
   - If `testsigning` is off, enable it and prompt for reboot.
   - Imports `the_chamber.cer` into `TrustedPublisher` and `Root` of `Cert:\LocalMachine`.
5. Writes `HKLM\…\Services\<service_name>` registry key with `ImagePath` pointing to
   `\??\<ProgramFiles path>\the_chamber.sys` and starts the driver via `NtLoadDriver`.

### GitHub release pipeline
`.github/workflows/release.yml`:
```yaml
on:
  push:
    tags: ['v*']
jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install WDK
        run: powershell -File tools/install_wdk.ps1
      - name: Build drivers
        run: powershell -File driver/build.ps1
      - name: Build chamber_fingerprint.sys
        run: powershell -File driver/fingerprint/build.ps1
      - name: Build patcher
        run: cl /O2 launcher/patcher/*.c /Fe:launcher/ui/patcher.exe
      - name: Publish launcher
        run: dotnet publish launcher/ui/TheChamber.csproj -c Release -o out/
      - name: Cross-sign
        run: powershell -File tools/sign.ps1 -Cert recovery\the_chamber_test.pfx -Target out\thechamber.exe
      - uses: softprops/action-gh-release@v2
        with:
          files: out/thechamber.exe
```

Self-signed cert `Subject="CN=The Chamber"` lives in-repo at
`recovery/the_chamber_test.pfx`; build pipeline uses it. The cert is the **only**
thing that remains constant across seed re-rolls — per the user's directive.

---

## Section 7 — Agent partition for next phase

Three agents run in parallel in their own worktrees. The merge boundary is
file-exclusive: no two agents edit the same file.

### Agent A — Launcher UI
**May read** (not touch): Sections 3, 4, 5, 6.

**May write**:
- `launcher/ui/TheChamber.csproj`
- `launcher/ui/App.xaml`, `App.xaml.cs`
- `launcher/ui/MainWindow.xaml`, `.cs`
- `launcher/ui/RandomizeSeedWindow.xaml`, `.cs`
- `launcher/ui/Controls/*.xaml`, `.cs`
- `launcher/ui/Services/SeedStore.cs` (reads/writes `%APPDATA%\The Chamber\seed_state.json`)
- `launcher/ui/Services/Derive.cs` (C# port of `derive()` — must match `driver/crypt.c` byte-for-byte)
- `launcher/ui/Services/Patcher.cs` (invokes `patcher.exe`)
- `launcher/ui/Resources/*.png`, `.ico`
- `launcher/patcher/main.c`, `patcher.c` (native C, cross-platform SHA-256 is fine since this runs under Windows but shares the pure-C implementation with the driver)
- `.github/workflows/release.yml`

**May NOT touch**: `driver/**`, `launcher/*.ps1` (the existing PowerShell launchers stay until the C# UI replaces them in a later wave), `audit/**`, `recovery/**`.

### Agent B — HV spoofing (CPU + self-CFG)
**May read**: Sections 1.a, 1.k, 2 (rows 1-17, 63-73), 3, 4.

**May write**:
- `driver/the_chamber.h` — add `CHAMBER_CFG_V2` struct, `CHAMBER_CFG_MAGIC_V2`, extern `g_chamber_cfg_v2`.
- `driver/the_chamber.c` — replace `g_chamber_cfg` with `g_chamber_cfg_v2`; read at init.
- `driver/svm_vmcb.c` — read `g_chamber_cfg_v2.guest_asid` at VMCB init.
- `driver/vmexit.c` — in `handle_cpuid`, add leaves 7, 0xB/0x1F, 0x15, 0x16, 0x80000001, 0x80000002-4, 0x80000008, 0x8000001D-F; rewrite from `g_chamber_cfg_v2`. In `handle_msr`, extend the explicit-rewrite table to cover 0x8B, 0x17, 0xC0000103, 0xC0010015.
- `driver/crypt.c`, `driver/crypt.h` — pure-C SHA-256 + `derive()`.
- `driver/identity.c`, `driver/identity.h` — `identity_compute_all()` + format wrappers. Called only from installer-side; driver side reads already-expanded CFG v2 fields. Shared C file used by Agent A's `patcher.exe`.
- `driver/stealth.c` — read `rename_donor_index` out of `g_chamber_cfg_v2` to pick cover module.
- `driver/build.ps1` — add `crypt.c`, `identity.c` to source list.

**May NOT touch**: `driver/fingerprint/**` (Agent C exclusive), `launcher/**`, `audit/**`, `.github/**`.

### Agent C — Per-process interceptor driver
New driver **`chamber_fingerprint.sys`** in `driver/fingerprint/`. Separate `.sys`,
separate signing, separate service — loaded alongside `the_chamber.sys` by the
launcher. Reads its own copy of `CHAMBER_CFG_V2` from `\Registry\Machine\…\Services\<service>\Parameters\CfgBlob` (populated by installer; same 632 bytes).

**May read**: Sections 1.b-1.j, 2 (rows 18-62), 3, 4.

**May write**:
- `driver/fingerprint/entry.c` — DriverEntry, loads CFG, registers Cm/Flt/IC callbacks.
- `driver/fingerprint/cm_filter.c` — `CmRegisterCallbackEx` for surfaces 24-34, 48, 56-58, 61.
- `driver/fingerprint/flt_filter.c` — `FltRegisterFilter` for surface 45.
- `driver/fingerprint/instrumentation.c` — process-attach notify callback that installs the instrumentation callback on `g_target_pid`.
- `driver/fingerprint/ic_trampoline.asm` — the x64 ASM instrumentation callback that catches syscall returns before the user-mode RIP resumes and dispatches to C handlers. Reads `R10` for original RIP, preserves caller state.
- `driver/fingerprint/syscall_rewrite.c` — syscall-return rewrite handlers for surfaces 18-23, 35-44, 46-47, 50-55, 59-60, 62.
- `driver/fingerprint/edid_template.c` — the 128-byte EDID template with checksum recompute.
- `driver/fingerprint/dmi_rewrite.c` — DMI blob walker that patches Type 0/1/2/3 fields in place.
- `driver/fingerprint/target_pid.c` — IOCTL interface so launcher can set `g_target_pid` at run start.
- `driver/fingerprint/build.ps1` — WDK build glue; shares `crypt.c` from `driver/` (symlink or build-side copy).
- `driver/fingerprint/the_chamber_fingerprint.inx` → **omit INF**, load via launcher like `the_chamber.sys`.

**May NOT touch**: `driver/*.c` outside `driver/fingerprint/`, `driver/*.h` outside what it creates, `launcher/**`, `audit/**`.

### Boundary assurance — `driver/vmexit.c`
Agent B owns all edits to `driver/vmexit.c`. Agent C does **not** touch `driver/vmexit.c`;
its parallel work lives entirely in `driver/fingerprint/`. The HV and the
interceptor driver communicate solely via (1) the shared CFG v2 blob format and
(2) the installer's single `patcher.exe` writing both locations with the same
seed-derived bytes. No runtime cross-driver IPC is required.

### Shared files between agents
- `driver/crypt.c`, `driver/crypt.h` — authored by Agent B, **read-only** to Agents A and C.
- `driver/identity.c`, `driver/identity.h` — authored by Agent B, called by Agent A's `patcher.exe` (via build-time include from `launcher/patcher/patcher.c`), **read-only** to Agent C.
- `driver/the_chamber.h` (CHAMBER_CFG_V2 struct) — authored by Agent B, **read-only** to Agent C. Agent C includes it from `driver/fingerprint/fingerprint_cfg.h` (a one-line wrapper).

### Merge order (next phase)
1. Agent B merges first (introduces CFG v2 and `crypt.c`).
2. Agent C rebases onto B and merges (depends on `the_chamber.h` from B).
3. Agent A rebases onto B+C and merges (depends on both drivers for signing + bundling).

No merge conflicts expected because file ownership is exclusive.

---

## Non-goals and accepted gaps

- **TPM EK spoofing** (surfaces 59-60): architecturally impossible. Mitigation: `tpm_absent_spoof` toggle reports "no TPM" via IC rewrite.
- **D3DKMT adapter path** (surface 49): no clean PG-safe intercept. Mitigation: CM covers the preceding `SetupDi*` path which most samples trust first.
- **SVM feature-flag spoofing for Intel-brand pick**: CPUID 0x1 EAX family bits can't change to Intel on a Zen 4 host without breaking CPUID consistency across intercepted and non-intercepted leaves. Brand-string pool is constrained to AMD by default; Intel brands only available when full feature-flag rewriting is enabled via a future toggle (post-Wave-4).
- **Timing-side-channel per-seed uniqueness**: not spoofed. TSC accumulator from Wave 2 still runs; the seed does not vary timing behavior. Samples that fingerprint on timing variance across reboots see a stable HV cost.

End of design.
