/* crypt.h -- pure-C SHA-256 and seed-derivation helpers used by both the
 * driver (kernel-mode) and the installer's patcher (user-mode). No link
 * against BCrypt or any CryptoAPI; the installer's build is self-contained
 * and the driver can run before the kernel crypto providers are warm.
 *
 * The derive() function is the sole bridge between the master seed and
 * every seed-derived field in CHAMBER_CFG_V2: both the driver and the
 * launcher port must agree byte-for-byte on the field-name strings and
 * the chaining rule so the UI, the on-disk blob, and the VMEXIT handler
 * read the same values.
 *
 * ASCII only. No branded identifiers. */

#ifndef CHAMBER_CRYPT_H
#define CHAMBER_CRYPT_H

/* Portable integer types. The driver pulls these from <ntddk.h>; the
 * user-mode patcher pulls them from <stdint.h>. Guard either way. */
#if defined(_KERNEL_MODE) || defined(NTDDI_VERSION)
#  include <ntddk.h>
typedef UCHAR     chamber_u8;
typedef ULONG     chamber_u32;
typedef ULONGLONG chamber_u64;
typedef SIZE_T    chamber_size;
#else
#  include <stdint.h>
#  include <stddef.h>
typedef uint8_t   chamber_u8;
typedef uint32_t  chamber_u32;
typedef uint64_t  chamber_u64;
typedef size_t    chamber_size;
#endif

/* SHA-256 one-shot: hash `len` bytes at `data` into `out[32]`. */
void chamber_sha256(const chamber_u8 *data,
                    chamber_size      len,
                    chamber_u8        out[32]);

/* SHA-256 "HMAC-like": concatenates `k || m` and hashes once. Not a true
 * HMAC (no ipad/opad); kept for parity with the design doc's named helper
 * so launcher and driver read the same bytes. */
void chamber_sha256_hmac_like(const chamber_u8 *k, chamber_size kl,
                              const chamber_u8 *m, chamber_size ml,
                              chamber_u8 out[32]);

/* derive(seed, field, outbuf, outlen):
 *   Expand (seed || field) into `outlen` bytes using iterated SHA-256.
 *   For outlen <= 32:  outbuf = SHA256(seed || field)[0:outlen]
 *   For outlen  > 32:  chain h0 = SHA256(seed || field);
 *                      h_{i+1} = SHA256(h_i || "continue");
 *                      outbuf = h0 || h1 || ... truncated to outlen
 * `field` is the ASCII field name; its trailing NUL is NOT part of the
 * hash input. The launcher's C# port must hash the same bytes. */
void chamber_derive(const chamber_u8 seed[32],
                    const char      *field,
                    chamber_u8      *outbuf,
                    chamber_size     outlen);

#endif /* CHAMBER_CRYPT_H */
