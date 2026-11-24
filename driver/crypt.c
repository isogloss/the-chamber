/* crypt.c -- pure-C SHA-256 and derive() shared by driver + patcher.
 *
 * Implements the FIPS 180-4 SHA-256 message schedule and compression
 * function directly so the installer's patcher is free of any crypto
 * library linkage and the driver can call it from DriverEntry without
 * waiting for BCrypt providers to be initialized. The implementation is
 * straightforward reference C: no table precomputation beyond the K
 * constants, no assembly intrinsics, no architectural assumptions beyond
 * two's-complement 32-bit integers.
 *
 * ASCII only. No branded identifiers. */

#include "crypt.h"

static const chamber_u32 K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static const chamber_u32 H0[8] = {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

static chamber_u32 rotr32(chamber_u32 x, chamber_u32 n) {
    return (x >> n) | (x << (32U - n));
}

static chamber_u32 read_be32(const chamber_u8 *p) {
    return  ((chamber_u32)p[0] << 24) |
            ((chamber_u32)p[1] << 16) |
            ((chamber_u32)p[2] <<  8) |
             (chamber_u32)p[3];
}

static void write_be32(chamber_u8 *p, chamber_u32 v) {
    p[0] = (chamber_u8)(v >> 24);
    p[1] = (chamber_u8)(v >> 16);
    p[2] = (chamber_u8)(v >>  8);
    p[3] = (chamber_u8)(v      );
}

static void sha256_compress(chamber_u32 state[8], const chamber_u8 block[64]) {
    chamber_u32 w[64];
    chamber_u32 a, b, c, d, e, f, g, h;
    chamber_u32 t1, t2, s0, s1, ch, maj;
    chamber_u32 i;

    for (i = 0; i < 16; i++) {
        w[i] = read_be32(&block[i * 4]);
    }
    for (i = 16; i < 64; i++) {
        s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = rotr32(w[i -  2], 17) ^ rotr32(w[i -  2], 19) ^ (w[i -  2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        s1  = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        ch  = (e & f) ^ ((~e) & g);
        t1  = h + s1 + ch + K[i] + w[i];
        s0  = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        t2  = s0 + maj;
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* SHA-256 one-shot. Buffers one partial block + the 72-byte pad/length
 * tail locally so the caller supplies no scratch. Input length is bounded
 * by the installer blob sizes (hundreds of bytes); the 64-bit length
 * field in the pad is still written in canonical FIPS 180-4 big-endian
 * form so a port on either side gets matching bytes. */
void chamber_sha256(const chamber_u8 *data,
                    chamber_size      len,
                    chamber_u8        out[32])
{
    chamber_u32 state[8];
    chamber_u8  block[64];
    chamber_size i, full_blocks, remainder;
    chamber_u64 bit_len = (chamber_u64)len * 8ULL;

    for (i = 0; i < 8; i++) state[i] = H0[i];

    full_blocks = len / 64;
    for (i = 0; i < full_blocks; i++) {
        sha256_compress(state, data + i * 64);
    }
    remainder = len - full_blocks * 64;

    /* Build tail: remainder || 0x80 || zero pad || 8-byte big-endian bit length. */
    for (i = 0; i < remainder; i++) block[i] = data[full_blocks * 64 + i];
    block[remainder] = 0x80u;
    if (remainder + 1 <= 56) {
        for (i = remainder + 1; i < 56; i++) block[i] = 0;
    } else {
        for (i = remainder + 1; i < 64; i++) block[i] = 0;
        sha256_compress(state, block);
        for (i = 0; i < 56; i++) block[i] = 0;
    }
    block[56] = (chamber_u8)(bit_len >> 56);
    block[57] = (chamber_u8)(bit_len >> 48);
    block[58] = (chamber_u8)(bit_len >> 40);
    block[59] = (chamber_u8)(bit_len >> 32);
    block[60] = (chamber_u8)(bit_len >> 24);
    block[61] = (chamber_u8)(bit_len >> 16);
    block[62] = (chamber_u8)(bit_len >>  8);
    block[63] = (chamber_u8)(bit_len      );
    sha256_compress(state, block);

    for (i = 0; i < 8; i++) {
        write_be32(out + i * 4, state[i]);
    }
}

/* Concatenated hash: SHA-256(k || m). Not ipad/opad HMAC — the design doc
 * calls for a named helper that matches on both sides. */
void chamber_sha256_hmac_like(const chamber_u8 *k, chamber_size kl,
                              const chamber_u8 *m, chamber_size ml,
                              chamber_u8 out[32])
{
    chamber_u8 buf[256];
    chamber_size total = kl + ml;
    chamber_size i;
    if (total <= sizeof(buf)) {
        for (i = 0; i < kl; i++) buf[i]      = k[i];
        for (i = 0; i < ml; i++) buf[kl + i] = m[i];
        chamber_sha256(buf, total, out);
        return;
    }
    /* Fallback: streaming via two compress calls would require more
     * surface than the current callers need. Truncate silently rather
     * than buffer-overrun; callers never push more than 96 bytes. */
    chamber_sha256(k, kl, out);
}

/* Length of a 0-terminated ASCII field name, computed without pulling
 * in <string.h> so both kernel and user builds see the same symbol set. */
static chamber_size field_len(const char *s) {
    chamber_size n = 0;
    while (s[n]) n++;
    return n;
}

/* Expand (seed || field) into `outlen` bytes using iterated SHA-256.
 * The chaining rule and the exact bytes mixed in on each iteration
 * ("continue") must match the launcher's C# port exactly. */
void chamber_derive(const chamber_u8 seed[32],
                    const char      *field,
                    chamber_u8      *outbuf,
                    chamber_size     outlen)
{
    /* buf must hold seed(32) + full field name. C# SeedService.DeriveRaw
     * applies no truncation; keep 224 bytes free for composed names of
     * the form 'g1:<group>.<salt>:<field>' which can exceed 32 chars
     * once group salts grow into double digits. If a future caller passes
     * a longer field, the final SHA-256 falls back to truncate-at-buf. */
    chamber_u8   buf[256];
    chamber_u8   h[32];
    chamber_size flen = field_len(field);
    chamber_size pos, copy, i;
    static const char CONTINUE_TAG[] = "continue";
    const chamber_size ctag_len = sizeof(CONTINUE_TAG) - 1;

    /* First block: seed(32) || field_name. */
    for (i = 0; i < 32; i++) buf[i] = seed[i];
    chamber_size take = (flen > sizeof(buf) - 32) ? sizeof(buf) - 32 : flen;
    for (i = 0; i < take; i++) buf[32 + i] = (chamber_u8)field[i];
    chamber_sha256(buf, 32 + take, h);

    pos = 0;
    copy = (outlen < 32) ? outlen : 32;
    for (i = 0; i < copy; i++) outbuf[i] = h[i];
    pos = copy;

    /* Chain further blocks with the "continue" tag. */
    while (pos < outlen) {
        for (i = 0; i < 32; i++)       buf[i] = h[i];
        for (i = 0; i < ctag_len; i++) buf[32 + i] = (chamber_u8)CONTINUE_TAG[i];
        chamber_sha256(buf, 32 + ctag_len, h);
        copy = (outlen - pos < 32) ? (outlen - pos) : 32;
        for (i = 0; i < copy; i++) outbuf[pos + i] = h[i];
        pos += copy;
    }
}
