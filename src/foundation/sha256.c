/* SHA-256 per FIPS 180-4. Straightforward reference implementation; validated
 * against the NIST test vectors in tests/test_cli.c. */

#include "foundation/sha256.h"

#include <stdint.h>
#include <string.h>

enum {
    SHA256_BLOCK_BYTES = CBM_SHA256_BLOCK_BYTES,
    SHA256_MESSAGE_WORDS = 16,
    SHA256_SCHEDULE_WORDS = 64,
    SHA256_STATE_WORDS = CBM_SHA256_STATE_WORDS,
    SHA256_BYTES_PER_WORD = 4,
    SHA256_WORD_BITS = 32,
    SHA256_BITS_PER_BYTE = 8,
    SHA256_LENGTH_FIELD_OFFSET = 56,
    SHA256_PAD_BYTE = 0x80,
    SHA256_LOW_NIBBLE_MASK = 0x0f,
    SHA256_SCHEDULE_SIGMA1_BACK = 2,
    SHA256_SCHEDULE_SIGMA0_BACK = 7,
    SHA256_SCHEDULE_SIGMA0_FAR_BACK = 15,
    SHA256_SCHEDULE_PREVIOUS_BLOCK = 16,
    SHA256_STATE_A = 0,
    SHA256_STATE_B = 1,
    SHA256_STATE_C = 2,
    SHA256_STATE_D = 3,
    SHA256_STATE_E = 4,
    SHA256_STATE_F = 5,
    SHA256_STATE_G = 6,
    SHA256_STATE_H = 7,
    SHA256_BYTE_SECOND = 1,
    SHA256_BYTE_THIRD = 2,
    SHA256_BYTE_FOURTH = 3,
    SHA256_SHIFT_MOST_SIGNIFICANT_BYTE = 24,
    SHA256_SHIFT_SECOND_BYTE = 16,
    SHA256_SHIFT_THIRD_BYTE = 8,
    SHA256_HEX_DIGITS_PER_BYTE = 2,
    SHA256_HIGH_NIBBLE_SHIFT = 4,
};

static const uint32_t sha256_round_constants[SHA256_SCHEDULE_WORDS] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (SHA256_WORD_BITS - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(cbm_sha256_ctx *c, const uint8_t *data) {
    uint32_t m[SHA256_SCHEDULE_WORDS];
    for (int i = 0, j = 0; i < SHA256_MESSAGE_WORDS; i++, j += SHA256_BYTES_PER_WORD) {
        m[i] = ((uint32_t)data[j] << SHA256_SHIFT_MOST_SIGNIFICANT_BYTE) |
               ((uint32_t)data[j + SHA256_BYTE_SECOND] << SHA256_SHIFT_SECOND_BYTE) |
               ((uint32_t)data[j + SHA256_BYTE_THIRD] << SHA256_SHIFT_THIRD_BYTE) |
               (uint32_t)data[j + SHA256_BYTE_FOURTH];
    }
    for (int i = SHA256_MESSAGE_WORDS; i < SHA256_SCHEDULE_WORDS; i++) {
        m[i] = SIG1(m[i - SHA256_SCHEDULE_SIGMA1_BACK]) + m[i - SHA256_SCHEDULE_SIGMA0_BACK] +
               SIG0(m[i - SHA256_SCHEDULE_SIGMA0_FAR_BACK]) + m[i - SHA256_SCHEDULE_PREVIOUS_BLOCK];
    }

    uint32_t a = c->state[SHA256_STATE_A];
    uint32_t b = c->state[SHA256_STATE_B];
    uint32_t cc = c->state[SHA256_STATE_C];
    uint32_t d = c->state[SHA256_STATE_D];
    uint32_t e = c->state[SHA256_STATE_E];
    uint32_t f = c->state[SHA256_STATE_F];
    uint32_t g = c->state[SHA256_STATE_G];
    uint32_t h = c->state[SHA256_STATE_H];

    for (int i = 0; i < SHA256_SCHEDULE_WORDS; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + sha256_round_constants[i] + m[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, cc);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }

    c->state[SHA256_STATE_A] += a;
    c->state[SHA256_STATE_B] += b;
    c->state[SHA256_STATE_C] += cc;
    c->state[SHA256_STATE_D] += d;
    c->state[SHA256_STATE_E] += e;
    c->state[SHA256_STATE_F] += f;
    c->state[SHA256_STATE_G] += g;
    c->state[SHA256_STATE_H] += h;
}

void cbm_sha256_init(cbm_sha256_ctx *c) {
    static const uint32_t initial_state[SHA256_STATE_WORDS] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    c->bitlen = 0;
    c->buflen = 0;
    memcpy(c->state, initial_state, sizeof(initial_state));
}

void cbm_sha256_update(cbm_sha256_ctx *c, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        c->buf[c->buflen++] = p[i];
        if (c->buflen == SHA256_BLOCK_BYTES) {
            sha256_transform(c, c->buf);
            c->bitlen += SHA256_BLOCK_BYTES * SHA256_BITS_PER_BYTE;
            c->buflen = 0;
        }
    }
}

void cbm_sha256_final(cbm_sha256_ctx *c, uint8_t out[CBM_SHA256_DIGEST_LEN]) {
    c->bitlen += (uint64_t)c->buflen * SHA256_BITS_PER_BYTE;

    size_t i = c->buflen;
    c->buf[i++] = SHA256_PAD_BYTE; /* append the '1' bit + zero padding */
    if (i > SHA256_LENGTH_FIELD_OFFSET) {
        while (i < SHA256_BLOCK_BYTES) {
            c->buf[i++] = 0;
        }
        sha256_transform(c, c->buf);
        i = 0;
    }
    while (i < SHA256_LENGTH_FIELD_OFFSET) {
        c->buf[i++] = 0;
    }
    /* append the 64-bit big-endian message length */
    for (size_t j = 0; j < SHA256_STATE_WORDS; j++) {
        c->buf[SHA256_LENGTH_FIELD_OFFSET + j] =
            (uint8_t)(c->bitlen >> (SHA256_LENGTH_FIELD_OFFSET - (SHA256_BITS_PER_BYTE * j)));
    }
    sha256_transform(c, c->buf);

    for (size_t j = 0; j < SHA256_STATE_WORDS; j++) {
        size_t byte_offset = j * SHA256_BYTES_PER_WORD;
        out[byte_offset] = (uint8_t)(c->state[j] >> SHA256_SHIFT_MOST_SIGNIFICANT_BYTE);
        out[byte_offset + SHA256_BYTE_SECOND] = (uint8_t)(c->state[j] >> SHA256_SHIFT_SECOND_BYTE);
        out[byte_offset + SHA256_BYTE_THIRD] = (uint8_t)(c->state[j] >> SHA256_SHIFT_THIRD_BYTE);
        out[byte_offset + SHA256_BYTE_FOURTH] = (uint8_t)(c->state[j]);
    }
}

void cbm_sha256_hex(const void *data, size_t len, char out[CBM_SHA256_HEX_CSTR_LEN]) {
    uint8_t digest[CBM_SHA256_DIGEST_LEN];
    cbm_sha256_ctx c;
    cbm_sha256_init(&c);
    cbm_sha256_update(&c, data, len);
    cbm_sha256_final(&c, digest);

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < CBM_SHA256_DIGEST_LEN; i++) {
        size_t hex_offset = i * SHA256_HEX_DIGITS_PER_BYTE;
        out[hex_offset] = hex[digest[i] >> SHA256_HIGH_NIBBLE_SHIFT];
        out[hex_offset + SHA256_BYTE_SECOND] = hex[digest[i] & SHA256_LOW_NIBBLE_MASK];
    }
    out[CBM_SHA256_HEX_LEN] = '\0';
}
