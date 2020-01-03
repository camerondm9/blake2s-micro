//  BLAKE2 - size-optimized implementations
//
//  Copyright 2012, Samuel Neves <sneves@dei.uc.pt> (original work)
//  Copyright 2018, Ayke van Laethem
//
//  You may use this under the terms of the CC0, the OpenSSL Licence, or
//  the Apache Public License 2.0, at your option. The terms of these
//  licenses can be found at:
//
//  - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
//  - OpenSSL license   : https://www.openssl.org/source/license.html
//  - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
//
//  More information about the BLAKE2 hash function can be found at
//  https://blake2.net.

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake2s.h"

static const uint32_t blake2s_IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

// These are the permutations. It packs two permutations per byte, see the
// first row.
static const uint8_t blake2s_sigma[10][8] = {
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
    { 0xea, 0x48, 0x9f, 0xd6, 0x1c, 0x02, 0xb7, 0x53 },
    { 0xb8, 0xc0, 0x52, 0xfd, 0xae, 0x36, 0x71, 0x94 },
    { 0x79, 0x31, 0xdc, 0xbe, 0x26, 0x5a, 0x40, 0xf8 },
    { 0x90, 0x57, 0x24, 0xaf, 0xe1, 0xbc, 0x68, 0x3d },
    { 0x2c, 0x6a, 0x0b, 0x83, 0x4d, 0x75, 0xfe, 0x19 },
    { 0xc5, 0x1f, 0xed, 0x4a, 0x07, 0x63, 0x92, 0x8b },
    { 0xdb, 0x7e, 0xc1, 0x39, 0x50, 0xf4, 0x86, 0x2a },
    { 0x6f, 0xe9, 0xb3, 0x08, 0xc2, 0xd7, 0x14, 0xa5 },
    { 0xa2, 0x84, 0x76, 0x15, 0xfb, 0x9e, 0x3c, 0xd0 },
};

// Rotate right by the given amount.
static inline uint32_t rotr32(const uint32_t w, const unsigned c) {
    return ( w >> c ) | ( w << ( 32 - c ) );
}

static void blake2s_set_lastblock(blake2s_state *S) {
    S->f0 = (uint32_t)-1;
}

static void blake2s_increment_counter(blake2s_state *S, const size_t inc) {
    S->t[0] += inc;
    if (BLAKE2S_64BIT) {
        S->t[1] += ( S->t[0] < inc );
    }
}

// blake2s initialization without key
void blake2s_init(blake2s_state *S) {
    memset(S, 0, sizeof(blake2s_state));
    memcpy(S->h, blake2s_IV, 8 * sizeof(S->h[0]));

    // set depth, fanout and digest length
    S->h[0] ^= (1UL << 24) | (1UL << 16) | BLAKE2S_OUTLEN;
}

static void blake2s_round(size_t r, const uint32_t m[16], uint32_t v[16]) {
    for (size_t i = 0; i < 8; i++) {
        size_t bit4 = i / 4; // 0, 0, 0, 0, 1, 1, 1, 1

        // Calculate the following table dynamically:
        //   a:    b:    c:     d:
        //   v[0]  v[4]  v[ 8]  v[12]
        //   v[1]  v[5]  v[ 9]  v[13]
        //   v[2]  v[6]  v[10]  v[14]
        //   v[3]  v[7]  v[11]  v[15]
        //   v[0]  v[5]  v[10]  v[15]
        //   v[1]  v[6]  v[11]  v[12]
        //   v[2]  v[7]  v[ 8]  v[13]
        //   v[3]  v[4]  v[ 9]  v[14]
        uint32_t *a = &v[(i + bit4 * 0) % 4 + 0];
        uint32_t *b = &v[(i + bit4 * 1) % 4 + 4];
        uint32_t *c = &v[(i + bit4 * 2) % 4 + 8];
        uint32_t *d = &v[(i + bit4 * 2 + bit4) % 4 + 12];

        const uint8_t sigma = blake2s_sigma[r][i];
        uint32_t m1 = m[sigma >> 4];
        uint32_t m2 = m[sigma & 0xf];

        *a = *a + *b + m1;
        *d = rotr32(*d ^ *a, 16);
        *c = *c + *d;
        *b = rotr32(*b ^ *c, 12);
        *a = *a + *b + m2;
        *d = rotr32(*d ^ *a, 8);
        *c = *c + *d;
        *b = rotr32(*b ^ *c, 7);
    }
}

static void blake2s_compress(blake2s_state *S, const uint8_t in[BLAKE2S_BLOCKBYTES]) {
    const uint32_t *m = (const uint32_t*)in;

    uint32_t v[16];
    memcpy(v, S->h, 8 * sizeof(v[0]));
    memcpy(v + 8, blake2s_IV, 8 * sizeof(v[0]));

    v[12] ^= S->t[0];
    v[13] ^= S->t[1];
    v[14] ^= S->f0;

    for (size_t r = 0; r < 10; r++) {
        blake2s_round(r, m, v);
    }

    for (size_t i = 0; i < 8; i++) {
        S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
    }
}

void blake2s_update(blake2s_state *S, const void *in, size_t inlen) {
    for (size_t i = 0; i < inlen; i++) {
        if (S->buflen == BLAKE2S_BLOCKBYTES) {
            blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
            blake2s_compress(S, S->buf);
            S->buflen = 0;
        }
        S->buf[S->buflen++] = ((uint8_t*)in)[i];
    }
}

void blake2s_final(blake2s_state *S, void *out) {
    blake2s_increment_counter(S, S->buflen);
    blake2s_set_lastblock(S);
    memset(S->buf + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen); // Padding
    blake2s_compress(S, S->buf);

    memcpy(out, S->h, BLAKE2S_OUTLEN);
}
