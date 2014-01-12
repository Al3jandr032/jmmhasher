/* This file is part of jmmhasher.
 * Copyright (C) 2014 Joshua Harley
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file LICENSE.txt. If not, see
 * http://www.gnu.org/licenses/.
 */

/* This MD4 implementation has been adapted from the public domain reference at
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 */

#include "md4.h"
#include <string.h>

/* The basic MD4 functions.
 *
 * F and G are optimized compared to their RFC 1320 definitions, with the
 * optimization for F borrowed from Colin Plumb's MD5 implementation.
 */
#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* The MD4 transformation for all three rounds. */
#define STEP(f, a, b, c, d, x, s) \
    (a) += f((b), (c), (d)) + (x); \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

/* SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#if defined(__i386__) || defined(__x86_64__) || defined(__vax__)
#define SET(n) (*(uint32_t *)&ptr[(n) * 4])
#define GET(n) SET(n)
#else
#define SET(n) (md4->block[(n)] = \
    (uint32_t)ptr[(n) * 4] | \
    ((uint32_t)ptr[(n) * 4 + 1] << 8) | \
    ((uint32_t)ptr[(n) * 4 + 2] << 16) | \
    ((uint32_t)ptr[(n) * 4 + 3] << 24))
#define GET(n) (md4->block[(n)])
#endif

/**
 * Performs the actual transformation of data for MD4 hashing in 64 byte blocks.
 * @param md4    The MD4 context to update.
 * @param data   The data to process.
 * @param length The length of the data to process. Must be a multiple of 64.
 * @returns Returns a pointer to any remaining data that didn't fit in a 64-byte
 *          block. The remaining data will always be less than 64 bytes.
 */
static const void* transform(MD4_Context* md4, const void* data, uint32_t length) {
    const unsigned char* ptr;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t saved_a;
    uint32_t saved_b;
    uint32_t saved_c;
    uint32_t saved_d;

    ptr = (const unsigned char *)data;
    a = md4->state[0];
    b = md4->state[1];
    c = md4->state[2];
    d = md4->state[3];

    do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;

        /* Round 1 */
        STEP(F, a, b, c, d, SET( 0),  3)
        STEP(F, d, a, b, c, SET( 1),  7)
        STEP(F, c, d, a, b, SET( 2), 11)
        STEP(F, b, c, d, a, SET( 3), 19)
        STEP(F, a, b, c, d, SET( 4),  3)
        STEP(F, d, a, b, c, SET( 5),  7)
        STEP(F, c, d, a, b, SET( 6), 11)
        STEP(F, b, c, d, a, SET( 7), 19)
        STEP(F, a, b, c, d, SET( 8),  3)
        STEP(F, d, a, b, c, SET( 9),  7)
        STEP(F, c, d, a, b, SET(10), 11)
        STEP(F, b, c, d, a, SET(11), 19)
        STEP(F, a, b, c, d, SET(12),  3)
        STEP(F, d, a, b, c, SET(13),  7)
        STEP(F, c, d, a, b, SET(14), 11)
        STEP(F, b, c, d, a, SET(15), 19)

        /* Round 2 */
        STEP(G, a, b, c, d, GET( 0) + 0x5a827999,  3)
        STEP(G, d, a, b, c, GET( 4) + 0x5a827999,  5)
        STEP(G, c, d, a, b, GET( 8) + 0x5a827999,  9)
        STEP(G, b, c, d, a, GET(12) + 0x5a827999, 13)
        STEP(G, a, b, c, d, GET( 1) + 0x5a827999,  3)
        STEP(G, d, a, b, c, GET( 5) + 0x5a827999,  5)
        STEP(G, c, d, a, b, GET( 9) + 0x5a827999,  9)
        STEP(G, b, c, d, a, GET(13) + 0x5a827999, 13)
        STEP(G, a, b, c, d, GET( 2) + 0x5a827999,  3)
        STEP(G, d, a, b, c, GET( 6) + 0x5a827999,  5)
        STEP(G, c, d, a, b, GET(10) + 0x5a827999,  9)
        STEP(G, b, c, d, a, GET(14) + 0x5a827999, 13)
        STEP(G, a, b, c, d, GET( 3) + 0x5a827999,  3)
        STEP(G, d, a, b, c, GET( 7) + 0x5a827999,  5)
        STEP(G, c, d, a, b, GET(11) + 0x5a827999,  9)
        STEP(G, b, c, d, a, GET(15) + 0x5a827999, 13)

        /* Round 3 */
        STEP(H, a, b, c, d, GET( 0) + 0x6ed9eba1,  3)
        STEP(H, d, a, b, c, GET( 8) + 0x6ed9eba1,  9)
        STEP(H, c, d, a, b, GET( 4) + 0x6ed9eba1, 11)
        STEP(H, b, c, d, a, GET(12) + 0x6ed9eba1, 15)
        STEP(H, a, b, c, d, GET( 2) + 0x6ed9eba1,  3)
        STEP(H, d, a, b, c, GET(10) + 0x6ed9eba1,  9)
        STEP(H, c, d, a, b, GET( 6) + 0x6ed9eba1, 11)
        STEP(H, b, c, d, a, GET(14) + 0x6ed9eba1, 15)
        STEP(H, a, b, c, d, GET( 1) + 0x6ed9eba1,  3)
        STEP(H, d, a, b, c, GET( 9) + 0x6ed9eba1,  9)
        STEP(H, c, d, a, b, GET( 5) + 0x6ed9eba1, 11)
        STEP(H, b, c, d, a, GET(13) + 0x6ed9eba1, 15)
        STEP(H, a, b, c, d, GET( 3) + 0x6ed9eba1,  3)
        STEP(H, d, a, b, c, GET(11) + 0x6ed9eba1,  9)
        STEP(H, c, d, a, b, GET( 7) + 0x6ed9eba1, 11)
        STEP(H, b, c, d, a, GET(15) + 0x6ed9eba1, 15)

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        ptr += 64;
    } while (length -= 64);

    md4->state[0] = a;
    md4->state[1] = b;
    md4->state[2] = c;
    md4->state[3] = d;

    return ptr;
}

/**
 * Performs the final operation on the MD4_Context structure, copies the
 * resulting hash to the array pointed to by result and clears the structure. If
 * the structure is to be reused, it needs to be initialized again.
 * @param md4    The MD4_Context structure to finalize.
 * @param result Pointer to an array of at least 16 bytes used to hold the
 *               resulting hash.
 * @remarks The result provided is converted for use in Little Endian CPU
 *          architectures.
 */
void MD4_final(MD4_Context* md4, unsigned char* result) {
    uint16_t used;
    uint16_t available;

    used = md4->lo & 0x3F;
    md4->buffer[used++] = 0x80;
    available = 64 - used;

    if (available < 8) {
        memset(&md4->buffer[used], 0, available);
        transform(md4, md4->buffer, 64);
        used = 0;
        available = 64;
    }

    memset(&md4->buffer[used], 0, available - 8);

    md4->lo <<= 3;
    md4->buffer[56] =  md4->lo & 0xFF;
    md4->buffer[57] = (md4->lo >>  8) & 0xFF;
    md4->buffer[58] = (md4->lo >> 16) & 0xFF;
    md4->buffer[59] = (md4->lo >> 24) & 0xFF;
    md4->buffer[60] =  md4->hi & 0xFF;
    md4->buffer[61] = (md4->hi >>  8) & 0xFF;
    md4->buffer[62] = (md4->hi >> 16) & 0xFF;
    md4->buffer[63] = (md4->hi >> 24) & 0xFF;

    transform(md4, md4->buffer, 64);

    result[0]  =  md4->state[0] & 0xFF;
    result[1]  = (md4->state[0] >>  8) & 0xFF;
    result[2]  = (md4->state[0] >> 16) & 0xFF;
    result[3]  = (md4->state[0] >> 24) & 0xFF;
    result[4]  =  md4->state[1] & 0xFF;
    result[5]  = (md4->state[1] >>  8) & 0xFF;
    result[6]  = (md4->state[1] >> 16) & 0xFF;
    result[7]  = (md4->state[1] >> 24) & 0xFF;
    result[8]  =  md4->state[2] & 0xFF;
    result[9]  = (md4->state[2] >>  8) & 0xFF;
    result[10] = (md4->state[2] >> 16) & 0xFF;
    result[11] = (md4->state[2] >> 24) & 0xFF;
    result[12] =  md4->state[3] & 0xFF;
    result[13] = (md4->state[3] >>  8) & 0xFF;
    result[14] = (md4->state[3] >> 16) & 0xFF;
    result[15] = (md4->state[3] >> 24) & 0xFF;

    memset(md4, 0, sizeof(*md4));
}

/**
 * Initializes a MD4_Context structure for use with MD4_Update.
 * @param md4 The structure to initialize.
 */
void MD4_init(MD4_Context* md4) {
    md4->lo = 0;
    md4->hi = 0;

    md4->state[0] = 0x67452301;
    md4->state[1] = 0xefcdab89;
    md4->state[2] = 0x98badcfe;
    md4->state[3] = 0x10325476;
}

/**
 * Updates the MD4 state with the data provided. The MD4_Context structure
 * should be initialized using the MD4_init function before calling this
 * function.
 * @param md4    The structure containing the intermediate MD4 information to
 *               update.
 * @param data   The data used to update the MD4 state.
 * @param length The length of the data to digest.
 */
void MD4_update(MD4_Context* md4, const void* data, uint32_t length) {
    uint32_t saved_lo;
    uint32_t used;
    uint32_t available;

    saved_lo = md4->lo;
    if ((md4->lo = (saved_lo + length) & 0x1FFFFFFF) < saved_lo) {
        md4->hi++;
    }

    used = saved_lo & 0x3F;

    if (used) {
        available = 64 - used;

        if (length < available) {
            memcpy(&md4->buffer[used], data, length);
            return;
        }

        memcpy(&md4->buffer[used], data, available);
        data = (const unsigned char*)data + available;
        length -= available;

        transform(md4, md4->buffer, 64);
    }

    if (length >= 64) {
        data = transform(md4, data, length & ~(uint32_t)0x3F);
        length &= 0x3F;
    }

    memcpy(md4->buffer, data, length);
}
