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

/* This MD5 implementation has been adapted from the public domain reference at
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 */

#include "md5.h"
#include "string.h"

/* The basic MD5 functions.
 *
 * F and G are optimized compared to their RFC 1321 definitions for
 * architectures that lack an AND-NOT instruction, just like in Colin Plumb's
 * implementation.
 */
#define F(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)  ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)  (((x) ^ (y)) ^ (z))
#define H2(x, y, z) ((x) ^ ((y) ^ (z)))
#define I(x, y, z)  ((y) ^ ((x) | ~(z)))

/* The MD5 transformation for all four rounds. */
#define STEP(f, a, b, c, d, x, t, s) \
    (a) += f((b), (c), (d)) + (x) + (t); \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
    (a) += (b);

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
#define SET(n) (md5->block[(n)] = \
    (uint32_t)ptr[(n) * 4] | \
    ((uint32_t)ptr[(n) * 4 + 1] << 8) | \
    ((uint32_t)ptr[(n) * 4 + 2] << 16) | \
    ((uint32_t)ptr[(n) * 4 + 3] << 24))
#define GET(n) (md5->block[(n)])
#endif

/**
 * Performs the actual transformation of data for MD5 hashing in 64 byte blocks.
 * @param md5    The MD5 context to update.
 * @param data   The data to process.
 * @param length The length of the data to process. Must be a multiple of 64.
 * @returns Returns a pointer to any remaining data that didn't fit in a 64-byte
 *          block. The remaining data will always be less than 64 bytes.
 */
static const void* transform(MD5_Context* md5, const void* data, uint32_t length) {
    const unsigned char* ptr;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t saved_a;
    uint32_t saved_b;
    uint32_t saved_c;
    uint32_t saved_d;

    ptr = (unsigned char*)data;
    a = md5->state[0];
    b = md5->state[1];
    c = md5->state[2];
    d = md5->state[3];


   do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;

        /* Round 1 */
        STEP(F, a, b, c, d, SET( 0), 0xd76aa478,  7)
        STEP(F, d, a, b, c, SET( 1), 0xe8c7b756, 12)
        STEP(F, c, d, a, b, SET( 2), 0x242070db, 17)
        STEP(F, b, c, d, a, SET( 3), 0xc1bdceee, 22)
        STEP(F, a, b, c, d, SET( 4), 0xf57c0faf,  7)
        STEP(F, d, a, b, c, SET( 5), 0x4787c62a, 12)
        STEP(F, c, d, a, b, SET( 6), 0xa8304613, 17)
        STEP(F, b, c, d, a, SET( 7), 0xfd469501, 22)
        STEP(F, a, b, c, d, SET( 8), 0x698098d8,  7)
        STEP(F, d, a, b, c, SET( 9), 0x8b44f7af, 12)
        STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
        STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
        STEP(F, a, b, c, d, SET(12), 0x6b901122,  7)
        STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
        STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
        STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)

        /* Round 2 */
        STEP(G, a, b, c, d, GET( 1), 0xf61e2562,  5)
        STEP(G, d, a, b, c, GET( 6), 0xc040b340,  9)
        STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
        STEP(G, b, c, d, a, GET( 0), 0xe9b6c7aa, 20)
        STEP(G, a, b, c, d, GET( 5), 0xd62f105d,  5)
        STEP(G, d, a, b, c, GET(10), 0x02441453,  9)
        STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
        STEP(G, b, c, d, a, GET( 4), 0xe7d3fbc8, 20)
        STEP(G, a, b, c, d, GET( 9), 0x21e1cde6,  5)
        STEP(G, d, a, b, c, GET(14), 0xc33707d6,  9)
        STEP(G, c, d, a, b, GET( 3), 0xf4d50d87, 14)
        STEP(G, b, c, d, a, GET( 8), 0x455a14ed, 20)
        STEP(G, a, b, c, d, GET(13), 0xa9e3e905,  5)
        STEP(G, d, a, b, c, GET( 2), 0xfcefa3f8,  9)
        STEP(G, c, d, a, b, GET( 7), 0x676f02d9, 14)
        STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)

        /* Round 3 */
        STEP(H,  a, b, c, d, GET( 5), 0xfffa3942,  4)
        STEP(H2, d, a, b, c, GET( 8), 0x8771f681, 11)
        STEP(H,  c, d, a, b, GET(11), 0x6d9d6122, 16)
        STEP(H2, b, c, d, a, GET(14), 0xfde5380c, 23)
        STEP(H,  a, b, c, d, GET( 1), 0xa4beea44,  4)
        STEP(H2, d, a, b, c, GET( 4), 0x4bdecfa9, 11)
        STEP(H,  c, d, a, b, GET( 7), 0xf6bb4b60, 16)
        STEP(H2, b, c, d, a, GET(10), 0xbebfbc70, 23)
        STEP(H,  a, b, c, d, GET(13), 0x289b7ec6,  4)
        STEP(H2, d, a, b, c, GET( 0), 0xeaa127fa, 11)
        STEP(H,  c, d, a, b, GET( 3), 0xd4ef3085, 16)
        STEP(H2, b, c, d, a, GET( 6), 0x04881d05, 23)
        STEP(H,  a, b, c, d, GET( 9), 0xd9d4d039,  4)
        STEP(H2, d, a, b, c, GET(12), 0xe6db99e5, 11)
        STEP(H,  c, d, a, b, GET(15), 0x1fa27cf8, 16)
        STEP(H2, b, c, d, a, GET( 2), 0xc4ac5665, 23)

        /* Round 4 */
        STEP(I, a, b, c, d, GET( 0), 0xf4292244,  6)
        STEP(I, d, a, b, c, GET( 7), 0x432aff97, 10)
        STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
        STEP(I, b, c, d, a, GET( 5), 0xfc93a039, 21)
        STEP(I, a, b, c, d, GET(12), 0x655b59c3,  6)
        STEP(I, d, a, b, c, GET( 3), 0x8f0ccc92, 10)
        STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
        STEP(I, b, c, d, a, GET( 1), 0x85845dd1, 21)
        STEP(I, a, b, c, d, GET( 8), 0x6fa87e4f,  6)
        STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
        STEP(I, c, d, a, b, GET( 6), 0xa3014314, 15)
        STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
        STEP(I, a, b, c, d, GET( 4), 0xf7537e82,  6)
        STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
        STEP(I, c, d, a, b, GET( 2), 0x2ad7d2bb, 15)
        STEP(I, b, c, d, a, GET( 9), 0xeb86d391, 21)

        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        ptr += 64;
    } while (length -= 64);

    md5->state[0] = a;
    md5->state[1] = b;
    md5->state[2] = c;
    md5->state[3] = d;

    return ptr;
}

/**
 * Performs the final operation on the MD5_Context structure, copies the
 * resulting hash to the array pointed to by result and clears the structure. If
 * the structure is to be reused, it needs to be initialized again.
 * @param md5    The MD5_Context structure to finalize.
 * @param result Pointer to an array of at least 16 bytes used to hold the
 *               resulting hash.
 * @remarks The result provided is converted for use in Little Endian CPU
 *          architectures.
 */
void MD5_final(MD5_Context* md5, unsigned char* result) {
    uint32_t used;
    uint32_t available;

    used = md5->lo & 0x3F;
    md5->buffer[used++] = 0x80;
    available = 64 - used;

    if (available < 8) {
        memset(&md5->buffer[used], 0, available);
        transform(md5, md5->buffer, 64);
        used = 0;
        available = 64;
    }

    memset(&md5->buffer[used], 0, available - 8);

    md5->lo <<= 3;
    md5->buffer[56] =  md5->lo & 0xFF;
    md5->buffer[57] = (md5->lo >>  8) & 0xFF;
    md5->buffer[58] = (md5->lo >> 16) & 0xFF;
    md5->buffer[59] = (md5->lo >> 24) & 0xFF;
    md5->buffer[60] =  md5->hi & 0xFF;
    md5->buffer[61] = (md5->hi >>  8) & 0xFF;
    md5->buffer[62] = (md5->hi >> 16) & 0xFF;
    md5->buffer[63] = (md5->hi >> 24) & 0xFF;

    // Transform for the final time.
    transform(md5, md5->buffer, 64);

    result[0]  =  md5->state[0] & 0xFF;
    result[1]  = (md5->state[0] >>  8) & 0xFF;
    result[2]  = (md5->state[0] >> 16) & 0xFF;
    result[3]  = (md5->state[0] >> 24) & 0xFF;
    result[4]  =  md5->state[1] & 0xFF;
    result[5]  = (md5->state[1] >>  8) & 0xFF;
    result[6]  = (md5->state[1] >> 16) & 0xFF;
    result[7]  = (md5->state[1] >> 24) & 0xFF;
    result[8]  =  md5->state[2] & 0xFF;
    result[ 9] = (md5->state[2] >>  8) & 0xFF;
    result[10] = (md5->state[2] >> 16) & 0xFF;
    result[11] = (md5->state[2] >> 24) & 0xFF;
    result[12] =  md5->state[3] & 0xFF;
    result[13] = (md5->state[3] >>  8) & 0xFF;
    result[14] = (md5->state[3] >> 16) & 0xFF;
    result[15] = (md5->state[3] >> 24) & 0xFF;

    memset(md5, 0, sizeof(*md5));
}

/**
 * Initializes a new MD5_Context structure for use with MD5_update.
 * @param md5 The structure that will be initialized.
 */
void MD5_init(MD5_Context* md5) {
    md5->hi = 0;
    md5->lo = 0;

    md5->state[0] = 0x67452301;
    md5->state[1] = 0xEFCDAB89;
    md5->state[2] = 0x98BADCFE;
    md5->state[3] = 0x10325476;
}

/**
 * Updates the MD5 state with the data provided. The MD5_Context structure
 * should be initialized using the MD5_init function before calling this
 * function.
 * @param md5    The structure containing the intermediate MD5 information to
 *               update.
 * @param data   The data used to update the MD5 state.
 * @param length The length of the data to digest.
 * @remarks
 * For best performance of this method, attempt to always use a buffer size that
 * is divisible by 64. Doing this will ensure the most efficient copying of data
 * for processing.
 */
void MD5_update(MD5_Context* md5, const void* data, uint32_t length) {
    uint32_t saved_lo;
    uint32_t used;
    uint32_t available;

    saved_lo = md5->lo;
    if ((md5->lo = (saved_lo + length) & 0x1FFFFFFF) < saved_lo) {
        ++md5->hi;
    }

    md5->hi += length >> 29;
    used = saved_lo & 0x3F;

    if (used) {
        available = 64 - used;
        if (length < available) {
            memcpy(&md5->buffer[used], data, length);
            return;
        }

        memcpy(&md5->buffer[used], data, available);
        data = (const unsigned char*)data + available;
        length -= available;
        transform(md5, md5->buffer, 64);
    }

    if (length >= 64) {
        data = transform(md5, data, length & ~(uint32_t)0x3F);
        length &= 0x3F;
    }

    memcpy(md5->buffer, data, length);
}
