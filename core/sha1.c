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

 /* This SHA1 implementation has been adapted from the public domain reference at
 * https://github.com/WaterJuice/CryptLib
 */

#include "sha1.h"
#include <memory.h>

/* blk0() and blk() perform the initial expand. */
#define rol(x, y) (((x) << (y)) | ((x) >> (32 - (y))))
#define blk0(i) (block[i] = (rol(block[i], 24) & 0xFF00FF00) | (rol(block[i], 8) & 0x00FF00FF))
#define blk(i) (block[i & 15] = rol(block[(i + 13) & 15] ^ block[(i + 8) & 15] ^ block[(i + 2) & 15] ^ block[i & 15], 1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v, w, x, y, z, i) z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); w=rol(w, 30);
#define R1(v, w, x, y, z, i) z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); w=rol(w, 30);
#define R2(v, w, x, y, z, i) z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); w=rol(w, 30);
#define R3(v, w, x, y, z, i) z += (((w | x) & y)|(w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); w=rol(w, 30);
#define R4(v, w, x, y, z, i) z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); w=rol(w, 30);

/**
 * Performs the actual transformation of the data for SHA1 hashing.
 * @param sha1 The SHA1 context to update.
 * @param data The data to process.
 * @remarks
 * The data must point to a data structure of at least 64-bytes. During the
 * execution of this function, only 64 bytes of data will be processed. However,
 * no bounds checking is done to ensure data is available.
 */
static void transform(SHA1_Context* sha1, const void* data) {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t *block = (uint32_t*)data;

    a = sha1->state[0];
    b = sha1->state[1];
    c = sha1->state[2];
    d = sha1->state[3];
    e = sha1->state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);

    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);

    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);

    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);

    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

    sha1->state[0] += a;
    sha1->state[1] += b;
    sha1->state[2] += c;
    sha1->state[3] += d;
    sha1->state[4] += e;
}

/**
 * Performs the final operation on the SHA1_Context structure, copies the
 * resulting hash to the array pointed to by result and clears the structure. If
 * the structure is to be reused, it needs to be initialized again.
 * @param sha1   The SHA1_Context structure to finalize.
 * @param result Pointer to an array of at least 20 bytes used to hold the
 *               resulting hash.
 * @remarks The result provided is converted for use in Little Endian CPU
 *          architectures.
 */
void SHA1_final(SHA1_Context* sha1, unsigned char* result) {
    unsigned char finalcount[8];

    finalcount[0] = (sha1->hi >> 24) & 0xFF;
    finalcount[1] = (sha1->hi >> 16) & 0xFF;
    finalcount[2] = (sha1->hi >>  8) & 0xFF;
    finalcount[3] =  sha1->hi & 0xFF;
    finalcount[4] = (sha1->lo >> 24) & 0xFF;
    finalcount[5] = (sha1->lo >> 16) & 0xFF;
    finalcount[6] = (sha1->lo >>  8) & 0xFF;
    finalcount[7] =  sha1->lo & 0xFF;

    SHA1_update(sha1, "\x80", 1);
    while ((sha1->lo & 504) != 448) {
        SHA1_update(sha1, "\0", 1);
    }

    SHA1_update(sha1, finalcount, 8);

    result[0]  = (sha1->state[0] >> 24) & 0xFF;
    result[1]  = (sha1->state[0] >> 16) & 0xFF;
    result[2]  = (sha1->state[0] >>  8) & 0xFF;
    result[3]  =  sha1->state[0] & 0xFF;
    result[4]  = (sha1->state[1] >> 24) & 0xFF;
    result[5]  = (sha1->state[1] >> 16) & 0xFF;
    result[6]  = (sha1->state[1] >>  8) & 0xFF;
    result[7]  =  sha1->state[1] & 0xFF;
    result[8]  = (sha1->state[2] >> 24) & 0xFF;
    result[9]  = (sha1->state[2] >> 16) & 0xFF;
    result[10] = (sha1->state[2] >>  8) & 0xFF;
    result[11]  =  sha1->state[2] & 0xFF;
    result[12] = (sha1->state[3] >> 24) & 0xFF;
    result[13] = (sha1->state[3] >> 16) & 0xFF;
    result[14] = (sha1->state[3] >>  8) & 0xFF;
    result[15] =  sha1->state[3] & 0xFF;
    result[16] = (sha1->state[4] >> 24) & 0xFF;
    result[17] = (sha1->state[4] >> 16) & 0xFF;
    result[18] = (sha1->state[4] >>  8) & 0xFF;
    result[19] =  sha1->state[4] & 0xFF;

    memset(sha1, 0, sizeof(*sha1));
}

/**
 * Initializes a new SHA1_Context structure for use with SHA1_update.
 * @param sha1 The structure to initialize.
 */
void SHA1_init(SHA1_Context* sha1) {
    sha1->hi = 0;
    sha1->lo = 0;

    sha1->state[0] = 0x67452301;
    sha1->state[1] = 0xEFCDAB89;
    sha1->state[2] = 0x98BADCFE;
    sha1->state[3] = 0x10325476;
    sha1->state[4] = 0xC3D2E1F0;
}

/**
 * Updates the SHA1 state with the data provided. The SHA1_Context structure
 * should be initialized using the SHA1_init function before calling this
 * function.
 * @param sha1   The structure containing the intermediate SHA1 information to
 *               update.
 * @param data   The data used to update the SHA1 state.
 * @param length The length of the data to digest.
 * @remarks
 * For best performance of this method, attempt to always fill a buffer to a
 * size that is a multiple of 64. Doing this will ensure the most efficient
 * copying of data for processing.
 */
void SHA1_update(SHA1_Context* sha1, const void* data, uint32_t length) {
    uint32_t i;
    uint32_t j;

    j = (sha1->lo >> 3) & 0x3F;
    if ((sha1->lo += length << 3) < (length << 3)) {
        ++sha1->hi;
    }

    sha1->hi += (length >> 29);
    if (j + length > 63) {
        i = 64 - j;
        memcpy(&sha1->buffer[j], data, i);
        transform(sha1, sha1->buffer);
        for (; i + 63 < length; i += 64) {
            transform(sha1, (const unsigned char*)data + i);
        }
        j = 0;
    } else {
        i = 0;
    }

    memcpy(&sha1->buffer[j], (const unsigned char*)data + i, length - i);
}
