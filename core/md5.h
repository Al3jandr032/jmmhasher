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

#ifndef __JMMHASHER_MD5_H_
#define __JMMHASHER_MD5_H_

/* This MD5 implementation has been adapted from the public domain reference at
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md5
 */

#include <stdint.h>

/**
 * Structure containing the intermediate state information for calculating the
 * MD5 hash of data.
 * @field hi     Holds the high 32-bits of the total bits of data processed.
 * @field lo     Holds the low 32-bits of the total bits of data processed.
 * @field state  Holds the transformation state between transformation calls.
 * @field buffer Holds the data to be transformed when processing data at odd
 *               offsets.
 * @field block  Only defined for little-endian architectures that don't
 *               tolerate unaligned memory accesses. Used by the GET/SET macros.
 */
typedef struct {
    uint32_t hi;
    uint32_t lo;
    uint32_t state[4];
    unsigned char buffer[64];
    #if !defined(__i386) && !defined(__x86_64__) && !defined(__vax__)
    uint32_t block[16];
    #endif
} MD5_Context;

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
void MD5_final(MD5_Context* md5, unsigned char* result);

/**
 * Initializes a new MD5_Context structure for use with MD5_update.
 * @param md5 The structure that will be initialized.
 */
void MD5_init(MD5_Context* md5);

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
void MD5_update(MD5_Context* md5, const void* data, uint32_t length);

#endif
