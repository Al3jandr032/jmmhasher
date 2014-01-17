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

#ifndef __JMMHASHER_SHA1_H_
#define __JMMHASHER_SHA1_H_

/* This SHA1 implementation has been adapted from the public domain reference at
 * https://github.com/WaterJuice/CryptLib
 */

#include <stdint.h>

/**
 * Structure containing the intermediate state information for calculating the
 * SHA1 hash of data.
 * @field hi     Holds the high 32-bits of the total bits of data processed.
 * @field lo     Holds the low 32-bits of the total bits of data processed.
 * @field state  Holds the transformation state between transformation calls.
 * @field buffer Holds the data to be transformed when processing data at odd
 *               offsets.
 */
typedef struct {
    uint32_t hi;
    uint32_t lo;
    uint32_t state[5];
    unsigned char buffer[64];
} SHA1_Context;

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
void SHA1_final(SHA1_Context* sha1, unsigned char* result);

/**
 * Initializes a new SHA1_Context structure for use with SHA1_update.
 * @param sha1 The structure to initialize.
 */
void SHA1_init(SHA1_Context* sha1);

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
void SHA1_update(SHA1_Context* sha1, const void* data, uint32_t length);

#endif
