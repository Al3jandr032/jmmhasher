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

#include <stdint.h>

/**
 * Structure containing the intermediate state information and final result for
 * calculating the MD5 hash of data.
 * @field buffer        Holds the current data buffer of data to process in the
 *                      transform function.
 * @field bufferLength  Count of the current amount of data in the buffer
 *                      awaiting transforming.
 * @field bitsProcessed Count of the total number of bits processed by the
 *                      transform function.
 * @field state         Holds the intermediate state of the MD5 function in
 *                      between transforms.
 * @field hash          Holds the final resulting hash of the MD5 function
 *                      converted for little endian use.
 */
typedef struct {
    unsigned char buffer[64];
    uint16_t bufferLength;
    uint64_t bitsProcessed;
    uint32_t state[4];
    unsigned char hash[16];
} MD5_Context;

/**
 * Performs the final operation on the MD5_Context structure and copies the
 * resulting hash to the hash buffer. The result in the hash is converted for
 * use in Little Endian CPU architectures.
 * @param md5 The MD5_Context structure to finalize.
 */
void MD5_final(MD5_Context* md5);

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
void MD5_update(MD5_Context* md5, unsigned char* data, uint32_t length);

#endif
