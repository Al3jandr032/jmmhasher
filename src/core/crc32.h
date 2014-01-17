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

#ifndef __JMMHASHER_CRC32_H_
#define __JMMHASHER_CRC32_H_

#include <stdint.h>

/**
 * Structure containing the intermediate digest of the CRC32 of data.
 * @field digest Holds the intermediate digest as the CRC32 is computed.
 */
typedef struct {
    uint32_t digest;
} CRC32_Context;

/**
 * Performs the final operation on the CRC32_Context structure and copies the
 * result to the hash char buffer. The result stored in hash is converted for
 * Little Endian architectures.
 * @param crc The CRC32 structure to finalize.
 * @param result Pointer to an array of at least 16 bytes used to hold the
 *               resulting hash.
 */
void CRC32_final(CRC32_Context* crc, unsigned char* result);

/**
 * Initializes a new CRC32_Context structure for use with CRC32_update.
 * @param crc The structure that will be initialized.
 */
void CRC32_init(CRC32_Context* crc);

/**
 * Update the CRC with the data provided. The CRC_Context structure should be
 * initialized using CRC32_init before calling this function.
 * @param crc    The structure containing the CRC digest to update.
 * @param data   The data used to update the CRC digest.
 * @param length The length of the data to digest.
 */
void CRC32_update(CRC32_Context* crc, const void* buf, uint32_t length);

#endif
