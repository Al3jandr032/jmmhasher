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

/**
 * Structure containing the intermediate digest and final result for
 * calculating the CRC32 of data.
 * @field digest Holds the intermediate digest as the CRC32 is computed.
 * @field hash   Holds the final result of the CRC32 digest converted for
 *               Big Endian architectures.
 */
typedef struct {
    unsigned int digest;
    unsigned char hash[4];
} CRC32;

/**
 * Performs the final operation on the CRC32 structure and copies the result
 * to the hash char buffer. The result stored in hash is converted for Big
 * Endian architectures.
 * @param crc The CRC32 structure to finalize.
 */
void CRC32_final(CRC32* crc);

/**
 * Initializes a new CRC32 structure for use with CRC32_update.
 * @param crc The structure that will be initialized.
 */
void CRC32_init(CRC32* crc);

/**
 * Update the CRC with the data provided. The CRC should be initialized
 * using CRC32_init before calling this function.
 * @param crc    The structure containing the CRC digest to update.
 * @param data   The data used to update the CRC digest.
 * @param length The length of the data to digest.
 */
void CRC32_update(CRC32* crc, unsigned char* buf, int length);

#endif
