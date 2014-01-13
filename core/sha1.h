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

#include <stdint.h>

typedef struct {
    uint32_t Message_Digest[5];
    uint32_t Length_Low;
    uint32_t Length_High;
    unsigned char Message_Block[64];
    int32_t Message_Block_Index;
    int32_t Computed;
    int32_t Corrupted;
} SHA1_Context;

void SHA1_final(SHA1_Context* sha1, unsigned char* result);

void SHA1_init(SHA1_Context* sha1);

void SHA1_update(SHA1_Context* sha1, const void* data, uint32_t length);

#endif
