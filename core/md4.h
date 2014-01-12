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

#ifndef __JMMHASHER_MD4_H_
#define __JMMHASHER_MD4_H_

/* This MD4 implementation has been adapted from the public domain reference at
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 */

#include <stdint.h>

typedef struct {
    uint32_t block[16];
    unsigned char buffer[64];
    uint32_t hi;
    uint32_t lo;
    uint32_t state[4];
} MD4_Context;

void MD4_final(MD4_Context* md4, unsigned char* result);

void MD4_init(MD4_Context* md4);

void MD4_update(MD4_Context* md4, const void* data, uint32_t length);

#endif
