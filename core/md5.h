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

typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned int bitlen[2];
    unsigned int state[4];
    unsigned char hash[16];
} MD5_Context;

void MD5_init(MD5_Context* md5);
void MD5_final(MD5_Context* md5);
void MD5_update(MD5_Context* md5, unsigned char* data, unsigned int length);

#endif
