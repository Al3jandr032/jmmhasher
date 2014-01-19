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

#ifndef __JMMHASHER_LIBHASHER_H_
#define __JMMHASHER_LIBHASHER_H_

#include <stdint.h>
#include <wchar.h>

#define OPTION_CRC32 0x01
#define OPTION_MD5   0x02
#define OPTION_SHA1  0x04
#define OPTION_ED2K  0x08

#define EXPORT __attribute__((visibility("default")))

typedef struct HashRequest {
    int32_t tag;
    int32_t options;
    wchar_t* filename;
    unsigned char result[72];
} HashRequest;

typedef int32_t HashProgressCallback(int32_t tag, int32_t progress);

EXPORT int HashFileWithSyncIO(
    HashRequest* request, HashProgressCallback* callback);

#endif
