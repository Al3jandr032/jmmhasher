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

#include "libhasher.h"
#include "core/crc32.h"
#include "core/md4.h"
#include "core/md5.h"
#include "core/sha1.h"

#include <fcntl.h> /* open, close */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* wcstombs_l */
#include <string.h> /* memset */

#include <xlocale.h> /* for locale awesomeness */

static void ConvertWideToMultiByte(wchar_t* input, char** output);

int HashFileWithSyncIO(HashRequest* request, HashProgressCallback* callback) {
    if (request == NULL) {
        return -1;
    }

    char* filename = NULL;
    ConvertWideToMultiByte(request->filename, &filename);
    if (filename == NULL) {
        printf("error\n");
        return -2;
    }

    int file = open(filename, O_RDONLY | O_SHLOCK);
    if (file == -1) {
        perror("HashFileWythSyncIO:open()");
        return -3;
    }

    close(file);

    printf("%s\n", filename);

    /* Set our options */
    char doCRC32 = request->options & OPTION_CRC32;
    char doMD5 = request->options & OPTION_MD5;
    char doSHA1 = request->options & OPTION_SHA1;
    char doED2k = request->options & OPTION_ED2K;

    /* clear the memory */
    memset(&request->result, 0, 72);

    free(filename);
}

void ConvertWideToMultiByte(wchar_t* input, char** output) {
    *output = NULL;

    if (input == NULL) {
        return;
    }

    /* Ensure we have the C locale type */
    locale_t utf8Locale = newlocale(LC_ALL_MASK, NULL, NULL);
    if (utf8Locale == NULL) {
        return;
    }

    size_t conversionSize = wcstombs_l(NULL, input, 0, utf8Locale);
    if (conversionSize == -1) {
        freelocale(utf8Locale);
        return;
    }

    char* conversion = (char*)malloc(conversionSize * sizeof(char));
    if (conversion == NULL) {
        freelocale(utf8Locale);
        return;
    }

    conversionSize = wcstombs_l(conversion, input, conversionSize, utf8Locale);
    if (conversionSize == -1) {
        freelocale(utf8Locale);
        free(conversion);
        return;
    }

    *output = conversion;
}
