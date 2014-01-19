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

/*** NOTE: This file is simply a quick and dirty test program for
           ensuring the library is working properly. */
#include "libhasher.h"
#include <stdint.h>
#include <stdio.h>
#include <memory.h>

#include <xlocale.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdint.h>

/**
 * Receives the callback from the hasher. Simply prints a *
 * to stdout for every call and flushes the buffer.
 * @param  tag      The optional tag.
 * @param  progress The total number of bytes read.
 * @return          Return 0 to continue hashing.
 */
int HashCallback(int tag, uint64_t progress) {
    printf("*");
    fflush(stdout);
    return 0;
}

/**
 * Simple helper method used to print the name of the hash and the results of
 * the hash in hex format.
 * @param hash   The name of the hash to print.
 * @param result The hash to print in hexadecimal format.
 * @param length The number of bytes in the hash.
 */
static void print_hash(char* hash, unsigned char* result, uint32_t length) {
    printf("    %s: ", hash);
    for (uint32_t idx = 0; idx < length; ++idx) {
        printf("%02x", result[idx]);
    }

    printf("\n");
}

/**
 * Main entry point for the test program.
 * @param  argc Unused.
 * @param  argv argv[1] contains the file to hash.
 * @return      Returns negative on failure, zero on success.
 */
int main(int argc, char** argv) {
    char* mbsfilename = argv[1];

    /* Convert the filename from char* to wchar_t* to test the
     * library. It's a pain, but it's designed to be called from
     * python, not C. */
    locale_t utf8 = newlocale(LC_ALL_MASK, NULL, NULL);
    size_t size = mbstowcs_l(NULL, mbsfilename, 0, utf8);
    wchar_t* wfilename = (wchar_t*)malloc(size * sizeof(wchar_t));
    size = mbstowcs_l(wfilename, mbsfilename, size, utf8);
    if (size == -1) {
        fprintf(stderr, "Error converting string.\n");
        return -1;
    }

    /* Set up our hash request. */
    HashRequest request;
    memset(&request, 0, sizeof(HashRequest));
    request.tag = 15;
    request.filename = wfilename;
    request.options = OPTION_ED2K;

    /* Hash the file. */
    int result = HashFileWithSyncIO(&request, HashCallback);

    /* Print the results. */
    printf("\nresult: %d\n", result);
    if (result == 0) {
        print_hash("  ED2K", &request.result[0], 16);
        print_hash(" CRC32", &request.result[16], 4);
        print_hash("   MD5", &request.result[20], 16);
        print_hash("  SHA1", &request.result[36], 20);
    }

    return 0;
}
