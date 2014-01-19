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

#include <errno.h>    /* errno */
#include <fcntl.h>    /* open, close */
#include <stdint.h>   /* standard data types */
#include <stdlib.h>   /* malloc, wcstombs_l */
#include <string.h>   /* memset */
#include <sys/stat.h> /* stat */
#include <unistd.h>   /* read */
#include <xlocale.h>  /* for locale awesomeness */

#define BLOCKSIZE  9728000
#define BUFFERSIZE BLOCKSIZE / 10

/**
 * Converts a wide char array string to a UTF-8 char array string using the
 * C locale.
 * @param input  The input wide char array to convert.
 * @param output The converted output. Can be NULL if the function failed in
 *               any way.
 */
static void ConvertWideToMultiByte(wchar_t* input, char** output);

/**
 * Accepts a HashRequest structure and attempts to calculate the requested hash
 * of the provided file using synchronous IO.
 * @param  request  The HashRequest containing the options and the file that
 *                  should be hashed.
 * @param  callback An optional callback parameter that will receive the total
 *                  number of bytes processed by the hashing algorithm and
 *                  provides the caller a chance to cancel the hash if desired.
 * @return          See the header file for return information.
 */
int HashFileWithSyncIO(HashRequest* request, HashProgressCallback* callback) {
    /* Simple guard condition. If we have no request, we can't process. */
    if (request == NULL) {
        return -1;
    }

    /* clear the result buffer */
    memset(&request->result, 0, 56);

    /* Set our options */
    char doCRC32 = request->options & OPTION_CRC32;
    char doMD5 = request->options & OPTION_MD5;
    char doSHA1 = request->options & OPTION_SHA1;
    char doED2k = request->options & OPTION_ED2K;

    /* If they didn't pass any valid options (or passed 0) then return since
     * we can't calculate a hash without knowing which algorithm(s) to use. */
    if (!doCRC32 && !doMD5 && !doSHA1 && !doED2k) {
        return -2;
    }

    /* Convert the filename from a wchar_t* to char* using UTF-8. */
    char* filename = NULL;
    ConvertWideToMultiByte(request->filename, &filename);
    if (filename == NULL) {
        return -3;
    }

    /* Try to open the file and free up filename since it isn't needed after
     * this point and helps reduce the code cleanup on failures. */
    int file = open(filename, O_RDONLY | O_SHLOCK);
    free(filename);
    if (file == -1) {
        return -4;
    }

    /* Set errno to zero in case we're called many times in the same process. */
    errno = 0;

    /* Set up our local variables. */
    CRC32_Context crc32;
    MD4_Context ed2k;
    MD5_Context md5;
    SHA1_Context sha1;
    uint32_t bytesRead;
    uint32_t ed2kHashLength = 0;
    uint32_t ed2kBlockIdx = 0;
    uint32_t ed2kBlocks = 0;
    uint32_t progressLoopCount = 0;
    uint64_t totalBytesRead = 0;
    uint8_t  ed2kLoopIdx = 0;
    unsigned char* fileData = NULL;
    unsigned char* ed2kHashes = NULL;

    /* Set up our hashes, also calculate the space needed for the ED2k hash if
     * we were requested to do that. */
    if (doED2k) {
        struct stat filestats;
        memset(&filestats, 0, sizeof(struct stat));
        if (fstat(file, &filestats) != 0) {
            close(file);
            return -5;
        }

        /* Determine the number of blocks needed for calculating the file's
         * ED2k hash. If the file isn't an even multiple of BLOCKSIZE then
         * we add one more block. */
        ed2kBlocks = filestats.st_size / BLOCKSIZE;
        if (filestats.st_size % BLOCKSIZE > 0) {
            ++ed2kBlocks;
        }

        /* Only allocate an array if we have more than one block to hash.
         * Files that are smaller in size than BLOCKSIZE simply use the
         * normal computed MD4 hash. */
        if (ed2kBlocks > 1) {
            ed2kHashLength = ed2kBlocks * 16;
            ed2kHashes = (unsigned char*)malloc(ed2kHashLength);
            if (ed2kHashes == NULL && errno == ENOMEM) {
                close(file);
                return -6;
            }
        }
    }
    if (doCRC32) { CRC32_init(&crc32); }
    if (doMD5) { MD5_init(&md5); }
    if (doSHA1) { SHA1_init(&sha1); }

    /* Allocate the file buffer. The BUFFERSIZE constant is a clean multiple of
     * the BLOCKSIZE for ED2k hashing, which will make looping easier. */
    fileData = (unsigned char*)malloc(BUFFERSIZE);
    if (fileData == NULL && errno == ENOMEM) {
        free(ed2kHashes);
        close(file);
        return -7;
    }

    /* Read the entire file until we hit the end. */
    while ((bytesRead = read(file, fileData, BUFFERSIZE)) != 0) {
        /* Double check that we haven't had a file read error. */
        if (bytesRead == -1) {
            /* We should never get EAGAIN, but handle it anyway. */
            if (errno == EAGAIN) {
                continue;
            }

            /* We've encountered an unexpected read error. Free up everything
             * and inform the caller that we've failed. */
            free(fileData);
            free(ed2kHashes);
            close(file);
            return -8;
        }

        totalBytesRead += bytesRead;
        if (callback && progressLoopCount % 10 == 0) {
            if(callback(request->tag, totalBytesRead) != 0) {
                free(fileData);
                free(ed2kHashes);
                close(file);
                return -9;
            }
        }
        progressLoopCount++;

        /* Update the hashes. */
        if (doED2k) {
            /* If we've looped 10 times, finish the current MD4 hash, update
             * the block counter and set the hash to be initialized again. */
            if (ed2kLoopIdx == 10) {
                MD4_final(&ed2k, &ed2kHashes[ed2kBlockIdx * 16]);
                ++ed2kBlockIdx;
                ed2kLoopIdx = 0;
            }

            /* If this is the first loop (or we just finished a hash)
             * initialize the MD4 hash for the next block. */
            if (ed2kLoopIdx == 0) {
                MD4_init(&ed2k);
            }

            ++ed2kLoopIdx;
            MD4_update(&ed2k, fileData, bytesRead);
        }
        if (doCRC32) { CRC32_update(&crc32, fileData, bytesRead); }
        if (doMD5) { MD5_update(&md5, fileData, bytesRead); }
        if (doSHA1) { SHA1_update(&sha1, fileData, bytesRead); }
    }

    /* Free our file buffer and close the file since we're done with it. */
    free(fileData);
    close(file);

    /* If we have a callback, call them one more time informing them of our
     * completion. We ignore the request to cancel since we're done anyway. */
    if (callback) {
        callback(request->tag, totalBytesRead);
    }

    /* Finalize all of the hashes that were selected and store the results in
     * the request result buffer. The order of the hashes are:
     *     0 - 15: ED2k
     *    16 - 19: CRC32
     *    20 - 35: MD5
     *    36 - 55: SHA1 */
    if (doED2k) {
        /* If we had just one block to process store the result of the block
         * directly in the result buffer. */
        if (ed2kBlocks == 1) {
            MD4_final(&ed2k, &request->result[0]);
        } else {
            /* Check to see if we were in a loop and finalize the final pending
             * block if we were.*/
            if (ed2kLoopIdx > 0) {
                MD4_final(&ed2k, &ed2kHashes[ed2kBlockIdx * 16]);
            }

            /* Calculate the MD4 hash of the concatenated hashes from each ED2k
             * block. The resulting hash is the final ED2k hash. */
            MD4_init(&ed2k);
            MD4_update(&ed2k, ed2kHashes, ed2kHashLength);
            MD4_final(&ed2k, &request->result[0]);

            free(ed2kHashes);
        }
    }
    if (doCRC32) { CRC32_final(&crc32, &request->result[16]); }
    if (doMD5) { MD5_final(&md5, &request->result[20]); }
    if (doSHA1) { SHA1_final(&sha1, &request->result[36]); }

    return 0;
}

/**
 * Converts a wide char array string to a UTF-8 char array string using the
 * C locale.
 * @param input  The input wide char array to convert.
 * @param output The converted output. Can be NULL if the function failed in
 *               any way.
 */
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

    /* Call the conversion once with no destination buffer and a size of zero so
     * we can tell it how big we need to make our destination buffer. */
    size_t conversionSize = wcstombs_l(NULL, input, 0, utf8Locale);
    if (conversionSize == -1) {
        freelocale(utf8Locale);
        return;
    }

    char* conversion = (char*)malloc(conversionSize * sizeof(char));
    if (conversion == NULL && errno == ENOMEM) {
        freelocale(utf8Locale);
        return;
    }

    conversionSize = wcstombs_l(conversion, input, conversionSize, utf8Locale);
    freelocale(utf8Locale);
    if (conversionSize == -1) {
        free(conversion);
        return;
    }

    *output = conversion;
}
