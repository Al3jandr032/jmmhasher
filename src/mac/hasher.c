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

#include <errno.h>  /* errno */
#include <fcntl.h>  /* open, close, ... */
#include <stdint.h> /* strcmp */
#include <stdio.h>  /* printf */
#include <stdlib.h> /* malloc */
#include <string.h> /* memset */

#include <sys/stat.h>  /* stat */
#include <unistd.h>    /* read */

#include "core/crc32.h"
#include "core/md4.h"
#include "core/md5.h"
#include "core/sha1.h"

/***** Definitions *****/
#define OPTION_NONE  0x00
#define OPTION_CRC32 0x01
#define OPTION_ED2K  0x02
#define OPTION_MD4   0x04
#define OPTION_MD5   0x08
#define OPTION_SHA1  0x10
#define OPTION_ALL \
    OPTION_CRC32 | OPTION_ED2K | OPTION_MD4 | \
    OPTION_MD5 | OPTION_SHA1

#define DO_CRC32 (options & OPTION_CRC32) == OPTION_CRC32
#define DO_ED2K  (options & OPTION_ED2K)  == OPTION_ED2K
#define DO_MD4   (options & OPTION_MD4)   == OPTION_MD4
#define DO_MD5   (options & OPTION_MD5)   == OPTION_MD5
#define DO_SHA1  (options & OPTION_SHA1)  == OPTION_SHA1

#define BLOCKSIZE  9728000
#define BUFFERSIZE BLOCKSIZE / 10

/***** Forward declarations *****/
/**
 * Simple helper method used to print the name of the hash and the results of
 * the hash in hex format.
 * @param hash   The name of the hash to print.
 * @param result The hash to print in hexadecimal format.
 * @param length The number of bytes in the hash.
 */
static void print_hash(char* hash, unsigned char* result, uint32_t length);

/**
 * Prints the available options and usage information for the program.
 */
static void print_usage();

/**
 * Calculates the hashes, specified in the options parameter, of each file found
 * in the array pointed to by the files parameter.
 * @param options   Holds the flags for each hash type that should be calculated
 *                  on each file in the array.
 * @param files     The names of the files that should be hashed. The array can
 *                  contain embedded NULLs but must be as long as the value
 *                  specified in the fileCount parameter.
 * @param fileCount The length of the number of files in the files array. The
 *                  count provided here must be the entire length of the files
 *                  array, included any embedded NULL items.
 */
 static void process_files(uint8_t options, char** files, uint32_t fileCount);

/***** Actual program/functions here *****/
/**
 * Main entry point for the program.
 * @param  argc The number of arguments for the program.
 * @param  argv The arguments for the program.
 * @return      Returns a negative value on failure, 0 on success.
 */
int main(int argc, char** argv) {
    uint8_t options = OPTION_NONE;

    printf("jmmhasher 0.2.0\n");
    if (argc < 2) {
        fprintf(stderr, "  ERROR: Missing required arguments.\n");
        print_usage();
        return -1;
    }

    char **files = (char**)malloc(sizeof(char*) * argc);
    if (!files) {
        fprintf(stderr, "  ERROR: Unable to allocate file array.\n");
        return -1;
    }

    /* Parse the available options */
    uint32_t fileCount = 0;
    uint32_t idx;
    for (idx = 1; idx < argc; ++idx) {
        if (strcmp("-h", argv[idx]) == 0 || strcmp("--help", argv[idx]) == 0) {
            print_usage();
            return 0;
        }

        if (strcmp("-4", argv[idx]) == 0 || strcmp("--md4", argv[idx]) == 0) {
            options |= OPTION_MD4;
            continue;
        }

        if (strcmp("-5", argv[idx]) == 0 || strcmp("--md5", argv[idx]) == 0) {
            options |= OPTION_MD5;
            continue;
        }

        if (strcmp("-c", argv[idx]) == 0 || strcmp("--crc32", argv[idx]) == 0) {
            options |= OPTION_CRC32;
            continue;
        }

        if (strcmp("-e", argv[idx]) == 0 || strcmp("--ed2k", argv[idx]) == 0) {
            options |= OPTION_ED2K;
            continue;
        }

        if (strcmp("-s", argv[idx]) == 0 || strcmp("--sha1", argv[idx]) == 0) {
            options |= OPTION_SHA1;
            continue;
        }

        if (strcmp("--", argv[idx]) == 0) {
            ++idx;
            break;
        }

        files[fileCount] = argv[idx];
        ++fileCount;
    }

    /* If they didn't set any options, default to OPTION_ALL. */
    if (options == OPTION_NONE) {
        options = OPTION_ALL;
    }

    /* Print the selected options. */
    printf("  Hashes: ");
    if (DO_CRC32) { printf("CRC32 "); }
    if (DO_ED2K) { printf("ED2K "); }
    if (DO_MD4) { printf("MD4 "); }
    if (DO_MD5) { printf("MD5 "); }
    if (DO_SHA1) { printf("SHA1 "); }
    printf("\n");

    /* Copy over any remaining files that might have been skipped due to the
     * "--" option. */
    while (idx < argc) {
        files[fileCount] = argv[idx];
        ++fileCount;
        ++idx;
    }

    /* Deduplicate any files if they appear twice on the list. */
    for (idx = 0; idx < fileCount; ++idx) {
        /* Don't attempt to compare a null pointer. */
        if (!files[idx]) {
            continue;
        }

        for (uint32_t idx2 = 0; idx2 < fileCount; ++idx2) {
            /* Don't compare against ourselves. */
            if (idx == idx2) {
                continue;
            }

            /* Don't attempt to compare a null pointer. */
            if (!files[idx2]) {
                continue;
            }

            /* If the filenames match, set the pointer to NULL and move to
             * the next one on the list. */
            if (strcmp(files[idx], files[idx2]) == 0) {
                files[idx2] = NULL;
            }
        }
    }

    process_files(options, files, fileCount);

    free(files);
    printf("\n");
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
 * Prints the available options and usage information for the program.
 */
static void print_usage() {
    printf("\nUSAGE:\n");
    printf(" -a, --all    Calculate using all available hashes of the input file(s).\n");
    printf("\n");
    printf(" -4, --md4    Calculate the MD4 hash of the input file(s).\n");
    printf(" -5, --md5    Calculate the MD5 hash of the input file(s).\n");
    printf(" -c, --crc32  Calculate the CRC32 hash of the input file(s).\n");
    printf(" -e, --ed2k   Calculate the ED2k hash of the input file(s).\n");
    printf(" -h, --help   Display this help screen.\n");
    printf(" -s, --sha1   Calculate the SHA1 hash of the input files.\n");
    printf("\n");
    printf("It is recommended you specify the command options first followed by two\n");
    printf("dashes to signify the end of the options and the start of the file list.\n");
    printf("If no options are specified, the default action is to hash using all available\n");
    printf("hashing methods (--all).\n");
    printf("\n");
    printf("EXAMPLES:\n");
    printf("jmmhasher -c --ed2k -- file1.mkv file2.mkv\n");
    printf("    Calculate the CRC32 and ED2k hashes of file1.mkv and file2.mkv.\n");
    printf("jmmhasher file1.mkv\n");
    printf("    Calculate all hashes for file1.mkv\n");
    printf("\n");
}

/**
 * Calculates the hashes, specified in the options parameter, of each file found
 * in the array pointed to by the files parameter.
 * @param options   Holds the flags for each hash type that should be calculated
 *                  on each file in the array.
 * @param files     The names of the files that should be hashed. The array can
 *                  contain embedded NULLs but must be as long as the value
 *                  specified in the fileCount parameter.
 * @param fileCount The length of the number of files in the files array. The
 *                  count provided here must be the entire length of the files
 *                  array, included any embedded NULL items.
 */
static void process_files(uint8_t options, char** files, uint32_t fileCount) {
    struct stat filestats = { 0 };
    CRC32_Context crc32 = { 0 };
    MD4_Context ed2k = { 0 };
    MD4_Context md4 = { 0 };
    MD5_Context md5 = { 0 };
    SHA1_Context sha1 = { 0 };
    uint32_t bytesRead = 0;
    uint32_t ed2kHashLength = 0;
    uint32_t ed2kBlockIdx = 0;
    uint32_t ed2kBlocks = 0;
    uint8_t  ed2kLoopIdx = 0;
    uint32_t loopIdx = 0;
    unsigned char result[72] = { 0 };
    unsigned char* fileData = NULL;
    unsigned char* ed2kHashes = NULL;

    for (loopIdx = 0; loopIdx < fileCount; ++loopIdx) {
        /* Reset errno back to zero for the next loop. */
        errno = 0;

        /* Duplicate files in the list were marked as NULL, and obviously we
         * can't process a NULL file, so move to the next. */
        if (files[loopIdx] == NULL) {
            continue;
        }

        /* Open the file as read only with shared reading. */
        printf("  %s: ", files[loopIdx]);
        int file = open(files[loopIdx], O_RDONLY | O_SHLOCK);
        if (file == -1) {
            printf("unable to open file. (%s)\n", strerror(errno));
            continue;
        }

        /* Read the stats of the file, we use the size and the mode flag. */
        memset(&filestats, 0, sizeof(struct stat));
        if (fstat(file, &filestats) != 0) {
            printf("unable to read file. %s\n", strerror(errno));
            close(file);
            continue;
        }

        /* If the file is a directory, skip it. */
        if (S_ISDIR(filestats.st_mode)) {
            printf("cannot process directories yet.\n");
            close(file);
            continue;
        }

        /* Initialize our hashes based on the options provided. */
        if (DO_CRC32) { CRC32_init(&crc32); }
        if (DO_MD4) { MD4_init(&md4); }
        if (DO_MD5) { MD5_init(&md5); }
        if (DO_SHA1) { SHA1_init(&sha1); }
        if (DO_ED2K) {
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
                    printf("unable to allocate buffer.\n");
                    close(file);
                    continue;
                }
            }
        }

        /* Allocate our file buffer. BUFFERSIZE is a clean multiple of the ED2k
         * BLOCKSIZE for easier ED2k hashing. */
        fileData = (unsigned char*)malloc(BUFFERSIZE);
        if (fileData == NULL && errno == ENOMEM) {
            printf("unable to allocate buffer.\n");
            close(file);

            if (DO_ED2K) {
                free(ed2kHashes);
                ed2kHashes = NULL;
            }

            continue;
        }

        /* Read the entire file until we hit the end. */
        while ((bytesRead = read(file, fileData, BUFFERSIZE)) != 0) {
            /* Double check that we haven't head a file read error. */
            if (bytesRead == -1) {
                /* We should never get EAGAIN, but handle it anyway. */
                if (errno == EAGAIN) {
                    continue;
                }

                /* It's an unexpected error. Free the ED2k hash (if one was
                 * allocated), close the file, and break out of the loop. We
                 * Don't need to free the data buffer as that's taken care of
                 * after the loop exits. */
                printf("error reading file. %s\n", strerror(errno));
                if (DO_CRC32) {
                    free(ed2kHashes);
                    ed2kHashes = NULL;
                }

                close(file);
                break;
            }

            /* Update the hashes */
            if (DO_CRC32) { CRC32_update(&crc32, fileData, bytesRead); }
            if (DO_MD4) { MD4_update(&md4, fileData, bytesRead); }
            if (DO_MD5) { MD5_update(&md5, fileData, bytesRead); }
            if (DO_SHA1) { SHA1_update(&sha1, fileData, bytesRead); }
            if (DO_ED2K) {
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
        }

        /* Release our file buffer. */
        free(fileData);
        fileData = NULL;

        /* There was an error while reading and we bailed out. Move on to the
         * next file in the list. */
        if (bytesRead == -1) {
            continue;
        }

        /* result stores all of the hashes
         *  0 -  3: CRC32
         *  4 - 19: MD4
         * 20 - 35: MD5
         * 36 - 55: SHA1
         * 56 - 71: ED2k */
        memset(&result, 0, 72);
        if (DO_CRC32) { CRC32_final(&crc32, &result[0]); }
        if (DO_MD4) { MD4_final(&md4, &result[4]); }
        if (DO_MD5) { MD5_final(&md5, &result[20]); }
        if (DO_SHA1) { SHA1_final(&sha1, &result[36]); }
        if (DO_ED2K) {
            /* If we just had one block. Store the result of the block directly
             * in the result buffer. */
            if (ed2kBlocks == 1) {
                MD4_final(&ed2k, &result[56]);
            } else {
                /* If we didn't finish a loop, finalize the final block. */
                if (ed2kLoopIdx > 0) {
                    MD4_final(&ed2k, &ed2kHashes[ed2kBlockIdx * 16]);
                }

                /* Calculate the MD4 hash of the hashes from the block. This is
                 * the final ED2k hash. */
                MD4_init(&ed2k);
                MD4_update(&ed2k, ed2kHashes, ed2kHashLength);
                MD4_final(&ed2k, &result[56]);

                /* Free the ED2k hash result buffer. */
                free(ed2kHashes);
                ed2kHashes = NULL;
            }
        }

        /* Print the hashes for the user. */
        printf("\n");
        if (DO_CRC32) { print_hash("CRC32", &result[0], 4); }
        if (DO_MD4) { print_hash("  MD4", &result[4], 16); }
        if (DO_MD5) { print_hash("  MD5", &result[20], 16); }
        if (DO_SHA1) { print_hash(" SHA1", &result[36], 20); }
        if (DO_ED2K) { print_hash(" ED2K", &result[56], 16); }

        printf("\n");
    }
}
