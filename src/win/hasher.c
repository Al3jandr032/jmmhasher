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

#include "core/crc32.h"
#include "core/md4.h"
#include "core/md5.h"
#include "core/sha1.h"

#define WIN32_LEAN_AND_MEAN
#define STRICT
#define _WIN32_WINNT 0x0601

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <sdkddkver.h>
#include <Windows.h>

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
static void print_hash(wchar_t* hash, unsigned char* result, uint32_t length);

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
 static void process_files(uint8_t options, wchar_t** files, uint32_t fileCount);

int wmain(int argc, wchar_t** argv) {
    uint8_t options = OPTION_NONE;
    int32_t fileCount = 0;
    int32_t idx = 0;
    int32_t idx2 = 0;
    wchar_t** files;

    wprintf(L"jmmhasher 0.2.0\n");
    if (argc < 2) {
        fwprintf(stderr, L"  ERROR: Missing required arguments.\n");
        print_usage();
        return -1;
    }

    files = (wchar_t**)malloc(sizeof(wchar_t*) * argc);
    if (!files) {
        fwprintf(stderr, L"  ERROR: Unable to allocate file array.\n");
        return -1;
    }

    for (idx = 1; idx < argc; ++idx) {
        if (wcscmp(L"-h", argv[idx]) == 0 || wcscmp(L"--help", argv[idx]) == 0) {
            print_usage();
            return 0;
        }

        if (wcscmp(L"-4", argv[idx]) == 0 || wcscmp(L"--md4", argv[idx]) == 0) {
            options |= OPTION_MD4;
            continue;
        }

        if (wcscmp(L"-5", argv[idx]) == 0 || wcscmp(L"--md5", argv[idx]) == 0) {
            options |= OPTION_MD5;
            continue;
        }

        if (wcscmp(L"-c", argv[idx]) == 0 || wcscmp(L"--crc32", argv[idx]) == 0) {
            options |= OPTION_CRC32;
            continue;
        }

        if (wcscmp(L"-e", argv[idx]) == 0 || wcscmp(L"--ed2k", argv[idx]) == 0) {
            options |= OPTION_ED2K;
            continue;
        }

        if (wcscmp(L"-s", argv[idx]) == 0 || wcscmp(L"--sha1", argv[idx]) == 0) {
            options |= OPTION_SHA1;
            continue;
        }

        if (wcscmp(L"--", argv[idx]) == 0) {
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
    wprintf(L"  Hashes: ");
    if (DO_CRC32) { wprintf(L"CRC32 "); }
    if (DO_ED2K) { wprintf(L"ED2K "); }
    if (DO_MD4) { wprintf(L"MD4 "); }
    if (DO_MD5) { wprintf(L"MD5 "); }
    if (DO_SHA1) { wprintf(L"SHA1 "); }
    wprintf(L"\n");

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

        for (idx2 = 0; idx2 < fileCount; ++idx2) {
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
            if (wcscmp(files[idx], files[idx2]) == 0) {
                files[idx2] = NULL;
            }
        }
    }

    process_files(options, files, fileCount);

    free(files);
    wprintf(L"\n");
    return 0;
}

/**
 * Simple helper method used to print the name of the hash and the results of
 * the hash in hex format.
 * @param hash   The name of the hash to print.
 * @param result The hash to print in hexadecimal format.
 * @param length The number of bytes in the hash.
 */
static void print_hash(wchar_t* hash, unsigned char* result, uint32_t length) {
    uint32_t idx;

    wprintf(L"    %s: ", hash);
    for (idx = 0; idx < length; ++idx) {
        wprintf(L"%02x", result[idx]);
    }

    wprintf(L"\n");
}

/**
 * Prints the available options and usage information for the program.
 */
static void print_usage() {
    wprintf(L"\nUSAGE:\n");
    wprintf(L" -a, --all    Calculate using all available hashes of the input file(s).\n");
    wprintf(L"\n");
    wprintf(L" -4, --md4    Calculate the MD4 hash of the input file(s).\n");
    wprintf(L" -5, --md5    Calculate the MD5 hash of the input file(s).\n");
    wprintf(L" -c, --crc32  Calculate the CRC32 hash of the input file(s).\n");
    wprintf(L" -e, --ed2k   Calculate the ED2k hash of the input file(s).\n");
    wprintf(L" -h, --help   Display this help screen.\n");
    wprintf(L" -s, --sha1   Calculate the SHA1 hash of the input files.\n");
    wprintf(L"\n");
    wprintf(L"It is recommended you specify the command options first followed by two\n");
    wprintf(L"dashes to signify the end of the options and the start of the file list.\n");
    wprintf(L"If no options are specified, the default action is to hash using all available\n");
    wprintf(L"hashing methods (--all).\n");
    wprintf(L"\n");
    wprintf(L"EXAMPLES:\n");
    wprintf(L"jmmhasher -c --ed2k -- file1.mkv file2.mkv\n");
    wprintf(L"    Calculate the CRC32 and ED2k hashes of file1.mkv and file2.mkv.\n");
    wprintf(L"jmmhasher file1.mkv\n");
    wprintf(L"    Calculate all hashes for file1.mkv\n");
    wprintf(L"\n");
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
static void process_files(uint8_t options, wchar_t** files, uint32_t fileCount) {
    CRC32_Context crc32 = { 0 };
    MD4_Context ed2k = { 0 };
    MD4_Context md4 = { 0 };
    MD5_Context md5 = { 0 };
    SHA1_Context sha1 = { 0 };
    DWORD bytesRead = 0;
    uint32_t ed2kHashLength = 0;
    uint32_t ed2kBlockIdx = 0;
    uint32_t ed2kBlocks = 0;
    uint8_t  ed2kLoopIdx = 0;
    uint32_t loopIdx = 0;
    unsigned char result[72] = { 0 };
    unsigned char* fileData = NULL;
    unsigned char* ed2kHashes = NULL;
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;


    for (loopIdx = 0; loopIdx < fileCount; ++loopIdx) {
        HANDLE file;
        BOOL readFailed = FALSE;
        errno = 0;

        if (files[loopIdx] == NULL) {
            continue;
        }

        wprintf(L"  %s: ", files[loopIdx]);
        file = CreateFileW(files[loopIdx], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            wprintf(L"unable to open file.\n");
            continue;
        }

        if (!GetFileAttributesExW(files[loopIdx], GetFileExInfoStandard, &fileInfo)) {
            wprintf(L"unable to get file info.\n");
            CloseHandle(file);
            continue;
        }

        if ((fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) {
            wprintf(L"cannot process directories yet.\n");
            CloseHandle(file);
            continue;
        }

        if (DO_CRC32) { CRC32_init(&crc32); }
        if (DO_MD4) { MD4_init(&md4); }
        if (DO_MD5) { MD5_init(&md5); }
        if (DO_SHA1) { SHA1_init(&sha1); }
        if (DO_ED2K) {
            uint64_t fileSize = (((uint64_t)fileInfo.nFileSizeHigh) << 32) | fileInfo.nFileSizeLow;
            ed2kBlocks = (uint32_t)(fileSize / BLOCKSIZE);
            if (fileSize % BLOCKSIZE > 0) {
                ++ed2kBlocks;
            }

            if (ed2kBlocks > 1) {
                ed2kHashLength = ed2kBlocks * 16;
                ed2kHashes = (unsigned char*)malloc(ed2kHashLength);
                if (ed2kHashes == NULL && errno == ENOMEM) {
                    wprintf(L"unable to allocate buffer.\n");
                    CloseHandle(file);
                    continue;
                }
            }
        }

        fileData = (unsigned char*)malloc(BUFFERSIZE);
        if (fileData == NULL && errno == ENOMEM) {
            wprintf(L"unable to allocate buffer.\n");
            CloseHandle(file);
            free(ed2kHashes);
            ed2kHashes = NULL;
            continue;
        }

        do {
            if (!ReadFile(file, fileData, BUFFERSIZE, &bytesRead, NULL)) {
                readFailed = TRUE;
                break;
            }

            if (bytesRead == 0) {
                break;
            }

            if (DO_CRC32) { CRC32_update(&crc32, fileData, bytesRead); }
            if (DO_MD4) { MD4_update(&md4, fileData, bytesRead); }
            if (DO_MD5) { MD5_update(&md5, fileData, bytesRead); }
            if (DO_SHA1) { SHA1_update(&sha1, fileData, bytesRead); }
            if (DO_ED2K) {
                if (ed2kLoopIdx == 10) {
                    MD4_final(&ed2k, &ed2kHashes[ed2kBlockIdx * 16]);
                    ++ed2kBlockIdx;
                    ed2kLoopIdx = 0;
                }

                if (ed2kLoopIdx == 0) {
                    MD4_init(&ed2k);
                }

                ++ed2kLoopIdx;
                MD4_update(&ed2k, fileData, bytesRead);
            }
        } while (bytesRead != 0);

        free(fileData);
        CloseHandle(file);

        if (readFailed) {
            free(ed2kHashes);
            continue;
        }

        SecureZeroMemory(&result, 72);
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
        wprintf(L"\n");
        if (DO_CRC32) { print_hash(L"CRC32", &result[0], 4); }
        if (DO_MD4) { print_hash(L"  MD4", &result[4], 16); }
        if (DO_MD5) { print_hash(L"  MD5", &result[20], 16); }
        if (DO_SHA1) { print_hash(L" SHA1", &result[36], 20); }
        if (DO_ED2K) { print_hash(L" ED2K", &result[56], 16); }

        wprintf(L"\n");

        wprintf(L" bytes: %d\n", bytesRead);
    }
}
