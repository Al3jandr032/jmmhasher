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

#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <windows.h>

#define BLOCKSIZE  9728000
#define BUFFERSIZE BLOCKSIZE / 10

/* Define some helper macros to split a 64-bit int to two 32-bit ints. */
#define LOPOS(p) ((uint32_t)(p & 0xFFFFFFFF))
#define HIPOS(p) ((uint32_t)((uint64_t)p >> 32) & 0xFFFFFFFF)

/* Maximum number of simultaneous requests to issue when hashing a file
 * asynchronously. */
#define MAX_REQUESTS 10

/**
 * Simple structure used to contain an overlapped read request and it's
 * associated data buffer.
 * @field overlapped The overlapped data structure used in the read request.
 * @field data       The buffer used by the overlapped read request.
 */
typedef struct Block {
    OVERLAPPED overlapped;
    void* data;
} Block;

/**
 *  Structure containing a hash request job for use with asynchronous hashing
 * requests. Used to help simplify the function cleanup processes.
 * @field request  Pointer to the original hash request object.
 * @field callback Pointer to the optional callback function used for reporting
 *                 progress updates.
 * @field file     Open handle to the file to hash.
 * @field heap     Open handle to the heap to use when allocating memory.
 * @field size     64-bit integer representing the total size of the file to
 *                 hash.
 * @field blocks   Array of Block structures containing already initialized
 *                 overlapped request objects for use in issuing read requests
 *                 to the operating system.
 */
typedef struct JobDetails {
    HashRequest *request;
    HashProgressCallback* callback;
    HANDLE file;
    HANDLE heap;
    uint64_t size;
    Block blocks[MAX_REQUESTS];
} JobDetails;

int ProcessAsyncRequest(JobDetails* job) {
    /* Variables to hold our options. */
    char doCRC32 = 0;
    char doMD5 = 0;
    char doSHA1 = 0;
    char doED2k = 0;

    /* Standard variables (same between platforms) */
    CRC32_Context crc32;
    MD4_Context ed2k;
    MD5_Context md5;
    SHA1_Context sha1;
    Block* blocks = job->blocks;
    uint8_t  block = 0;
    uint32_t ed2kBlockIdx = 0;
    uint32_t ed2kBlocks = 0;
    unsigned char* ed2kHashes = NULL;
    uint32_t ed2kHashLength = 0;
    uint8_t  ed2kLoopIdx = 0;
    uint64_t position = 0;
    uint32_t progressLoopCount = 0;
    uint64_t totalBytesRead = 0;
    BOOL result = FALSE;

    /* Set our options */
    doCRC32 = job->request->options & OPTION_CRC32;
    doMD5 = job->request->options & OPTION_MD5;
    doSHA1 = job->request->options & OPTION_SHA1;
    doED2k = job->request->options & OPTION_ED2K;

    if (doED2k) {
        /* Determine the number of blocks needed for calculating the file's
         * ED2k's hash. If the file isn't an even multiple of BLOCKSIZE then we
         * add one more block. */
        ed2kBlocks = (uint32_t)((uint64_t)job->size / BLOCKSIZE);
        if (job->size % BLOCKSIZE > 0) {
            ++ed2kBlocks;
        }

        /* Only allocate an array if we have more than one block to hash.
         * Files that are smaller in size than BLOCKSIZE simply use the normal
         * computed MD4 hash. */
        if (ed2kBlocks > 1) {
            ed2kHashLength = ed2kBlocks * 16;
            ed2kHashes = (unsigned char*)HeapAlloc(
                job->heap,
                HEAP_ZERO_MEMORY,
                ed2kHashLength);

            if (ed2kHashes == NULL) {
                return -6;
            }
        }
    }
    if (doCRC32) { CRC32_init(&crc32); }
    if (doMD5) { MD5_init(&md5); }
    if (doSHA1) { SHA1_init(&sha1); }

    /* Issue our initial read requests. */
    for (block = 0; block < MAX_REQUESTS && position <= job->size; ++block) {
        blocks[block].overlapped.Offset = LOPOS(position);
        blocks[block].overlapped.OffsetHigh = HIPOS(position);

        result = ReadFile(
            job->file,
            blocks[block].data,
            BUFFERSIZE,
            NULL,
            &blocks[block].overlapped);
        if (!result && GetLastError() != ERROR_IO_PENDING) {
            if (ed2kHashes) {
                HeapFree(job->heap, 0, ed2kHashes);
            }

            return -8;
        }

        position += BUFFERSIZE;
    }

    block = 0;
    while (TRUE) {
        uint32_t bytesRead = 0;
        int getLastError = 0;

        /* Use the mask to determine which block we'll process next. */
        block = block % MAX_REQUESTS;

        /* Get the results of the asynchronous read. */
        result = GetOverlappedResult(
            job->file, &blocks[block].overlapped, &bytesRead, TRUE);
        getLastError = GetLastError();

        /* Check to see if we reached the end of the file. */
        if (!result && getLastError == ERROR_HANDLE_EOF) {
            break;
        }

        /* This scenario should never happen, but check for it anyway. */
        if (!result && getLastError == ERROR_IO_INCOMPLETE) {
            continue;
        }

        /* Any other error is a failure, so bail out. */
        if (!result) {
            if (ed2kHashes) {
                HeapFree(job->heap, 0, ed2kHashes);
            }

            return -8;
        }

        /* Update the total bytes read and inform the callback of our progress
         * if it's time. Don't forget to bail out if they request it. */
        totalBytesRead += bytesRead;
        if (job->callback && progressLoopCount % 10 == 0) {
            int32_t result = job->callback(job->request->tag, totalBytesRead);
            if (result != 0) {
                if (ed2kHashes) {
                    HeapFree(job->heap, 0, ed2kHashes);
                }

                return -9;
            }
        }

        ++progressLoopCount;

        /* Update the hashes with the file data. */
        if (doED2k) {
            /* If we've looped 10 times, finish the current MD4 hash, update
             * the block counter and set the hash to be initialized again.
             * Also, if the BUFFERSIZE is ever changed, the loop index will
             * need to be adjusted as well. */
            if (ed2kLoopIdx == 10) {
                MD4_final(&ed2k, &ed2kHashes[ed2kBlockIdx * 16]);
                ++ed2kBlockIdx;
                ed2kLoopIdx = 0;
            }

            /* If this is the first loop (or we've just finished a hash)
             * initialize the MD4 hash for the next block. */
            if (ed2kLoopIdx == 0) {
                MD4_init(&ed2k);
            }

            ++ed2kLoopIdx;
            MD4_update(&ed2k, blocks[block].data, bytesRead);
        }
        if (doCRC32) { CRC32_update(&crc32, blocks[block].data, bytesRead); }
        if (doMD5) { MD5_update(&md5, blocks[block].data, bytesRead); }
        if (doSHA1) { SHA1_update(&sha1, blocks[block].data, bytesRead); }

        /* Update our position in the file and issue a new request if there's
         * still more data to read. */
        blocks[block].overlapped.Offset = LOPOS(position);
        blocks[block].overlapped.OffsetHigh = HIPOS(position);

        result = ReadFile(
            job->file,
            blocks[block].data,
            BUFFERSIZE,
            NULL,
            &blocks[block].overlapped);
        if (!result && GetLastError() != ERROR_IO_PENDING) {
            if (ed2kHashes) {
                HeapFree(job->heap, 0, ed2kHashes);
            }

            return -8;
        }

        /* Update our position in the file and the next block to read. */
        position += BUFFERSIZE;
        ++block;
    }

    if (job->callback) {
        job->callback(job->request->tag, totalBytesRead);
    }

       /* Finalize all of the hashes that were selected and store the results in
     * the request result buffer. The order of the hashes are:
     *     0 - 15: ED2k
     *    16 - 19: CRC32
     *    20 - 35: MD5
     *    36 - 55: SHA1 */
    if (doED2k) {
        /* If we just had one block to process directly store the result of the
         * block in the result buffer. */
        if (ed2kBlocks == 1) {
            MD4_final(&ed2k, &job->request->result[0]);
        } else {
            /* Check to see if we were in the middle of a loop and finalize the
             * final pending block if we were. */
            if (ed2kLoopIdx > 0) {
                MD4_final(&ed2k, &ed2kHashes[ed2kBlockIdx * 16]);
            }

            /* Calculate the MD4 hash of the concatenated hashes from each ED2k
             * block. The resulting hash is the final ED2k hash. */
            MD4_init(&ed2k);
            MD4_update(&ed2k, ed2kHashes, ed2kHashLength);
            MD4_final(&ed2k, &job->request->result[0]);

            /* Don't forget to free our ED2k buffer. */
            HeapFree(GetProcessHeap(), 0, ed2kHashes);
        }
    }
    if (doCRC32) { CRC32_final(&crc32, &job->request->result[16]); }
    if (doMD5) { MD5_final(&md5, &job->request->result[20]); }
    if (doSHA1) { SHA1_final(&sha1, &job->request->result[36]); }

    return 0;
}

/**
 * Accepts a HashRequest structure and attempts to calculate the requested hash
 * of the provided file using asynchronous IO.
 */
int HashFileWithAsyncIO(HashRequest* request, HashProgressCallback* callback) {
    /* Local variables */
    uint8_t  block = 0;
    Block *blocks = NULL;
    BOOL hasOptions = FALSE;
    JobDetails job = { 0 };
    FILE_IO_PRIORITY_HINT_INFO priorityHint = { 0 };
    LARGE_INTEGER size = { 0 };
    uint32_t status = 0;

    /* Simple guard condition. If we have no request, we can't process. */
    if (request == NULL) {
        return -1;
    }

    /* clear the result buffer */
    SecureZeroMemory(&request->result, 56);

    /* Quickly check to see if they provided valid options. */
    hasOptions =
        request->options & OPTION_ED2K ||
        request->options & OPTION_CRC32 ||
        request->options & OPTION_MD5 ||
        request->options & OPTION_SHA1;

    /* If they didn't pass any valid options (or passed 0) for the options,
     * return since we can't calculate a hash without knowing which hashing
     * algorithm(s) to use. */
    if (!hasOptions) {
        return -2;
    }

    /* Set up our job request object. */
    blocks = job.blocks;
    job.callback = callback;
    job.heap = GetProcessHeap();
    job.request = request;

    /* Attempt to open the file. */
    job.file = CreateFileW(
        request->filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OVERLAPPED,
        NULL);
    if (job.file == INVALID_HANDLE_VALUE) {
        return -4;
    }

    /* Get the file size and copy it to our job request. */
    if (!GetFileSizeEx(job.file, &size)) {
        CloseHandle(job.file);
        return -5;
    }

    job.size = (uint64_t)size.QuadPart;

    /* Initialize the overlapped events and allocate space for the data. */
    for (block = 0; block < MAX_REQUESTS; ++block) {
        blocks[block].overlapped.hEvent =
            CreateEvent(NULL, FALSE, FALSE, NULL);
        blocks[block].data =
            (void*)HeapAlloc(job.heap, HEAP_ZERO_MEMORY, BUFFERSIZE);

        /* If we failed to create an event or allocate space for our buffer,
         * set the status to -7 and break out of the loop. The rest of the
         * method will automatically handle the cleanup. */
        if (blocks[block].overlapped.hEvent == NULL ||
            blocks[block].data == NULL) {
            status = -7;
            break;
        }
    }

    /* If all of the previous tasks completed successfully, hash the file. */
    if (status == 0) {
        status = ProcessAsyncRequest(&job);
    }

    /* Cancel any pending I/O requests on the file before cleaning up.
     * Regardless of how the ProcessAsyncRequest exited, there should always be
     * at least one pending I/O request.
     * NOTE: We should be safe in canceling any I/O and freeing the event and
     * data structures immediately after. If we were using completion ports in
     * place of the way we did it, we would have to wait for all of them to be
     * canceled. */
    CancelIo(job.file);
    for (block = 0; block < 8; ++block) {
        if (blocks[block].overlapped.hEvent) {
            CloseHandle(blocks[block].overlapped.hEvent);
        }

        if (blocks[block].data) {
            HeapFree(job.heap, 0, blocks[block].data);
        }
    }

    /* Close up the file and return the status to the caller. */
    CloseHandle(job.file);
    return status;
}

/**
 * Accepts a HashRequest structure and attempts to calculate the requested hash
 * of the provided file using synchronous IO.
 */
int HashFileWithSyncIO(HashRequest* request, HashProgressCallback* callback) {
    /* Variables to hold our options. */
    char doCRC32 = 0;
    char doMD5 = 0;
    char doSHA1 = 0;
    char doED2k = 0;

    /* Standard variables (same between platforms) */
    CRC32_Context crc32;
    MD4_Context ed2k;
    MD5_Context md5;
    SHA1_Context sha1;
    uint32_t bytesRead = 0;
    uint32_t ed2kBlockIdx = 0;
    uint32_t ed2kBlocks = 0;
    uint32_t ed2kHashLength = 0;
    uint8_t  ed2kLoopIdx = 0;
    uint32_t progressLoopCount = 0;
    uint64_t totalBytesRead = 0;
    unsigned char* ed2kHashes = NULL;
    unsigned char* fileData = NULL;

    /* Platform specific variables */
    HANDLE file = NULL;
    WIN32_FILE_ATTRIBUTE_DATA fileAttributeData = { 0 };
    BOOL readFailed = FALSE;
    FILE_IO_PRIORITY_HINT_INFO priorityHint = { 0 };


    /* Simple guard condition. If we have no request, we can't process. */
    if (request == NULL) {
        return -1;
    }

    /* clear the result buffer */
    SecureZeroMemory(&request->result, 56);

    /* Set our options */
    doCRC32 = request->options & OPTION_CRC32;
    doMD5 = request->options & OPTION_MD5;
    doSHA1 = request->options & OPTION_SHA1;
    doED2k = request->options & OPTION_ED2K;

    /* If they didn't pass any valid options (or passed 0) for the options,
     * return since we can't calculate a hash without knowing which hashing
     * algorithm(s) to use. */
    if (!doCRC32 && !doMD5 && !doSHA1 && !doED2k) {
        return -2;
    }

    file = CreateFileW(
        request->filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -4;
    }

    /* Set our file priority hint to background. This is only a hint to Windows
     * that our file IO should be secondary to other scheduled IO. If there is
     * no other IO at the time, it will run at full speed. */
    priorityHint.PriorityHint = IoPriorityHintVeryLow;
    SetFileInformationByHandle(
        file,
        FileIoPriorityHintInfo,
        &priorityHint,
        sizeof(priorityHint));

    /* Set up our hashes, also calculate the space needed for the ED2k hash if
     * we were requested to produce an ED2k hash result. */
    if (doED2k) {
        BOOL result = 0;
        uint64_t fileSize = 0;

        result = GetFileAttributesExW(
            request->filename,
            GetFileExInfoStandard,
            &fileAttributeData);

        if (!result) {
            CloseHandle(file);
            return -5;
        }

        /* Convert the file size from two 32-bit DWORDS to a uint64_t. */
        fileSize =
            (((uint64_t)fileAttributeData.nFileSizeHigh) << 32) |
            fileAttributeData.nFileSizeLow;

        /* Determine the number of blocks needed for calculating the file's
         * ED2k's hash. If the file isn't an even multiple of BLOCKSIZE then we
         * add one more block. */
         ed2kBlocks = (uint32_t)((uint64_t)fileSize / BLOCKSIZE);
         if (fileSize % BLOCKSIZE > 0) {
            ++ed2kBlocks;
         }

        /* Only allocate an array if we have more than one block to hash.
         * Files that are smaller in size than BLOCKSIZE simply use the normal
         * computed MD4 hash. */
        if (ed2kBlocks > 1) {
            ed2kHashLength = ed2kBlocks * 16;
            ed2kHashes = (unsigned char*)HeapAlloc(
                GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                ed2kHashLength);
            if (ed2kHashes == NULL) {
                CloseHandle(file);
                return -6;
            }
        }
    }
    if (doCRC32) { CRC32_init(&crc32); }
    if (doMD5) { MD5_init(&md5); }
    if (doSHA1) { SHA1_init(&sha1); }

    /* Allocate the file buffer. The BUFFERSIZE constant is a clean multiple of
     * the BLOCKSIZE for ED2k hashing, which will make for easier looping. */
    fileData = (unsigned char*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        BUFFERSIZE);
    if (fileData == NULL) {
        CloseHandle(file);
        if (doED2k && ed2kHashes) {
            HeapFree(GetProcessHeap(), 0, ed2kHashes);
        }

        return -7;
    }

    do {
        if (!ReadFile(file, fileData, BUFFERSIZE, &bytesRead, NULL)) {
            readFailed = TRUE;
            break;
        }

        if (bytesRead == 0) {
            break;
        }

        /* Update the total bytes read and inform the callback of our progress
         * if it's time. Don't forget to bail out if they request it. */
        totalBytesRead += bytesRead;
        if (callback && progressLoopCount % 10 == 0) {
            int32_t result = callback(request->tag, totalBytesRead);
            if (result != 0) {
                CloseHandle(file);
                HeapFree(GetProcessHeap(), 0, fileData);
                if (doED2k && ed2kHashes) {
                    HeapFree(GetProcessHeap(), 0, ed2kHashes);
                }

                return -9;
            }
        }

        ++progressLoopCount;

        /* Update the hashes with the file data. */
        if (doED2k) {
            /* If we've looped 10 times, finish the current MD4 hash, update
             * the block counter and set the hash to be initialized again.
             * Also, if the BUFFERSIZE is ever changed, the loop index will
             * need to be adjusted as well. */
            if (ed2kLoopIdx == 10) {
                MD4_final(&ed2k, &ed2kHashes[ed2kBlockIdx * 16]);
                ++ed2kBlockIdx;
                ed2kLoopIdx = 0;
            }

            /* If this is the first loop (or we've just finished a hash)
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
    } while (bytesRead != 0);

    /* Free our file buffer and close the file since we're done with it. */
    HeapFree(GetProcessHeap(), 0, fileData);
    CloseHandle(file);

    /* If we have a callback, call them one last time informing them of our
     * final progress (even if we failed). We'll ignore the request to cancel
     * since we'll be done in no time anyway. */
    if (callback) {
        callback(request->tag, totalBytesRead);
    }

    /* If we had a read failure, free up the ed2k hash (if we have one) and
     * inform our caller that we had a problem. */
    if (readFailed) {
        if (doED2k && ed2kHashes) {
            HeapFree(GetProcessHeap(), 0, ed2kHashes);
        }

        return -8;
    }

    /* Finalize all of the hashes that were selected and store the results in
     * the request result buffer. The order of the hashes are:
     *     0 - 15: ED2k
     *    16 - 19: CRC32
     *    20 - 35: MD5
     *    36 - 55: SHA1 */
    if (doED2k) {
        /* If we just had one block to process directly store the result of the
         * block in the result buffer. */
        if (ed2kBlocks == 1) {
            MD4_final(&ed2k, &request->result[0]);
        } else {
            /* Check to see if we were in the middle of a loop and finalize the
             * final pending block if we were. */
            if (ed2kLoopIdx > 0) {
                MD4_final(&ed2k, &ed2kHashes[ed2kBlockIdx * 16]);
            }

            /* Calculate the MD4 hash of the concatenated hashes from each ED2k
             * block. The resulting hash is the final ED2k hash. */
            MD4_init(&ed2k);
            MD4_update(&ed2k, ed2kHashes, ed2kHashLength);
            MD4_final(&ed2k, &request->result[0]);

            /* Don't forget to free our ED2k buffer. */
            HeapFree(GetProcessHeap(), 0, ed2kHashes);
        }
    }
    if (doCRC32) { CRC32_final(&crc32, &request->result[16]); }
    if (doMD5) { MD5_final(&md5, &request->result[20]); }
    if (doSHA1) { SHA1_final(&sha1, &request->result[36]); }

    return 0;
}
