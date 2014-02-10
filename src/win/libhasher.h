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

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HASHERDLL)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif

#define OPTION_ED2K  0x01
#define OPTION_CRC32 0x02
#define OPTION_MD5   0x04
#define OPTION_SHA1  0x08

/**
 * Structure used to communicate and coordinate the hashing request, hashing
 * options, and the resulting hash(es) of the file.
 * @field tag      Optional metadata tag used to identify the request during a
 *                 callback. Useful if multiple files are being hashed
 *                 simultaneously and the UI needs to provide feedback. This
 *                 value is not used by the any of the hashing algorithms.
 * @field options  Bitfield representing the options to pass to the hasher. The
 *                 available options for hashing are:
 *                   0x01: Calculate the ED2k hash.
 *                   0x02: Calculate the CRC32.
 *                   0x04: Calculate the MD5 hash.
 *                   0x08: Calculate the SHA1 hash.
 *                 One or more of these options can be combined by performing a
 *                 bitwise OR operation on the values.
 * @field filename The full path and name to the file that should be hashed. For
 *                 compatibility with python, this field is defined as a
 *                 wchar_t.
 * @field result   If the function completed successfully, this field will
 *                 contain the results of each individual hash result that was
 *                 requested using the options field. Any hash not requested or
 *                 if the function exited with a failure will have zeros for the
 *                 computed hash. This field is always 56 bytes long. The layout
 *                 of the results are:
 *                    0 - 15: The result of the ED2k hash.
 *                   16 - 19: The CRC32 digest result.
 *                   20 - 35: The result of the MD5 hash.
 *                   36 - 55: The result of the SHA1 hash.
 */
typedef struct HashRequest {
    int32_t tag;
    int32_t options;
    wchar_t* filename;
    unsigned char result[56];
} HashRequest;

/**
 * Callback method used to report hashing progress on a given request.
 * @param  tag      The optional tag value provided in the original HashRequest.
 * @param  progress The progress of the total bytes processed by the hashing
 *                  algorithm(s).
 * @return          Return 0 if hashing should continue. Return any other value
 *                  to indicate that hashing should be aborted. The return value
 *                  of the final callback (when the progress parameter is equal
 *                  to the total size of the file) is ignored and the results
 *                  will still be finalized and returned successfully.
 */
typedef int32_t HashProgressCallback(int32_t tag, uint64_t progress);

/**
 * Accepts a HashRequest structure and attempts to calculate the requested hash
 * of the provided file using asynchronous IO.
 * @param  request  The HashRequest containing the options and the file that
 *                  should be hashed. See the description of the structure for
 *                  more information on how to set it up.
 * @param  callback An optional callback parameter that will receive the total
 *                  number of bytes processed by the hashing algorithm and
 *                  provides the caller a chance to cancel the hash if desired.
 * @return          Returns 0 on success and a negative number on failure. All
 *                  of the defined return values are:
 *                     0: No error. The function completed successfully.
 *                    -1: No request was provided. (request was NULL).
 *                    -2: No valid options were provided. (request.options was
 *                        either 0 or didn't have any recognizable options set.)
 *                    -3: Failure to convert the filename from a wide char array
 *                        to a multi-byte char array.
 *                    -4: Unable to open the requested file.
 *                    -5: Unable to get the size of the file to determine the
 *                        number of ED2k blocks necessary.
 *                    -6: Unable to allocate enough memory to hold the
 *                        intermediate hash results for ED2k.
 *                    -7: Unable to allocate a buffer to hold the file data as
 *                        it's being processed.
 *                    -8: An unexpected error occurred while reading the file.
 *                    -9: A cancellation request was returned by the callback
 *                        function provided in the callback parameter. (A non-
 *                        zero value was returned from the callback)
 * @remarks
 * There are two versions of this method, both with the same parameters and return
 * results. However, the HashFileWithAsyncIO version uses asynchronous IO requests
 * to read the file to hash. This may help on systems where the file I/O takes
 * longer to complete than it does to compute the hash per disk read. Both
 * versions use the low priority mechanism to play nice with potential users on
 * the system.
 */
EXPORT int HashFileWithAsyncIO(
    HashRequest* request, HashProgressCallback* callback);

/**
 * Accepts a HashRequest structure and attempts to calculate the requested hash
 * of the provided file using synchronous IO. See the HashFileWithAsyncIO
 * function for details of the parameters and return values.
 */
EXPORT int HashFileWithSyncIO(
    HashRequest* request, HashProgressCallback* callback);

#ifdef __cplusplus
}
#endif

#endif
