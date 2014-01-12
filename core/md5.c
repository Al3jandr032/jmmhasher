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

#include "md5.h"
#include "string.h"

#define ROTLEFT(a,b) ((a << b) | (a >> (32 - b)))

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define FF(a, b, c, d, m, s, t) a += F(b, c, d) + m + t; a = b + ROTLEFT(a, s);
#define GG(a, b, c, d, m, s, t) a += G(b, c, d) + m + t; a = b + ROTLEFT(a, s);
#define HH(a, b, c, d, m, s, t) a += H(b, c, d) + m + t; a = b + ROTLEFT(a, s);
#define II(a, b, c, d, m, s, t) a += I(b, c, d) + m + t; a = b + ROTLEFT(a, s);

/**
 * Performs the actual transformation of data for MD5 hashing.
 * @param md5  The MD5 context to update.
 * @param data The data to process. Must be a length of 64.
 */
void transform(MD5_Context* md5, unsigned char data[]) {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t m[16];
    uint32_t i;
    uint32_t j;

    // Since we're processing data using little edian types, we need to reverse
    // the order of the incoming bytes for processing. On the final output, we
    // will re-reverse them to get the proper output.
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j]) +
               (data[j + 1] <<  8) +
               (data[j + 2] << 16) +
               (data[j + 3] << 24);
    }

    a = md5->state[0];
    b = md5->state[1];
    c = md5->state[2];
    d = md5->state[3];

    FF(a, b, c, d, m[0],   7, 0xd76aa478);
    FF(d, a, b, c, m[1],  12, 0xe8c7b756);
    FF(c, d, a, b, m[2],  17, 0x242070db);
    FF(b, c, d, a, m[3],  22, 0xc1bdceee);
    FF(a, b, c, d, m[4],   7, 0xf57c0faf);
    FF(d, a, b, c, m[5],  12, 0x4787c62a);
    FF(c, d, a, b, m[6],  17, 0xa8304613);
    FF(b, c, d, a, m[7],  22, 0xfd469501);
    FF(a, b, c, d, m[8],   7, 0x698098d8);
    FF(d, a, b, c, m[9],  12, 0x8b44f7af);
    FF(c, d, a, b, m[10], 17, 0xffff5bb1);
    FF(b, c, d, a, m[11], 22, 0x895cd7be);
    FF(a, b, c, d, m[12],  7, 0x6b901122);
    FF(d, a, b, c, m[13], 12, 0xfd987193);
    FF(c, d, a, b, m[14], 17, 0xa679438e);
    FF(b, c, d, a, m[15], 22, 0x49b40821);

    GG(a, b, c, d, m[1],   5, 0xf61e2562);
    GG(d, a, b, c, m[6],   9, 0xc040b340);
    GG(c, d, a, b, m[11], 14, 0x265e5a51);
    GG(b, c, d, a, m[0],  20, 0xe9b6c7aa);
    GG(a, b, c, d, m[5],   5, 0xd62f105d);
    GG(d, a, b, c, m[10],  9, 0x02441453);
    GG(c, d, a, b, m[15], 14, 0xd8a1e681);
    GG(b, c, d, a, m[4],  20, 0xe7d3fbc8);
    GG(a, b, c, d, m[9],   5, 0x21e1cde6);
    GG(d, a, b, c, m[14],  9, 0xc33707d6);
    GG(c, d, a, b, m[3],  14, 0xf4d50d87);
    GG(b, c, d, a, m[8],  20, 0x455a14ed);
    GG(a, b, c, d, m[13],  5, 0xa9e3e905);
    GG(d, a, b, c, m[2],   9, 0xfcefa3f8);
    GG(c, d, a, b, m[7],  14, 0x676f02d9);
    GG(b, c, d, a, m[12], 20, 0x8d2a4c8a);

    HH(a, b, c, d, m[5],   4, 0xfffa3942);
    HH(d, a, b, c, m[8],  11, 0x8771f681);
    HH(c, d, a, b, m[11], 16, 0x6d9d6122);
    HH(b, c, d, a, m[14], 23, 0xfde5380c);
    HH(a, b, c, d, m[1],   4, 0xa4beea44);
    HH(d, a, b, c, m[4],  11, 0x4bdecfa9);
    HH(c, d, a, b, m[7],  16, 0xf6bb4b60);
    HH(b, c, d, a, m[10], 23, 0xbebfbc70);
    HH(a, b, c, d, m[13],  4, 0x289b7ec6);
    HH(d, a, b, c, m[0],  11, 0xeaa127fa);
    HH(c, d, a, b, m[3],  16, 0xd4ef3085);
    HH(b, c, d, a, m[6],  23, 0x04881d05);
    HH(a, b, c, d, m[9],   4, 0xd9d4d039);
    HH(d, a, b, c, m[12], 11, 0xe6db99e5);
    HH(c, d, a, b, m[15], 16, 0x1fa27cf8);
    HH(b, c, d, a, m[2],  23, 0xc4ac5665);

    II(a, b, c, d, m[0],   6, 0xf4292244);
    II(d, a, b, c, m[7],  10, 0x432aff97);
    II(c, d, a, b, m[14], 15, 0xab9423a7);
    II(b, c, d, a, m[5],  21, 0xfc93a039);
    II(a, b, c, d, m[12],  6, 0x655b59c3);
    II(d, a, b, c, m[3],  10, 0x8f0ccc92);
    II(c, d, a, b, m[10], 15, 0xffeff47d);
    II(b, c, d, a, m[1],  21, 0x85845dd1);
    II(a, b, c, d, m[8],   6, 0x6fa87e4f);
    II(d, a, b, c, m[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, m[6],  15, 0xa3014314);
    II(b, c, d, a, m[13], 21, 0x4e0811a1);
    II(a, b, c, d, m[4],   6, 0xf7537e82);
    II(d, a, b, c, m[11], 10, 0xbd3af235);
    II(c, d, a, b, m[2],  15, 0x2ad7d2bb);
    II(b, c, d, a, m[9],  21, 0xeb86d391);

    md5->state[0] += a;
    md5->state[1] += b;
    md5->state[2] += c;
    md5->state[3] += d;
}

/**
 * Performs the final operation on the MD5_Context structure and copies the
 * resulting hash to the hash buffer. The result in the hash is converted for
 * use in Little Endian CPU architectures.
 * @param md5 The MD5_Context structure to finalize.
 */
void MD5_final(MD5_Context* md5) {
    uint16_t remain;

    // Pad whatever data is left in the buffer.
    if (md5->bufferLength < 56) {
        remain = 56 - md5->bufferLength;
        if (remain > 0) {
            memset(md5->buffer + md5->bufferLength, 0, remain);
        }

        md5->buffer[md5->bufferLength] = 0x80;
    } else if (md5->bufferLength >= 56) {
        remain = 64 - md5->bufferLength;
        if (remain > 0) {
            memset(md5->buffer + md5->bufferLength, 0, remain);
        }

        md5->buffer[md5->bufferLength] = 0x80;
        transform(md5, md5->buffer);
        memset(md5->buffer, 0, 56);
    }

    md5->bitsProcessed += (8 * md5->bufferLength);

    // Append the padding to the total message's length in bits and transform.
    md5->buffer[56] =  md5->bitsProcessed & 0xFF;
    md5->buffer[57] = (md5->bitsProcessed >>  8) & 0xFF;
    md5->buffer[58] = (md5->bitsProcessed >> 16) & 0xFF;
    md5->buffer[59] = (md5->bitsProcessed >> 24) & 0xFF;
    md5->buffer[60] = (md5->bitsProcessed >> 32) & 0xFF;
    md5->buffer[61] = (md5->bitsProcessed >> 40) & 0xFF;
    md5->buffer[62] = (md5->bitsProcessed >> 48) & 0xFF;
    md5->buffer[63] = (md5->bitsProcessed >> 56) & 0xFF;

    // Transform for the final time.
    transform(md5, md5->buffer);

    md5->hash[ 0] =  md5->state[0] & 0xFF;
    md5->hash[ 1] = (md5->state[0] >>  8) & 0xFF;
    md5->hash[ 2] = (md5->state[0] >> 16) & 0xFF;
    md5->hash[ 3] = (md5->state[0] >> 24) & 0xFF;
    md5->hash[ 4] =  md5->state[1] & 0xFF;
    md5->hash[ 5] = (md5->state[1] >>  8) & 0xFF;
    md5->hash[ 6] = (md5->state[1] >> 16) & 0xFF;
    md5->hash[ 7] = (md5->state[1] >> 24) & 0xFF;
    md5->hash[ 8] =  md5->state[2] & 0xFF;
    md5->hash[ 9] = (md5->state[2] >>  8) & 0xFF;
    md5->hash[10] = (md5->state[2] >> 16) & 0xFF;
    md5->hash[11] = (md5->state[2] >> 24) & 0xFF;
    md5->hash[12] =  md5->state[3] & 0xFF;
    md5->hash[13] = (md5->state[3] >>  8) & 0xFF;
    md5->hash[14] = (md5->state[3] >> 16) & 0xFF;
    md5->hash[15] = (md5->state[3] >> 24) & 0xFF;
}

/**
 * Initializes a new MD5_Context structure for use with MD5_update.
 * @param md5 The structure that will be initialized.
 */
void MD5_init(MD5_Context* md5) {
    md5->bufferLength = 0;
    md5->bitsProcessed = 0;

    md5->state[0] = 0x67452301;
    md5->state[1] = 0xEFCDAB89;
    md5->state[2] = 0x98BADCFE;
    md5->state[3] = 0x10325476;
}

/**
 * Updates the MD5 state with the data provided. The MD5_Context structure
 * should be initialized using the MD5_init function before calling this
 * function.
 * @param md5    The structure containing the intermediate MD5 information to
 *               update.
 * @param data   The data used to update the MD5 state.
 * @param length The length of the data to digest.
 * @remarks
 * For best performance of this method, attempt to always use a buffer size that
 * is divisible by 64. Doing this will ensure the most efficient copying of data
 * for processing.
 */
void MD5_update(MD5_Context* md5, unsigned char* data, uint32_t length) {
    uint16_t remaining;

    // Take care of the easy situation first.
    if (length == 0) {
        return;
    }

    // If they gave us data that's divisible by 64 this turned out to be
    // much easier.
    if (md5->bufferLength == 0 && length % 64 == 0) {
        md5->bufferLength = 64;

        while (length > 0) {
            memcpy(md5->buffer, data, 64);
            data += 64;
            length -= 64;

            transform(md5, md5->buffer);
            md5->bitsProcessed += 512;
        }

        md5->bufferLength = 0;
        return;
    }

    // If the number of bytes to be processed is less than or equal to the
    // remaining space in the buffer, copy it over.
    remaining = 64 - md5->bufferLength;
    if (length <= remaining) {
        memcpy(md5->buffer + md5->bufferLength, data, length);
        md5->bufferLength += length;

        // If the data managed to fill us up entirely, process the chunk.
        if (md5->bufferLength == 64) {
            transform(md5, md5->buffer);
            md5->bitsProcessed += 512;
            md5->bufferLength = 0;
        }

        return;
    }

    // At this point, the data they're giving us is larger than the remaining
    // space in the buffer, so we'll go ahead and copy part of it and process
    // it directly. Remember to reset datalen and update bitlen.
    memcpy(md5->buffer + md5->bufferLength, data, remaining);
    transform(md5, md5->buffer);
    data += remaining;
    length -= remaining;
    md5->bufferLength = 0;
    md5->bitsProcessed += 512;

    // Now, copy the available data over in 64-byte chunks until we have one
    // chunk remaining that's less than 64 bytes.
    while (length > 64) {
        memcpy(md5->buffer, data, 64);
        data += 64;
        length -= 64;

        transform(md5, md5->buffer);
        md5->bitsProcessed += 512;
    }

    // At this point, length should be less than or equal to 64. So copy it over
    // just like we've been doing. Also at this point, since we've been
    // processing 64-byte chunks, datalen is zero, so we copy back at the
    // beginning of the data array.
    memcpy(md5->buffer, data, length);
    md5->bufferLength = length;

    // If they managed to give us a perfect 64 byte chunk, process it.
    if (md5->bufferLength == 64) {
        transform(md5, md5->buffer);
        md5->bitsProcessed += 512;
        md5->bufferLength = 0;
    }
}
