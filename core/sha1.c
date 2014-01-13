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

#include "sha1.h"
#include <string.h>

#define CIRCULAR_SHIFT(x, y) ((((x) << (y)) & 0xFFFFFFFF) | ((x) >> (32 - (y))))

void transform(SHA1_Context* sha1) {
    const uint32_t K[] = {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };

    int32_t t;
    uint32_t temp;
    uint32_t W[80];
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    uint32_t E;

    for (t = 0; t < 16; ++t) {
        W[t] = ((unsigned) sha1->Message_Block[t * 4]) << 24;
        W[t] |= ((unsigned) sha1->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((unsigned) sha1->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((unsigned) sha1->Message_Block[t * 4 + 3]);
    }

    for(t = 0; t < 20; ++t) {
        temp =  CIRCULAR_SHIFT(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; ++t) {
        temp = CIRCULAR_SHIFT(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; ++t) {
        temp = CIRCULAR_SHIFT(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; ++t) {
        temp = CIRCULAR_SHIFT(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        temp &= 0xFFFFFFFF;
        E = D;
        D = C;
        C = CIRCULAR_SHIFT(30,B);
        B = A;
        A = temp;
    }

    sha1->Message_Digest[0] = (sha1->Message_Digest[0] + A) & 0xFFFFFFFF;
    sha1->Message_Digest[1] = (sha1->Message_Digest[1] + B) & 0xFFFFFFFF;
    sha1->Message_Digest[2] = (sha1->Message_Digest[2] + C) & 0xFFFFFFFF;
    sha1->Message_Digest[3] = (sha1->Message_Digest[3] + D) & 0xFFFFFFFF;
    sha1->Message_Digest[4] = (sha1->Message_Digest[4] + E) & 0xFFFFFFFF;

    sha1->Message_Block_Index = 0;
}

void pad_message(SHA1_Context* sha1) {
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (sha1->Message_Block_Index > 55) {
        sha1->Message_Block[sha1->Message_Block_Index++] = 0x80;
        while(sha1->Message_Block_Index < 64) {
            sha1->Message_Block[sha1->Message_Block_Index++] = 0;
        }

        transform(sha1);

        while(sha1->Message_Block_Index < 56) {
            sha1->Message_Block[sha1->Message_Block_Index++] = 0;
        }
    } else {
        sha1->Message_Block[sha1->Message_Block_Index++] = 0x80;
        while(sha1->Message_Block_Index < 56) {
            sha1->Message_Block[sha1->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    sha1->Message_Block[56] = (sha1->Length_High >> 24) & 0xFF;
    sha1->Message_Block[57] = (sha1->Length_High >> 16) & 0xFF;
    sha1->Message_Block[58] = (sha1->Length_High >> 8) & 0xFF;
    sha1->Message_Block[59] = (sha1->Length_High) & 0xFF;
    sha1->Message_Block[60] = (sha1->Length_Low >> 24) & 0xFF;
    sha1->Message_Block[61] = (sha1->Length_Low >> 16) & 0xFF;
    sha1->Message_Block[62] = (sha1->Length_Low >> 8) & 0xFF;
    sha1->Message_Block[63] = (sha1->Length_Low) & 0xFF;

    transform(sha1);
}

void SHA1_final(SHA1_Context* sha1, unsigned char* result) {
    if (sha1->Corrupted) {
        return;
    }

    if (!sha1->Computed) {
        pad_message(sha1);
        sha1->Computed = 1;
    }

    memcpy(result, sha1->Message_Digest, 20);
}

void SHA1_init(SHA1_Context* sha1) {
    sha1->Length_Low = 0;
    sha1->Length_High = 0;
    sha1->Message_Block_Index = 0;

    sha1->Message_Digest[0] = 0x67452301;
    sha1->Message_Digest[1] = 0xEFCDAB89;
    sha1->Message_Digest[2] = 0x98BADCFE;
    sha1->Message_Digest[3] = 0x10325476;
    sha1->Message_Digest[4] = 0xC3D2E1F0;

    sha1->Computed = 0;
    sha1->Corrupted = 0;
}

void SHA1_update(SHA1_Context* sha1, const void* data, uint32_t length) {
    unsigned char* ptr;

    ptr = (unsigned char *)data;

    if (!length) {
        return;
    }

    if (sha1->Computed || sha1->Corrupted) {
        sha1->Corrupted = 1;
        return;
    }

    while (length-- && !sha1->Corrupted) {
        sha1->Message_Block[sha1->Message_Block_Index++] = *ptr;
        sha1->Length_Low += 8;
        if (sha1->Length_Low == 0) {
            sha1->Length_High++;
            if (sha1->Length_High == 0) {
                sha1->Corrupted = 1;
                return;
            }
        }

        if (sha1->Message_Block_Index == 64) {
            transform(sha1);
        }

        ptr++;
    }
}
