#include "core/crc32.h"
#include "core/md5.h"
#include "core/md4.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

/**
 * Computes the CRC32 on the contents of the provided file.
 * @param filename The name of the file to process.
 */
void hash_file_crc32(char* filename) {
    int file = open(filename, O_RDONLY | O_SHLOCK);
    if (file == -1) {
        fprintf(stderr, "Unable to open file %s: %s\n", filename, strerror(errno));
        return;
    }

    CRC32_Context crc32;
    CRC32_init(&crc32);

    int bytesRead;
    unsigned char data[1024];
    while ((bytesRead = read(file, data, 1024)) != 0) {
        CRC32_update(&crc32, data, bytesRead);
    }

    unsigned char result[16];
    CRC32_final(&crc32, result);

    close(file);

    printf("  ");
    for (int i = 0; i < 4; ++i) {
        printf("%02x", result[i]);
    }
    printf(" %s\n", filename);
}

void hash_file_ed2k(char* filename) {
    int file = open(filename, O_RDONLY | O_SHLOCK);
    if (file == -1) {
        fprintf(stderr, "Unable to open file %s: %s\n", filename, strerror(errno));
        return;
    }

    #define BLOCKSIZE 9728000 //9520 * 1024

    struct stat stat;
    memset(&stat, 0, sizeof(struct stat));

    if (fstat(file, &stat) != 0) {
        fprintf(stderr, "Unable to fstat file: %s\n", strerror(errno));
        return;
    }

    printf("File: %s\n  Size: %llu\n", filename, stat.st_size);
    uint32_t blocks = stat.st_size / BLOCKSIZE;
    if (stat.st_size % BLOCKSIZE > 0) {
        blocks++;
    }

    printf("  Blocks: %d\n", blocks);

    uint32_t hashlength = blocks * 16;
    unsigned char* hashes = (unsigned char*)malloc(hashlength);
    if (hashes == NULL && errno == ENOMEM) {
        fprintf(stderr, "Unable to allocate enough space for hashing.\n");
        close(file);
        return;
    }

    unsigned char* data = (unsigned char *)malloc(BLOCKSIZE);
    MD4_Context md4;

    int bytesRead = 0;
    uint32_t loop = 0;
    uint32_t offset = 0;
    while ((bytesRead = read(file, data, BLOCKSIZE)) != 0) {
        MD4_init(&md4);
        MD4_update(&md4, data, bytesRead);

        offset = loop * 16;
        MD4_final(&md4, &hashes[offset]);
        ++loop;
    }

    free(data);

    for (int i = 0; i < hashlength; i++) {
        if (i % 16 == 0) {
            printf("\n Block %03d: ", i / 16);
        }

        printf("%02x", hashes[i]);
    }

    unsigned char finalhash[16];
    MD4_init(&md4);
    MD4_update(&md4, hashes, hashlength);
    MD4_final(&md4, finalhash);

    printf("\n  ed2k: ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", finalhash[i]);
    }
    printf("  %s\n", filename);


    free(hashes);
    close(file);
}

/** Computes the MD4 on the contents of the provided file.
 * @param filename The name of the file to process.
 */
void hash_file_md4(char* filename) {
    int file = open(filename, O_RDONLY | O_SHLOCK);
    if (file == -1) {
        fprintf(stderr, "Unable to open file %s: %s\n", filename, strerror(errno));
        return;
    }

    MD4_Context md4;
    MD4_init(&md4);

    int bytesRead;
    unsigned char data[1024];
    while ((bytesRead = read(file, data, 1024)) != 0) {
        MD4_update(&md4, data, bytesRead);
    }

    unsigned char result[16];
    MD4_final(&md4, result);

    close(file);

    printf("  ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", result[i]);
    }
    printf(" %s\n", filename);
}

/**
 * Computes the MD5 on the contents of the provided file.
 * @param filename The name of the file to process.
 */
void hash_file_md5(char* filename) {
    int file = open(filename, O_RDONLY | O_SHLOCK);
    if (file == -1) {
        fprintf(stderr, "Unable to open file %s: %s\n", filename, strerror(errno));
        return;
    }

    MD5_Context md4;
    MD5_init(&md4);

    int bytesRead;
    unsigned char data[1024];
    while ((bytesRead = read(file, data, 1024)) != 0) {
        MD5_update(&md4, data, bytesRead);
    }

    unsigned char result[16];
    MD5_final(&md4, result);

    close(file);

    printf("  ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", result[i]);
    }
    printf(" %s\n", filename);
}

/**
 * Main entry point for the mac test program.
 * @param  argc The number of arguments the program was called with.
 * @param  argv The arguments the program was called with.
 * @return      Returns a negative value on failure or zero on success.
 */
int main(int argc, char** argv) {
    printf("jmmhasher, mactest. Version: 0.1.0\n");
    if (argc < 2) {
        fprintf(stderr, "NO INPUT FILE\n");
        return -1;
    }

    for (int i = 1; i < argc; ++i) {
        hash_file_crc32(argv[i]);
        //hash_file_md5(argv[i]);
        //hash_file_md4(argv[i]);
        //hash_file_ed2k(argv[i]);
    }

    return 0;
}
