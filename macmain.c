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

/**
 * Computes the CRC32 on the contents of the provided file.
 * @param filename The name of the file to process.
 */
void hash_file_crc32(char* filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "%s cannot be opened.\n", filename);
        return;
    }

    CRC32_Context crc;
    CRC32_init(&crc);

    int bytes;
    unsigned char data[1024];
    while ((bytes = fread(data, 1, 1024, file)) != 0) {
        CRC32_update(&crc, data, bytes);
    }
    CRC32_final(&crc);

    fclose(file);

    printf("  ");
    for (int i = 0; i < 4; ++i) {
        printf("%02x", crc.hash[i]);
    }
    printf(" %s\n", filename);
}

void hash_file_md4(char* filename) {
    int file = open(filename, O_RDONLY | O_SHLOCK);
    if (file == -1) {
        fprintf(stderr, "Unable to open file %s: %s\n", filename, strerror(errno));
    }

    MD4_Context md4;
    MD4_init(&md4);

    int bytesRead;
    unsigned char data[1024];
    while ((bytesRead = read(file, data, 1024)) != 0) {
        MD4_update(&md4, data, bytesRead);
    }

    unsigned char result[16];
    MD4_final(&md4, &result);

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
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        fprintf(stderr, "%s cannot be opened.\n", filename);
        return;
    }

    MD5_Context md5;
    MD5_init(&md5);

    int bytes;
    unsigned char data[1024];
    while ((bytes = fread(data, 1, 1024, file)) != 0) {
        MD5_update(&md5, data, bytes);
    }
    MD5_final(&md5);

    fclose(file);

    printf("  ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", md5.hash[i]);
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
        //hash_file_crc32(argv[i]);
        //hash_file_md5(argv[i]);
        hash_file_md4(argv[i]);
    }

    return 0;
}
