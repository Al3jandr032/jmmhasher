#include "core/crc32.h"
#include <stdio.h>

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

    CRC32 crc;
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
    }

    return 0;
}
