#include <errno.h>  /* errno */
#include <fcntl.h>  /* open, read, ... */
#include <stdint.h> /* strcmp */
#include <stdio.h>  /* printf */
#include <stdlib.h> /* malloc */
#include <string.h>

#include <sys/stat.h>  /* stat */
#include <sys/types.h> /*                  */
#include <sys/uio.h>   /* needed for read? */
#include <unistd.h>    /*                  */

#include "core/crc32.h"
#include "core/md4.h"
#include "core/md5.h"
#include "core/sha1.h"


#define OPTION_NONE  0x00
#define OPTION_CRC32 0x01
#define OPTION_ED2K  0x02
#define OPTION_MD4   0x04
#define OPTION_MD5   0x08
#define OPTION_SHA1  0x10
#define OPTION_BREAK 0x80
#define OPTION_ALL \
    OPTION_CRC32 | OPTION_ED2K | OPTION_MD4 | \
    OPTION_MD5 | OPTION_SHA1

#define DO_CRC32 (options & OPTION_CRC32) == OPTION_CRC32
#define DO_ED2K  (options & OPTION_ED2K) == OPTION_ED2K
#define DO_MD4   (options & OPTION_MD4) == OPTION_MD4
#define DO_MD5   (options & OPTION_MD5) == OPTION_MD5
#define DO_SHA1  (options & OPTION_SHA1) == OPTION_SHA1

#define BLOCKSIZE 9728000
#define BUFFERSIZE BLOCKSIZE / 10

static void print_hash(char* title, unsigned char* result, uint32_t length);
static void print_usage();
static void process_files(uint8_t options, char** files, uint32_t fileCount);

int main(int argc, char** argv) {
    uint8_t options = 0;

    printf("jmmhasher 0.2.0\n");
    if (argc < 2) {
        fprintf(stderr, "  ERROR: Missing required arguments.\n");
        print_usage();
        return -1;
    }

    char **files = (char**)malloc(sizeof(char*) * argc);
    if (!files) {
        fprintf(stderr, "Error allocating file array.\n");
        return -1;
    }

    /* Parse the available options */
    uint32_t fileCount = 0;
    uint32_t idx;
    for (idx = 1; idx < argc; ++idx) {
        if (strncmp("-h", argv[idx], 2) == 0 || strncmp("--help", argv[idx], 6) == 0) {
            print_usage();
            return 0;
        }

        if (strncmp("-4", argv[idx], 2) == 0 || strncmp("--md4", argv[idx], 5) == 0) {
            options |= OPTION_MD4;
            continue;
        }

        if (strncmp("-5", argv[idx], 2) == 0 || strncmp("--md5", argv[idx], 5) == 0) {
            options |= OPTION_MD5;
            continue;
        }

        if (strncmp("-c", argv[idx], 2) == 0 || strncmp("--crc32", argv[idx], 7) == 0) {
            options |= OPTION_CRC32;
            continue;
        }

        if (strncmp("-e", argv[idx], 2) == 0 || strncmp("--ed2k", argv[idx], 6) == 0) {
            options |= OPTION_ED2K;
            continue;
        }

        if (strncmp("-s", argv[idx], 2) == 0 || strncmp("--sha1", argv[idx], 6) == 0) {
            options |= OPTION_SHA1;
            continue;
        }

        if (strncmp("--", argv[idx], 2) == 0) {
            options |= OPTION_BREAK;
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
    printf("Options: ");
    if (DO_CRC32) {
        printf("CRC32 ");
    }

    if (DO_MD4) {
        printf("MD4 ");
    }

    if (DO_MD5) {
        printf("MD5 ");
    }

    if (DO_ED2K) {
        printf("ED2K ");
    }

    if (DO_SHA1) {
        printf("SHA1 ");
    }
    printf("\n");

    /* Copy over any remaining files that might have been skipped due to the
     * "--" option. */
    while (idx < argc) {
        if (strcmp("--", argv[idx]) != 0) {
            files[fileCount] = argv[idx];
            ++fileCount;
        }

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

static void process_files(uint8_t options, char** files, uint32_t fileCount) {
    char *filename;
    for (uint32_t idx = 0; idx < fileCount; ++idx) {
        filename = files[idx];
        if (filename == NULL) {
            continue;
        }

        printf("  %s: ", filename);
        int file = open(filename, O_RDONLY | O_SHLOCK);
        if (file == -1) {
            printf("unable to open file. (%s)\n", strerror(errno));
            continue;
        }

        struct stat filestats;
        memset(&filestats, 0, sizeof(struct stat));

        if (fstat(file, &filestats) != 0) {
            printf("unable to read file. %s\n", strerror(errno));
            continue;
        }

        if (S_ISDIR(filestats.st_mode)) {
            printf("cannot process directories yet.\n");
            continue;
        }

        CRC32_Context crc32;
        MD4_Context ed2k;
        MD4_Context md4;
        MD5_Context md5;
        SHA1_Context sha1;

        if (DO_CRC32) { CRC32_init(&crc32); }
        if (DO_MD4) { MD4_init(&md4); }
        if (DO_MD5) { MD5_init(&md5); }
        if (DO_SHA1) { SHA1_init(&sha1); }

        uint32_t bytesRead = 0;
        unsigned char* data = (unsigned char*)malloc(BUFFERSIZE);
        if (!data) {
            printf("unable to allocate buffer.\n");
            continue;
        }

        while ((bytesRead = read(file, data, BUFFERSIZE)) != 0) {
            if (DO_CRC32) { CRC32_update(&crc32, data, bytesRead); }
            if (DO_MD4) { MD4_update(&md4, data, bytesRead); }
            if (DO_MD5) { MD5_update(&md5, data, bytesRead); }
            if (DO_SHA1) { SHA1_update(&sha1, data, bytesRead); }
        }

        free(data);
        /* result stores all of the hashes
         *  0 -  3: CRC32
         *  4 - 19: MD4
         * 20 - 35: MD5
         * 36 - 55: SHA1
         * 56 - 71: ED2k */
        unsigned char result[72];
        if (DO_CRC32) { CRC32_final(&crc32, &result[0]); }
        if (DO_MD4) { MD4_final(&md4, &result[4]); }
        if (DO_MD5) { MD5_final(&md5, &result[20]); }
        if (DO_SHA1) { SHA1_final(&sha1, &result[36]); }

        printf("\n");
        if (DO_CRC32) { print_hash("CRC32", &result[0], 4); }
        if (DO_MD4) { print_hash("  MD4", &result[4], 16); }
        if (DO_MD5) { print_hash("  MD5", &result[20], 16); }
        if (DO_SHA1) { print_hash(" SHA1", &result[36], 20); }

        printf("\n");
    }
}

static void print_hash(char* title, unsigned char* result, uint32_t length) {
    printf("    %s: ", title);
    for (uint32_t idx = 0; idx < length; ++idx) {
        printf("%02x", result[idx]);
    }
    printf("\n");
}
