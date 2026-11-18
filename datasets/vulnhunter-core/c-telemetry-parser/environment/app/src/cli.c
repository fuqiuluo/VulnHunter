#include "pkt_parser.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bundle_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 1;
    }
    long fsize = ftell(fp);
    if (fsize < 0 || fsize > 4 * 1024 * 1024) {
        fclose(fp);
        fprintf(stderr, "Invalid input size\n");
        return 1;
    }
    rewind(fp);

    uint8_t *raw = (uint8_t *)malloc((size_t)fsize > 0 ? (size_t)fsize : 1U);
    if (raw == NULL) {
        fclose(fp);
        return 1;
    }

    size_t nread = fread(raw, 1, (size_t)fsize, fp);
    fclose(fp);
    if (nread != (size_t)fsize) {
        free(raw);
        return 1;
    }

    pkt_bundle_t bundle;
    pkt_status_t st = pkt_parse_bundle(raw, nread, &bundle);
    free(raw);

    if (st != PKT_OK) {
        fprintf(stderr, "Parse rejected (status=%d)\n", (int)st);
        return 1;
    }

    uint64_t digest = pkt_payload_fnv1a(&bundle);
    printf("OK session=%" PRIu32 " bytes=%zu fnv1a=%016" PRIx64 "\n",
           bundle.session_id, bundle.payload_len, digest);
    pkt_free_bundle(&bundle);
    return 0;
}
