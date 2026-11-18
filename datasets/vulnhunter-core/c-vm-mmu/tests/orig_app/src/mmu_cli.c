#include "vmm_trace.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TRACE_FILE_BYTES (2 * 1024 * 1024)

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <workload.bin>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen workload");
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 1;
    }

    long fsize = ftell(fp);
    if (fsize <= 0 || fsize > MAX_TRACE_FILE_BYTES) {
        fclose(fp);
        fprintf(stderr, "Invalid workload file size\n");
        return 1;
    }
    rewind(fp);

    uint8_t *raw = (uint8_t *)malloc((size_t)fsize);
    if (raw == NULL) {
        fclose(fp);
        return 1;
    }

    size_t nread = fread(raw, 1U, (size_t)fsize, fp);
    fclose(fp);
    if (nread != (size_t)fsize) {
        free(raw);
        return 1;
    }

    vmm_trace_summary_t summary;
    vmm_status_t st = vmm_exec_trace_bytes(raw, nread, &summary);
    free(raw);

    if (st != VMM_OK) {
        fprintf(stderr, "Workload rejected (status=%d)\n", (int)st);
        return 1;
    }

    printf("OK workers=%" PRIu32 " ops=%" PRIu64 " faults=%" PRIu64
           " splits=%" PRIu64 " zaps=%" PRIu64
           " guest_digest=%016" PRIx64 " img_digest=%016" PRIx64 "\n",
           summary.worker_count,
           summary.ops_retired,
           summary.faults,
           summary.cow_splits,
           summary.balloon_zaps,
           summary.guest_digest,
           summary.image_ro_digest);

    return 0;
}
