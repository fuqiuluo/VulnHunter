#include "sqe_vm.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *fw_path  = "firmware/sequencer.fw";
    const char *csb_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            fw_path = argv[++i];
        } else if (argv[i][0] != '-' && csb_path == NULL) {
            csb_path = argv[i];
        } else {
            fprintf(stderr, "Usage: %s [-f <firmware.fw>] <submission.bin>\n", argv[0]);
            return 1;
        }
    }

    if (csb_path == NULL) {
        fprintf(stderr, "Usage: %s [-f <firmware.fw>] <submission.bin>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(csb_path, "rb");
    if (fp == NULL) {
        perror("fopen submission");
        return 1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 1;
    }
    long fsize = ftell(fp);
    if (fsize <= 0 || fsize > 4 * 1024 * 1024) {
        fclose(fp);
        fprintf(stderr, "Invalid submission size\n");
        return 1;
    }
    rewind(fp);

    uint8_t *raw = (uint8_t *)malloc((size_t)fsize);
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

    sqe_vm_t vm;
    if (sqe_vm_init(&vm) != SQE_OK) {
        free(raw);
        return 1;
    }

    sqe_status_t st = sqe_vm_load_firmware_file(&vm, fw_path);
    if (st != SQE_OK) {
        fprintf(stderr, "Firmware load failed (status=%d)\n", (int)st);
        sqe_vm_destroy(&vm);
        free(raw);
        return 1;
    }

    sqe_exec_summary_t summary;
    st = sqe_vm_exec_csb(&vm, raw, nread, &summary);
    free(raw);

    if (st != SQE_OK) {
        fprintf(stderr, "Submission rejected (status=%d halt=0x%04x)\n",
                (int)st, (unsigned)vm.halt_code);
        sqe_vm_destroy(&vm);
        return 1;
    }

    printf("OK session=%" PRIu32 " draws=%" PRIu32 " ops=%" PRIu32 " pkts=%" PRIu32 " digest=%016" PRIx64 "\n",
           summary.session_id,
           summary.draw_count,
           summary.dispatch_count,
           summary.pkt_retired,
           summary.output_digest);

    sqe_vm_destroy(&vm);
    return 0;
}
