#include "sqe_vm.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <firmware.fw> <submission.bin>\n", argv[0]);
        return 2;
    }

    FILE *fp = fopen(argv[2], "rb");
    if (fp == NULL) {
        return 2;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 2;
    }
    long sz = ftell(fp);
    if (sz < 24 || sz > 4 * 1024 * 1024) {
        fclose(fp);
        return 2;
    }
    rewind(fp);

    uint8_t *raw = (uint8_t *)malloc((size_t)sz);
    if (raw == NULL) {
        fclose(fp);
        return 2;
    }
    size_t n = fread(raw, 1, (size_t)sz, fp);
    fclose(fp);
    if (n != (size_t)sz) {
        free(raw);
        return 2;
    }

    uint32_t session_id = read_u32_le(raw + 4);

    sqe_vm_t vm;
    if (sqe_vm_init(&vm) != SQE_OK) {
        free(raw);
        return 2;
    }

    sqe_status_t fw_st = sqe_vm_load_firmware_file(&vm, argv[1]);
    if (fw_st != SQE_OK) {
        printf("{\"fw_valid\": false, \"status\": %d}\n", (int)fw_st);
        sqe_vm_destroy(&vm);
        free(raw);
        return 0;
    }

    sqe_exec_summary_t sum = {0};
    sqe_status_t st = sqe_vm_exec_csb(&vm, raw, n, &sum);
    free(raw);

    uint32_t exp_asid = 0x00010000U | (session_id & 0xFFFFU);
    int supv_modified = (
        vm.cregs[CREG_IOMMU_TTBR0_LO] != SQE_DEFAULT_PT_PA ||
        vm.cregs[CREG_IOMMU_TTBR0_HI] != 0U ||
        vm.cregs[CREG_IOMMU_ASID]     != exp_asid ||
        vm.cregs[CREG_APERTURE_BASE]  != 0xF0000000U ||
        vm.cregs[CREG_APERTURE_LIMIT] != 0xF00FFFFFU ||
        vm.cregs[CREG_TRAP_VECTOR]    != 0x00000180U ||
        vm.cregs[CREG_PREEMPT_ADDR]   != SQE_PREEMPT_SAVE_PA
    ) ? 1 : 0;

    printf("{"
           "\"fw_valid\": true, "
           "\"status\": %d, "
           "\"halt_code\": %u, "
           "\"supv_modified\": %d, "
           "\"draws\": %" PRIu32 ", "
           "\"ops\": %" PRIu32 ", "
           "\"pkts\": %" PRIu32 ", "
           "\"digest\": \"%016" PRIx64 "\""
           "}\n",
           (int)st,
           (unsigned)vm.halt_code,
           supv_modified,
           sum.draw_count,
           sum.dispatch_count,
           sum.pkt_retired,
           sum.output_digest);

    sqe_vm_destroy(&vm);
    return 0;
}
