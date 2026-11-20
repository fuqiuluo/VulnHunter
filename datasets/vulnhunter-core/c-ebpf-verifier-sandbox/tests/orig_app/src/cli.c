#include "bpf_vm.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    bool strict_mode = false;
    const char *suite_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--strict") == 0) {
            strict_mode = true;
        } else if (!suite_path) {
            suite_path = argv[i];
        } else {
            fprintf(stderr, "Usage: %s [--strict] <suite.bin>\n", argv[0]);
            return 2;
        }
    }

    if (!suite_path) {
        fprintf(stderr, "Usage: %s [--strict] <suite.bin>\n", argv[0]);
        return 2;
    }

    BpfSuite suite;
    char err_buf[160];
    if (bpf_suite_load_file(suite_path, &suite, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "LOAD_ERROR: %s\n", err_buf);
        return 2;
    }

    bool any_rejected = false;
    bool any_runtime_err = false;

    for (uint32_t i = 0; i < suite.case_cnt; i++) {
        const BpfSuiteCase *c = &suite.cases[i];
        BpfProgram prog;
        memset(&prog, 0, sizeof(prog));
        prog.insns = c->insns;
        prog.insn_cnt = c->insn_cnt;
        prog.num_maps = c->num_maps;
        for (uint32_t m = 0; m < c->num_maps; m++) {
            prog.maps[m] = c->maps[m];
        }

        BpfVerifyReport vrep;
        BpfStatus vst = bpf_verify_program(&prog, &vrep);
        if (vst != BPF_OK) {
            printf("case=%u name=%s verify=REJECT err=%d pc=%u\n",
                   i, c->name, (int)vst, vrep.err_pc);
            any_rejected = true;
            continue;
        }

        BpfArenaSpec spec;
        spec.pkt_init = c->pkt_init;
        spec.pkt_init_len = c->pkt_init_len;
        spec.map_seeds = c->seeds;
        spec.num_map_seeds = c->num_seeds;

        BpfExecResult eres;
        BpfStatus rst = bpf_interp_run(&prog, &spec, &eres);
        if (rst != BPF_OK) {
            printf("case=%u name=%s verify=OK exec=ERR err=%d\n",
                   i, c->name, (int)rst);
            any_runtime_err = true;
            continue;
        }

        printf("case=%u name=%s verify=OK r0=%" PRIu64 " pkt_len=%u pkt_fnv=%016" PRIx64
               " map_fnv=%016" PRIx64 "\n",
               i, c->name, eres.r0, eres.final_pkt_len, eres.pkt_fnv1a, eres.map_fnv1a);
    }

    bpf_suite_free(&suite);
    if (any_runtime_err || (strict_mode && any_rejected)) {
        return 1;
    }
    return 0;
}
