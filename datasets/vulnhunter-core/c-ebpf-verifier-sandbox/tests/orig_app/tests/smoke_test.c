#include "bpf_vm.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_valid_packet_parser_and_csum(void) {
    /*
     * Parses a 20-byte header:
     *   if pkt_len < 20 -> return 0
     *   proto = pkt[9] (ALU32 mask/check)
     *   if proto != 6 -> return 1
     *   csum = HELPER_CSUM_FOLD(pkt, 20)
     *   return (csum << 16) | dst_port
     */
    const BpfInsn insns[] = {
        BPF_ALU64_REG(ALU_MOV, BPF_REG_6, BPF_REG_1),              /* 0: r6 = ctx */
        BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, BPF_CTX_OFF_PKT_LEN), /* 1: r2 = ctx->pkt_len */
        BPF_JMP64_IMM(JMP_JGE, BPF_REG_2, 20, 2),                  /* 2: if r2 >= 20 goto +2 (pc=5) */
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),                      /* 3: r0 = 0 */
        BPF_EXIT_INSN(),                                           /* 4: exit */
        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, BPF_CTX_OFF_DATA), /* 5: r7 = ctx->data */
        BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_7, 9),               /* 6: r3 = pkt[9] */
        BPF_ALU32_IMM(ALU_AND, BPF_REG_3, 0xff),                   /* 7: r3 &= 0xff (ALU32) */
        BPF_JMP32_IMM(JMP_JEQ, BPF_REG_3, 6, 2),                   /* 8: if r3 == 6 goto +2 (pc=11) */
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 1),                      /* 9: r0 = 1 */
        BPF_EXIT_INSN(),                                           /* 10: exit */
        BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_7, 16),              /* 11: r8 = *(u16*)(pkt + 16) */
        BPF_ALU64_REG(ALU_MOV, BPF_REG_1, BPF_REG_7),              /* 12: r1 = pkt */
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_2, 20),                     /* 13: r2 = 20 */
        BPF_CALL_HELPER_INSN(HELPER_CSUM_FOLD),                    /* 14: r0 = csum_fold(pkt, 20) */
        BPF_ALU64_IMM(ALU_LSH, BPF_REG_0, 16),                     /* 15: r0 <<= 16 */
        BPF_ALU64_REG(ALU_OR, BPF_REG_0, BPF_REG_8),               /* 16: r0 |= r8 */
        BPF_EXIT_INSN(),                                           /* 17: exit */
    };

    BpfProgram prog;
    memset(&prog, 0, sizeof(prog));
    prog.insns = insns;
    prog.insn_cnt = (uint32_t)(sizeof(insns) / sizeof(insns[0]));

    BpfVerifyReport rep;
    assert(bpf_verify_program(&prog, &rep) == BPF_OK);

    uint8_t pkt[24];
    memset(pkt, 0x11, sizeof(pkt));
    pkt[9] = 6u;
    pkt[16] = 0x50u;
    pkt[17] = 0x00u; /* little-endian 0x0050 = 80 */

    BpfArenaSpec spec = { pkt, sizeof(pkt), NULL, 0 };
    BpfExecResult res;
    assert(bpf_interp_run(&prog, &spec, &res) == BPF_OK);

    uint16_t exp_csum = bpf_csum_fold16(pkt, 20);
    uint64_t exp_r0 = ((uint64_t)exp_csum << 16) | 0x0050ULL;
    assert(res.r0 == exp_r0);

    /* Short packet falls into drop branch cleanly */
    BpfArenaSpec short_spec = { pkt, 8, NULL, 0 };
    assert(bpf_interp_run(&prog, &short_spec, &res) == BPF_OK);
    assert(res.r0 == 0ULL);
}

static void test_map_lookup_variable_offset_and_spill(void) {
    /*
     * Looks up map 0 key=1, spills map_val ptr to [R10 - 16], reloads it,
     * indexes by bounded scalar (pkt[0] & 7) * 4 inside 64-byte map entry,
     * increments counter, and returns updated value.
     */
    const BpfInsn insns[] = {
        BPF_ALU64_REG(ALU_MOV, BPF_REG_6, BPF_REG_1),              /* 0: r6 = ctx */
        BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, BPF_CTX_OFF_PKT_LEN), /* 1 */
        BPF_JMP64_IMM(JMP_JGE, BPF_REG_2, 4, 2),                   /* 2 */
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),                      /* 3 */
        BPF_EXIT_INSN(),                                           /* 4 */
        BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 1),                      /* 5: *(u32*)(r10 - 4) = 1 */
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_1, 0),                      /* 6: r1 = map_id 0 */
        BPF_ALU64_REG(ALU_MOV, BPF_REG_2, BPF_REG_10),             /* 7: r2 = r10 */
        BPF_ALU64_IMM(ALU_ADD, BPF_REG_2, -4),                     /* 8: r2 = r10 - 4 */
        BPF_CALL_HELPER_INSN(HELPER_MAP_LOOKUP_ELEM),              /* 9: r0 = lookup(0, &key) */
        BPF_JMP64_IMM(JMP_JNE, BPF_REG_0, 0, 2),                   /* 10: if r0 != NULL goto +2 */
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),                      /* 11 */
        BPF_EXIT_INSN(),                                           /* 12 */
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),           /* 13: spill map_ptr to [r10-16] */
        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, BPF_CTX_OFF_DATA), /* 14: r7 = pkt */
        BPF_LDX_MEM(BPF_B, BPF_REG_3, BPF_REG_7, 0),               /* 15: r3 = pkt[0] */
        BPF_ALU64_IMM(ALU_AND, BPF_REG_3, 7),                      /* 16: r3 in [0, 7] */
        BPF_ALU64_IMM(ALU_LSH, BPF_REG_3, 2),                      /* 17: r3 in [0, 28] */
        BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -16),           /* 18: reload map_ptr */
        BPF_ALU64_REG(ALU_ADD, BPF_REG_4, BPF_REG_3),              /* 19: r4 = map_ptr + r3 */
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_4, 0),              /* 20: r0 = *(u64*)(r4 + 0) */
        BPF_ALU64_IMM(ALU_ADD, BPF_REG_0, 42),                     /* 21: r0 += 42 */
        BPF_STX_MEM(BPF_DW, BPF_REG_4, BPF_REG_0, 0),              /* 22: *(u64*)(r4 + 0) = r0 */
        BPF_EXIT_INSN(),                                           /* 23: exit */
    };

    BpfProgram prog;
    memset(&prog, 0, sizeof(prog));
    prog.insns = insns;
    prog.insn_cnt = (uint32_t)(sizeof(insns) / sizeof(insns[0]));
    prog.num_maps = 1;
    prog.maps[0] = (BpfMapDef){ 4, 64, 4 };

    BpfVerifyReport rep;
    assert(bpf_verify_program(&prog, &rep) == BPF_OK);

    uint8_t seed_val[64];
    memset(seed_val, 0, sizeof(seed_val));
    uint64_t init_v = 1000ULL;
    memcpy(seed_val + 12, &init_v, 8); /* index 3 * 4 = 12 */

    BpfMapSeed seed = { 0, 1, seed_val, sizeof(seed_val) };
    uint8_t pkt[4] = { 3u, 0u, 0u, 0u };
    BpfArenaSpec spec = { pkt, sizeof(pkt), &seed, 1 };
    BpfExecResult res;
    assert(bpf_interp_run(&prog, &spec, &res) == BPF_OK);
    assert(res.r0 == 1042ULL);
}

static void test_nested_subprogs_and_pkt_resize(void) {
    /*
     * Root calls sub1 (rel +6), which calls sub2 (rel +5), preserving R6 across calls,
     * then resizes packet to 32 bytes, reloads CTX->data, writes computed tag, and exits.
     */
    const BpfInsn insns[] = {
        /* main (pc 0..10) */
        BPF_ALU64_REG(ALU_MOV, BPF_REG_6, BPF_REG_1),              /* 0 */
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_1, 15),                     /* 1 */
        BPF_CALL_REL_INSN(8),                                      /* 2 -> target 11 */
        BPF_ALU64_REG(ALU_MOV, BPF_REG_7, BPF_REG_0),              /* 3 */
        BPF_ALU64_REG(ALU_MOV, BPF_REG_1, BPF_REG_6),              /* 4 */
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_2, 32),                     /* 5 */
        BPF_CALL_HELPER_INSN(HELPER_PKT_RESIZE),                   /* 6 */
        BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, BPF_CTX_OFF_DATA), /* 7 */
        BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_7, 24),             /* 8 */
        BPF_ALU64_REG(ALU_MOV, BPF_REG_0, BPF_REG_7),              /* 9 */
        BPF_EXIT_INSN(),                                           /* 10 */

        /* sub1 (pc 11..16) */
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -8),            /* 11 */
        BPF_ALU64_IMM(ALU_MUL, BPF_REG_1, 2),                      /* 12 */
        BPF_CALL_REL_INSN(3),                                      /* 13 -> target 17 */
        BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -8),            /* 14 */
        BPF_ALU64_REG(ALU_ADD, BPF_REG_0, BPF_REG_2),              /* 15 */
        BPF_EXIT_INSN(),                                           /* 16 */

        /* sub2 (pc 17..19) */
        BPF_ALU64_REG(ALU_MOV, BPF_REG_0, BPF_REG_1),              /* 17 */
        BPF_ALU64_IMM(ALU_ADD, BPF_REG_0, 7),                      /* 18 */
        BPF_EXIT_INSN(),                                           /* 19 */
    };

    BpfProgram prog;
    memset(&prog, 0, sizeof(prog));
    prog.insns = insns;
    prog.insn_cnt = (uint32_t)(sizeof(insns) / sizeof(insns[0]));

    BpfVerifyReport rep;
    assert(bpf_verify_program(&prog, &rep) == BPF_OK);

    uint8_t init_pkt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    BpfArenaSpec spec = { init_pkt, sizeof(init_pkt), NULL, 0 };
    BpfExecResult res;
    assert(bpf_interp_run(&prog, &spec, &res) == BPF_OK);
    /* sub2(30) = 37, sub1(15) = 37 + 15 = 52 */
    assert(res.r0 == 52ULL);
    assert(res.final_pkt_len == 32u);
}

static void test_basic_verifier_rejections(void) {
    /* 1. Uninitialized register read */
    const BpfInsn uninit_prog[] = {
        BPF_ALU64_REG(ALU_MOV, BPF_REG_0, BPF_REG_2),
        BPF_EXIT_INSN(),
    };
    BpfProgram p1 = { uninit_prog, 2, 0, {{0}} };
    assert(bpf_verify_program(&p1, NULL) == BPF_ERR_UNINIT_REG);

    /* 2. Write to read-only R10 */
    const BpfInsn ro_r10_prog[] = {
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_10, 0),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    BpfProgram p2 = { ro_r10_prog, 3, 0, {{0}} };
    assert(bpf_verify_program(&p2, NULL) == BPF_ERR_READ_ONLY_REG);

    /* 3. Back-edge loop rejection */
    const BpfInsn loop_prog[] = {
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),
        BPF_JMP_JA(-1),
        BPF_EXIT_INSN(),
    };
    BpfProgram p3 = { loop_prog, 3, 0, {{0}} };
    assert(bpf_verify_program(&p3, NULL) == BPF_ERR_CFG_CYCLE);
}

int main(void) {
    test_valid_packet_parser_and_csum();
    test_map_lookup_variable_offset_and_spill();
    test_nested_subprogs_and_pkt_resize();
    test_basic_verifier_rejections();
    printf("smoke_test: all baseline checks passed\n");
    return 0;
}
