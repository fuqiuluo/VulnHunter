#include "bpf_vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BpfStatus verify_fail(BpfVerifyReport *rep, BpfStatus st, uint32_t pc, const char *msg) {
    if (rep) {
        rep->status = st;
        rep->err_pc = pc;
        snprintf(rep->message, sizeof(rep->message), "%s", msg);
    }
    return st;
}

static BpfStatus verify_from(const BpfProgram *prog, BpfCfgState *cfg, uint32_t start_pc,
                             const BpfVerifierState *initial_st, BpfVerifyReport *rep) {
    if (cfg_is_subsumed(cfg, start_pc, initial_st)) {
        rep->states_pruned++;
        return BPF_OK;
    }

    BpfVerifierState *st = (BpfVerifierState *)malloc(sizeof(*st));
    if (!st) return verify_fail(rep, BPF_ERR_COMPLEXITY, start_pc, "verifier state oom");
    *st = *initial_st;

    uint32_t pc = start_pc;
    for (;;) {
        if (pc != start_pc && cfg->is_leader[pc]) {
            BpfStatus sub = verify_from(prog, cfg, pc, st, rep);
            free(st);
            if (sub == BPF_OK) cfg_record_visited(cfg, start_pc, initial_st);
            return sub;
        }
        if (rep->insns_explored++ >= BPF_MAX_VERIFY_STEPS) {
            free(st);
            return verify_fail(rep, BPF_ERR_COMPLEXITY, pc, "verifier step budget exceeded");
        }

        const BpfInsn *insn = &prog->insns[pc];
        uint8_t op = insn->opcode, cls = BPF_CLASS(op);
        BpfFrameState *cur_f = &st->frames[st->frame_depth];

        if (op == OP_LDDW_IMM) {
            uint64_t val = (uint32_t)insn->imm | ((uint64_t)(uint32_t)prog->insns[pc + 1u].imm << 32);
            reg_set_scalar_const(&cur_f->regs[insn->dst_reg], val);
            pc += 2u;
            continue;
        }
        if (cls == CLS_ALU64 || cls == CLS_ALU32) {
            BpfStatus ast = bpf_reg_is_pointer(cur_f->regs[insn->dst_reg].type)
                                ? bpf_verify_ptr_alu(insn, cur_f, pc, rep)
                                : bpf_eval_scalar_alu(insn, cur_f, pc, rep);
            if (ast != BPF_OK) { free(st); return ast; }
            pc++;
            continue;
        }
        if (cls == CLS_LDX) {
            BpfStatus lst = bpf_verify_ldx(prog, insn, st, pc, rep);
            if (lst != BPF_OK) { free(st); return lst; }
            pc++;
            continue;
        }
        if (cls == CLS_ST || cls == CLS_STX) {
            BpfStatus sst = bpf_verify_store(prog, insn, st, pc, rep);
            if (sst != BPF_OK) { free(st); return sst; }
            pc++;
            continue;
        }
        if (op == OP_CALL_HELPER) {
            BpfStatus hst = bpf_verify_helper_call(prog, insn->imm, st, pc, rep);
            if (hst != BPF_OK) { free(st); return hst; }
            pc++;
            continue;
        }
        if (op == OP_CALL_REL) {
            uint32_t callee_pc = 0;
            BpfStatus cst = bpf_verify_call_rel(insn, st, pc, &callee_pc, rep);
            if (cst != BPF_OK) { free(st); return cst; }
            BpfStatus sub = verify_from(prog, cfg, callee_pc, st, rep);
            free(st);
            if (sub == BPF_OK) cfg_record_visited(cfg, start_pc, initial_st);
            return sub;
        }
        if (op == OP_EXIT) {
            bool prog_done = false;
            uint32_t ret_pc = 0;
            BpfStatus est = bpf_verify_exit(st, pc, &prog_done, &ret_pc, rep);
            if (est != BPF_OK) { free(st); return est; }
            if (prog_done) {
                free(st);
                cfg_record_visited(cfg, start_pc, initial_st);
                return BPF_OK;
            }
            BpfStatus sub = verify_from(prog, cfg, ret_pc, st, rep);
            free(st);
            if (sub == BPF_OK) cfg_record_visited(cfg, start_pc, initial_st);
            return sub;
        }
        if (cls == CLS_JMP64 && BPF_OP(op) == JMP_JA) {
            uint32_t tgt = (uint32_t)((int64_t)pc + 1 + insn->off);
            BpfStatus sub = verify_from(prog, cfg, tgt, st, rep);
            free(st);
            if (sub == BPF_OK) cfg_record_visited(cfg, start_pc, initial_st);
            return sub;
        }
        if (cls == CLS_JMP64 || cls == CLS_JMP32) {
            BpfVerifierState *fall_st = (BpfVerifierState *)malloc(sizeof(*fall_st));
            BpfVerifierState *taken_st = (BpfVerifierState *)malloc(sizeof(*taken_st));
            if (!fall_st || !taken_st) {
                free(fall_st); free(taken_st); free(st);
                return verify_fail(rep, BPF_ERR_COMPLEXITY, pc, "branch state oom");
            }
            bool fall_ok = false, taken_ok = false;
            BpfStatus bst = bpf_refine_branch(insn, st, fall_st, &fall_ok, taken_st, &taken_ok, pc, rep);
            free(st);
            if (bst != BPF_OK) { free(fall_st); free(taken_st); return bst; }
            if (!fall_ok && !taken_ok) {
                free(fall_st); free(taken_st);
                return verify_fail(rep, BPF_ERR_INVALID_PROG, pc, "both branches unreachable");
            }

            uint32_t taken_pc = (uint32_t)((int64_t)pc + 1 + insn->off);
            BpfStatus res = fall_ok ? verify_from(prog, cfg, pc + 1u, fall_st, rep) : BPF_OK;
            if (res == BPF_OK && taken_ok) res = verify_from(prog, cfg, taken_pc, taken_st, rep);
            free(fall_st); free(taken_st);
            if (res == BPF_OK) cfg_record_visited(cfg, start_pc, initial_st);
            return res;
        }
        free(st);
        return verify_fail(rep, BPF_ERR_INVALID_PROG, pc, "unhandled opcode");
    }
}

BpfStatus bpf_verify_program(const BpfProgram *prog, BpfVerifyReport *rep) {
    BpfVerifyReport local_rep;
    if (!rep) rep = &local_rep;
    memset(rep, 0, sizeof(*rep));

    BpfCfgState *cfg = (BpfCfgState *)malloc(sizeof(*cfg));
    if (!cfg) return verify_fail(rep, BPF_ERR_COMPLEXITY, 0, "cfg oom");
    cfg_init(cfg);

    BpfStatus cfg_st = bpf_check_cfg(prog, cfg, rep);
    if (cfg_st != BPF_OK) { cfg_destroy(cfg); free(cfg); return cfg_st; }

    BpfVerifierState *init_st = (BpfVerifierState *)calloc(1, sizeof(*init_st));
    if (!init_st) { cfg_destroy(cfg); free(cfg); return verify_fail(rep, BPF_ERR_COMPLEXITY, 0, "state oom"); }

    for (uint32_t r = 0; r < BPF_MAX_REGS; r++) reg_set_uninit(&init_st->frames[0].regs[r]);
    init_st->frames[0].regs[BPF_REG_1].type = REG_CTX_PTR;
    init_st->frames[0].regs[BPF_REG_10].type = REG_STACK_PTR;
    init_st->frames[0].regs[BPF_REG_10].frame_owner = 0u;

    BpfStatus vst = verify_from(prog, cfg, 0u, init_st, rep);
    if (vst == BPF_OK) {
        rep->status = BPF_OK;
        snprintf(rep->message, sizeof(rep->message), "verified (%u steps, %u pruned)",
                 rep->insns_explored, rep->states_pruned);
    }
    free(init_st);
    cfg_destroy(cfg);
    free(cfg);
    return vst;
}
