#include "bpf_vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { DFS_WHITE = 0, DFS_GRAY = 1, DFS_BLACK = 2 };

void cfg_init(BpfCfgState *cfg) { memset(cfg, 0, sizeof(*cfg)); }

void cfg_destroy(BpfCfgState *cfg) {
    if (!cfg) return;
    for (uint32_t i = 0; i < BPF_MAX_INSNS; i++) {
        BpfVisitedEntry *ent = cfg->visited[i];
        while (ent) {
            BpfVisitedEntry *next = ent->next;
            free(ent);
            ent = next;
        }
        cfg->visited[i] = NULL;
        cfg->visited_cnt[i] = 0;
    }
}

static BpfStatus cfg_fail(BpfVerifyReport *rep, BpfStatus st, uint32_t pc, const char *msg) {
    if (rep) {
        rep->status = st;
        rep->err_pc = pc;
        snprintf(rep->message, sizeof(rep->message), "%s", msg);
    }
    return st;
}

static bool valid_alu_op(uint8_t op_bits) {
    switch (op_bits) {
        case ALU_ADD: case ALU_SUB: case ALU_MUL: case ALU_DIV: case ALU_OR:
        case ALU_AND: case ALU_LSH: case ALU_RSH: case ALU_NEG: case ALU_MOD:
        case ALU_XOR: case ALU_MOV: case ALU_ARSH:
            return true;
        default:
            return false;
    }
}

static bool valid_cond_jmp_op(uint8_t op_bits) {
    switch (op_bits) {
        case JMP_JEQ: case JMP_JGT: case JMP_JGE: case JMP_JSET: case JMP_JNE:
        case JMP_JSGT: case JMP_JSGE: case JMP_JLT: case JMP_JLE: case JMP_JSLT: case JMP_JSLE:
            return true;
        default:
            return false;
    }
}

static BpfStatus visit_edge(const BpfProgram *prog, const BpfCfgState *cfg,
                            uint32_t from_pc, uint32_t to_pc, uint8_t *color, BpfVerifyReport *rep);

static BpfStatus dfs_acyclic(const BpfProgram *prog, const BpfCfgState *cfg,
                             uint32_t pc, uint8_t *color, BpfVerifyReport *rep) {
    color[pc] = DFS_GRAY;
    const BpfInsn *insn = &prog->insns[pc];
    uint8_t op = insn->opcode, cls = BPF_CLASS(op);
    BpfStatus st = BPF_OK;

    if (op == OP_EXIT) {
        color[pc] = DFS_BLACK;
        return BPF_OK;
    }
    if (op == OP_CALL_REL) {
        uint32_t tgt = (uint32_t)((int64_t)pc + 1 + insn->imm);
        st = visit_edge(prog, cfg, pc, tgt, color, rep);
        if (st == BPF_OK) st = visit_edge(prog, cfg, pc, pc + 1u, color, rep);
        color[pc] = DFS_BLACK;
        return st;
    }
    if (cls == CLS_JMP64 && BPF_OP(op) == JMP_JA && op != OP_CALL_HELPER) {
        uint32_t tgt = (uint32_t)((int64_t)pc + 1 + insn->off);
        st = visit_edge(prog, cfg, pc, tgt, color, rep);
        color[pc] = DFS_BLACK;
        return st;
    }
    if ((cls == CLS_JMP64 || cls == CLS_JMP32) && op != OP_CALL_HELPER) {
        uint32_t tgt = (uint32_t)((int64_t)pc + 1 + insn->off);
        st = visit_edge(prog, cfg, pc, pc + 1u, color, rep);
        if (st == BPF_OK) st = visit_edge(prog, cfg, pc, tgt, color, rep);
        color[pc] = DFS_BLACK;
        return st;
    }

    uint32_t next_pc = pc + ((op == OP_LDDW_IMM) ? 2u : 1u);
    st = visit_edge(prog, cfg, pc, next_pc, color, rep);
    color[pc] = DFS_BLACK;
    return st;
}

static BpfStatus visit_edge(const BpfProgram *prog, const BpfCfgState *cfg,
                            uint32_t from_pc, uint32_t to_pc, uint8_t *color, BpfVerifyReport *rep) {
    if (color[to_pc] == DFS_GRAY) {
        return cfg_fail(rep, BPF_ERR_CFG_CYCLE, from_pc, "cycle or back-edge detected in CFG");
    }
    if (color[to_pc] == DFS_WHITE) {
        return dfs_acyclic(prog, cfg, to_pc, color, rep);
    }
    return BPF_OK;
}

BpfStatus bpf_check_cfg(const BpfProgram *prog, BpfCfgState *cfg, BpfVerifyReport *rep) {
    if (!prog || !prog->insns || prog->insn_cnt == 0 || prog->insn_cnt > BPF_MAX_INSNS)
        return cfg_fail(rep, BPF_ERR_INVALID_PROG, 0, "invalid instruction count");
    if (prog->num_maps > BPF_MAX_MAPS)
        return cfg_fail(rep, BPF_ERR_INVALID_PROG, 0, "map count exceeds limit");

    for (uint32_t m = 0; m < prog->num_maps; m++) {
        const BpfMapDef *md = &prog->maps[m];
        if (md->key_size != 4 || md->value_size == 0 || md->value_size > BPF_MAX_MAP_VALUE_SIZE ||
            md->max_entries == 0 || md->max_entries > BPF_MAX_MAP_ENTRIES)
            return cfg_fail(rep, BPF_ERR_INVALID_PROG, 0, "invalid map descriptor");
    }

    cfg->is_leader[0] = true;
    for (uint32_t pc = 0; pc < prog->insn_cnt; pc++) {
        const BpfInsn *insn = &prog->insns[pc];
        if (insn->dst_reg >= BPF_MAX_REGS || insn->src_reg >= BPF_MAX_REGS)
            return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "register index out of range");

        uint8_t op = insn->opcode, cls = BPF_CLASS(op);
        if (op == OP_LDDW_IMM) {
            if (insn->dst_reg == BPF_REG_10) return cfg_fail(rep, BPF_ERR_READ_ONLY_REG, pc, "R10 is read-only");
            if (pc + 1 >= prog->insn_cnt || prog->insns[pc + 1].opcode != 0 ||
                prog->insns[pc + 1].dst_reg != 0 || prog->insns[pc + 1].src_reg != 0)
                return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "malformed LDDW instruction");
            cfg->is_lddw_hi[pc + 1] = true;
            if (pc + 2 >= prog->insn_cnt) return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "fallthrough past end");
            pc++;
            continue;
        }

        switch (cls) {
            case CLS_LDX:
                if (op != OP_LDX_B && op != OP_LDX_H && op != OP_LDX_W && op != OP_LDX_DW)
                    return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "unsupported LDX opcode");
                if (insn->dst_reg == BPF_REG_10) return cfg_fail(rep, BPF_ERR_READ_ONLY_REG, pc, "R10 is read-only");
                if (pc + 1 >= prog->insn_cnt) return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "fallthrough past end");
                break;
            case CLS_ST:
                if (op != OP_ST_B && op != OP_ST_H && op != OP_ST_W && op != OP_ST_DW)
                    return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "unsupported ST opcode");
                if (pc + 1 >= prog->insn_cnt) return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "fallthrough past end");
                break;
            case CLS_STX:
                if (op != OP_STX_B && op != OP_STX_H && op != OP_STX_W && op != OP_STX_DW)
                    return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "unsupported STX opcode");
                if (pc + 1 >= prog->insn_cnt) return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "fallthrough past end");
                break;
            case CLS_ALU32:
            case CLS_ALU64:
                if (insn->dst_reg == BPF_REG_10) return cfg_fail(rep, BPF_ERR_READ_ONLY_REG, pc, "R10 is read-only");
                if (!valid_alu_op(BPF_OP(op))) return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "unsupported ALU op");
                if (BPF_OP(op) == ALU_NEG && BPF_SRC(op) != BPF_K)
                    return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "ALU_NEG requires BPF_K");
                if (pc + 1 >= prog->insn_cnt) return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "fallthrough past end");
                break;
            case CLS_JMP64:
                if (op == OP_EXIT) break;
                if (op == OP_CALL_HELPER) {
                    if (pc + 1 >= prog->insn_cnt) return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "fallthrough past end");
                    break;
                }
                if (op == OP_CALL_REL) {
                    int64_t tgt = (int64_t)pc + 1 + insn->imm;
                    if (tgt < 0 || tgt >= (int64_t)prog->insn_cnt || pc + 1 >= prog->insn_cnt)
                        return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "OP_CALL_REL target out of bounds");
                    cfg->is_leader[(uint32_t)tgt] = cfg->is_leader[pc + 1] = true;
                    break;
                }
                if (BPF_OP(op) == JMP_JA) {
                    if (BPF_SRC(op) != BPF_K) return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "invalid JMP_JA");
                    int64_t tgt = (int64_t)pc + 1 + insn->off;
                    if (tgt < 0 || tgt >= (int64_t)prog->insn_cnt)
                        return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "JMP_JA target out of bounds");
                    cfg->is_leader[(uint32_t)tgt] = true;
                    break;
                }
                if (!valid_cond_jmp_op(BPF_OP(op))) return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "invalid JMP64");
                {
                    int64_t tgt = (int64_t)pc + 1 + insn->off;
                    if (tgt < 0 || tgt >= (int64_t)prog->insn_cnt || pc + 1 >= prog->insn_cnt)
                        return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "JMP64 target out of bounds");
                    cfg->is_leader[(uint32_t)tgt] = cfg->is_leader[pc + 1] = true;
                }
                break;
            case CLS_JMP32:
                if (!valid_cond_jmp_op(BPF_OP(op))) return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "invalid JMP32");
                {
                    int64_t tgt = (int64_t)pc + 1 + insn->off;
                    if (tgt < 0 || tgt >= (int64_t)prog->insn_cnt || pc + 1 >= prog->insn_cnt)
                        return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "JMP32 target out of bounds");
                    cfg->is_leader[(uint32_t)tgt] = cfg->is_leader[pc + 1] = true;
                }
                break;
            default:
                return cfg_fail(rep, BPF_ERR_INVALID_PROG, pc, "unsupported opcode class");
        }
    }

    for (uint32_t pc = 0; pc < prog->insn_cnt; pc++) {
        if (cfg->is_leader[pc] && cfg->is_lddw_hi[pc])
            return cfg_fail(rep, BPF_ERR_CFG_TARGET, pc, "jump into middle of LDDW");
    }

    uint8_t color[BPF_MAX_INSNS];
    memset(color, 0, sizeof(color));
    return dfs_acyclic(prog, cfg, 0, color, rep);
}

static bool reg_subsumes(const BpfRegState *cached, const BpfRegState *cur) {
    if (cached->type == REG_UNINIT) return true;
    if (cur->type != cached->type) return false;
    if (cached->type == REG_SCALAR) {
        if (cached->is_pkt_len && !cur->is_pkt_len) return false;
        return cur->bounds.umin64 >= cached->bounds.umin64 &&
               cur->bounds.umax64 <= cached->bounds.umax64 &&
               cur->bounds.smin64 >= cached->bounds.smin64 &&
               cur->bounds.smax64 <= cached->bounds.smax64;
    }
    if (cur->id != cached->id || cur->map_id != cached->map_id || cur->frame_owner != cached->frame_owner)
        return false;
    if (cur->nullable && !cached->nullable) return false;
    if (cur->fixed_off != cached->fixed_off) return false;
    return true;
}

bool state_subsumes(const BpfVerifierState *cached, const BpfVerifierState *cur) {
    if (cur->frame_depth != cached->frame_depth || cur->pkt_range < cached->pkt_range) return false;
    for (uint32_t d = 0; d < cur->frame_depth; d++) {
        if (cur->call_ret_pc[d] != cached->call_ret_pc[d]) return false;
    }
    for (uint32_t f = 0; f <= cur->frame_depth; f++) {
        const BpfFrameState *cf = &cached->frames[f], *nf = &cur->frames[f];
        for (uint32_t r = 0; r < BPF_MAX_REGS; r++) {
            if (!reg_subsumes(&cf->regs[r], &nf->regs[r])) return false;
        }
        for (uint32_t s = 0; s < BPF_STACK_SLOTS; s++) {
            for (uint32_t b = s * 8; b < s * 8 + 8; b++) {
                if (cf->stack_bytes[b] != STACK_UNINIT && nf->stack_bytes[b] != cf->stack_bytes[b])
                    return false;
            }
            if (cf->slot_has_spill[s]) {
                if (!nf->slot_has_spill[s] || !reg_subsumes(&cf->spill_reg[s], &nf->spill_reg[s]))
                    return false;
            }
        }
    }
    return true;
}

bool cfg_is_subsumed(const BpfCfgState *cfg, uint32_t pc, const BpfVerifierState *cur) {
    if (!cfg->is_leader[pc]) return false;
    for (const BpfVisitedEntry *ent = cfg->visited[pc]; ent != NULL; ent = ent->next) {
        if (state_subsumes(&ent->state, cur)) return true;
    }
    return false;
}

void cfg_record_visited(BpfCfgState *cfg, uint32_t pc, const BpfVerifierState *st) {
    if (!cfg->is_leader[pc] || cfg->visited_cnt[pc] >= BPF_VISITED_PER_PC) return;
    BpfVisitedEntry *ent = (BpfVisitedEntry *)calloc(1, sizeof(*ent));
    if (!ent) return;
    ent->state = *st;
    ent->next = cfg->visited[pc];
    cfg->visited[pc] = ent;
    cfg->visited_cnt[pc]++;
}
