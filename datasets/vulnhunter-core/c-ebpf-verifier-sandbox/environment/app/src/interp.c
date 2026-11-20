#include "bpf_vm.h"

#include <stdlib.h>
#include <string.h>

typedef struct { uint64_t data; uint64_t pkt_len; } BpfRuntimeCtx;

typedef struct {
    uint32_t key_size, value_size, max_entries;
    uint8_t *entries[BPF_MAX_MAP_ENTRIES];
} BpfRuntimeMap;

uint64_t bpf_fnv1a64(const uint8_t *data, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) { h ^= (uint64_t)data[i]; h *= 1099511628211ULL; }
    return h;
}

uint16_t bpf_csum_fold16(const uint8_t *data, size_t len) {
    uint32_t sum = 0u;
    size_t i = 0;
    for (; i + 1 < len; i += 2) sum += (uint16_t)data[i] | ((uint16_t)data[i + 1] << 8);
    if (i < len) sum += (uint16_t)data[i];
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint64_t arsh64_rt(uint64_t u, uint32_t sh) {
    sh &= 63u;
    if (sh == 0u) return u;
    uint64_t res = u >> sh;
    if (u & (1ULL << 63)) res |= (~0ULL) << (64u - sh);
    return res;
}

static uint32_t arsh32_rt(uint32_t u, uint32_t sh) {
    sh &= 31u;
    if (sh == 0u) return u;
    uint32_t res = u >> sh;
    if (u & (1u << 31)) res |= (~0u) << (32u - sh);
    return res;
}

static uint64_t exec_alu64(uint8_t alu_op, uint64_t d, uint64_t s) {
    switch (alu_op) {
        case ALU_ADD: return d + s;  case ALU_SUB: return d - s;
        case ALU_MUL: return d * s;  case ALU_DIV: return s ? (d / s) : 0ULL;
        case ALU_MOD: return s ? (d % s) : d; case ALU_OR:  return d | s;
        case ALU_AND: return d & s;  case ALU_XOR: return d ^ s;
        case ALU_LSH: return d << (s & 63ULL); case ALU_RSH: return d >> (s & 63ULL);
        case ALU_ARSH: return arsh64_rt(d, (uint32_t)s);
        case ALU_NEG: return 0ULL - d; case ALU_MOV: return s;
        default: return d;
    }
}

static uint64_t exec_alu32(uint8_t alu_op, uint32_t d, uint32_t s) {
    uint32_t r = d;
    switch (alu_op) {
        case ALU_ADD: r = d + s; break; case ALU_SUB: r = d - s; break;
        case ALU_MUL: r = d * s; break; case ALU_DIV: r = s ? (d / s) : 0u; break;
        case ALU_MOD: r = s ? (d % s) : d; break; case ALU_OR:  r = d | s; break;
        case ALU_AND: r = d & s; break; case ALU_XOR: r = d ^ s; break;
        case ALU_LSH: r = d << (s & 31u); break; case ALU_RSH: r = d >> (s & 31u); break;
        case ALU_ARSH: r = arsh32_rt(d, s); break;
        case ALU_NEG: r = 0u - d; break; case ALU_MOV: r = s; break;
        default: break;
    }
    return (uint64_t)r;
}

static bool eval_jmp64(uint8_t jop, uint64_t d, uint64_t s) {
    switch (jop) {
        case JMP_JEQ: return d == s; case JMP_JNE: return d != s;
        case JMP_JGT: return d > s;  case JMP_JGE: return d >= s;
        case JMP_JLT: return d < s;  case JMP_JLE: return d <= s;
        case JMP_JSET: return (d & s) != 0ULL;
        case JMP_JSGT: return (int64_t)d > (int64_t)s;  case JMP_JSGE: return (int64_t)d >= (int64_t)s;
        case JMP_JSLT: return (int64_t)d < (int64_t)s;  case JMP_JSLE: return (int64_t)d <= (int64_t)s;
        default: return false;
    }
}

static bool eval_jmp32(uint8_t jop, uint32_t d, uint32_t s) {
    switch (jop) {
        case JMP_JEQ: return d == s; case JMP_JNE: return d != s;
        case JMP_JGT: return d > s;  case JMP_JGE: return d >= s;
        case JMP_JLT: return d < s;  case JMP_JLE: return d <= s;
        case JMP_JSET: return (d & s) != 0u;
        case JMP_JSGT: return (int32_t)d > (int32_t)s;  case JMP_JSGE: return (int32_t)d >= (int32_t)s;
        case JMP_JSLT: return (int32_t)d < (int32_t)s;  case JMP_JSLE: return (int32_t)d <= (int32_t)s;
        default: return false;
    }
}

static void cleanup_arena(uint8_t *pkt_buf, BpfRuntimeMap *maps, uint32_t num_maps, uint8_t **frame_stacks) {
    free(pkt_buf);
    for (uint32_t m = 0; m < num_maps; m++)
        for (uint32_t e = 0; e < maps[m].max_entries; e++) free(maps[m].entries[e]);
    for (uint32_t f = 0; f < BPF_MAX_FRAMES; f++) free(frame_stacks[f]);
}

static uint64_t compute_maps_digest(const BpfRuntimeMap *maps, uint32_t num_maps) {
    uint64_t h = 14695981039346656037ULL;
    for (uint32_t m = 0; m < num_maps; m++)
        for (uint32_t e = 0; e < maps[m].max_entries; e++)
            for (uint32_t b = 0; b < maps[m].value_size; b++) {
                h ^= (uint64_t)maps[m].entries[e][b];
                h *= 1099511628211ULL;
            }
    return h;
}

BpfStatus bpf_interp_run(const BpfProgram *prog, const BpfArenaSpec *spec, BpfExecResult *out) {
    if (!prog || !out) return BPF_ERR_RUNTIME;
    memset(out, 0, sizeof(*out));

    uint32_t pkt_len = (spec && spec->pkt_init) ? spec->pkt_init_len : 0u;
    if (pkt_len > BPF_MAX_PKT_SIZE) return BPF_ERR_RUNTIME;

    uint8_t *pkt_buf = (uint8_t *)(pkt_len ? malloc(pkt_len) : calloc(1, 1));
    if (!pkt_buf) return BPF_ERR_RUNTIME;
    if (pkt_len > 0u) memcpy(pkt_buf, spec->pkt_init, pkt_len);

    BpfRuntimeMap maps[BPF_MAX_MAPS];
    memset(maps, 0, sizeof(maps));
    uint8_t *frame_stacks[BPF_MAX_FRAMES];
    memset(frame_stacks, 0, sizeof(frame_stacks));

    for (uint32_t m = 0; m < prog->num_maps; m++) {
        maps[m].key_size = prog->maps[m].key_size;
        maps[m].value_size = prog->maps[m].value_size;
        maps[m].max_entries = prog->maps[m].max_entries;
        for (uint32_t e = 0; e < maps[m].max_entries; e++) {
            maps[m].entries[e] = (uint8_t *)calloc(1, maps[m].value_size);
            if (!maps[m].entries[e]) { cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks); return BPF_ERR_RUNTIME; }
        }
    }

    if (spec && spec->map_seeds) {
        for (uint32_t i = 0; i < spec->num_map_seeds; i++) {
            const BpfMapSeed *sd = &spec->map_seeds[i];
            if (sd->map_id < prog->num_maps && sd->key < maps[sd->map_id].max_entries && sd->value) {
                uint32_t cp = (sd->value_len > maps[sd->map_id].value_size) ? maps[sd->map_id].value_size : sd->value_len;
                memcpy(maps[sd->map_id].entries[sd->key], sd->value, cp);
            }
        }
    }

    frame_stacks[0] = (uint8_t *)calloc(1, BPF_STACK_SIZE);
    if (!frame_stacks[0]) { cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks); return BPF_ERR_RUNTIME; }

    BpfRuntimeCtx ctx_view = { (uint64_t)(uintptr_t)pkt_buf, (uint64_t)pkt_len };
    uint64_t regs[BPF_MAX_REGS] = { 0 };
    regs[BPF_REG_1] = (uint64_t)(uintptr_t)&ctx_view;
    regs[BPF_REG_10] = (uint64_t)(uintptr_t)(frame_stacks[0] + BPF_STACK_SIZE);

    uint32_t ret_pcs[BPF_MAX_CALL_DEPTH] = { 0 };
    uint32_t depth = 0u, pc = 0u, steps = 0u;

    while (pc < prog->insn_cnt) {
        if (steps++ >= BPF_MAX_RUN_STEPS) { cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks); return BPF_ERR_COMPLEXITY; }
        const BpfInsn *insn = &prog->insns[pc];
        uint8_t op = insn->opcode, cls = BPF_CLASS(op);

        if (op == OP_LDDW_IMM) {
            regs[insn->dst_reg] = (uint64_t)(uint32_t)insn->imm | ((uint64_t)(uint32_t)prog->insns[pc + 1u].imm << 32);
            pc += 2u; continue;
        }
        if (cls == CLS_ALU64) {
            uint64_t s = (BPF_SRC(op) == BPF_X) ? regs[insn->src_reg] : (uint64_t)(int64_t)insn->imm;
            regs[insn->dst_reg] = exec_alu64(BPF_OP(op), regs[insn->dst_reg], s);
            pc++; continue;
        }
        if (cls == CLS_ALU32) {
            uint32_t s = (BPF_SRC(op) == BPF_X) ? (uint32_t)regs[insn->src_reg] : (uint32_t)insn->imm;
            regs[insn->dst_reg] = exec_alu32(BPF_OP(op), (uint32_t)regs[insn->dst_reg], s);
            pc++; continue;
        }
        if (cls == CLS_LDX) {
            uintptr_t addr = (uintptr_t)(regs[insn->src_reg] + (uint64_t)(int64_t)insn->off);
            uint32_t sz = bpf_mem_access_size(BPF_SIZE(op));
            uint64_t v = 0;
            memcpy(&v, (const void *)addr, sz);
            regs[insn->dst_reg] = v;
            pc++; continue;
        }
        if (cls == CLS_ST || cls == CLS_STX) {
            uintptr_t addr = (uintptr_t)(regs[insn->dst_reg] + (uint64_t)(int64_t)insn->off);
            uint64_t val = (cls == CLS_STX) ? regs[insn->src_reg] : (uint64_t)(int64_t)insn->imm;
            memcpy((void *)addr, &val, bpf_mem_access_size(BPF_SIZE(op)));
            pc++; continue;
        }
        if (op == OP_CALL_HELPER) {
            switch ((BpfHelperId)insn->imm) {
                case HELPER_MAP_LOOKUP_ELEM: {
                    uint32_t mid = (uint32_t)regs[BPF_REG_1], key = 0;
                    memcpy(&key, (const void *)(uintptr_t)regs[BPF_REG_2], 4);
                    regs[BPF_REG_0] = (mid < prog->num_maps && key < maps[mid].max_entries)
                                          ? (uint64_t)(uintptr_t)maps[mid].entries[key] : 0ULL;
                    break;
                }
                case HELPER_MAP_UPDATE_ELEM: {
                    uint32_t mid = (uint32_t)regs[BPF_REG_1], key = 0;
                    memcpy(&key, (const void *)(uintptr_t)regs[BPF_REG_2], 4);
                    if (mid < prog->num_maps && key < maps[mid].max_entries) {
                        memcpy(maps[mid].entries[key], (const void *)(uintptr_t)regs[BPF_REG_3], maps[mid].value_size);
                        regs[BPF_REG_0] = 0ULL;
                    } else regs[BPF_REG_0] = (uint64_t)(-1LL);
                    break;
                }
                case HELPER_PKT_RESIZE: {
                    uint32_t new_len = (uint32_t)regs[BPF_REG_2];
                    if (new_len == 0u || new_len > BPF_MAX_PKT_SIZE) regs[BPF_REG_0] = (uint64_t)(-1LL);
                    else {
                        uint8_t *fresh = (uint8_t *)calloc(1, new_len);
                        if (!fresh) { cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks); return BPF_ERR_RUNTIME; }
                        uint32_t cp = ((uint32_t)ctx_view.pkt_len < new_len) ? (uint32_t)ctx_view.pkt_len : new_len;
                        if (cp > 0u) memcpy(fresh, pkt_buf, cp);
                        free(pkt_buf);
                        pkt_buf = fresh;
                        ctx_view.data = (uint64_t)(uintptr_t)pkt_buf;
                        ctx_view.pkt_len = (uint64_t)new_len;
                        regs[BPF_REG_0] = 0ULL;
                    }
                    break;
                }
                case HELPER_CSUM_FOLD:
                    regs[BPF_REG_0] = (uint64_t)bpf_csum_fold16((const uint8_t *)(uintptr_t)regs[BPF_REG_1], (uint32_t)regs[BPF_REG_2]);
                    break;
                default:
                    cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks);
                    return BPF_ERR_RUNTIME;
            }
            for (uint32_t r = BPF_REG_1; r <= BPF_REG_5; r++) regs[r] = 0ULL;
            pc++; continue;
        }
        if (op == OP_CALL_REL) {
            if (depth >= BPF_MAX_CALL_DEPTH) { cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks); return BPF_ERR_CALL_DEPTH; }
            ret_pcs[depth++] = pc + 1u;
            frame_stacks[depth] = (uint8_t *)calloc(1, BPF_STACK_SIZE);
            if (!frame_stacks[depth]) { cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks); return BPF_ERR_RUNTIME; }
            regs[BPF_REG_0] = 0ULL;
            regs[BPF_REG_10] = (uint64_t)(uintptr_t)(frame_stacks[depth] + BPF_STACK_SIZE);
            pc = (uint32_t)((int64_t)pc + 1 + insn->imm);
            continue;
        }
        if (op == OP_EXIT) {
            if (depth == 0u) {
                out->status = BPF_OK;
                out->r0 = regs[BPF_REG_0];
                out->final_pkt_len = (uint32_t)ctx_view.pkt_len;
                out->pkt_fnv1a = bpf_fnv1a64(pkt_buf, (size_t)ctx_view.pkt_len);
                out->map_fnv1a = compute_maps_digest(maps, prog->num_maps);
                out->steps_executed = steps;
                cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks);
                return BPF_OK;
            }
            free(frame_stacks[depth]);
            frame_stacks[depth--] = NULL;
            for (uint32_t r = BPF_REG_1; r <= BPF_REG_5; r++) regs[r] = 0ULL;
            regs[BPF_REG_10] = (uint64_t)(uintptr_t)(frame_stacks[depth] + BPF_STACK_SIZE);
            pc = ret_pcs[depth];
            continue;
        }
        if (cls == CLS_JMP64 && BPF_OP(op) == JMP_JA) { pc = (uint32_t)((int64_t)pc + 1 + insn->off); continue; }
        if (cls == CLS_JMP64) {
            uint64_t s = (BPF_SRC(op) == BPF_X) ? regs[insn->src_reg] : (uint64_t)(int64_t)insn->imm;
            pc = eval_jmp64(BPF_OP(op), regs[insn->dst_reg], s) ? (uint32_t)((int64_t)pc + 1 + insn->off) : (pc + 1u);
            continue;
        }
        if (cls == CLS_JMP32) {
            uint32_t s = (BPF_SRC(op) == BPF_X) ? (uint32_t)regs[insn->src_reg] : (uint32_t)insn->imm;
            pc = eval_jmp32(BPF_OP(op), (uint32_t)regs[insn->dst_reg], s) ? (uint32_t)((int64_t)pc + 1 + insn->off) : (pc + 1u);
            continue;
        }
        cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks);
        return BPF_ERR_RUNTIME;
    }
    cleanup_arena(pkt_buf, maps, prog->num_maps, frame_stacks);
    return BPF_ERR_RUNTIME;
}
