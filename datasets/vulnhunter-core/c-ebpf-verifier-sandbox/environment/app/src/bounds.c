#include "bpf_vm.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static BpfStatus bounds_fail(BpfVerifyReport *rep, BpfStatus st, uint32_t pc, const char *msg) {
    if (rep) {
        rep->status = st;
        rep->err_pc = pc;
        snprintf(rep->message, sizeof(rep->message), "%s", msg);
    }
    return st;
}

static int64_t arsh64_safe(int64_t v, uint32_t sh) {
    if (sh == 0) return v;
    uint64_t u = (uint64_t)v >> sh;
    if (v < 0) u |= (~0ULL) << (64u - sh);
    return (int64_t)u;
}

static int32_t arsh32_safe(int32_t v, uint32_t sh) {
    if (sh == 0) return v;
    uint32_t u = (uint32_t)v >> sh;
    if (v < 0) u |= (~0u) << (32u - sh);
    return (int32_t)u;
}

static uint64_t mask_below_msb64(uint64_t v) {
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16; v |= v >> 32;
    return v;
}

static uint32_t mask_below_msb32(uint32_t v) {
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16;
    return v;
}

void bounds_init_unknown(ScalarBounds *b) {
    b->umin64 = 0ULL; b->umax64 = UINT64_MAX;
    b->smin64 = INT64_MIN; b->smax64 = INT64_MAX;
}

void bounds_init_const(ScalarBounds *b, uint64_t val) {
    b->umin64 = b->umax64 = val;
    b->smin64 = b->smax64 = (int64_t)val;
}

bool bounds_is_const(const ScalarBounds *b) { return b->umin64 == b->umax64; }

void bounds_normalize(ScalarBounds *b) {
    if (b->smin64 >= 0 || b->smax64 < 0) {
        if ((uint64_t)b->smin64 > b->umin64) b->umin64 = (uint64_t)b->smin64;
        if ((uint64_t)b->smax64 < b->umax64) b->umax64 = (uint64_t)b->smax64;
    }
    if (b->umax64 <= (uint64_t)INT64_MAX || b->umin64 >= 0x8000000000000000ULL) {
        if ((int64_t)b->umin64 > b->smin64) b->smin64 = (int64_t)b->umin64;
        if ((int64_t)b->umax64 < b->smax64) b->smax64 = (int64_t)b->umax64;
    }
}

void reg_set_uninit(BpfRegState *r) { memset(r, 0, sizeof(*r)); r->type = REG_UNINIT; }

void reg_set_scalar_const(BpfRegState *r, uint64_t val) {
    memset(r, 0, sizeof(*r));
    r->type = REG_SCALAR;
    bounds_init_const(&r->bounds, val);
}

void reg_set_scalar_unknown(BpfRegState *r) {
    memset(r, 0, sizeof(*r));
    r->type = REG_SCALAR;
    bounds_init_unknown(&r->bounds);
}

static void extract_bounds32(const ScalarBounds *b, uint32_t *umin32, uint32_t *umax32,
                             int32_t *smin32, int32_t *smax32) {
    if ((b->umin64 >> 32) == (b->umax64 >> 32)) {
        uint32_t lo = (uint32_t)b->umin64, hi = (uint32_t)b->umax64;
        *umin32 = lo; *umax32 = hi;
        if (((lo ^ hi) & 0x80000000u) == 0u) {
            *smin32 = (int32_t)lo; *smax32 = (int32_t)hi;
        } else {
            *smin32 = INT32_MIN; *smax32 = INT32_MAX;
        }
    } else {
        *umin32 = 0u; *umax32 = UINT32_MAX;
        *smin32 = INT32_MIN; *smax32 = INT32_MAX;
    }
}

static void tighten32(uint32_t *umin32, uint32_t *umax32, int32_t *smin32, int32_t *smax32) {
    if (*smin32 >= 0 || *smax32 < 0) {
        if ((uint32_t)*smin32 > *umin32) *umin32 = (uint32_t)*smin32;
        if ((uint32_t)*smax32 < *umax32) *umax32 = (uint32_t)*smax32;
    }
    if (*umax32 <= 0x7fffffffu || *umin32 >= 0x80000000u) {
        if ((int32_t)*umin32 > *smin32) *smin32 = (int32_t)*umin32;
        if ((int32_t)*umax32 < *smax32) *smax32 = (int32_t)*umax32;
    }
}

static void sync_alu32_bounds(ScalarBounds *b, uint32_t umin32, uint32_t umax32,
                              int32_t smin32, int32_t smax32) {
    tighten32(&umin32, &umax32, &smin32, &smax32);
    b->umin64 = (uint64_t)umin32;
    b->umax64 = (uint64_t)umax32;
    b->smin64 = (int64_t)smin32;
    b->smax64 = (int64_t)smax32;
}

static BpfStatus eval_alu64(uint8_t alu_op, ScalarBounds *d, const ScalarBounds *s,
                            bool src_is_imm, int32_t imm, uint32_t pc, BpfVerifyReport *rep) {
    bool dc = bounds_is_const(d), sc = bounds_is_const(s);
    switch (alu_op) {
        case ALU_MOV: *d = *s; return BPF_OK;
        case ALU_ADD: {
            __uint128_t ulo = (__uint128_t)d->umin64 + s->umin64, uhi = (__uint128_t)d->umax64 + s->umax64;
            __int128 slo = (__int128)d->smin64 + s->smin64, shi = (__int128)d->smax64 + s->smax64;
            d->umin64 = ((ulo >> 64) == (uhi >> 64)) ? (uint64_t)ulo : 0ULL;
            d->umax64 = ((ulo >> 64) == (uhi >> 64)) ? (uint64_t)uhi : UINT64_MAX;
            d->smin64 = (slo >= INT64_MIN && shi <= INT64_MAX) ? (int64_t)slo : INT64_MIN;
            d->smax64 = (slo >= INT64_MIN && shi <= INT64_MAX) ? (int64_t)shi : INT64_MAX;
            bounds_normalize(d);
            return BPF_OK;
        }
        case ALU_SUB: {
            __int128 ulo = (__int128)d->umin64 - s->umax64, uhi = (__int128)d->umax64 - s->umin64;
            __int128 slo = (__int128)d->smin64 - s->smax64, shi = (__int128)d->smax64 - s->smin64;
            bool ok_u = (ulo >= 0 && uhi >= 0) || (ulo < 0 && uhi < 0);
            d->umin64 = ok_u ? (uint64_t)ulo : 0ULL;
            d->umax64 = ok_u ? (uint64_t)uhi : UINT64_MAX;
            d->smin64 = (slo >= INT64_MIN && shi <= INT64_MAX) ? (int64_t)slo : INT64_MIN;
            d->smax64 = (slo >= INT64_MIN && shi <= INT64_MAX) ? (int64_t)shi : INT64_MAX;
            bounds_normalize(d);
            return BPF_OK;
        }
        case ALU_MUL:
            if (dc && sc) { bounds_init_const(d, d->umin64 * s->umin64); return BPF_OK; }
            if (d->umax64 <= (uint64_t)INT32_MAX && s->umax64 <= (uint64_t)INT32_MAX) {
                d->umin64 *= s->umin64; d->umax64 *= s->umax64;
                d->smin64 = (int64_t)d->umin64; d->smax64 = (int64_t)d->umax64;
                bounds_normalize(d);
            } else bounds_init_unknown(d);
            return BPF_OK;
        case ALU_DIV:
            if (src_is_imm && imm == 0) return bounds_fail(rep, BPF_ERR_DIV_ZERO, pc, "div by zero");
            if (dc && sc) { bounds_init_const(d, s->umin64 ? d->umin64 / s->umin64 : 0ULL); return BPF_OK; }
            d->umax64 = s->umin64 ? (d->umax64 / s->umin64) : d->umax64;
            d->umin64 = (s->umin64 && s->umax64) ? (d->umin64 / s->umax64) : 0ULL;
            d->smin64 = INT64_MIN; d->smax64 = INT64_MAX;
            bounds_normalize(d);
            return BPF_OK;
        case ALU_MOD:
            if (src_is_imm && imm == 0) return bounds_fail(rep, BPF_ERR_DIV_ZERO, pc, "mod by zero");
            if (dc && sc) { bounds_init_const(d, s->umin64 ? d->umin64 % s->umin64 : d->umin64); return BPF_OK; }
            if (s->umin64 > 0 && s->umax64 - 1 < d->umax64) d->umax64 = s->umax64 - 1;
            d->umin64 = 0ULL; d->smin64 = INT64_MIN; d->smax64 = INT64_MAX;
            bounds_normalize(d);
            return BPF_OK;
        case ALU_AND:
            if (dc && sc) { bounds_init_const(d, d->umin64 & s->umin64); return BPF_OK; }
            d->umin64 = 0ULL;
            if (s->umax64 < d->umax64) d->umax64 = s->umax64;
            d->smin64 = INT64_MIN; d->smax64 = INT64_MAX;
            bounds_normalize(d);
            return BPF_OK;
        case ALU_OR:
            if (dc && sc) { bounds_init_const(d, d->umin64 | s->umin64); return BPF_OK; }
            if (s->umin64 > d->umin64) d->umin64 = s->umin64;
            d->umax64 = mask_below_msb64(d->umax64 | s->umax64);
            d->smin64 = INT64_MIN; d->smax64 = INT64_MAX;
            bounds_normalize(d);
            return BPF_OK;
        case ALU_XOR:
            if (dc && sc) { bounds_init_const(d, d->umin64 ^ s->umin64); return BPF_OK; }
            d->umin64 = 0ULL; d->umax64 = mask_below_msb64(d->umax64 | s->umax64);
            d->smin64 = INT64_MIN; d->smax64 = INT64_MAX;
            bounds_normalize(d);
            return BPF_OK;
        case ALU_LSH:
            if (s->umax64 >= 64ULL) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "LSH64 >= 64");
            if (sc) {
                uint32_t sh = (uint32_t)s->umin64;
                if (sh == 0) return BPF_OK;
                if (dc) { bounds_init_const(d, d->umin64 << sh); return BPF_OK; }
                if ((d->umax64 >> (64u - sh)) == 0ULL) {
                    d->umin64 <<= sh; d->umax64 <<= sh;
                    d->smin64 = INT64_MIN; d->smax64 = INT64_MAX;
                    bounds_normalize(d);
                    return BPF_OK;
                }
            }
            bounds_init_unknown(d);
            return BPF_OK;
        case ALU_RSH:
            if (s->umax64 >= 64ULL) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "RSH64 >= 64");
            d->umin64 >>= (uint32_t)s->umax64;
            d->umax64 >>= (uint32_t)s->umin64;
            d->smin64 = INT64_MIN; d->smax64 = INT64_MAX;
            bounds_normalize(d);
            return BPF_OK;
        case ALU_ARSH:
            if (s->umax64 >= 64ULL) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "ARSH64 >= 64");
            if (sc) {
                uint32_t sh = (uint32_t)s->umin64;
                d->smin64 = arsh64_safe(d->smin64, sh);
                d->smax64 = arsh64_safe(d->smax64, sh);
                d->umin64 = 0ULL; d->umax64 = UINT64_MAX;
                bounds_normalize(d);
            } else bounds_init_unknown(d);
            return BPF_OK;
        case ALU_NEG:
            if (dc) bounds_init_const(d, 0ULL - d->umin64);
            else if (d->smin64 > INT64_MIN) {
                int64_t lo = -d->smax64, hi = -d->smin64;
                d->smin64 = lo; d->smax64 = hi; d->umin64 = 0ULL; d->umax64 = UINT64_MAX;
                bounds_normalize(d);
            } else bounds_init_unknown(d);
            return BPF_OK;
        default:
            return bounds_fail(rep, BPF_ERR_INVALID_PROG, pc, "unknown ALU64 op");
    }
}

static BpfStatus eval_alu32(uint8_t alu_op, ScalarBounds *d, const ScalarBounds *s,
                            bool src_is_imm, int32_t imm, uint32_t pc, BpfVerifyReport *rep) {
    uint32_t du_min, du_max, su_min, su_max;
    int32_t ds_min, ds_max, ss_min, ss_max;
    extract_bounds32(d, &du_min, &du_max, &ds_min, &ds_max);
    extract_bounds32(s, &su_min, &su_max, &ss_min, &ss_max);
    bool dc = (du_min == du_max), sc = (su_min == su_max);

    switch (alu_op) {
        case ALU_MOV:
            sync_alu32_bounds(d, su_min, su_max, ss_min, ss_max);
            return BPF_OK;
        case ALU_ADD: {
            uint64_t ulo = (uint64_t)du_min + su_min, uhi = (uint64_t)du_max + su_max;
            int64_t slo = (int64_t)ds_min + ss_min, shi = (int64_t)ds_max + ss_max;
            bool ok_u = ((ulo >> 32) == (uhi >> 32)), ok_s = (slo >= INT32_MIN && shi <= INT32_MAX);
            sync_alu32_bounds(d, ok_u ? (uint32_t)ulo : 0u, ok_u ? (uint32_t)uhi : UINT32_MAX,
                              ok_s ? (int32_t)slo : INT32_MIN, ok_s ? (int32_t)shi : INT32_MAX);
            return BPF_OK;
        }
        case ALU_SUB: {
            int64_t ulo = (int64_t)du_min - su_max, uhi = (int64_t)du_max - su_min;
            int64_t slo = (int64_t)ds_min - ss_max, shi = (int64_t)ds_max - ss_min;
            bool ok_u = (ulo >= 0 && uhi >= 0) || (ulo < 0 && uhi < 0);
            bool ok_s = (slo >= INT32_MIN && shi <= INT32_MAX);
            sync_alu32_bounds(d, ok_u ? (uint32_t)ulo : 0u, ok_u ? (uint32_t)uhi : UINT32_MAX,
                              ok_s ? (int32_t)slo : INT32_MIN, ok_s ? (int32_t)shi : INT32_MAX);
            return BPF_OK;
        }
        case ALU_MUL:
            if (dc && sc) { uint32_t v = du_min * su_min; sync_alu32_bounds(d, v, v, (int32_t)v, (int32_t)v); }
            else if ((uint64_t)du_max * su_max <= (uint64_t)INT32_MAX) {
                uint32_t lo = du_min * su_min, hi = du_max * su_max;
                sync_alu32_bounds(d, lo, hi, (int32_t)lo, (int32_t)hi);
            } else sync_alu32_bounds(d, 0u, UINT32_MAX, INT32_MIN, INT32_MAX);
            return BPF_OK;
        case ALU_DIV:
            if (src_is_imm && imm == 0) return bounds_fail(rep, BPF_ERR_DIV_ZERO, pc, "ALU32 div by zero");
            if (dc && sc) { uint32_t v = su_min ? du_min / su_min : 0u; sync_alu32_bounds(d, v, v, (int32_t)v, (int32_t)v); }
            else sync_alu32_bounds(d, (su_min && su_max) ? du_min / su_max : 0u, su_min ? du_max / su_min : du_max, INT32_MIN, INT32_MAX);
            return BPF_OK;
        case ALU_MOD:
            if (src_is_imm && imm == 0) return bounds_fail(rep, BPF_ERR_DIV_ZERO, pc, "ALU32 mod by zero");
            if (dc && sc) { uint32_t v = su_min ? du_min % su_min : du_min; sync_alu32_bounds(d, v, v, (int32_t)v, (int32_t)v); }
            else {
                uint32_t rmax = (su_min > 0u && su_max - 1u < du_max) ? (su_max - 1u) : du_max;
                sync_alu32_bounds(d, 0u, rmax, INT32_MIN, INT32_MAX);
            }
            return BPF_OK;
        case ALU_AND:
            if (dc && sc) { uint32_t v = du_min & su_min; sync_alu32_bounds(d, v, v, (int32_t)v, (int32_t)v); }
            else sync_alu32_bounds(d, 0u, (du_max < su_max) ? du_max : su_max, INT32_MIN, INT32_MAX);
            return BPF_OK;
        case ALU_OR:
            if (dc && sc) { uint32_t v = du_min | su_min; sync_alu32_bounds(d, v, v, (int32_t)v, (int32_t)v); }
            else sync_alu32_bounds(d, (du_min > su_min) ? du_min : su_min, mask_below_msb32(du_max | su_max), INT32_MIN, INT32_MAX);
            return BPF_OK;
        case ALU_XOR:
            if (dc && sc) { uint32_t v = du_min ^ su_min; sync_alu32_bounds(d, v, v, (int32_t)v, (int32_t)v); }
            else sync_alu32_bounds(d, 0u, mask_below_msb32(du_max | su_max), INT32_MIN, INT32_MAX);
            return BPF_OK;
        case ALU_LSH:
            if (su_max >= 32u) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "LSH32 >= 32");
            if (sc && su_min == 0u) { sync_alu32_bounds(d, du_min, du_max, ds_min, ds_max); return BPF_OK; }
            if (sc && dc) { uint32_t v = du_min << su_min; sync_alu32_bounds(d, v, v, (int32_t)v, (int32_t)v); return BPF_OK; }
            if (sc && (du_max >> (32u - su_min)) == 0u) {
                sync_alu32_bounds(d, du_min << su_min, du_max << su_min, INT32_MIN, INT32_MAX);
                return BPF_OK;
            }
            sync_alu32_bounds(d, 0u, UINT32_MAX, INT32_MIN, INT32_MAX);
            return BPF_OK;
        case ALU_RSH:
            if (su_max >= 32u) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "RSH32 >= 32");
            sync_alu32_bounds(d, du_min >> su_max, du_max >> su_min, INT32_MIN, INT32_MAX);
            return BPF_OK;
        case ALU_ARSH:
            if (su_max >= 32u) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "ARSH32 >= 32");
            if (sc) sync_alu32_bounds(d, 0u, UINT32_MAX, arsh32_safe(ds_min, su_min), arsh32_safe(ds_max, su_min));
            else sync_alu32_bounds(d, 0u, UINT32_MAX, INT32_MIN, INT32_MAX);
            return BPF_OK;
        case ALU_NEG:
            if (dc) { uint32_t v = 0u - du_min; sync_alu32_bounds(d, v, v, (int32_t)v, (int32_t)v); }
            else sync_alu32_bounds(d, 0u, UINT32_MAX, INT32_MIN, INT32_MAX);
            return BPF_OK;
        default:
            return bounds_fail(rep, BPF_ERR_INVALID_PROG, pc, "unknown ALU32 op");
    }
}

BpfStatus bpf_eval_scalar_alu(const BpfInsn *insn, BpfFrameState *frame, uint32_t pc, BpfVerifyReport *rep) {
    uint8_t cls = BPF_CLASS(insn->opcode), alu_op = BPF_OP(insn->opcode);
    bool is_x = (BPF_SRC(insn->opcode) == BPF_X);
    BpfRegState *dst = &frame->regs[insn->dst_reg];

    if (alu_op != ALU_MOV && dst->type != REG_SCALAR) {
        return bounds_fail(rep, BPF_ERR_UNINIT_REG, pc, "ALU dst is not an initialized scalar");
    }

    ScalarBounds src_b;
    if (is_x) {
        const BpfRegState *src = &frame->regs[insn->src_reg];
        if (src->type == REG_UNINIT) return bounds_fail(rep, BPF_ERR_UNINIT_REG, pc, "ALU src uninitialized");
        if (cls == CLS_ALU64 && alu_op == ALU_MOV) { *dst = *src; return BPF_OK; }
        if (src->type != REG_SCALAR) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "pointer in scalar ALU");
        src_b = src->bounds;
    } else {
        bounds_init_const(&src_b, (cls == CLS_ALU64) ? (uint64_t)(int64_t)insn->imm : (uint64_t)(uint32_t)insn->imm);
    }

    if (alu_op == ALU_MOV) reg_set_scalar_unknown(dst);
    else dst->is_pkt_len = false;

    return (cls == CLS_ALU64) ? eval_alu64(alu_op, &dst->bounds, &src_b, !is_x, insn->imm, pc, rep)
                              : eval_alu32(alu_op, &dst->bounds, &src_b, !is_x, insn->imm, pc, rep);
}

static uint8_t invert_jmp_op(uint8_t op) {
    switch (op) {
        case JMP_JEQ:  return JMP_JNE;  case JMP_JNE:  return JMP_JEQ;
        case JMP_JGT:  return JMP_JLE;  case JMP_JGE:  return JMP_JLT;
        case JMP_JLT:  return JMP_JGE;  case JMP_JLE:  return JMP_JGT;
        case JMP_JSGT: return JMP_JSLE; case JMP_JSGE: return JMP_JSLT;
        case JMP_JSLT: return JMP_JSGE; case JMP_JSLE: return JMP_JSGT;
        default:       return op;
    }
}

static bool refine_cond64(uint8_t jop, ScalarBounds *d, ScalarBounds *s) {
    switch (jop) {
        case JMP_JEQ: {
            uint64_t lo = (d->umin64 > s->umin64) ? d->umin64 : s->umin64;
            uint64_t hi = (d->umax64 < s->umax64) ? d->umax64 : s->umax64;
            int64_t slo = (d->smin64 > s->smin64) ? d->smin64 : s->smin64;
            int64_t shi = (d->smax64 < s->smax64) ? d->smax64 : s->smax64;
            if (lo > hi || slo > shi) return false;
            d->umin64 = s->umin64 = lo; d->umax64 = s->umax64 = hi;
            d->smin64 = s->smin64 = slo; d->smax64 = s->smax64 = shi;
            break;
        }
        case JMP_JNE:
            if (bounds_is_const(d) && bounds_is_const(s) && d->umin64 == s->umin64) return false;
            if (bounds_is_const(s)) {
                uint64_t k = s->umin64; int64_t sk = (int64_t)k;
                if (d->umin64 == k && d->umin64 < UINT64_MAX) d->umin64++;
                if (d->umax64 == k && d->umax64 > 0ULL) d->umax64--;
                if (d->smin64 == sk && d->smin64 < INT64_MAX) d->smin64++;
                if (d->smax64 == sk && d->smax64 > INT64_MIN) d->smax64--;
            }
            break;
        case JMP_JLT:
            if (s->umax64 == 0ULL || d->umin64 >= s->umax64) return false;
            if (s->umax64 - 1ULL < d->umax64) d->umax64 = s->umax64 - 1ULL;
            if (d->umin64 + 1ULL > s->umin64) s->umin64 = d->umin64 + 1ULL;
            break;
        case JMP_JLE:
            if (d->umin64 > s->umax64) return false;
            if (s->umax64 < d->umax64) d->umax64 = s->umax64;
            if (d->umin64 > s->umin64) s->umin64 = d->umin64;
            break;
        case JMP_JGT:  return refine_cond64(JMP_JLT, s, d);
        case JMP_JGE:  return refine_cond64(JMP_JLE, s, d);
        case JMP_JSLT:
            if (s->smax64 == INT64_MIN || d->smin64 >= s->smax64) return false;
            if (s->smax64 - 1 < d->smax64) d->smax64 = s->smax64 - 1;
            if (d->smin64 + 1 > s->smin64) s->smin64 = d->smin64 + 1;
            break;
        case JMP_JSLE:
            if (d->smin64 > s->smax64) return false;
            if (s->smax64 < d->smax64) d->smax64 = s->smax64;
            if (d->smin64 > s->smin64) s->smin64 = d->smin64;
            break;
        case JMP_JSGT: return refine_cond64(JMP_JSLT, s, d);
        case JMP_JSGE: return refine_cond64(JMP_JSLE, s, d);
        case JMP_JSET:
            if (bounds_is_const(d) && bounds_is_const(s)) return (d->umin64 & s->umin64) != 0ULL;
            return !(d->umax64 == 0ULL || s->umax64 == 0ULL);
        default: return true;
    }
    bounds_normalize(d);
    bounds_normalize(s);
    return d->umin64 <= d->umax64 && d->smin64 <= d->smax64;
}

static bool refine_cond32(uint8_t jop, ScalarBounds *d, ScalarBounds *s) {
    uint32_t du_min, du_max, su_min, su_max;
    int32_t ds_min, ds_max, ss_min, ss_max;
    extract_bounds32(d, &du_min, &du_max, &ds_min, &ds_max);
    extract_bounds32(s, &su_min, &su_max, &ss_min, &ss_max);
    bool d_zero_hi = (d->umax64 <= 0xffffffffULL), s_zero_hi = (s->umax64 <= 0xffffffffULL);

    switch (jop) {
        case JMP_JEQ: {
            uint32_t lo = (du_min > su_min) ? du_min : su_min, hi = (du_max < su_max) ? du_max : su_max;
            int32_t slo = (ds_min > ss_min) ? ds_min : ss_min, shi = (ds_max < ss_max) ? ds_max : ss_max;
            if (lo > hi || slo > shi) return false;
            du_min = su_min = lo; du_max = su_max = hi; ds_min = ss_min = slo; ds_max = ss_max = shi;
            break;
        }
        case JMP_JNE:
            if (du_min == du_max && su_min == su_max && du_min == su_min) return false;
            if (su_min == su_max) {
                uint32_t k = su_min; int32_t sk = (int32_t)k;
                if (du_min == k && du_min < UINT32_MAX) du_min++;
                if (du_max == k && du_max > 0u) du_max--;
                if (ds_min == sk && ds_min < INT32_MAX) ds_min++;
                if (ds_max == sk && ds_max > INT32_MIN) ds_max--;
            }
            break;
        case JMP_JLT:
            if (su_max == 0u || du_min >= su_max) return false;
            if (su_max - 1u < du_max) du_max = su_max - 1u;
            if (du_min + 1u > su_min) su_min = du_min + 1u;
            break;
        case JMP_JLE:
            if (du_min > su_max) return false;
            if (su_max < du_max) du_max = su_max;
            if (du_min > su_min) su_min = du_min;
            break;
        case JMP_JGT:  return refine_cond32(JMP_JLT, s, d);
        case JMP_JGE:  return refine_cond32(JMP_JLE, s, d);
        case JMP_JSLT:
            if (ss_max == INT32_MIN || ds_min >= ss_max) return false;
            if (ss_max - 1 < ds_max) ds_max = ss_max - 1;
            if (ds_min + 1 > ss_min) ss_min = ds_min + 1;
            break;
        case JMP_JSLE:
            if (ds_min > ss_max) return false;
            if (ss_max < ds_max) ds_max = ss_max;
            if (ds_min > ss_min) ss_min = ds_min;
            break;
        case JMP_JSGT: return refine_cond32(JMP_JSLT, s, d);
        case JMP_JSGE: return refine_cond32(JMP_JSLE, s, d);
        case JMP_JSET:
            if (du_min == du_max && su_min == su_max) return (du_min & su_min) != 0u;
            return !(du_max == 0u || su_max == 0u);
        default: return true;
    }

    tighten32(&du_min, &du_max, &ds_min, &ds_max);
    tighten32(&su_min, &su_max, &ss_min, &ss_max);
    if (du_min > du_max || ds_min > ds_max || su_min > su_max || ss_min > ss_max) return false;
    if (d_zero_hi) sync_alu32_bounds(d, du_min, du_max, ds_min, ds_max);
    if (s_zero_hi) sync_alu32_bounds(s, su_min, su_max, ss_min, ss_max);
    return true;
}

static void refresh_pkt_range_from_reg(BpfVerifierState *st, const BpfRegState *r) {
    if (r->type == REG_SCALAR && r->is_pkt_len) {
        uint64_t proven = (r->bounds.umin64 > BPF_MAX_PKT_SIZE) ? BPF_MAX_PKT_SIZE : r->bounds.umin64;
        if ((uint32_t)proven > st->pkt_range) st->pkt_range = (uint32_t)proven;
    }
}

static void mark_ptr_nullness(BpfVerifierState *st, uint32_t ptr_id, bool is_null) {
    for (uint32_t f = 0; f <= st->frame_depth; f++) {
        BpfFrameState *fr = &st->frames[f];
        for (uint32_t r = 0; r < BPF_MAX_REGS; r++) {
            BpfRegState *reg = &fr->regs[r];
            if (reg->type == REG_MAP_VALUE_PTR && reg->nullable && reg->id == ptr_id) {
                if (is_null) reg_set_scalar_const(reg, 0ULL);
                else { reg->nullable = false; reg->id = reg->map_id; }
            }
        }
        for (uint32_t s = 0; s < BPF_STACK_SLOTS; s++) {
            if (fr->slot_has_spill[s]) {
                BpfRegState *sp = &fr->spill_reg[s];
                if (sp->type == REG_MAP_VALUE_PTR && sp->nullable && sp->id == ptr_id) {
                    if (is_null) {
                        reg_set_scalar_const(sp, 0ULL);
                        fr->slot_has_spill[s] = false;
                        for (uint32_t b = s * 8; b < s * 8 + 8; b++) fr->stack_bytes[b] = STACK_MISC;
                    } else { sp->nullable = false; sp->id = sp->map_id; }
                }
            }
        }
    }
}

BpfStatus bpf_refine_branch(const BpfInsn *insn, const BpfVerifierState *base,
                            BpfVerifierState *fallthrough_st, bool *fallthrough_reachable,
                            BpfVerifierState *taken_st, bool *taken_reachable,
                            uint32_t pc, BpfVerifyReport *rep) {
    uint8_t cls = BPF_CLASS(insn->opcode), jop = BPF_OP(insn->opcode);
    bool is_x = (BPF_SRC(insn->opcode) == BPF_X);
    const BpfFrameState *cur_f = &base->frames[base->frame_depth];
    const BpfRegState *dst = &cur_f->regs[insn->dst_reg];

    if (dst->type == REG_UNINIT) return bounds_fail(rep, BPF_ERR_UNINIT_REG, pc, "branch dst uninit");

    if (dst->type == REG_MAP_VALUE_PTR && dst->nullable && !is_x && insn->imm == 0 &&
        cls == CLS_JMP64 && (jop == JMP_JEQ || jop == JMP_JNE)) {
        *fallthrough_st = *base; *taken_st = *base;
        *fallthrough_reachable = *taken_reachable = true;
        bool taken_is_null = (jop == JMP_JEQ);
        mark_ptr_nullness(taken_st, dst->id, taken_is_null);
        mark_ptr_nullness(fallthrough_st, dst->id, !taken_is_null);
        return BPF_OK;
    }

    if (dst->type != REG_SCALAR) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "pointer branch invalid");
    if (is_x) {
        const BpfRegState *src = &cur_f->regs[insn->src_reg];
        if (src->type == REG_UNINIT) return bounds_fail(rep, BPF_ERR_UNINIT_REG, pc, "branch src uninit");
        if (src->type != REG_SCALAR) return bounds_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "pointer src branch invalid");
    }

    *fallthrough_st = *base; *taken_st = *base;
    BpfFrameState *tf = &taken_st->frames[taken_st->frame_depth];
    BpfFrameState *ff = &fallthrough_st->frames[fallthrough_st->frame_depth];

    if (is_x && insn->dst_reg == insn->src_reg) {
        ScalarBounds t1 = tf->regs[insn->dst_reg].bounds, t2 = t1;
        *taken_reachable = (cls == CLS_JMP64) ? refine_cond64(jop, &t1, &t2) : refine_cond32(jop, &t1, &t2);
        if (jop == JMP_JSET) *fallthrough_reachable = (t1.umin64 == 0ULL);
        else {
            uint8_t inv = invert_jmp_op(jop);
            ScalarBounds f1 = ff->regs[insn->dst_reg].bounds, f2 = f1;
            *fallthrough_reachable = (cls == CLS_JMP64) ? refine_cond64(inv, &f1, &f2) : refine_cond32(inv, &f1, &f2);
        }
        return BPF_OK;
    }

    ScalarBounds imm_t, imm_f;
    ScalarBounds *ts_ptr = NULL, *fs_ptr = NULL;
    if (is_x) {
        ts_ptr = &tf->regs[insn->src_reg].bounds;
        fs_ptr = &ff->regs[insn->src_reg].bounds;
    } else {
        uint64_t kv = (cls == CLS_JMP64) ? (uint64_t)(int64_t)insn->imm : (uint64_t)(uint32_t)insn->imm;
        bounds_init_const(&imm_t, kv); bounds_init_const(&imm_f, kv);
        ts_ptr = &imm_t; fs_ptr = &imm_f;
    }

    *taken_reachable = (cls == CLS_JMP64) ? refine_cond64(jop, &tf->regs[insn->dst_reg].bounds, ts_ptr)
                                          : refine_cond32(jop, &tf->regs[insn->dst_reg].bounds, ts_ptr);
    if (jop == JMP_JSET) {
        const ScalarBounds *db = &ff->regs[insn->dst_reg].bounds;
        uint64_t mask = (cls == CLS_JMP64) ? UINT64_MAX : 0xffffffffULL;
        *fallthrough_reachable = (bounds_is_const(db) && bounds_is_const(fs_ptr))
                                     ? (((db->umin64 & fs_ptr->umin64) & mask) == 0ULL) : true;
    } else {
        uint8_t inv = invert_jmp_op(jop);
        *fallthrough_reachable = (cls == CLS_JMP64) ? refine_cond64(inv, &ff->regs[insn->dst_reg].bounds, fs_ptr)
                                                    : refine_cond32(inv, &ff->regs[insn->dst_reg].bounds, fs_ptr);
    }

    if (*taken_reachable) {
        refresh_pkt_range_from_reg(taken_st, &tf->regs[insn->dst_reg]);
        if (is_x) refresh_pkt_range_from_reg(taken_st, &tf->regs[insn->src_reg]);
    }
    if (*fallthrough_reachable) {
        refresh_pkt_range_from_reg(fallthrough_st, &ff->regs[insn->dst_reg]);
        if (is_x) refresh_pkt_range_from_reg(fallthrough_st, &ff->regs[insn->src_reg]);
    }
    return BPF_OK;
}
