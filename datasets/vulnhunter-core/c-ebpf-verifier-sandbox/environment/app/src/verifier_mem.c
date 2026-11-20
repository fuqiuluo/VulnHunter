#include "bpf_vm.h"

#include <stdio.h>
#include <string.h>

static BpfStatus mem_fail(BpfVerifyReport *rep, BpfStatus st, uint32_t pc, const char *msg) {
    if (rep) {
        rep->status = st;
        rep->err_pc = pc;
        snprintf(rep->message, sizeof(rep->message), "%s", msg);
    }
    return st;
}

uint32_t bpf_mem_access_size(uint8_t size_code) {
    switch (size_code) {
        case BPF_B: return 1u; case BPF_H: return 2u;
        case BPF_W: return 4u; case BPF_DW: return 8u;
        default: return 0u;
    }
}

bool bpf_reg_is_pointer(BpfRegType t) {
    return t == REG_CTX_PTR || t == REG_PKT_PTR || t == REG_MAP_VALUE_PTR || t == REG_STACK_PTR;
}

static void set_loaded_scalar(BpfRegState *dst, uint32_t size) {
    reg_set_scalar_unknown(dst);
    if (size < 8u) {
        uint64_t mask = (size == 1u) ? 0xffULL : (size == 2u) ? 0xffffULL : 0xffffffffULL;
        dst->bounds.umin64 = 0ULL; dst->bounds.umax64 = mask;
        dst->bounds.smin64 = 0LL;  dst->bounds.smax64 = (int64_t)mask;
    }
}

BpfStatus bpf_verify_ptr_alu(const BpfInsn *insn, BpfFrameState *frame, uint32_t pc, BpfVerifyReport *rep) {
    uint8_t cls = BPF_CLASS(insn->opcode), alu_op = BPF_OP(insn->opcode);
    bool is_x = (BPF_SRC(insn->opcode) == BPF_X);
    BpfRegState *dst = &frame->regs[insn->dst_reg];

    if (alu_op == ALU_MOV) return bpf_eval_scalar_alu(insn, frame, pc, rep);
    if (cls != CLS_ALU64) return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "ALU32 on pointer forbidden");
    if (dst->type == REG_CTX_PTR) return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "REG_CTX_PTR arithmetic forbidden");
    if (dst->nullable) return mem_fail(rep, BPF_ERR_NULL_PTR, pc, "nullable pointer arithmetic forbidden");
    if (alu_op != ALU_ADD && alu_op != ALU_SUB) return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "invalid pointer ALU");

    if (!is_x) {
        int64_t delta = (alu_op == ALU_ADD) ? (int64_t)insn->imm : -(int64_t)insn->imm;
        int64_t next_off = (int64_t)dst->fixed_off + delta;
        if (next_off < -(int64_t)BPF_MAX_VAR_OFF || next_off > (int64_t)BPF_MAX_VAR_OFF)
            return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "pointer constant offset out of range");
        dst->fixed_off = (int32_t)next_off;
        return BPF_OK;
    }

    const BpfRegState *src = &frame->regs[insn->src_reg];
    if (src->type == REG_UNINIT) return mem_fail(rep, BPF_ERR_UNINIT_REG, pc, "uninitialized pointer offset");
    if (src->type != REG_SCALAR) return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "pointer-pointer arithmetic");

    if (bounds_is_const(&src->bounds)) {
        int64_t sval = (int64_t)src->bounds.umin64;
        if (sval < -(int64_t)BPF_MAX_VAR_OFF || sval > (int64_t)BPF_MAX_VAR_OFF)
            return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "scalar pointer offset out of range");
        int64_t next_off = (int64_t)dst->fixed_off + ((alu_op == ALU_ADD) ? sval : -sval);
        if (next_off < -(int64_t)BPF_MAX_VAR_OFF || next_off > (int64_t)BPF_MAX_VAR_OFF)
            return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "combined pointer offset out of range");
        dst->fixed_off = (int32_t)next_off;
        return BPF_OK;
    }

    if (alu_op != ALU_ADD || src->bounds.smin64 < 0 || src->bounds.umax64 > BPF_MAX_VAR_OFF ||
        dst->idx_umax + src->bounds.umax64 > BPF_MAX_VAR_OFF)
        return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "unbounded or negative variable pointer offset");

    dst->idx_umin += src->bounds.umin64;
    dst->idx_umax += src->bounds.umax64;
    return BPF_OK;
}

static BpfStatus check_readable_span(const BpfProgram *prog, const BpfVerifierState *st,
                                     const BpfRegState *ptr, int32_t insn_off, uint32_t size,
                                     uint32_t pc, BpfVerifyReport *rep) {
    if (ptr->type == REG_UNINIT) return mem_fail(rep, BPF_ERR_UNINIT_REG, pc, "deref of uninit reg");
    if (!bpf_reg_is_pointer(ptr->type) || ptr->type == REG_CTX_PTR)
        return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "expected readable data pointer");
    if (ptr->nullable) return mem_fail(rep, BPF_ERR_NULL_PTR, pc, "deref of nullable pointer");

    int64_t min_off = (int64_t)ptr->fixed_off + (int64_t)ptr->idx_umin + insn_off;
    int64_t max_end = (int64_t)ptr->fixed_off + (int64_t)ptr->idx_umax + insn_off + size;

    if (ptr->type == REG_PKT_PTR) {
        if (min_off < 0 || max_end > (int64_t)st->pkt_range)
            return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "packet read out of bounds");
        return BPF_OK;
    }
    if (ptr->type == REG_MAP_VALUE_PTR) {
        if (ptr->map_id >= prog->num_maps || min_off < 0 || max_end > (int64_t)prog->maps[ptr->map_id].value_size)
            return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "map value read out of bounds");
        return BPF_OK;
    }
    if (ptr->type == REG_STACK_PTR) {
        if (ptr->frame_owner >= BPF_MAX_FRAMES || min_off < -(int64_t)BPF_STACK_SIZE || max_end > 0)
            return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "stack read out of bounds");
        const BpfFrameState *fr = &st->frames[ptr->frame_owner];
        for (uint32_t b = (uint32_t)(BPF_STACK_SIZE + min_off); b < (uint32_t)(BPF_STACK_SIZE + max_end); b++) {
            if (fr->stack_bytes[b] != STACK_MISC)
                return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "stack read hits non-scalar byte");
        }
        return BPF_OK;
    }
    return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "unsupported pointer kind");
}

BpfStatus bpf_verify_ldx(const BpfProgram *prog, const BpfInsn *insn, BpfVerifierState *st,
                         uint32_t pc, BpfVerifyReport *rep) {
    uint32_t size = bpf_mem_access_size(BPF_SIZE(insn->opcode));
    BpfFrameState *cur_f = &st->frames[st->frame_depth];
    BpfRegState ptr = cur_f->regs[insn->src_reg];
    BpfRegState *dst = &cur_f->regs[insn->dst_reg];

    if (ptr.type == REG_UNINIT) return mem_fail(rep, BPF_ERR_UNINIT_REG, pc, "LDX base uninitialized");
    if (!bpf_reg_is_pointer(ptr.type)) return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "LDX base not pointer");
    if (ptr.nullable) return mem_fail(rep, BPF_ERR_NULL_PTR, pc, "LDX on nullable pointer");

    if (ptr.type == REG_CTX_PTR) {
        if (ptr.fixed_off != 0 || ptr.idx_umax != 0 || size != 8u)
            return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "invalid context access");
        if (insn->off == BPF_CTX_OFF_DATA) {
            memset(dst, 0, sizeof(*dst));
            dst->type = REG_PKT_PTR;
            return BPF_OK;
        }
        if (insn->off == BPF_CTX_OFF_PKT_LEN) {
            reg_set_scalar_unknown(dst);
            dst->bounds.umin64 = 0ULL; dst->bounds.umax64 = BPF_MAX_PKT_SIZE;
            dst->bounds.smin64 = 0LL;  dst->bounds.smax64 = BPF_MAX_PKT_SIZE;
            dst->is_pkt_len = true;
            return BPF_OK;
        }
        return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "unknown context offset");
    }

    if (ptr.type == REG_STACK_PTR) {
        if (ptr.frame_owner >= BPF_MAX_FRAMES) return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "bad stack owner");
        int64_t min_off = (int64_t)ptr.fixed_off + (int64_t)ptr.idx_umin + insn->off;
        int64_t max_end = (int64_t)ptr.fixed_off + (int64_t)ptr.idx_umax + insn->off + size;
        if (min_off < -(int64_t)BPF_STACK_SIZE || max_end > 0)
            return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "LDX stack out of bounds");

        const BpfFrameState *target_f = &st->frames[ptr.frame_owner];
        uint32_t lo = (uint32_t)(BPF_STACK_SIZE + min_off), hi = (uint32_t)(BPF_STACK_SIZE + max_end);

        if (size == 8u && ptr.idx_umin == ptr.idx_umax && (lo % 8u == 0u) && target_f->slot_has_spill[lo / 8u]) {
            *dst = target_f->spill_reg[lo / 8u];
            return BPF_OK;
        }
        for (uint32_t b = lo; b < hi; b++) {
            if (target_f->stack_bytes[b] != STACK_MISC)
                return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "LDX invalid or partial stack slot");
        }
        set_loaded_scalar(dst, size);
        return BPF_OK;
    }

    BpfStatus st_rd = check_readable_span(prog, st, &ptr, insn->off, size, pc, rep);
    if (st_rd != BPF_OK) return st_rd;
    set_loaded_scalar(dst, size);
    return BPF_OK;
}

BpfStatus bpf_verify_store(const BpfProgram *prog, const BpfInsn *insn, BpfVerifierState *st,
                           uint32_t pc, BpfVerifyReport *rep) {
    uint8_t cls = BPF_CLASS(insn->opcode);
    uint32_t size = bpf_mem_access_size(BPF_SIZE(insn->opcode));
    BpfFrameState *cur_f = &st->frames[st->frame_depth];
    const BpfRegState *ptr = &cur_f->regs[insn->dst_reg];

    if (ptr->type == REG_UNINIT) return mem_fail(rep, BPF_ERR_UNINIT_REG, pc, "store base uninitialized");
    if (!bpf_reg_is_pointer(ptr->type) || ptr->type == REG_CTX_PTR)
        return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "store base not writable pointer");
    if (ptr->nullable) return mem_fail(rep, BPF_ERR_NULL_PTR, pc, "store to nullable pointer");

    const BpfRegState *src = NULL;
    bool storing_ptr = false;
    if (cls == CLS_STX) {
        src = &cur_f->regs[insn->src_reg];
        if (src->type == REG_UNINIT) return mem_fail(rep, BPF_ERR_UNINIT_REG, pc, "STX src uninitialized");
        storing_ptr = bpf_reg_is_pointer(src->type);
    }

    int64_t min_off = (int64_t)ptr->fixed_off + (int64_t)ptr->idx_umin + insn->off;
    int64_t max_end = (int64_t)ptr->fixed_off + (int64_t)ptr->idx_umax + insn->off + size;

    if (ptr->type == REG_PKT_PTR) {
        if (storing_ptr) return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "pointer leak to packet");
        if (min_off < 0 || max_end > (int64_t)st->pkt_range)
            return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "packet store out of bounds");
        return BPF_OK;
    }
    if (ptr->type == REG_MAP_VALUE_PTR) {
        if (storing_ptr) return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "pointer leak to map");
        if (ptr->map_id >= prog->num_maps || min_off < 0 || max_end > (int64_t)prog->maps[ptr->map_id].value_size)
            return mem_fail(rep, BPF_ERR_OOB_ACCESS, pc, "map store out of bounds");
        return BPF_OK;
    }
    if (ptr->type == REG_STACK_PTR) {
        if (ptr->frame_owner >= BPF_MAX_FRAMES || min_off < -(int64_t)BPF_STACK_SIZE || max_end > 0)
            return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "stack store out of bounds");

        BpfFrameState *target_f = &st->frames[ptr->frame_owner];
        uint32_t lo = (uint32_t)(BPF_STACK_SIZE + min_off), hi = (uint32_t)(BPF_STACK_SIZE + max_end);

        if (storing_ptr) {
            if (size != 8u || ptr->idx_umin != ptr->idx_umax || (lo % 8u != 0u))
                return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "unaligned or narrow pointer spill");
            uint32_t slot = lo / 8u;
            target_f->slot_has_spill[slot] = true;
            target_f->spill_reg[slot] = *src;
            for (uint32_t b = lo; b < lo + 8u; b++) target_f->stack_bytes[b] = STACK_SPILL_PTR;
            return BPF_OK;
        }

        if (ptr->idx_umin == ptr->idx_umax) {
            if (size == 8u && (lo % 8u == 0u)) {
                uint32_t slot = lo / 8u;
                target_f->slot_has_spill[slot] = false;
                memset(&target_f->spill_reg[slot], 0, sizeof(target_f->spill_reg[slot]));
                if (cls == CLS_STX && src != NULL) {
                    target_f->slot_has_spill[slot] = true;
                    target_f->spill_reg[slot] = *src;
                }
            }
            for (uint32_t b = lo; b < hi; b++) target_f->stack_bytes[b] = STACK_MISC;
        } else {
            for (uint32_t b = lo; b < hi; b++) {
                if (target_f->stack_bytes[b] == STACK_SPILL_PTR) target_f->stack_bytes[b] = STACK_MISC;
            }
        }
        return BPF_OK;
    }
    return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "unsupported store base");
}

static void invalidate_live_pkt_regs(BpfVerifierState *st) {
    BpfFrameState *cur_f = &st->frames[st->frame_depth];
    for (uint32_t r = 0; r < BPF_MAX_REGS; r++) {
        if (cur_f->regs[r].type == REG_PKT_PTR) reg_set_uninit(&cur_f->regs[r]);
        else if (cur_f->regs[r].type == REG_SCALAR) cur_f->regs[r].is_pkt_len = false;
    }
}

BpfStatus bpf_verify_helper_call(const BpfProgram *prog, int32_t helper_id, BpfVerifierState *st,
                                 uint32_t pc, BpfVerifyReport *rep) {
    BpfFrameState *cur_f = &st->frames[st->frame_depth];
    const BpfRegState *r1 = &cur_f->regs[BPF_REG_1];
    const BpfRegState *r2 = &cur_f->regs[BPF_REG_2];
    const BpfRegState *r3 = &cur_f->regs[BPF_REG_3];
    BpfRegState ret_reg;
    reg_set_uninit(&ret_reg);

    switch ((BpfHelperId)helper_id) {
        case HELPER_MAP_LOOKUP_ELEM: {
            if (r1->type != REG_SCALAR || !bounds_is_const(&r1->bounds) || r1->bounds.umin64 >= prog->num_maps)
                return mem_fail(rep, BPF_ERR_HELPER_ARG, pc, "invalid map_id in lookup");
            uint32_t mid = (uint32_t)r1->bounds.umin64;
            BpfStatus ks = check_readable_span(prog, st, r2, 0, prog->maps[mid].key_size, pc, rep);
            if (ks != BPF_OK) return ks;
            memset(&ret_reg, 0, sizeof(ret_reg));
            ret_reg.type = REG_MAP_VALUE_PTR; ret_reg.map_id = mid;
            ret_reg.id = ++st->next_ptr_id;   ret_reg.nullable = true;
            break;
        }
        case HELPER_MAP_UPDATE_ELEM: {
            if (r1->type != REG_SCALAR || !bounds_is_const(&r1->bounds) || r1->bounds.umin64 >= prog->num_maps)
                return mem_fail(rep, BPF_ERR_HELPER_ARG, pc, "invalid map_id in update");
            uint32_t mid = (uint32_t)r1->bounds.umin64;
            BpfStatus ks = check_readable_span(prog, st, r2, 0, prog->maps[mid].key_size, pc, rep);
            if (ks != BPF_OK) return ks;
            BpfStatus vs = check_readable_span(prog, st, r3, 0, prog->maps[mid].value_size, pc, rep);
            if (vs != BPF_OK) return vs;
            reg_set_scalar_unknown(&ret_reg);
            ret_reg.bounds.smin64 = -1LL; ret_reg.bounds.smax64 = 0LL;
            break;
        }
        case HELPER_PKT_RESIZE: {
            if (r1->type != REG_CTX_PTR || r1->fixed_off != 0 || r1->idx_umax != 0)
                return mem_fail(rep, BPF_ERR_HELPER_ARG, pc, "pkt_resize R1 must be REG_CTX_PTR");
            if (r2->type != REG_SCALAR || r2->bounds.smin64 < 1 ||
                r2->bounds.umin64 < 1ULL || r2->bounds.umax64 > BPF_MAX_PKT_SIZE)
                return mem_fail(rep, BPF_ERR_HELPER_ARG, pc, "pkt_resize R2 out of [1, 4096]");
            uint32_t guaranteed = (uint32_t)r2->bounds.umin64;
            invalidate_live_pkt_regs(st);
            st->pkt_range = guaranteed;
            reg_set_scalar_const(&ret_reg, 0ULL);
            break;
        }
        case HELPER_CSUM_FOLD: {
            if (r2->type != REG_SCALAR || r2->bounds.smin64 < 1 ||
                r2->bounds.umin64 < 1ULL || r2->bounds.umax64 > 1024ULL)
                return mem_fail(rep, BPF_ERR_HELPER_ARG, pc, "csum_fold R2 out of [1, 1024]");
            BpfStatus bs = check_readable_span(prog, st, r1, 0, (uint32_t)r2->bounds.umax64, pc, rep);
            if (bs != BPF_OK) return bs;
            set_loaded_scalar(&ret_reg, 2u);
            break;
        }
        default:
            return mem_fail(rep, BPF_ERR_HELPER_ARG, pc, "unknown helper ID");
    }

    cur_f->regs[BPF_REG_0] = ret_reg;
    for (uint32_t r = BPF_REG_1; r <= BPF_REG_5; r++) reg_set_uninit(&cur_f->regs[r]);
    return BPF_OK;
}

BpfStatus bpf_verify_call_rel(const BpfInsn *insn, BpfVerifierState *st, uint32_t pc,
                              uint32_t *target_pc, BpfVerifyReport *rep) {
    if (st->frame_depth >= BPF_MAX_CALL_DEPTH)
        return mem_fail(rep, BPF_ERR_CALL_DEPTH, pc, "call depth exceeds limit");

    uint32_t cur_d = st->frame_depth, next_d = cur_d + 1u;
    st->call_ret_pc[cur_d] = pc + 1u;
    BpfFrameState *caller = &st->frames[cur_d], *callee = &st->frames[next_d];
    memset(callee, 0, sizeof(*callee));
    reg_set_uninit(&callee->regs[BPF_REG_0]);
    for (uint32_t r = BPF_REG_1; r <= BPF_REG_9; r++) callee->regs[r] = caller->regs[r];
    callee->regs[BPF_REG_10].type = REG_STACK_PTR;
    callee->regs[BPF_REG_10].frame_owner = (uint8_t)next_d;

    st->frame_depth = next_d;
    *target_pc = (uint32_t)((int64_t)pc + 1 + insn->imm);
    return BPF_OK;
}

BpfStatus bpf_verify_exit(BpfVerifierState *st, uint32_t pc, bool *prog_done,
                          uint32_t *ret_pc, BpfVerifyReport *rep) {
    uint32_t d = st->frame_depth;
    BpfFrameState *cur_f = &st->frames[d];
    if (cur_f->regs[BPF_REG_0].type == REG_UNINIT)
        return mem_fail(rep, BPF_ERR_UNINIT_REG, pc, "OP_EXIT with uninitialized R0");

    if (d == 0u) {
        if (cur_f->regs[BPF_REG_0].type != REG_SCALAR)
            return mem_fail(rep, BPF_ERR_TYPE_MISMATCH, pc, "root OP_EXIT must return scalar R0");
        *prog_done = true; *ret_pc = 0u;
        return BPF_OK;
    }

    uint32_t prev_d = d - 1u;
    BpfFrameState *caller = &st->frames[prev_d];
    caller->regs[BPF_REG_0] = cur_f->regs[BPF_REG_0];
    for (uint32_t r = BPF_REG_1; r <= BPF_REG_5; r++) reg_set_uninit(&caller->regs[r]);
    for (uint32_t r = BPF_REG_6; r <= BPF_REG_9; r++) caller->regs[r] = cur_f->regs[r];

    st->frame_depth = prev_d;
    *prog_done = false;
    *ret_pc = st->call_ret_pc[prev_d];
    return BPF_OK;
}
