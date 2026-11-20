#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"

python3 - "$APP_DIR" <<'PYEOF'
import json
import sys
from pathlib import Path

app = Path(sys.argv[1]).resolve()

# 1. Fix ALU32 zero-extension vs signed-64 bound desynchronization in src/bounds.c
bounds_path = app / "src" / "bounds.c"
bounds_src = bounds_path.read_text(encoding="utf-8")
old_sync = """static void sync_alu32_bounds(ScalarBounds *b, uint32_t umin32, uint32_t umax32,
                              int32_t smin32, int32_t smax32) {
    tighten32(&umin32, &umax32, &smin32, &smax32);
    b->umin64 = (uint64_t)umin32;
    b->umax64 = (uint64_t)umax32;
    b->smin64 = (int64_t)smin32;
    b->smax64 = (int64_t)smax32;
}"""
new_sync = """static void sync_alu32_bounds(ScalarBounds *b, uint32_t umin32, uint32_t umax32,
                              int32_t smin32, int32_t smax32) {
    tighten32(&umin32, &umax32, &smin32, &smax32);
    b->umin64 = (uint64_t)umin32;
    b->umax64 = (uint64_t)umax32;
    b->smin64 = (int64_t)(uint64_t)umin32;
    b->smax64 = (int64_t)(uint64_t)umax32;
}"""
assert old_sync in bounds_src, "Failed to locate sync_alu32_bounds in src/bounds.c"
bounds_path.write_text(bounds_src.replace(old_sync, new_sync, 1), encoding="utf-8")

# 2. Fix visited-state pointer variable offset subsumption in src/cfg.c
cfg_path = app / "src" / "cfg.c"
cfg_src = cfg_path.read_text(encoding="utf-8")
old_reg_sub = """    if (cur->nullable && !cached->nullable) return false;
    if (cur->fixed_off != cached->fixed_off) return false;
    return true;"""
new_reg_sub = """    if (cur->nullable && !cached->nullable) return false;
    if (cur->fixed_off != cached->fixed_off) return false;
    if (cur->idx_umin < cached->idx_umin || cur->idx_umax > cached->idx_umax) return false;
    return true;"""
assert old_reg_sub in cfg_src, "Failed to locate reg_subsumes pointer check in src/cfg.c"
cfg_path.write_text(cfg_src.replace(old_reg_sub, new_reg_sub, 1), encoding="utf-8")

# 3. Fix partial stack spill overwrite, subprogram stack escape, and HELPER_PKT_RESIZE stack spills in src/verifier_mem.c
mem_path = app / "src" / "verifier_mem.c"
mem_src = mem_path.read_text(encoding="utf-8")

old_stack_span = """    if (ptr->type == REG_STACK_PTR) {
        if (ptr->frame_owner >= BPF_MAX_FRAMES || min_off < -(int64_t)BPF_STACK_SIZE || max_end > 0)
            return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "stack read out of bounds");"""
new_stack_span = """    if (ptr->type == REG_STACK_PTR) {
        if (ptr->frame_owner > st->frame_depth || min_off < -(int64_t)BPF_STACK_SIZE || max_end > 0)
            return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "stack read out of bounds");"""
assert old_stack_span in mem_src, "Failed to locate check_readable_span stack check"
mem_src = mem_src.replace(old_stack_span, new_stack_span, 1)

old_ldx_stack = """    if (ptr.type == REG_STACK_PTR) {
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
        }"""

new_ldx_stack = """    if (ptr.type == REG_STACK_PTR) {
        if (ptr.frame_owner > st->frame_depth) return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "bad stack owner");
        int64_t min_off = (int64_t)ptr.fixed_off + (int64_t)ptr.idx_umin + insn->off;
        int64_t max_end = (int64_t)ptr.fixed_off + (int64_t)ptr.idx_umax + insn->off + size;
        if (min_off < -(int64_t)BPF_STACK_SIZE || max_end > 0)
            return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "LDX stack out of bounds");

        const BpfFrameState *target_f = &st->frames[ptr.frame_owner];
        uint32_t lo = (uint32_t)(BPF_STACK_SIZE + min_off), hi = (uint32_t)(BPF_STACK_SIZE + max_end);

        if (size == 8u && ptr.idx_umin == ptr.idx_umax && (lo % 8u == 0u) && target_f->slot_has_spill[lo / 8u]) {
            const BpfRegState *sp = &target_f->spill_reg[lo / 8u];
            bool valid_spill = true;
            if (bpf_reg_is_pointer(sp->type)) {
                for (uint32_t b = lo; b < lo + 8u; b++) {
                    if (target_f->stack_bytes[b] != STACK_SPILL_PTR) valid_spill = false;
                }
            }
            if (valid_spill) {
                *dst = *sp;
                return BPF_OK;
            }
        }"""
assert old_ldx_stack in mem_src, "Failed to locate bpf_verify_ldx stack block"
mem_src = mem_src.replace(old_ldx_stack, new_ldx_stack, 1)

old_store_stack = """    if (ptr->type == REG_STACK_PTR) {
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
    }"""

new_store_stack = """    if (ptr->type == REG_STACK_PTR) {
        if (ptr->frame_owner > st->frame_depth || min_off < -(int64_t)BPF_STACK_SIZE || max_end > 0)
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

        /* Scrub any overlapped 8-byte spilled slot before writing raw scalar bytes */
        for (uint32_t s = lo / 8u; s <= (hi - 1u) / 8u; s++) {
            if (target_f->slot_has_spill[s]) {
                target_f->slot_has_spill[s] = false;
                memset(&target_f->spill_reg[s], 0, sizeof(target_f->spill_reg[s]));
            }
            for (uint32_t sb = s * 8u; sb < s * 8u + 8u; sb++) {
                if (target_f->stack_bytes[sb] == STACK_SPILL_PTR)
                    target_f->stack_bytes[sb] = STACK_MISC;
            }
        }

        if (ptr->idx_umin == ptr->idx_umax) {
            if (size == 8u && (lo % 8u == 0u) && cls == CLS_STX && src != NULL) {
                uint32_t slot = lo / 8u;
                target_f->slot_has_spill[slot] = true;
                target_f->spill_reg[slot] = *src;
            }
            for (uint32_t b = lo; b < hi; b++) target_f->stack_bytes[b] = STACK_MISC;
        }
        return BPF_OK;
    }"""
assert old_store_stack in mem_src, "Failed to locate bpf_verify_store stack block"
mem_src = mem_src.replace(old_store_stack, new_store_stack, 1)

old_inv_pkt = """static void invalidate_live_pkt_regs(BpfVerifierState *st) {
    BpfFrameState *cur_f = &st->frames[st->frame_depth];
    for (uint32_t r = 0; r < BPF_MAX_REGS; r++) {
        if (cur_f->regs[r].type == REG_PKT_PTR) reg_set_uninit(&cur_f->regs[r]);
        else if (cur_f->regs[r].type == REG_SCALAR) cur_f->regs[r].is_pkt_len = false;
    }
}"""

new_inv_pkt = """static void invalidate_live_pkt_regs(BpfVerifierState *st) {
    for (uint32_t f = 0; f <= st->frame_depth; f++) {
        BpfFrameState *fr = &st->frames[f];
        for (uint32_t r = 0; r < BPF_MAX_REGS; r++) {
            if (fr->regs[r].type == REG_PKT_PTR) reg_set_uninit(&fr->regs[r]);
            else if (fr->regs[r].type == REG_SCALAR) fr->regs[r].is_pkt_len = false;
        }
        for (uint32_t s = 0; s < BPF_STACK_SLOTS; s++) {
            if (fr->slot_has_spill[s]) {
                if (fr->spill_reg[s].type == REG_PKT_PTR) {
                    fr->slot_has_spill[s] = false;
                    memset(&fr->spill_reg[s], 0, sizeof(fr->spill_reg[s]));
                    for (uint32_t b = s * 8u; b < s * 8u + 8u; b++) {
                        if (fr->stack_bytes[b] == STACK_SPILL_PTR)
                            fr->stack_bytes[b] = STACK_MISC;
                    }
                } else if (fr->spill_reg[s].type == REG_SCALAR) {
                    fr->spill_reg[s].is_pkt_len = false;
                }
            }
        }
    }
}"""
assert old_inv_pkt in mem_src, "Failed to locate invalidate_live_pkt_regs"
mem_src = mem_src.replace(old_inv_pkt, new_inv_pkt, 1)

old_exit = """    uint32_t prev_d = d - 1u;
    BpfFrameState *caller = &st->frames[prev_d];
    caller->regs[BPF_REG_0] = cur_f->regs[BPF_REG_0];
    for (uint32_t r = BPF_REG_1; r <= BPF_REG_5; r++) reg_set_uninit(&caller->regs[r]);
    for (uint32_t r = BPF_REG_6; r <= BPF_REG_9; r++) caller->regs[r] = cur_f->regs[r];

    st->frame_depth = prev_d;
    *prog_done = false;
    *ret_pc = st->call_ret_pc[prev_d];
    return BPF_OK;"""

new_exit = """    if (cur_f->regs[BPF_REG_0].type == REG_STACK_PTR && cur_f->regs[BPF_REG_0].frame_owner >= d)
        return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "callee stack pointer cannot escape in R0");
    for (uint32_t r = BPF_REG_6; r <= BPF_REG_9; r++) {
        if (cur_f->regs[r].type == REG_STACK_PTR && cur_f->regs[r].frame_owner >= d)
            return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "callee stack pointer cannot escape in R6..R9");
    }
    for (uint32_t f = 0; f < d; f++) {
        BpfFrameState *anc = &st->frames[f];
        for (uint32_t s = 0; s < BPF_STACK_SLOTS; s++) {
            if (anc->slot_has_spill[s] && anc->spill_reg[s].type == REG_STACK_PTR &&
                anc->spill_reg[s].frame_owner >= d) {
                return mem_fail(rep, BPF_ERR_STACK_ACCESS, pc, "callee stack pointer escaped into caller stack");
            }
        }
    }

    uint32_t prev_d = d - 1u;
    BpfFrameState *caller = &st->frames[prev_d];
    caller->regs[BPF_REG_0] = cur_f->regs[BPF_REG_0];
    for (uint32_t r = BPF_REG_1; r <= BPF_REG_5; r++) reg_set_uninit(&caller->regs[r]);
    for (uint32_t r = BPF_REG_6; r <= BPF_REG_9; r++) caller->regs[r] = cur_f->regs[r];
    memset(cur_f, 0, sizeof(*cur_f));

    st->frame_depth = prev_d;
    *prog_done = false;
    *ret_pc = st->call_ret_pc[prev_d];
    return BPF_OK;"""
assert old_exit in mem_src, "Failed to locate bpf_verify_exit frame pop block"
mem_src = mem_src.replace(old_exit, new_exit, 1)
mem_path.write_text(mem_src, encoding="utf-8")

# 4. Add regression tests in tests/soundness_regression_test.c
reg_test_c = r'''#include "bpf_vm.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_alu32_zext_signed64_soundness(void) {
    const BpfInsn insns[] = {
        BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_1, 0),
        BPF_ALU64_REG(ALU_MOV, BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(ALU_ADD, BPF_REG_2, -4),
        BPF_CALL_HELPER_INSN(HELPER_MAP_LOOKUP_ELEM),
        BPF_JMP64_IMM(JMP_JNE, BPF_REG_0, 0, 2),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),
        BPF_EXIT_INSN(),
        BPF_ALU32_IMM(ALU_MOV, BPF_REG_2, (int32_t)0x80000000u),
        BPF_ALU64_IMM(ALU_ARSH, BPF_REG_2, 63),
        BPF_ALU64_IMM(ALU_ADD, BPF_REG_2, 1),
        BPF_ALU64_IMM(ALU_LSH, BPF_REG_2, 9),
        BPF_ALU64_REG(ALU_ADD, BPF_REG_0, BPF_REG_2),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    BpfProgram prog = {0};
    prog.insns = insns;
    prog.insn_cnt = (uint32_t)(sizeof(insns) / sizeof(insns[0]));
    prog.num_maps = 1;
    prog.maps[0] = (BpfMapDef){4, 64, 2};
    assert(bpf_verify_program(&prog, NULL) != BPF_OK);
}

static void test_pruning_var_offset_and_partial_spill(void) {
    const BpfInsn prune_insns[] = {
        BPF_ALU64_REG(ALU_MOV, BPF_REG_6, BPF_REG_1),
        BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, BPF_CTX_OFF_PKT_LEN),
        BPF_JMP64_IMM(JMP_JGE, BPF_REG_2, 8, 2),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),
        BPF_EXIT_INSN(),
        BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_1, 0),
        BPF_ALU64_REG(ALU_MOV, BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(ALU_ADD, BPF_REG_2, -4),
        BPF_CALL_HELPER_INSN(HELPER_MAP_LOOKUP_ELEM),
        BPF_JMP64_IMM(JMP_JNE, BPF_REG_0, 0, 2),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),
        BPF_EXIT_INSN(),
        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, BPF_CTX_OFF_DATA),
        BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_7, 0),
        BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_7, 4),
        BPF_JMP64_IMM(JMP_JNE, BPF_REG_2, 0, 5),
        BPF_ALU64_IMM(ALU_AND, BPF_REG_3, 7),
        BPF_ALU64_REG(ALU_ADD, BPF_REG_0, BPF_REG_3),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_2, 0),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_3, 0),
        BPF_JMP_JA(4),
        BPF_ALU64_IMM(ALU_AND, BPF_REG_3, 1023),
        BPF_ALU64_REG(ALU_ADD, BPF_REG_0, BPF_REG_3),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_2, 0),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_3, 0),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    BpfProgram p1 = {0};
    p1.insns = prune_insns;
    p1.insn_cnt = (uint32_t)(sizeof(prune_insns) / sizeof(prune_insns[0]));
    p1.num_maps = 1;
    p1.maps[0] = (BpfMapDef){4, 64, 2};
    assert(bpf_verify_program(&p1, NULL) != BPF_OK);

    const BpfInsn spill_insns[] = {
        BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_1, 0),
        BPF_ALU64_REG(ALU_MOV, BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(ALU_ADD, BPF_REG_2, -4),
        BPF_CALL_HELPER_INSN(HELPER_MAP_LOOKUP_ELEM),
        BPF_JMP64_IMM(JMP_JNE, BPF_REG_0, 0, 2),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),
        BPF_EXIT_INSN(),
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -16),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_2, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -16),
        BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_10, -16),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_3, 0),
        BPF_EXIT_INSN(),
    };
    BpfProgram p2 = {0};
    p2.insns = spill_insns;
    p2.insn_cnt = (uint32_t)(sizeof(spill_insns) / sizeof(spill_insns[0]));
    p2.num_maps = 1;
    p2.maps[0] = (BpfMapDef){4, 64, 2};
    assert(bpf_verify_program(&p2, NULL) != BPF_OK);
}

static void test_subprog_stack_escape_and_pkt_resize_spill(void) {
    const BpfInsn esc_insns[] = {
        BPF_CALL_REL_INSN(2),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, -8),
        BPF_EXIT_INSN(),
        BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 123),
        BPF_ALU64_REG(ALU_MOV, BPF_REG_0, BPF_REG_10),
        BPF_EXIT_INSN(),
    };
    BpfProgram p3 = {0};
    p3.insns = esc_insns;
    p3.insn_cnt = (uint32_t)(sizeof(esc_insns) / sizeof(esc_insns[0]));
    assert(bpf_verify_program(&p3, NULL) != BPF_OK);

    const BpfInsn resize_insns[] = {
        BPF_ALU64_REG(ALU_MOV, BPF_REG_6, BPF_REG_1),
        BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, BPF_CTX_OFF_PKT_LEN),
        BPF_JMP64_IMM(JMP_JGE, BPF_REG_2, 16, 2),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_0, 0),
        BPF_EXIT_INSN(),
        BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_6, BPF_CTX_OFF_DATA),
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_3, -8),
        BPF_ALU64_REG(ALU_MOV, BPF_REG_1, BPF_REG_6),
        BPF_ALU64_IMM(ALU_MOV, BPF_REG_2, 64),
        BPF_CALL_HELPER_INSN(HELPER_PKT_RESIZE),
        BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_10, -8),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_4, 0),
        BPF_EXIT_INSN(),
    };
    BpfProgram p4 = {0};
    p4.insns = resize_insns;
    p4.insn_cnt = (uint32_t)(sizeof(resize_insns) / sizeof(resize_insns[0]));
    assert(bpf_verify_program(&p4, NULL) != BPF_OK);
}

int main(void) {
    test_alu32_zext_signed64_soundness();
    test_pruning_var_offset_and_partial_spill();
    test_subprog_stack_escape_and_pkt_resize_spill();
    printf("soundness_regression_test: all verifier soundness checks passed\n");
    return 0;
}
'''
(app / "tests" / "soundness_regression_test.c").write_text(reg_test_c, encoding="utf-8")

# 5. Write /app/report.json
report = {
    "files": [
        "src/bounds.c",
        "src/cfg.c",
        "src/verifier_mem.c",
        "tests/soundness_regression_test.c",
    ],
    "findings": [
        {
            "file": "src/bounds.c",
            "function": "sync_alu32_bounds",
            "issue": (
                "ALU32 instructions zero-extend 32-bit results into 64-bit registers in interp.c "
                "(producing values in [0, 0xFFFFFFFF]), whereas sync_alu32_bounds sign-extended "
                "32-bit smin32/smax32 into negative smin64/smax64 values for ALU32 and JMP32 "
                "refinements when bit 31 was set. Fixed sync_alu32_bounds to project zero-extended "
                "[umin32, umax32] into non-negative 64-bit signed bounds."
            ),
        },
        {
            "file": "src/cfg.c",
            "function": "reg_subsumes",
            "issue": (
                "Visited-state pruning checked pointer id, map_id, frame_owner, and fixed_off "
                "without requiring cur->idx_umin >= cached->idx_umin and cur->idx_umax <= cached->idx_umax, "
                "allowing wider variable pointer offsets on later diamond branches to be pruned against "
                "narrower cached states. Enforced variable offset interval inclusion in reg_subsumes."
            ),
        },
        {
            "file": "src/verifier_mem.c",
            "function": "bpf_verify_store",
            "issue": (
                "Partial (<8-byte) or variable-offset scalar stores overlapping an 8-byte STACK_SPILL_PTR "
                "slot left slot_has_spill[slot] active so subsequent LDX_DW reloaded a corrupted host "
                "pointer. Added slot-wide spill scrubbing that clears slot_has_spill and downgrades all "
                "8 bytes of any overlapped spilled pointer slot to STACK_MISC."
            ),
        },
        {
            "file": "src/verifier_mem.c",
            "function": "bpf_verify_exit / invalidate_live_pkt_regs",
            "issue": (
                "Subprogram OP_EXIT allowed REG_STACK_PTR values with frame_owner >= d to escape back "
                "to the caller via R0, R6..R9, or caller stack spills after interp.c freed the subprogram "
                "stack frame, and HELPER_PKT_RESIZE invalidated live packet registers in the current frame "
                "without clearing REG_PKT_PTR spills on the stack across active frames. Added frame-owner "
                "escape rejection on OP_EXIT and full cross-frame register + stack-spill packet pointer "
                "invalidation on HELPER_PKT_RESIZE."
            ),
        },
    ],
    "summary": (
        "Remediated four static-verifier soundness discrepancies across ALU32/JMP32 64-bit bound "
        "projection, CFG join-point variable pointer offset subsumption, partial stack spill overwrites, "
        "subprogram stack-frame lifetime enforcement, and cross-frame packet pointer invalidation upon "
        "HELPER_PKT_RESIZE."
    ),
}
(app / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PYEOF

make -C "$APP_DIR" clean all test
