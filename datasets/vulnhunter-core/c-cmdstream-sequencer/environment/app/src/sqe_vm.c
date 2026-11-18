#include "sqe_vm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static uint64_t fnv1a_step_u32(uint64_t h, uint32_t v) {
    for (int i = 0; i < 4; i++) {
        h ^= (uint64_t)((v >> (i * 8)) & 0xFFU);
        h *= 1099511628211ULL;
    }
    return h;
}

sqe_status_t sqe_vm_init(sqe_vm_t *vm) {
    if (vm == NULL) {
        return SQE_ERR_IO;
    }
    memset(vm, 0, sizeof(*vm));
    vm->phys_ram = (uint8_t *)calloc(1U, SQE_PHYS_RAM_SIZE);
    if (vm->phys_ram == NULL) {
        return SQE_ERR_IO;
    }
    return SQE_OK;
}

void sqe_vm_destroy(sqe_vm_t *vm) {
    if (vm != NULL) {
        free(vm->phys_ram);
        vm->phys_ram = NULL;
    }
}

sqe_status_t sqe_vm_load_firmware_mem(sqe_vm_t *vm, const uint8_t *buf, size_t len) {
    if (vm == NULL || buf == NULL) {
        return SQE_ERR_FW_INVALID;
    }
    const size_t hdr_bytes = (8U + SQE_JMPTBL_SIZE) * sizeof(uint32_t);
    if (len < hdr_bytes + 16U * sizeof(uint32_t) || (len % sizeof(uint32_t)) != 0U) {
        return SQE_ERR_FW_INVALID;
    }

    sqe_fw_header_t hdr;
    hdr.magic       = read_u32_le(buf + 0);
    hdr.fw_version  = read_u32_le(buf + 4);
    hdr.code_words  = read_u32_le(buf + 8);
    hdr.entry_pc    = read_u32_le(buf + 12);
    hdr.dispatch_pc = read_u32_le(buf + 16);
    hdr.crc32       = read_u32_le(buf + 20);
    hdr.arch_rev    = read_u32_le(buf + 24);
    hdr.flags       = read_u32_le(buf + 28);

    if (hdr.magic != SQE_FW_MAGIC ||
        hdr.code_words < 16U ||
        hdr.code_words > SQE_MAX_CODE_WORDS ||
        hdr.entry_pc >= hdr.code_words ||
        hdr.dispatch_pc >= hdr.code_words) {
        return SQE_ERR_FW_INVALID;
    }

    size_t expected_len = hdr_bytes + (size_t)hdr.code_words * sizeof(uint32_t);
    if (len != expected_len) {
        return SQE_ERR_FW_INVALID;
    }

    uint32_t calc_crc = sqe_crc32(buf + 32U, len - 32U);
    if (calc_crc != hdr.crc32) {
        return SQE_ERR_FW_INVALID;
    }

    for (size_t i = 0; i < SQE_JMPTBL_SIZE; i++) {
        hdr.jmptbl[i] = read_u32_le(buf + 32U + i * 4U);
        if (hdr.jmptbl[i] >= hdr.code_words) {
            return SQE_ERR_FW_INVALID;
        }
    }

    vm->fw_hdr = hdr;
    memset(vm->code, 0, sizeof(vm->code));
    const uint8_t *code_ptr = buf + hdr_bytes;
    for (uint32_t i = 0; i < hdr.code_words; i++) {
        vm->code[i] = read_u32_le(code_ptr + (size_t)i * 4U);
    }
    return SQE_OK;
}

sqe_status_t sqe_vm_load_firmware_file(sqe_vm_t *vm, const char *fw_path) {
    if (vm == NULL || fw_path == NULL) {
        return SQE_ERR_IO;
    }
    FILE *fp = fopen(fw_path, "rb");
    if (fp == NULL) {
        return SQE_ERR_IO;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return SQE_ERR_IO;
    }
    long sz = ftell(fp);
    if (sz <= 0 || sz > 256 * 1024) {
        fclose(fp);
        return SQE_ERR_FW_INVALID;
    }
    rewind(fp);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(fp);
        return SQE_ERR_IO;
    }
    size_t n = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (n != (size_t)sz) {
        free(buf);
        return SQE_ERR_IO;
    }

    sqe_status_t st = sqe_vm_load_firmware_mem(vm, buf, n);
    free(buf);
    return st;
}

static void sqe_setup_default_pagetable(sqe_vm_t *vm) {
    uint8_t *pt_base = vm->phys_ram + SQE_DEFAULT_PT_PA;
    memset(pt_base, 0, SQE_NUM_PTES * sizeof(uint32_t));

    /* Map Ring-0 command page [0x00001000..0x00001FFF] as supervisor-only read */
    uint32_t ring0_vpn = SQE_RING0_VA / SQE_PAGE_SIZE;
    write_u32_le(pt_base + ring0_vpn * 4U,
                 SQE_RING0_PA | SQE_PTE_VALID | SQE_PTE_READ | SQE_PTE_RING0_ONLY);

    /* Identity-map user submission region [0x00100000..0x001FFFFF] */
    for (uint32_t va = SQE_USER_VA_BASE; va < SQE_USER_VA_LIMIT; va += SQE_PAGE_SIZE) {
        uint32_t vpn = va / SQE_PAGE_SIZE;
        write_u32_le(pt_base + vpn * 4U, va | SQE_PTE_VALID | SQE_PTE_READ | SQE_PTE_WRITE);
    }

    /* Identity-map render target / output region [0x00200000..0x002FFFFF] */
    for (uint32_t va = SQE_RT_VA_BASE; va < SQE_RT_VA_LIMIT; va += SQE_PAGE_SIZE) {
        uint32_t vpn = va / SQE_PAGE_SIZE;
        write_u32_le(pt_base + vpn * 4U, va | SQE_PTE_VALID | SQE_PTE_READ | SQE_PTE_WRITE);
    }
}

static sqe_status_t sqe_mmu_translate(const sqe_vm_t *vm, uint32_t va, int is_write, uint32_t *pa_out) {
    if ((va & 3U) != 0U || va >= SQE_PHYS_RAM_SIZE) {
        return SQE_ERR_MMU_FAULT;
    }
    if (vm->cregs[CREG_IOMMU_TTBR0_HI] != 0U) {
        return SQE_ERR_MMU_FAULT;
    }

    uint32_t ttbr0 = vm->cregs[CREG_IOMMU_TTBR0_LO];
    if ((ttbr0 & (SQE_PAGE_SIZE - 1U)) != 0U ||
        ttbr0 + SQE_NUM_PTES * sizeof(uint32_t) > SQE_PHYS_RAM_SIZE) {
        return SQE_ERR_MMU_FAULT;
    }

    uint32_t vpn = va / SQE_PAGE_SIZE;
    uint32_t pte = read_u32_le(vm->phys_ram + ttbr0 + vpn * 4U);
    if ((pte & SQE_PTE_VALID) == 0U) {
        return SQE_ERR_MMU_FAULT;
    }
    if ((pte & SQE_PTE_RING0_ONLY) != 0U && vm->stream_depth != 0U) {
        return SQE_ERR_MMU_FAULT;
    }
    if (is_write && (pte & SQE_PTE_WRITE) == 0U) {
        return SQE_ERR_MMU_FAULT;
    }
    if (!is_write && (pte & SQE_PTE_READ) == 0U) {
        return SQE_ERR_MMU_FAULT;
    }

    uint32_t pa = (pte & SQE_PAGE_MASK) | (va & (SQE_PAGE_SIZE - 1U));
    if (pa + 4U > SQE_PHYS_RAM_SIZE) {
        return SQE_ERR_MMU_FAULT;
    }
    *pa_out = pa;
    return SQE_OK;
}

static sqe_status_t sqe_mmu_read_u32(const sqe_vm_t *vm, uint32_t va, uint32_t *val_out) {
    uint32_t pa = 0;
    sqe_status_t st = sqe_mmu_translate(vm, va, 0, &pa);
    if (st != SQE_OK) {
        return st;
    }
    *val_out = read_u32_le(vm->phys_ram + pa);
    return SQE_OK;
}

static sqe_status_t sqe_mmu_write_u32(sqe_vm_t *vm, uint32_t va, uint32_t val) {
    uint32_t pa = 0;
    sqe_status_t st = sqe_mmu_translate(vm, va, 1, &pa);
    if (st != SQE_OK) {
        return st;
    }
    write_u32_le(vm->phys_ram + pa, val);
    return SQE_OK;
}

static uint32_t sqe_creg_read(const sqe_vm_t *vm, uint16_t reg) {
    if (reg >= SQE_NUM_CREGS) {
        return 0U;
    }
    if (reg == CREG_STREAM_STATUS) {
        uint32_t flags = SQE_SSTAT_FLAG_ACTIVE;
        if (vm->cregs[CREG_PREDICATE_VAL] != 0U) {
            flags |= SQE_SSTAT_FLAG_PRED_EN | SQE_SSTAT_FLAG_COND_PASS;
        }
        uint32_t ctx = (vm->cregs[CREG_CTX_BANK_SEL] & 0xFU) << SQE_SSTAT_CTX_SHIFT;
        uint32_t sg  = (vm->cregs[CREG_ACTIVE_SG_SLOT] & 0xFU) << SQE_SSTAT_SG_SLOT_SHIFT;
        uint32_t dep = vm->stream_depth & SQE_SSTAT_DEPTH_MASK;
        return flags | ctx | sg | dep;
    }
    if (reg == CREG_PKT_REM) {
        return (vm->pkt_idx < vm->pkt_cnt) ? (vm->pkt_cnt - vm->pkt_idx) : 0U;
    }
    return vm->cregs[reg];
}

static sqe_status_t sqe_run_backend(sqe_vm_t *vm, uint32_t cmd) {
    if (cmd == SQE_BACKEND_DRAW) {
        uint32_t prim = vm->cregs[CREG_DRAW_PRIM_ARG];
        uint32_t rt_va = vm->cregs[CREG_COLOR_BASE_VA];
        uint64_t h = vm->pipeline_hash;
        h = fnv1a_step_u32(h, prim);
        h = fnv1a_step_u32(h, vm->cregs[CREG_VP_XY]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_VP_WH]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_SCISSOR_XY]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_SCISSOR_WH]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_RASTER_STATE]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_DEPTH_STENCIL]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_BLEND_STATE]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_VS_PROG_ID]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_FS_PROG_ID]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_PUSH_CONST_HASH]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_DESC_TABLE_HASH]);
        vm->pipeline_hash = h;

        if (rt_va != 0U) {
            uint32_t slot_off = (vm->cregs[CREG_DRAW_COUNT] & 0xFFU) * 4U;
            sqe_status_t st = sqe_mmu_write_u32(vm, rt_va + slot_off, (uint32_t)(h ^ (h >> 32)));
            if (st != SQE_OK) {
                return st;
            }
        }
        vm->cregs[CREG_DRAW_COUNT]++;
        return SQE_OK;
    }

    if (cmd == SQE_BACKEND_COMPUTE) {
        uint64_t h = vm->pipeline_hash;
        h = fnv1a_step_u32(h, vm->cregs[CREG_CS_PROG_ID]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_WORKGROUP_DIM]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_DRAW_PRIM_ARG]);
        h = fnv1a_step_u32(h, vm->cregs[CREG_SSBO_RANGE_CFG]);
        vm->pipeline_hash = h;
        vm->cregs[CREG_DISPATCH_COUNT]++;
        return SQE_OK;
    }

    if (cmd == SQE_BACKEND_DMA_COPY || cmd == SQE_BACKEND_BLIT_2D) {
        uint32_t src_va = vm->cregs[CREG_DMA_SRC_VA];
        uint32_t dst_va = vm->cregs[CREG_DMA_DST_VA];
        uint32_t words  = vm->cregs[CREG_DMA_LEN_WORDS];
        if (words > 4096U) {
            vm->halted = 1U;
            vm->halt_code = SQE_HALT_BAD_ARG;
            return SQE_OK;
        }
        for (uint32_t i = 0; i < words; i++) {
            uint32_t v = 0;
            sqe_status_t st = sqe_mmu_read_u32(vm, src_va + i * 4U, &v);
            if (st != SQE_OK) {
                return st;
            }
            if (cmd == SQE_BACKEND_BLIT_2D) {
                v ^= vm->cregs[CREG_MRT_FORMAT];
            }
            st = sqe_mmu_write_u32(vm, dst_va + i * 4U, v);
            if (st != SQE_OK) {
                return st;
            }
        }
        vm->pipeline_hash = fnv1a_step_u32(vm->pipeline_hash, words ^ dst_va);
        vm->cregs[CREG_DISPATCH_COUNT]++;
        return SQE_OK;
    }

    if (cmd == SQE_BACKEND_DMA_FILL) {
        uint32_t dst_va = vm->cregs[CREG_DMA_DST_VA];
        uint32_t val    = vm->cregs[CREG_DMA_SRC_VA];
        uint32_t words  = vm->cregs[CREG_DMA_LEN_WORDS];
        if (words > 4096U) {
            vm->halted = 1U;
            vm->halt_code = SQE_HALT_BAD_ARG;
            return SQE_OK;
        }
        for (uint32_t i = 0; i < words; i++) {
            sqe_status_t st = sqe_mmu_write_u32(vm, dst_va + i * 4U, val);
            if (st != SQE_OK) {
                return st;
            }
        }
        vm->pipeline_hash = fnv1a_step_u32(vm->pipeline_hash, val ^ words);
        vm->cregs[CREG_DISPATCH_COUNT]++;
        return SQE_OK;
    }

    if (cmd == SQE_BACKEND_EVENT_WRITE) {
        uint32_t dst_va = vm->cregs[CREG_DMA_DST_VA];
        uint32_t tag    = vm->cregs[CREG_DMA_SRC_VA];
        return sqe_mmu_write_u32(vm, dst_va, tag);
    }

    return SQE_OK;
}

static sqe_status_t sqe_creg_write(sqe_vm_t *vm, uint16_t reg, uint32_t val) {
    if (reg >= SQE_NUM_CREGS) {
        return SQE_OK;
    }
    if (reg == CREG_STREAM_STATUS || reg == CREG_PKT_REM) {
        return SQE_OK; /* Hardware read-only status registers */
    }
    if (reg == CREG_STREAM_REWIND) {
        if (val != 0U) {
            sqe_stream_frame_t *f = &vm->stream_stack[vm->stream_depth];
            f->cur_va     = f->last_pkt_va;
            f->rem_dwords = f->last_pkt_rem;
        }
        return SQE_OK;
    }
    if (reg == CREG_BACKEND_EXEC) {
        vm->cregs[reg] = val;
        return sqe_run_backend(vm, val);
    }
    vm->cregs[reg] = val;
    return SQE_OK;
}

static sqe_status_t sqe_do_pktnext(sqe_vm_t *vm) {
    while (vm->stream_stack[vm->stream_depth].rem_dwords == 0U && vm->stream_depth > 0U) {
        vm->stream_depth--;
        if (vm->stream_depth < SQE_MAX_STREAM_DEPTH) {
            vm->cregs[CREG_ACTIVE_SG_SLOT] = 0U;
        }
    }

    sqe_stream_frame_t *frame = &vm->stream_stack[vm->stream_depth];
    if (frame->rem_dwords == 0U) {
        vm->halted = 1U;
        vm->halt_code = SQE_HALT_BAD_PKT;
        return SQE_ERR_UC_FAULT;
    }

    uint32_t hdr = 0;
    sqe_status_t st = sqe_mmu_read_u32(vm, frame->cur_va, &hdr);
    if (st != SQE_OK) {
        return st;
    }

    uint32_t tag = (hdr >> 28) & 0xFU;
    uint32_t opc = (hdr >> 16) & 0x3FU;
    uint32_t cnt = hdr & 0xFFFFU;
    if (tag != SQE_PKT7_TAG || cnt > SQE_MAX_PKT_PAYLOAD || (1U + cnt) > frame->rem_dwords) {
        vm->halted = 1U;
        vm->halt_code = SQE_HALT_BAD_PKT;
        return SQE_ERR_UC_FAULT;
    }

    frame->last_pkt_va  = frame->cur_va;
    frame->last_pkt_rem = frame->rem_dwords;

    for (uint32_t i = 0; i < cnt; i++) {
        st = sqe_mmu_read_u32(vm, frame->cur_va + (1U + i) * 4U, &vm->pkt_fifo[i]);
        if (st != SQE_OK) {
            return st;
        }
    }

    frame->cur_va     += (1U + cnt) * 4U;
    frame->rem_dwords -= (1U + cnt);

    vm->pkt_idx = 0U;
    vm->pkt_cnt = cnt;
    vm->cregs[CREG_PKT_OPCODE] = opc;
    vm->cregs[CREG_PKT_COUNT]  = cnt;
    vm->cregs[CREG_PKT_RETIRED]++;

    vm->pc = vm->fw_hdr.jmptbl[opc];
    return SQE_OK;
}

static void sqe_build_ring0_bootstrap(sqe_vm_t *vm, uint32_t session_id, uint32_t ib1_va, uint32_t ib1_dwords) {
    uint8_t *ring0 = vm->phys_ram + SQE_RING0_PA;
    uint32_t words[16];
    uint32_t n = 0;

    /* 1. Initialize IOMMU translation base and session ASID */
    words[n++] = SQE_PKT7_HDR(PKT_IOMMU_TTBR_UPDATE, 3);
    words[n++] = SQE_DEFAULT_PT_PA;
    words[n++] = 0x00000000U;
    words[n++] = 0x00010000U | (session_id & 0xFFFFU);

    /* 2. Lock protected register aperture */
    words[n++] = SQE_PKT7_HDR(PKT_APERTURE_WIN_CFG, 2);
    words[n++] = 0xF0000000U;
    words[n++] = 0xF00FFFFFU;

    /* 3. Install trap vector & preemption context save buffer */
    words[n++] = SQE_PKT7_HDR(PKT_TRAP_VECTOR_SET, 1);
    words[n++] = 0x00000180U;

    words[n++] = SQE_PKT7_HDR(PKT_PREEMPT_RING_CFG, 1);
    words[n++] = SQE_PREEMPT_SAVE_PA;

    /* 4. Dispatch user primary indirect buffer (IB1) */
    words[n++] = SQE_PKT7_HDR(PKT_RING_BOOTSTRAP_IB1, 2);
    words[n++] = ib1_va;
    words[n++] = ib1_dwords;

    /* 5. Complete Ring-0 submission */
    words[n++] = SQE_PKT7_HDR(PKT_RING_COMPLETE, 0);

    for (uint32_t i = 0; i < n; i++) {
        write_u32_le(ring0 + i * 4U, words[i]);
    }

    vm->stream_depth = 0U;
    vm->stream_stack[0].cur_va       = SQE_RING0_VA;
    vm->stream_stack[0].rem_dwords   = n;
    vm->stream_stack[0].last_pkt_va  = SQE_RING0_VA;
    vm->stream_stack[0].last_pkt_rem = n;
}

sqe_status_t sqe_vm_exec_csb(sqe_vm_t *vm, const uint8_t *csb_buf, size_t csb_len, sqe_exec_summary_t *out) {
    if (vm == NULL || vm->phys_ram == NULL || csb_buf == NULL || csb_len < 24U) {
        return SQE_ERR_CSB_FORMAT;
    }
    if (vm->fw_hdr.magic != SQE_FW_MAGIC) {
        return SQE_ERR_FW_INVALID;
    }

    uint32_t magic      = read_u32_le(csb_buf + 0);
    uint32_t session_id = read_u32_le(csb_buf + 4);
    uint32_t ib1_va     = read_u32_le(csb_buf + 8);
    uint32_t ib1_dwords = read_u32_le(csb_buf + 12);
    uint32_t seg_count  = read_u32_le(csb_buf + 16);
    uint32_t flags      = read_u32_le(csb_buf + 20);
    (void)flags;

    if (magic != CSB_MAGIC ||
        seg_count == 0U || seg_count > CSB_MAX_SEGMENTS ||
        ib1_dwords == 0U || ib1_dwords > CSB_MAX_IB_DWORDS ||
        (ib1_va & 3U) != 0U ||
        ib1_va < SQE_USER_VA_BASE ||
        ib1_va + ib1_dwords * 4U > SQE_USER_VA_LIMIT) {
        return SQE_ERR_CSB_FORMAT;
    }

    /* Reset dynamic VM state and physical memory */
    memset(vm->gprs, 0, sizeof(vm->gprs));
    memset(vm->cregs, 0, sizeof(vm->cregs));
    memset(vm->sram, 0, sizeof(vm->sram));
    memset(vm->call_stack, 0, sizeof(vm->call_stack));
    memset(vm->stream_stack, 0, sizeof(vm->stream_stack));
    memset(vm->pkt_fifo, 0, sizeof(vm->pkt_fifo));
    memset(vm->phys_ram, 0, SQE_PHYS_RAM_SIZE);

    vm->call_sp       = 0U;
    vm->pkt_idx       = 0U;
    vm->pkt_cnt       = 0U;
    vm->halted        = 0U;
    vm->halt_code     = 0U;
    vm->cycles        = 0U;
    vm->pipeline_hash = 14695981039346656037ULL;

    /* Copy user segments into user physical memory */
    size_t cursor = 24U;
    for (uint32_t i = 0; i < seg_count; i++) {
        if (cursor + 8U > csb_len) {
            return SQE_ERR_CSB_FORMAT;
        }
        uint32_t dst_va   = read_u32_le(csb_buf + cursor);
        uint32_t byte_len = read_u32_le(csb_buf + cursor + 4U);
        cursor += 8U;

        if (byte_len == 0U || (byte_len & 3U) != 0U || (dst_va & 3U) != 0U ||
            dst_va < SQE_USER_VA_BASE || dst_va > SQE_USER_VA_LIMIT ||
            byte_len > (SQE_USER_VA_LIMIT - dst_va) ||
            cursor + byte_len > csb_len) {
            return SQE_ERR_CSB_FORMAT;
        }
        memcpy(vm->phys_ram + dst_va, csb_buf + cursor, byte_len);
        cursor += byte_len;
    }
    if (cursor != csb_len) {
        return SQE_ERR_CSB_FORMAT;
    }

    /* Setup kernel page tables and Ring-0 bootstrap stream */
    sqe_setup_default_pagetable(vm);
    vm->cregs[CREG_IOMMU_TTBR0_LO] = SQE_DEFAULT_PT_PA;
    vm->cregs[CREG_COLOR_BASE_VA]  = SQE_RT_VA_BASE;
    sqe_build_ring0_bootstrap(vm, session_id, ib1_va, ib1_dwords);

    vm->pc = vm->fw_hdr.entry_pc;

    /* Execute microcontroller loop */
    while (!vm->halted) {
        if (vm->cycles >= SQE_MAX_CYCLES) {
            return SQE_ERR_CYCLE_LIMIT;
        }
        if (vm->pc >= vm->fw_hdr.code_words) {
            vm->halted = 1U;
            vm->halt_code = SQE_HALT_BAD_PKT;
            return SQE_ERR_UC_FAULT;
        }

        uint32_t insn = vm->code[vm->pc];
        uint32_t cur_pc = vm->pc;
        uint32_t next_pc = cur_pc + 1U;
        vm->cycles++;

        uint8_t op   = sqe_dec_op(insn);
        uint8_t rd   = sqe_dec_rd(insn);
        uint8_t rs   = sqe_dec_rs(insn);
        uint8_t rt   = sqe_dec_rt(insn);
        uint16_t u16 = sqe_dec_uimm(insn);
        int16_t s16  = sqe_dec_simm(insn);

        uint32_t v_rd = (rd == 0U) ? 0U : vm->gprs[rd];
        uint32_t v_rs = (rs == 0U) ? 0U : vm->gprs[rs];
        uint32_t v_rt = (rt == 0U) ? 0U : vm->gprs[rt];
        uint32_t wb   = v_rd;
        int do_wb     = 0;

        switch (op) {
            case OP_NOP:
                break;
            case OP_MOV:
                wb = v_rs;
                do_wb = 1;
                break;
            case OP_MOVI:
                wb = (uint32_t)u16;
                do_wb = 1;
                break;
            case OP_MOVHI:
                wb = (v_rd & 0x0000FFFFU) | ((uint32_t)u16 << 16);
                do_wb = 1;
                break;
            case OP_ADD:
                wb = v_rs + v_rt;
                do_wb = 1;
                break;
            case OP_ADDI:
                wb = v_rs + (uint32_t)(int32_t)s16;
                do_wb = 1;
                break;
            case OP_SUB:
                wb = v_rs - v_rt;
                do_wb = 1;
                break;
            case OP_SUBI:
                wb = v_rs - (uint32_t)u16;
                do_wb = 1;
                break;
            case OP_AND:
                wb = v_rs & v_rt;
                do_wb = 1;
                break;
            case OP_ANDI:
                wb = v_rs & (uint32_t)u16;
                do_wb = 1;
                break;
            case OP_OR:
                wb = v_rs | v_rt;
                do_wb = 1;
                break;
            case OP_ORI:
                wb = v_rs | (uint32_t)u16;
                do_wb = 1;
                break;
            case OP_XOR:
                wb = v_rs ^ v_rt;
                do_wb = 1;
                break;
            case OP_XORI:
                wb = v_rs ^ (uint32_t)u16;
                do_wb = 1;
                break;
            case OP_SHL:
                wb = v_rs << (u16 & 31U);
                do_wb = 1;
                break;
            case OP_SHR:
                wb = v_rs >> (u16 & 31U);
                do_wb = 1;
                break;
            case OP_BEQ:
                if (v_rd == v_rs) {
                    next_pc = (uint32_t)((int32_t)next_pc + (int32_t)s16);
                }
                break;
            case OP_BNE:
                if (v_rd != v_rs) {
                    next_pc = (uint32_t)((int32_t)next_pc + (int32_t)s16);
                }
                break;
            case OP_BLTU:
                if (v_rd < v_rs) {
                    next_pc = (uint32_t)((int32_t)next_pc + (int32_t)s16);
                }
                break;
            case OP_BGEU:
                if (v_rd >= v_rs) {
                    next_pc = (uint32_t)((int32_t)next_pc + (int32_t)s16);
                }
                break;
            case OP_JMP:
                next_pc = (uint32_t)u16;
                break;
            case OP_CALL:
                if (vm->call_sp >= SQE_MAX_CALL_DEPTH) {
                    vm->halted = 1U;
                    vm->halt_code = SQE_HALT_BAD_PKT;
                    return SQE_ERR_UC_FAULT;
                }
                vm->call_stack[vm->call_sp++] = next_pc;
                next_pc = (uint32_t)u16;
                break;
            case OP_RET:
                if (vm->call_sp == 0U) {
                    vm->halted = 1U;
                    vm->halt_code = SQE_HALT_BAD_PKT;
                    return SQE_ERR_UC_FAULT;
                }
                next_pc = vm->call_stack[--vm->call_sp];
                break;
            case OP_CREAD:
                wb = sqe_creg_read(vm, u16);
                do_wb = 1;
                break;
            case OP_CWRITE: {
                sqe_status_t st = sqe_creg_write(vm, u16, v_rs);
                if (st != SQE_OK) {
                    return st;
                }
                if (vm->halted) {
                    return (vm->halt_code == SQE_HALT_OK) ? SQE_OK : SQE_ERR_UC_FAULT;
                }
                break;
            }
            case OP_LDW:
                wb = vm->sram[(v_rs + (uint32_t)u16) & (SQE_SRAM_WORDS - 1U)];
                do_wb = 1;
                break;
            case OP_STW:
                vm->sram[(v_rs + (uint32_t)u16) & (SQE_SRAM_WORDS - 1U)] = v_rd;
                break;
            case OP_PKTREAD:
                if (vm->pkt_idx >= vm->pkt_cnt) {
                    vm->halted = 1U;
                    vm->halt_code = SQE_HALT_BAD_PKT;
                    return SQE_ERR_UC_FAULT;
                }
                wb = vm->pkt_fifo[vm->pkt_idx++];
                do_wb = 1;
                break;
            case OP_PKTNEXT: {
                sqe_status_t st = sqe_do_pktnext(vm);
                if (st != SQE_OK) {
                    return st;
                }
                next_pc = vm->pc;
                break;
            }
            case OP_SPUSH:
                if (v_rs == 0U || v_rs > CSB_MAX_IB_DWORDS || (v_rd & 3U) != 0U) {
                    vm->halted = 1U;
                    vm->halt_code = SQE_HALT_BAD_ALIGN;
                    return SQE_ERR_UC_FAULT;
                }
                if (vm->stream_depth >= SQE_MAX_STREAM_DEPTH) {
                    vm->halted = 1U;
                    vm->halt_code = SQE_HALT_IB_DEPTH;
                    return SQE_ERR_UC_FAULT;
                }
                vm->stream_depth++;
                vm->stream_stack[vm->stream_depth].cur_va       = v_rd;
                vm->stream_stack[vm->stream_depth].rem_dwords   = v_rs;
                vm->stream_stack[vm->stream_depth].last_pkt_va  = v_rd;
                vm->stream_stack[vm->stream_depth].last_pkt_rem = v_rs;
                break;
            case OP_HALT:
                vm->halted = 1U;
                vm->halt_code = u16;
                break;
            default:
                vm->halted = 1U;
                vm->halt_code = SQE_HALT_BAD_PKT;
                return SQE_ERR_UC_FAULT;
        }

        if (do_wb && rd != 0U) {
            vm->gprs[rd] = wb;
        }
        vm->gprs[0] = 0U;
        vm->pc = next_pc;
    }

    if (vm->halt_code != SQE_HALT_OK) {
        return SQE_ERR_UC_FAULT;
    }

    /* Compute combined output digest over render target window + pipeline state */
    uint64_t digest = vm->pipeline_hash;
    const uint8_t *rt_mem = vm->phys_ram + SQE_RT_VA_BASE;
    for (size_t i = 0; i < SQE_RT_DIGEST_BYTES; i++) {
        digest ^= (uint64_t)rt_mem[i];
        digest *= 1099511628211ULL;
    }

    if (out != NULL) {
        out->session_id     = session_id;
        out->draw_count     = vm->cregs[CREG_DRAW_COUNT];
        out->dispatch_count = vm->cregs[CREG_DISPATCH_COUNT];
        out->pkt_retired    = vm->cregs[CREG_PKT_RETIRED];
        out->halt_code      = vm->halt_code;
        out->output_digest  = digest;
    }
    return SQE_OK;
}
