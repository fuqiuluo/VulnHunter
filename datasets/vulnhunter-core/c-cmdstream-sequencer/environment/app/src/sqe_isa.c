#include "sqe_isa.h"
#include "sqe_pkt.h"

#include <ctype.h>
#include <string.h>

static const sqe_op_info_t k_op_table[OP_COUNT] = {
    { OP_NOP,     "nop",     INSN_FMT_NONE       },
    { OP_MOV,     "mov",     INSN_FMT_RD_RS      },
    { OP_MOVI,    "movi",    INSN_FMT_RD_UIMM    },
    { OP_MOVHI,   "movhi",   INSN_FMT_RD_UIMM    },
    { OP_ADD,     "add",     INSN_FMT_RD_RS_RT   },
    { OP_ADDI,    "addi",    INSN_FMT_RD_RS_SIMM },
    { OP_SUB,     "sub",     INSN_FMT_RD_RS_RT   },
    { OP_SUBI,    "subi",    INSN_FMT_RD_RS_UIMM },
    { OP_AND,     "and",     INSN_FMT_RD_RS_RT   },
    { OP_ANDI,    "andi",    INSN_FMT_RD_RS_UIMM },
    { OP_OR,      "or",      INSN_FMT_RD_RS_RT   },
    { OP_ORI,     "ori",     INSN_FMT_RD_RS_UIMM },
    { OP_XOR,     "xor",     INSN_FMT_RD_RS_RT   },
    { OP_XORI,    "xori",    INSN_FMT_RD_RS_UIMM },
    { OP_SHL,     "shl",     INSN_FMT_RD_RS_UIMM },
    { OP_SHR,     "shr",     INSN_FMT_RD_RS_UIMM },
    { OP_BEQ,     "beq",     INSN_FMT_BRANCH     },
    { OP_BNE,     "bne",     INSN_FMT_BRANCH     },
    { OP_BLTU,    "bltu",    INSN_FMT_BRANCH     },
    { OP_BGEU,    "bgeu",    INSN_FMT_BRANCH     },
    { OP_JMP,     "jmp",     INSN_FMT_TARGET     },
    { OP_CALL,    "call",    INSN_FMT_TARGET     },
    { OP_RET,     "ret",     INSN_FMT_NONE       },
    { OP_CREAD,   "cread",   INSN_FMT_CREAD      },
    { OP_CWRITE,  "cwrite",  INSN_FMT_CWRITE     },
    { OP_LDW,     "ldw",     INSN_FMT_RD_RS_UIMM },
    { OP_STW,     "stw",     INSN_FMT_RD_RS_UIMM },
    { OP_PKTREAD, "pktread", INSN_FMT_RD         },
    { OP_PKTNEXT, "pktnext", INSN_FMT_NONE       },
    { OP_SPUSH,   "spush",   INSN_FMT_RD_RS      },
    { OP_HALT,    "halt",    INSN_FMT_UIMM_ONLY  }
};

static const char *const k_creg_names[SQE_NUM_CREGS] = {
    [CREG_FW_BOOT_STATE]    = "CREG_FW_BOOT_STATE",
    [CREG_STREAM_STATUS]    = "CREG_STREAM_STATUS",
    [CREG_PKT_OPCODE]       = "CREG_PKT_OPCODE",
    [CREG_PKT_COUNT]        = "CREG_PKT_COUNT",
    [CREG_PKT_REM]          = "CREG_PKT_REM",
    [CREG_STREAM_REWIND]    = "CREG_STREAM_REWIND",
    [CREG_SG_ENABLE_MASK]   = "CREG_SG_ENABLE_MASK",
    [CREG_SG_DIRTY_MASK]    = "CREG_SG_DIRTY_MASK",
    [CREG_ACTIVE_SG_SLOT]   = "CREG_ACTIVE_SG_SLOT",
    [CREG_PREDICATE_VAL]    = "CREG_PREDICATE_VAL",
    [CREG_LAST_MARKER]      = "CREG_LAST_MARKER",
    [CREG_FENCE_SEQ]        = "CREG_FENCE_SEQ",
    [CREG_VP_XY]            = "CREG_VP_XY",
    [CREG_VP_WH]            = "CREG_VP_WH",
    [CREG_SCISSOR_XY]       = "CREG_SCISSOR_XY",
    [CREG_SCISSOR_WH]       = "CREG_SCISSOR_WH",
    [CREG_RASTER_STATE]     = "CREG_RASTER_STATE",
    [CREG_DEPTH_STENCIL]    = "CREG_DEPTH_STENCIL",
    [CREG_BLEND_STATE]      = "CREG_BLEND_STATE",
    [CREG_MRT_FORMAT]       = "CREG_MRT_FORMAT",
    [CREG_COLOR_BASE_VA]    = "CREG_COLOR_BASE_VA",
    [CREG_ZBUF_BASE_VA]     = "CREG_ZBUF_BASE_VA",
    [CREG_VTX_BASE_VA]      = "CREG_VTX_BASE_VA",
    [CREG_IDX_BASE_VA]      = "CREG_IDX_BASE_VA",
    [CREG_VS_PROG_ID]       = "CREG_VS_PROG_ID",
    [CREG_FS_PROG_ID]       = "CREG_FS_PROG_ID",
    [CREG_CS_PROG_ID]       = "CREG_CS_PROG_ID",
    [CREG_WORKGROUP_DIM]    = "CREG_WORKGROUP_DIM",
    [CREG_PUSH_CONST_HASH]  = "CREG_PUSH_CONST_HASH",
    [CREG_DESC_TABLE_HASH]  = "CREG_DESC_TABLE_HASH",
    [CREG_DMA_SRC_VA]       = "CREG_DMA_SRC_VA",
    [CREG_DMA_DST_VA]       = "CREG_DMA_DST_VA",
    [CREG_DMA_LEN_WORDS]    = "CREG_DMA_LEN_WORDS",
    [CREG_DRAW_PRIM_ARG]    = "CREG_DRAW_PRIM_ARG",
    [CREG_BACKEND_EXEC]     = "CREG_BACKEND_EXEC",
    [CREG_DRAW_COUNT]       = "CREG_DRAW_COUNT",
    [CREG_DISPATCH_COUNT]   = "CREG_DISPATCH_COUNT",
    [CREG_PKT_RETIRED]      = "CREG_PKT_RETIRED",
    [CREG_PERF_ACCUM_LO]    = "CREG_PERF_ACCUM_LO",
    [CREG_PERF_ACCUM_HI]    = "CREG_PERF_ACCUM_HI",
    [CREG_IOMMU_TTBR0_LO]   = "CREG_IOMMU_TTBR0_LO",
    [CREG_IOMMU_TTBR0_HI]   = "CREG_IOMMU_TTBR0_HI",
    [CREG_IOMMU_ASID]       = "CREG_IOMMU_ASID",
    [CREG_IOMMU_TLB_INV]    = "CREG_IOMMU_TLB_INV",
    [CREG_APERTURE_BASE]    = "CREG_APERTURE_BASE",
    [CREG_APERTURE_LIMIT]   = "CREG_APERTURE_LIMIT",
    [CREG_TRAP_VECTOR]      = "CREG_TRAP_VECTOR",
    [CREG_PREEMPT_ADDR]     = "CREG_PREEMPT_ADDR",
    [CREG_DEPTH_BIAS]       = "CREG_DEPTH_BIAS",
    [CREG_BLEND_COLOR]      = "CREG_BLEND_COLOR",
    [CREG_CLIP_CTRL]        = "CREG_CLIP_CTRL",
    [CREG_TESS_LEVEL]       = "CREG_TESS_LEVEL",
    [CREG_BINNING_MODE]     = "CREG_BINNING_MODE",
    [CREG_VTX_STRIDE]       = "CREG_VTX_STRIDE",
    [CREG_IDX_TYPE]         = "CREG_IDX_TYPE",
    [CREG_TEX_SAMPLER_CFG]  = "CREG_TEX_SAMPLER_CFG",
    [CREG_UBO_RANGE_CFG]    = "CREG_UBO_RANGE_CFG",
    [CREG_SSBO_RANGE_CFG]   = "CREG_SSBO_RANGE_CFG",
    [CREG_ICACHE_TAG]       = "CREG_ICACHE_TAG",
    [CREG_TILE_RESOLVE_CFG] = "CREG_TILE_RESOLVE_CFG",
    [CREG_OCCLUSION_ACCUM]  = "CREG_OCCLUSION_ACCUM",
    [CREG_TIMESTAMP_LO]     = "CREG_TIMESTAMP_LO",
    [CREG_CTX_BANK_SEL]     = "CREG_CTX_BANK_SEL",
    [CREG_SCRATCH_REG]      = "CREG_SCRATCH_REG"
};

static const char *const k_pkt_names[SQE_JMPTBL_SIZE] = {
    [PKT_ILLEGAL]              = "PKT_ILLEGAL",
    [PKT_NOP]                  = "PKT_NOP",
    [PKT_INDIRECT_BUFFER]      = "PKT_INDIRECT_BUFFER",
    [PKT_COND_EXEC]            = "PKT_COND_EXEC",
    [PKT_SET_PREDICATE]        = "PKT_SET_PREDICATE",
    [PKT_CONTEXT_SWITCH_YIELD] = "PKT_CONTEXT_SWITCH_YIELD",
    [PKT_WAIT_REG_MEM]         = "PKT_WAIT_REG_MEM",
    [PKT_EVENT_WRITE]          = "PKT_EVENT_WRITE",
    [PKT_FENCE_SIGNAL]         = "PKT_FENCE_SIGNAL",
    [PKT_SET_MARKER]           = "PKT_SET_MARKER",
    [PKT_SET_STATE_GROUP]      = "PKT_SET_STATE_GROUP",
    [PKT_MASK_STATE_GROUP]     = "PKT_MASK_STATE_GROUP",
    [PKT_CLEAR_STATE_GROUPS]   = "PKT_CLEAR_STATE_GROUPS",
    [PKT_LATCH_STATE_SUMMARY]  = "PKT_LATCH_STATE_SUMMARY",
    [PKT_SET_VIEWPORT]         = "PKT_SET_VIEWPORT",
    [PKT_SET_SCISSOR]          = "PKT_SET_SCISSOR",
    [PKT_SET_RASTER_MODE]      = "PKT_SET_RASTER_MODE",
    [PKT_SET_DEPTH_BIAS]       = "PKT_SET_DEPTH_BIAS",
    [PKT_SET_DEPTH_STENCIL]    = "PKT_SET_DEPTH_STENCIL",
    [PKT_SET_BLEND_CONST]      = "PKT_SET_BLEND_CONST",
    [PKT_SET_BLEND_CTRL]       = "PKT_SET_BLEND_CTRL",
    [PKT_SET_COLOR_TARGET]     = "PKT_SET_COLOR_TARGET",
    [PKT_SET_Z_TARGET]         = "PKT_SET_Z_TARGET",
    [PKT_SET_MSAA_CONFIG]      = "PKT_SET_MSAA_CONFIG",
    [PKT_SET_VTX_BINDING]      = "PKT_SET_VTX_BINDING",
    [PKT_SET_IDX_BUFFER]       = "PKT_SET_IDX_BUFFER",
    [PKT_SET_VTX_ATTR]         = "PKT_SET_VTX_ATTR",
    [PKT_SET_CLIP_CONTROL]     = "PKT_SET_CLIP_CONTROL",
    [PKT_SET_TESSELLATION]     = "PKT_SET_TESSELLATION",
    [PKT_SET_BINNING_CFG]      = "PKT_SET_BINNING_CFG",
    [PKT_LOAD_VS_PROGRAM]      = "PKT_LOAD_VS_PROGRAM",
    [PKT_LOAD_FS_PROGRAM]      = "PKT_LOAD_FS_PROGRAM",
    [PKT_LOAD_CS_PROGRAM]      = "PKT_LOAD_CS_PROGRAM",
    [PKT_SET_PUSH_CONST]       = "PKT_SET_PUSH_CONST",
    [PKT_BIND_TEX_DESC]        = "PKT_BIND_TEX_DESC",
    [PKT_BIND_SAMPLER_DESC]    = "PKT_BIND_SAMPLER_DESC",
    [PKT_BIND_UBO_RANGE]       = "PKT_BIND_UBO_RANGE",
    [PKT_BIND_SSBO_RANGE]      = "PKT_BIND_SSBO_RANGE",
    [PKT_SET_LOCAL_WORKGROUP]  = "PKT_SET_LOCAL_WORKGROUP",
    [PKT_INVALIDATE_ICACHE]    = "PKT_INVALIDATE_ICACHE",
    [PKT_DRAW_AUTO]            = "PKT_DRAW_AUTO",
    [PKT_DRAW_INDEXED]         = "PKT_DRAW_INDEXED",
    [PKT_DRAW_INSTANCED]       = "PKT_DRAW_INSTANCED",
    [PKT_DISPATCH_COMPUTE]     = "PKT_DISPATCH_COMPUTE",
    [PKT_BLIT_2D_RECT]         = "PKT_BLIT_2D_RECT",
    [PKT_DMA_FILL_BUFFER]      = "PKT_DMA_FILL_BUFFER",
    [PKT_DMA_COPY_BUFFER]      = "PKT_DMA_COPY_BUFFER",
    [PKT_RESOLVE_TILE_BUFFER]  = "PKT_RESOLVE_TILE_BUFFER",
    [PKT_PERF_SAMPLE]          = "PKT_PERF_SAMPLE",
    [PKT_TIMESTAMP_WRITE]      = "PKT_TIMESTAMP_WRITE",
    [PKT_ACCUM_OCCLUSION]      = "PKT_ACCUM_OCCLUSION",
    [PKT_PIPELINE_STAT_SNAP]   = "PKT_PIPELINE_STAT_SNAP",
    [PKT_IOMMU_TTBR_UPDATE]    = "PKT_IOMMU_TTBR_UPDATE",
    [PKT_APERTURE_WIN_CFG]     = "PKT_APERTURE_WIN_CFG",
    [PKT_TRAP_VECTOR_SET]      = "PKT_TRAP_VECTOR_SET",
    [PKT_PREEMPT_RING_CFG]     = "PKT_PREEMPT_RING_CFG",
    [PKT_RING_BOOTSTRAP_IB1]   = "PKT_RING_BOOTSTRAP_IB1",
    [PKT_RING_COMPLETE]        = "PKT_RING_COMPLETE"
};

static int str_eq_nocase(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

const sqe_op_info_t *sqe_isa_lookup_op(uint8_t opcode) {
    if (opcode >= OP_COUNT) {
        return NULL;
    }
    return &k_op_table[opcode];
}

const sqe_op_info_t *sqe_isa_lookup_mnemonic(const char *mnemonic) {
    if (mnemonic == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < OP_COUNT; i++) {
        if (str_eq_nocase(mnemonic, k_op_table[i].mnemonic)) {
            return &k_op_table[i];
        }
    }
    return NULL;
}

const char *sqe_isa_creg_name(uint16_t creg_id) {
    if (creg_id >= SQE_NUM_CREGS) {
        return NULL;
    }
    return k_creg_names[creg_id];
}

int sqe_isa_creg_by_name(const char *name) {
    if (name == NULL) {
        return -1;
    }
    for (int i = 0; i < (int)SQE_NUM_CREGS; i++) {
        if (k_creg_names[i] != NULL && str_eq_nocase(name, k_creg_names[i])) {
            return i;
        }
    }
    return -1;
}

const char *sqe_isa_pkt_name(uint8_t pkt_opc) {
    if (pkt_opc >= SQE_JMPTBL_SIZE) {
        return NULL;
    }
    return k_pkt_names[pkt_opc];
}

int sqe_isa_pkt_by_name(const char *name) {
    if (name == NULL) {
        return -1;
    }
    for (int i = 0; i < (int)SQE_JMPTBL_SIZE; i++) {
        if (k_pkt_names[i] != NULL && str_eq_nocase(name, k_pkt_names[i])) {
            return i;
        }
    }
    return -1;
}

uint32_t sqe_crc32(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint32_t)p[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = -(crc & 1U);
            crc = (crc >> 1) ^ (0xEDB88320U & mask);
        }
    }
    return ~crc;
}
