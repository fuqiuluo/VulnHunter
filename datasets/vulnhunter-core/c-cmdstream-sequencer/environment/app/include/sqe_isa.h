#ifndef SQE_ISA_H
#define SQE_ISA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QRISC-32 Sequencer Microcode Architecture (Gen7.4)
 *
 * Fixed-width 32-bit instruction encoding:
 *   [31:26] op     (6-bit opcode, 0x00..0x1E)
 *   [25:21] rd     (5-bit GPR index, $r00..$r31; $r00 is hardwired 0)
 *   [20:16] rs     (5-bit GPR index, $r00..$r31)
 *   [15:11] rt     (5-bit GPR index for R-type ALU instructions)
 *   [15:0]  imm16  (16-bit signed/unsigned immediate or PC target)
 */

#define SQE_FW_MAGIC          0x53514546U  /* "SQEF" */
#define SQE_FW_VERSION        0x00020104U
#define SQE_FW_ARCH_REV       0x00000740U
#define SQE_JMPTBL_SIZE       64U
#define SQE_MAX_CODE_WORDS    8192U
#define SQE_NUM_GPRS          32U
#define SQE_NUM_CREGS         64U
#define SQE_SRAM_WORDS        1024U

typedef struct {
    uint32_t magic;
    uint32_t fw_version;
    uint32_t code_words;
    uint32_t entry_pc;
    uint32_t dispatch_pc;
    uint32_t crc32;
    uint32_t arch_rev;
    uint32_t flags;
    uint32_t jmptbl[SQE_JMPTBL_SIZE];
} sqe_fw_header_t;

typedef enum {
    OP_NOP     = 0x00,
    OP_MOV     = 0x01,
    OP_MOVI    = 0x02,
    OP_MOVHI   = 0x03,
    OP_ADD     = 0x04,
    OP_ADDI    = 0x05,
    OP_SUB     = 0x06,
    OP_SUBI    = 0x07,
    OP_AND     = 0x08,
    OP_ANDI    = 0x09,
    OP_OR      = 0x0A,
    OP_ORI     = 0x0B,
    OP_XOR     = 0x0C,
    OP_XORI    = 0x0D,
    OP_SHL     = 0x0E,
    OP_SHR     = 0x0F,
    OP_BEQ     = 0x10,
    OP_BNE     = 0x11,
    OP_BLTU    = 0x12,
    OP_BGEU    = 0x13,
    OP_JMP     = 0x14,
    OP_CALL    = 0x15,
    OP_RET     = 0x16,
    OP_CREAD   = 0x17,
    OP_CWRITE  = 0x18,
    OP_LDW     = 0x19,
    OP_STW     = 0x1A,
    OP_PKTREAD = 0x1B,
    OP_PKTNEXT = 0x1C,
    OP_SPUSH   = 0x1D,
    OP_HALT    = 0x1E,
    OP_COUNT   = 0x1F
} sqe_opcode_t;

/* Control Register Map (0x00 .. 0x3F) */
typedef enum {
    CREG_FW_BOOT_STATE    = 0x00,
    CREG_STREAM_STATUS    = 0x01,
    CREG_PKT_OPCODE       = 0x02,
    CREG_PKT_COUNT        = 0x03,
    CREG_PKT_REM          = 0x04,
    CREG_STREAM_REWIND    = 0x05,
    CREG_SG_ENABLE_MASK   = 0x06,
    CREG_SG_DIRTY_MASK    = 0x07,
    CREG_ACTIVE_SG_SLOT   = 0x08,
    CREG_PREDICATE_VAL    = 0x09,
    CREG_LAST_MARKER      = 0x0A,
    CREG_FENCE_SEQ        = 0x0B,

    CREG_VP_XY            = 0x0C,
    CREG_VP_WH            = 0x0D,
    CREG_SCISSOR_XY       = 0x0E,
    CREG_SCISSOR_WH       = 0x0F,
    CREG_RASTER_STATE     = 0x10,
    CREG_DEPTH_STENCIL    = 0x11,
    CREG_BLEND_STATE      = 0x12,
    CREG_MRT_FORMAT       = 0x13,
    CREG_COLOR_BASE_VA    = 0x14,
    CREG_ZBUF_BASE_VA     = 0x15,
    CREG_VTX_BASE_VA      = 0x16,
    CREG_IDX_BASE_VA      = 0x17,
    CREG_VS_PROG_ID       = 0x18,
    CREG_FS_PROG_ID       = 0x19,
    CREG_CS_PROG_ID       = 0x1A,
    CREG_WORKGROUP_DIM    = 0x1B,
    CREG_PUSH_CONST_HASH  = 0x1C,
    CREG_DESC_TABLE_HASH  = 0x1D,
    CREG_DMA_SRC_VA       = 0x1E,
    CREG_DMA_DST_VA       = 0x1F,

    CREG_DMA_LEN_WORDS    = 0x20,
    CREG_DRAW_PRIM_ARG    = 0x21,
    CREG_BACKEND_EXEC     = 0x22,
    CREG_DRAW_COUNT       = 0x23,
    CREG_DISPATCH_COUNT   = 0x24,
    CREG_PKT_RETIRED      = 0x25,
    CREG_PERF_ACCUM_LO    = 0x26,
    CREG_PERF_ACCUM_HI    = 0x27,

    CREG_IOMMU_TTBR0_LO   = 0x28,
    CREG_IOMMU_TTBR0_HI   = 0x29,
    CREG_IOMMU_ASID       = 0x2A,
    CREG_IOMMU_TLB_INV    = 0x2B,
    CREG_APERTURE_BASE    = 0x2C,
    CREG_APERTURE_LIMIT   = 0x2D,
    CREG_TRAP_VECTOR      = 0x2E,
    CREG_PREEMPT_ADDR     = 0x2F,

    CREG_DEPTH_BIAS       = 0x30,
    CREG_BLEND_COLOR      = 0x31,
    CREG_CLIP_CTRL        = 0x32,
    CREG_TESS_LEVEL       = 0x33,
    CREG_BINNING_MODE     = 0x34,
    CREG_VTX_STRIDE       = 0x35,
    CREG_IDX_TYPE         = 0x36,
    CREG_TEX_SAMPLER_CFG  = 0x37,
    CREG_UBO_RANGE_CFG    = 0x38,
    CREG_SSBO_RANGE_CFG   = 0x39,
    CREG_ICACHE_TAG       = 0x3A,
    CREG_TILE_RESOLVE_CFG = 0x3B,
    CREG_OCCLUSION_ACCUM  = 0x3C,
    CREG_TIMESTAMP_LO     = 0x3D,
    CREG_CTX_BANK_SEL     = 0x3E,
    CREG_SCRATCH_REG      = 0x3F
} sqe_creg_id_t;

/* CREG_STREAM_STATUS bitfields */
#define SQE_SSTAT_DEPTH_MASK      0x00000007U
#define SQE_SSTAT_SG_SLOT_SHIFT   4U
#define SQE_SSTAT_SG_SLOT_MASK    0x000000F0U
#define SQE_SSTAT_CTX_SHIFT       8U
#define SQE_SSTAT_CTX_MASK        0x00000F00U
#define SQE_SSTAT_FLAG_ACTIVE     0x00010000U
#define SQE_SSTAT_FLAG_PRED_EN    0x00020000U
#define SQE_SSTAT_FLAG_COND_PASS  0x00040000U

/* CREG_BACKEND_EXEC trigger commands */
#define SQE_BACKEND_DRAW          1U
#define SQE_BACKEND_COMPUTE       2U
#define SQE_BACKEND_DMA_COPY      3U
#define SQE_BACKEND_DMA_FILL      4U
#define SQE_BACKEND_BLIT_2D       5U
#define SQE_BACKEND_EVENT_WRITE   6U

/* Microcode fault halt codes */
#define SQE_HALT_OK               0x0000U
#define SQE_HALT_BAD_PKT          0x0010U
#define SQE_HALT_PRIV_VIOLATION   0x0011U
#define SQE_HALT_IB_DEPTH         0x0012U
#define SQE_HALT_SG_NEST          0x0013U
#define SQE_HALT_BAD_ARG          0x0014U
#define SQE_HALT_BAD_ALIGN        0x0015U

static inline uint32_t sqe_enc_r(uint8_t op, uint8_t rd, uint8_t rs, uint8_t rt) {
    return ((uint32_t)(op & 0x3FU) << 26) |
           ((uint32_t)(rd & 0x1FU) << 21) |
           ((uint32_t)(rs & 0x1FU) << 16) |
           ((uint32_t)(rt & 0x1FU) << 11);
}

static inline uint32_t sqe_enc_i(uint8_t op, uint8_t rd, uint8_t rs, uint16_t imm16) {
    return ((uint32_t)(op & 0x3FU) << 26) |
           ((uint32_t)(rd & 0x1FU) << 21) |
           ((uint32_t)(rs & 0x1FU) << 16) |
           (uint32_t)imm16;
}

static inline uint8_t sqe_dec_op(uint32_t insn)   { return (uint8_t)((insn >> 26) & 0x3FU); }
static inline uint8_t sqe_dec_rd(uint32_t insn)   { return (uint8_t)((insn >> 21) & 0x1FU); }
static inline uint8_t sqe_dec_rs(uint32_t insn)   { return (uint8_t)((insn >> 16) & 0x1FU); }
static inline uint8_t sqe_dec_rt(uint32_t insn)   { return (uint8_t)((insn >> 11) & 0x1FU); }
static inline uint16_t sqe_dec_uimm(uint32_t insn){ return (uint16_t)(insn & 0xFFFFU); }
static inline int16_t sqe_dec_simm(uint32_t insn) { return (int16_t)(uint16_t)(insn & 0xFFFFU); }

typedef enum {
    INSN_FMT_NONE = 0,     /* nop, ret, pktnext */
    INSN_FMT_RD,           /* pktread $rd */
    INSN_FMT_RD_RS,        /* mov $rd, $rs ; spush $rd, $rs */
    INSN_FMT_RD_RS_RT,     /* add, sub, and, or, xor */
    INSN_FMT_RD_UIMM,      /* movi, movhi */
    INSN_FMT_RD_RS_UIMM,   /* subi, andi, ori, xori, shl, shr, ldw, stw */
    INSN_FMT_RD_RS_SIMM,   /* addi */
    INSN_FMT_BRANCH,       /* beq, bne, bltu, bgeu ($rd, $rs, @rel) */
    INSN_FMT_TARGET,       /* jmp, call (@abs_pc) */
    INSN_FMT_CREAD,        /* cread $rd, CREG */
    INSN_FMT_CWRITE,       /* cwrite CREG, $rs */
    INSN_FMT_UIMM_ONLY     /* halt uimm16 */
} sqe_insn_fmt_t;

typedef struct {
    uint8_t        opcode;
    const char    *mnemonic;
    sqe_insn_fmt_t fmt;
} sqe_op_info_t;

const sqe_op_info_t *sqe_isa_lookup_op(uint8_t opcode);
const sqe_op_info_t *sqe_isa_lookup_mnemonic(const char *mnemonic);
const char *sqe_isa_creg_name(uint16_t creg_id);
int sqe_isa_creg_by_name(const char *name);
const char *sqe_isa_pkt_name(uint8_t pkt_opc);
int sqe_isa_pkt_by_name(const char *name);
uint32_t sqe_crc32(const void *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SQE_ISA_H */
