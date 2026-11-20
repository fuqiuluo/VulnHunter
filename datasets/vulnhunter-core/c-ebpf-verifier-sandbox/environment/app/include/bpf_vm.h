#ifndef BPF_VM_H
#define BPF_VM_H

/*
 * bpf_sandbox — Embedded Register-Based Bytecode Static Verifier & Arena VM
 *
 * Register ABI:
 *   R0      : Return value from helpers, subprogram calls, and program exit
 *   R1..R5  : Caller-saved argument / scratch registers (R1 = REG_CTX_PTR at entry)
 *   R6..R9  : Callee-saved registers preserved across helpers & OP_CALL_REL
 *   R10     : Read-only frame pointer to top of current frame's 512-byte stack
 *
 * Context Descriptor (REG_CTX_PTR, read-only via LDX_DW):
 *   [ctx + 0] : uint64_t data    -> yields REG_PKT_PTR at offset 0
 *   [ctx + 8] : uint64_t pkt_len -> yields REG_SCALAR tagged with is_pkt_len
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BPF_MAX_REGS            11
#define BPF_STACK_SIZE          512
#define BPF_STACK_SLOTS         (BPF_STACK_SIZE / 8)
#define BPF_MAX_CALL_DEPTH      4
#define BPF_MAX_FRAMES          (BPF_MAX_CALL_DEPTH + 1)
#define BPF_MAX_INSNS           1024
#define BPF_MAX_MAPS            8
#define BPF_MAX_MAP_ENTRIES     64
#define BPF_MAX_MAP_VALUE_SIZE  512
#define BPF_MAX_PKT_SIZE        4096
#define BPF_MAX_VAR_OFF         65536u
#define BPF_MAX_VERIFY_STEPS    32768u
#define BPF_MAX_RUN_STEPS       65536u
#define BPF_VISITED_PER_PC      8u

enum {
    BPF_REG_0 = 0, BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5,
    BPF_REG_6, BPF_REG_7, BPF_REG_8, BPF_REG_9, BPF_REG_10
};

#define BPF_CLASS(op)   ((uint8_t)((op) & 0x07u))
#define CLS_LD          0x00u
#define CLS_LDX         0x01u
#define CLS_ST          0x02u
#define CLS_STX         0x03u
#define CLS_ALU32       0x04u
#define CLS_JMP64       0x05u
#define CLS_JMP32       0x06u
#define CLS_ALU64       0x07u

#define BPF_SRC(op)     ((uint8_t)((op) & 0x08u))
#define BPF_K           0x00u
#define BPF_X           0x08u
#define BPF_OP(op)      ((uint8_t)((op) & 0xf0u))
#define BPF_SIZE(op)    ((uint8_t)((op) & 0x18u))
#define BPF_MODE(op)    ((uint8_t)((op) & 0xe0u))
#define BPF_W           0x00u
#define BPF_H           0x08u
#define BPF_B           0x10u
#define BPF_DW          0x18u
#define BPF_IMM_MODE    0x00u
#define BPF_MEM_MODE    0x60u

#define OP_LDDW_IMM     (CLS_LD  | BPF_DW | BPF_IMM_MODE)
#define OP_LDX_B        (CLS_LDX | BPF_B  | BPF_MEM_MODE)
#define OP_LDX_H        (CLS_LDX | BPF_H  | BPF_MEM_MODE)
#define OP_LDX_W        (CLS_LDX | BPF_W  | BPF_MEM_MODE)
#define OP_LDX_DW       (CLS_LDX | BPF_DW | BPF_MEM_MODE)
#define OP_ST_B         (CLS_ST  | BPF_B  | BPF_MEM_MODE)
#define OP_ST_H         (CLS_ST  | BPF_H  | BPF_MEM_MODE)
#define OP_ST_W         (CLS_ST  | BPF_W  | BPF_MEM_MODE)
#define OP_ST_DW        (CLS_ST  | BPF_DW | BPF_MEM_MODE)
#define OP_STX_B        (CLS_STX | BPF_B  | BPF_MEM_MODE)
#define OP_STX_H        (CLS_STX | BPF_H  | BPF_MEM_MODE)
#define OP_STX_W        (CLS_STX | BPF_W  | BPF_MEM_MODE)
#define OP_STX_DW       (CLS_STX | BPF_DW | BPF_MEM_MODE)

#define ALU_ADD  0x00u
#define ALU_SUB  0x10u
#define ALU_MUL  0x20u
#define ALU_DIV  0x30u
#define ALU_OR   0x40u
#define ALU_AND  0x50u
#define ALU_LSH  0x60u
#define ALU_RSH  0x70u
#define ALU_NEG  0x80u
#define ALU_MOD  0x90u
#define ALU_XOR  0xa0u
#define ALU_MOV  0xb0u
#define ALU_ARSH 0xc0u

#define JMP_JA   0x00u
#define JMP_JEQ  0x10u
#define JMP_JGT  0x20u
#define JMP_JGE  0x30u
#define JMP_JSET 0x40u
#define JMP_JNE  0x50u
#define JMP_JSGT 0x60u
#define JMP_JSGE 0x70u
#define JMP_JLT  0xa0u
#define JMP_JLE  0xb0u
#define JMP_JSLT 0xc0u
#define JMP_JSLE 0xd0u

#define OP_CALL_HELPER  0x85u
#define OP_CALL_REL     0x8du
#define OP_EXIT         0x95u

#define BPF_CTX_OFF_DATA     0
#define BPF_CTX_OFF_PKT_LEN  8

typedef enum {
    HELPER_NONE            = 0,
    HELPER_MAP_LOOKUP_ELEM = 1,
    HELPER_MAP_UPDATE_ELEM = 2,
    HELPER_PKT_RESIZE      = 3,
    HELPER_CSUM_FOLD       = 4
} BpfHelperId;

typedef struct {
    uint8_t opcode;
    uint8_t dst_reg;
    uint8_t src_reg;
    int16_t off;
    int32_t imm;
} BpfInsn;

#define BPF_INSN(op, dst, src, ofs, im) \
    ((BpfInsn){ (uint8_t)(op), (uint8_t)(dst), (uint8_t)(src), (int16_t)(ofs), (int32_t)(im) })
#define BPF_ALU64_REG(op, dst, src)      BPF_INSN(CLS_ALU64 | BPF_X | (op), (dst), (src), 0, 0)
#define BPF_ALU64_IMM(op, dst, imm)      BPF_INSN(CLS_ALU64 | BPF_K | (op), (dst), 0, 0, (imm))
#define BPF_ALU32_REG(op, dst, src)      BPF_INSN(CLS_ALU32 | BPF_X | (op), (dst), (src), 0, 0)
#define BPF_ALU32_IMM(op, dst, imm)      BPF_INSN(CLS_ALU32 | BPF_K | (op), (dst), 0, 0, (imm))
#define BPF_JMP64_REG(op, dst, src, ofs) BPF_INSN(CLS_JMP64 | BPF_X | (op), (dst), (src), (ofs), 0)
#define BPF_JMP64_IMM(op, dst, imm, ofs) BPF_INSN(CLS_JMP64 | BPF_K | (op), (dst), 0, (ofs), (imm))
#define BPF_JMP32_REG(op, dst, src, ofs) BPF_INSN(CLS_JMP32 | BPF_X | (op), (dst), (src), (ofs), 0)
#define BPF_JMP32_IMM(op, dst, imm, ofs) BPF_INSN(CLS_JMP32 | BPF_K | (op), (dst), 0, (ofs), (imm))
#define BPF_JMP_JA(ofs)                  BPF_INSN(CLS_JMP64 | BPF_K | JMP_JA, 0, 0, (ofs), 0)
#define BPF_LDX_MEM(sz, dst, src, ofs)   BPF_INSN(CLS_LDX | (sz) | BPF_MEM_MODE, (dst), (src), (ofs), 0)
#define BPF_STX_MEM(sz, dst, src, ofs)   BPF_INSN(CLS_STX | (sz) | BPF_MEM_MODE, (dst), (src), (ofs), 0)
#define BPF_ST_MEM(sz, dst, ofs, imm)    BPF_INSN(CLS_ST  | (sz) | BPF_MEM_MODE, (dst), 0, (ofs), (imm))
#define BPF_LDDW_LO(dst, lo32)           BPF_INSN(OP_LDDW_IMM, (dst), 0, 0, (int32_t)(uint32_t)(lo32))
#define BPF_LDDW_HI(hi32)                BPF_INSN(0, 0, 0, 0, (int32_t)(uint32_t)(hi32))
#define BPF_CALL_HELPER_INSN(hid)        BPF_INSN(OP_CALL_HELPER, 0, 0, 0, (int32_t)(hid))
#define BPF_CALL_REL_INSN(rel_ofs)       BPF_INSN(OP_CALL_REL, 0, 1, 0, (int32_t)(rel_ofs))
#define BPF_EXIT_INSN()                  BPF_INSN(OP_EXIT, 0, 0, 0, 0)

typedef enum {
    REG_UNINIT        = 0,
    REG_SCALAR        = 1,
    REG_CTX_PTR       = 2,
    REG_PKT_PTR       = 3,
    REG_MAP_VALUE_PTR = 4,
    REG_STACK_PTR     = 5
} BpfRegType;

#define PTR_TO_CTX        REG_CTX_PTR
#define PTR_TO_PACKET     REG_PKT_PTR
#define PTR_TO_MAP_VALUE  REG_MAP_VALUE_PTR
#define PTR_TO_STACK      REG_STACK_PTR

typedef struct {
    uint64_t umin64;
    uint64_t umax64;
    int64_t  smin64;
    int64_t  smax64;
} ScalarBounds;

typedef struct {
    BpfRegType   type;
    uint32_t     id;
    uint32_t     map_id;
    uint8_t      frame_owner;
    bool         nullable;
    bool         is_pkt_len;
    int32_t      fixed_off;
    uint64_t     idx_umin;
    uint64_t     idx_umax;
    ScalarBounds bounds;
} BpfRegState;

typedef enum {
    STACK_UNINIT    = 0,
    STACK_MISC      = 1,
    STACK_SPILL_PTR = 2
} BpfStackByteType;

typedef struct {
    BpfRegState regs[BPF_MAX_REGS];
    uint8_t     stack_bytes[BPF_STACK_SIZE];
    bool        slot_has_spill[BPF_STACK_SLOTS];
    BpfRegState spill_reg[BPF_STACK_SLOTS];
} BpfFrameState;

typedef struct {
    uint32_t      frame_depth;
    uint32_t      call_ret_pc[BPF_MAX_CALL_DEPTH];
    uint32_t      pkt_range;
    uint32_t      next_ptr_id;
    BpfFrameState frames[BPF_MAX_FRAMES];
} BpfVerifierState;

typedef enum {
    BPF_OK                = 0,
    BPF_ERR_INVALID_PROG  = 1,
    BPF_ERR_CFG_CYCLE     = 2,
    BPF_ERR_CFG_TARGET    = 3,
    BPF_ERR_UNINIT_REG    = 4,
    BPF_ERR_READ_ONLY_REG = 5,
    BPF_ERR_TYPE_MISMATCH = 6,
    BPF_ERR_OOB_ACCESS    = 7,
    BPF_ERR_NULL_PTR      = 8,
    BPF_ERR_STACK_ACCESS  = 9,
    BPF_ERR_CALL_DEPTH    = 10,
    BPF_ERR_HELPER_ARG    = 11,
    BPF_ERR_COMPLEXITY    = 12,
    BPF_ERR_DIV_ZERO      = 13,
    BPF_ERR_RUNTIME       = 14
} BpfStatus;

typedef struct {
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
} BpfMapDef;

typedef struct {
    const BpfInsn *insns;
    uint32_t       insn_cnt;
    uint32_t       num_maps;
    BpfMapDef      maps[BPF_MAX_MAPS];
} BpfProgram;

typedef struct {
    BpfStatus status;
    uint32_t  err_pc;
    uint32_t  insns_explored;
    uint32_t  states_pruned;
    char      message[160];
} BpfVerifyReport;

typedef struct BpfVisitedEntry {
    BpfVerifierState        state;
    struct BpfVisitedEntry *next;
} BpfVisitedEntry;

typedef struct {
    bool             is_leader[BPF_MAX_INSNS];
    bool             is_lddw_hi[BPF_MAX_INSNS];
    uint8_t          visited_cnt[BPF_MAX_INSNS];
    BpfVisitedEntry *visited[BPF_MAX_INSNS];
} BpfCfgState;

typedef struct {
    uint32_t       map_id;
    uint32_t       key;
    const uint8_t *value;
    uint32_t       value_len;
} BpfMapSeed;

typedef struct {
    const uint8_t    *pkt_init;
    uint32_t          pkt_init_len;
    const BpfMapSeed *map_seeds;
    uint32_t          num_map_seeds;
} BpfArenaSpec;

typedef struct {
    BpfStatus status;
    uint64_t  r0;
    uint32_t  final_pkt_len;
    uint64_t  pkt_fnv1a;
    uint64_t  map_fnv1a;
    uint32_t  steps_executed;
} BpfExecResult;

#define BPFS_MAGIC   0x53465042u
#define BPFS_VERSION 1u

typedef struct {
    char       name[48];
    BpfInsn   *insns;
    uint32_t   insn_cnt;
    uint32_t   num_maps;
    BpfMapDef  maps[BPF_MAX_MAPS];
    uint8_t   *pkt_init;
    uint32_t   pkt_init_len;
    BpfMapSeed *seeds;
    uint8_t   **seed_bufs;
    uint32_t   num_seeds;
} BpfSuiteCase;

typedef struct {
    uint32_t      case_cnt;
    BpfSuiteCase *cases;
} BpfSuite;

void      cfg_init(BpfCfgState *cfg);
void      cfg_destroy(BpfCfgState *cfg);
BpfStatus bpf_check_cfg(const BpfProgram *prog, BpfCfgState *cfg, BpfVerifyReport *rep);
bool      state_subsumes(const BpfVerifierState *cached, const BpfVerifierState *cur);
bool      cfg_is_subsumed(const BpfCfgState *cfg, uint32_t pc, const BpfVerifierState *cur);
void      cfg_record_visited(BpfCfgState *cfg, uint32_t pc, const BpfVerifierState *st);

void      bounds_init_unknown(ScalarBounds *b);
void      bounds_init_const(ScalarBounds *b, uint64_t val);
bool      bounds_is_const(const ScalarBounds *b);
void      bounds_normalize(ScalarBounds *b);
void      reg_set_uninit(BpfRegState *r);
void      reg_set_scalar_const(BpfRegState *r, uint64_t val);
void      reg_set_scalar_unknown(BpfRegState *r);
BpfStatus bpf_eval_scalar_alu(const BpfInsn *insn, BpfFrameState *frame, uint32_t pc, BpfVerifyReport *rep);
BpfStatus bpf_refine_branch(const BpfInsn *insn, const BpfVerifierState *base,
                            BpfVerifierState *fallthrough_st, bool *fallthrough_reachable,
                            BpfVerifierState *taken_st, bool *taken_reachable,
                            uint32_t pc, BpfVerifyReport *rep);

uint32_t  bpf_mem_access_size(uint8_t size_code);
bool      bpf_reg_is_pointer(BpfRegType t);
BpfStatus bpf_verify_ptr_alu(const BpfInsn *insn, BpfFrameState *frame, uint32_t pc, BpfVerifyReport *rep);
BpfStatus bpf_verify_ldx(const BpfProgram *prog, const BpfInsn *insn, BpfVerifierState *st, uint32_t pc, BpfVerifyReport *rep);
BpfStatus bpf_verify_store(const BpfProgram *prog, const BpfInsn *insn, BpfVerifierState *st, uint32_t pc, BpfVerifyReport *rep);
BpfStatus bpf_verify_helper_call(const BpfProgram *prog, int32_t helper_id, BpfVerifierState *st, uint32_t pc, BpfVerifyReport *rep);
BpfStatus bpf_verify_call_rel(const BpfInsn *insn, BpfVerifierState *st, uint32_t pc, uint32_t *target_pc, BpfVerifyReport *rep);
BpfStatus bpf_verify_exit(BpfVerifierState *st, uint32_t pc, bool *prog_done, uint32_t *ret_pc, BpfVerifyReport *rep);

BpfStatus bpf_verify_program(const BpfProgram *prog, BpfVerifyReport *rep);
uint64_t  bpf_fnv1a64(const uint8_t *data, size_t len);
uint16_t  bpf_csum_fold16(const uint8_t *data, size_t len);
BpfStatus bpf_interp_run(const BpfProgram *prog, const BpfArenaSpec *spec, BpfExecResult *out);
int       bpf_suite_load_file(const char *path, BpfSuite *out_suite, char *err_buf, size_t err_cap);
void      bpf_suite_free(BpfSuite *suite);

#endif /* BPF_VM_H */
