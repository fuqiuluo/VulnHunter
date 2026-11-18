#ifndef SQE_VM_H
#define SQE_VM_H

#include "sqe_isa.h"
#include "sqe_pkt.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Physical & Virtual Memory Geometry */
#define SQE_PHYS_RAM_SIZE        (4U * 1024U * 1024U) /* 4 MiB Physical RAM */
#define SQE_PAGE_SIZE            4096U
#define SQE_PAGE_MASK            0xFFFFF000U
#define SQE_NUM_PTES             1024U                /* Maps 4 MiB VA space [0x000000..0x3FFFFF] */

/* Physical Regions */
#define SQE_RING0_PA             0x00001000U
#define SQE_DEFAULT_PT_PA        0x00004000U
#define SQE_PREEMPT_SAVE_PA      0x00008000U

/* GPU Virtual Address Regions in Default User Context */
#define SQE_RING0_VA             0x00001000U
#define SQE_USER_VA_BASE         0x00100000U
#define SQE_USER_VA_LIMIT        0x00200000U          /* 1 MiB user command & buffer region */
#define SQE_RT_VA_BASE           0x00200000U
#define SQE_RT_VA_LIMIT          0x00300000U          /* 1 MiB render target / output region */
#define SQE_RT_DIGEST_BYTES      4096U

/* IOMMU PTE Bits */
#define SQE_PTE_VALID            0x00000001U
#define SQE_PTE_READ             0x00000002U
#define SQE_PTE_WRITE            0x00000004U
#define SQE_PTE_RING0_ONLY       0x00000008U

/* Hardware Execution Limits */
#define SQE_MAX_STREAM_DEPTH     4U   /* 0=Ring0, 1=IB1, 2=IB2, 3=IB3, 4=StateGroup */
#define SQE_MAX_CALL_DEPTH       8U
#define SQE_MAX_PKT_PAYLOAD      64U
#define SQE_MAX_CYCLES           250000U

typedef enum {
    SQE_OK               = 0,
    SQE_ERR_IO           = 1,
    SQE_ERR_FW_INVALID   = 2,
    SQE_ERR_CSB_FORMAT   = 3,
    SQE_ERR_MMU_FAULT    = 4,
    SQE_ERR_UC_FAULT     = 5,
    SQE_ERR_CYCLE_LIMIT  = 6
} sqe_status_t;

typedef struct {
    uint32_t cur_va;
    uint32_t rem_dwords;
    uint32_t last_pkt_va;
    uint32_t last_pkt_rem;
} sqe_stream_frame_t;

typedef struct {
    /* Loaded Firmware Image */
    sqe_fw_header_t    fw_hdr;
    uint32_t           code[SQE_MAX_CODE_WORDS];

    /* Microcontroller State */
    uint32_t           pc;
    uint32_t           gprs[SQE_NUM_GPRS];
    uint32_t           cregs[SQE_NUM_CREGS];
    uint32_t           sram[SQE_SRAM_WORDS];

    uint32_t           call_stack[SQE_MAX_CALL_DEPTH];
    uint32_t           call_sp;

    /* Stream Fetcher Stack (depth 0..4) */
    sqe_stream_frame_t stream_stack[SQE_MAX_STREAM_DEPTH + 1U];
    uint32_t           stream_depth;

    /* Current Packet Payload FIFO */
    uint32_t           pkt_fifo[SQE_MAX_PKT_PAYLOAD];
    uint32_t           pkt_idx;
    uint32_t           pkt_cnt;

    /* Execution Bookkeeping */
    uint32_t           halted;
    uint16_t           halt_code;
    uint64_t           cycles;
    uint64_t           pipeline_hash;

    /* Physical Memory Backing */
    uint8_t           *phys_ram;
} sqe_vm_t;

typedef struct {
    uint32_t session_id;
    uint32_t draw_count;
    uint32_t dispatch_count;
    uint32_t pkt_retired;
    uint16_t halt_code;
    uint64_t output_digest;
} sqe_exec_summary_t;

sqe_status_t sqe_vm_init(sqe_vm_t *vm);
void sqe_vm_destroy(sqe_vm_t *vm);
sqe_status_t sqe_vm_load_firmware_file(sqe_vm_t *vm, const char *fw_path);
sqe_status_t sqe_vm_load_firmware_mem(sqe_vm_t *vm, const uint8_t *buf, size_t len);
sqe_status_t sqe_vm_exec_csb(sqe_vm_t *vm, const uint8_t *csb_buf, size_t csb_len, sqe_exec_summary_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SQE_VM_H */
