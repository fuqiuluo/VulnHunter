#ifndef VMM_TRACE_H
#define VMM_TRACE_H

#include "vmm_mmu.h"

#define VMM_TRACE_MAGIC          0x314D4D56U /* "VMM1" */
#define VMM_TRACE_MAX_WORKERS    8U
#define VMM_TRACE_MAX_CMDS       4096U
#define VMM_TRACE_MAX_REPEAT     20000U

typedef enum {
    VMM_OP_GUEST_LOAD     = 0x01,
    VMM_OP_GUEST_STORE    = 0x02,
    VMM_OP_HOST_DMA_WRITE = 0x03,
    VMM_OP_HOST_PATCH     = 0x04,
    VMM_OP_BALLOON_ZAP    = 0x05,
    VMM_OP_PROTECT_SLOT   = 0x06,
} vmm_trace_opcode_t;

#define VMM_CMD_ALLOW_FAULT      0x01U

typedef struct {
    uint32_t magic;
    uint32_t image_seed;
    uint16_t slot_count;
    uint16_t worker_count;
    uint32_t flags;
    uint64_t reserved;
} vmm_trace_header_t;

typedef struct {
    uint32_t slot_id;
    uint32_t slot_flags;
    uint64_t base_gpa;
    uint32_t npages;
    uint32_t image_base_page;
} vmm_trace_slot_desc_t;

typedef struct {
    uint32_t worker_id;
    uint32_t repeat_count;
    uint32_t cmd_count;
    uint32_t reserved;
} vmm_trace_worker_hdr_t;

typedef struct {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t len;
    uint32_t aux;
    uint64_t gpa;
    uint64_t pattern;
} vmm_trace_cmd_t;

typedef struct {
    uint32_t worker_count;
    uint64_t ops_retired;
    uint64_t faults;
    uint64_t cow_splits;
    uint64_t balloon_zaps;
    uint64_t guest_digest;
    uint64_t image_ro_digest;
    uint64_t baseline_ro_digest;
} vmm_trace_summary_t;

vmm_status_t vmm_exec_trace_bytes(
    const uint8_t *buf,
    size_t len,
    vmm_trace_summary_t *out_summary
);

#endif /* VMM_TRACE_H */
