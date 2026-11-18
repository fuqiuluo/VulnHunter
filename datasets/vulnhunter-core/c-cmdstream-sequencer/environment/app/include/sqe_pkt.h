#ifndef SQE_PKT_H
#define SQE_PKT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Command-Stream Submission Bundle (CSB1) Wire Format (little-endian):
 *
 * Header (24 bytes):
 *   [0..3]   uint32_t magic          (CSB_MAGIC = 0x43534231 "CSB1")
 *   [4..7]   uint32_t session_id
 *   [8..11]  uint32_t ib1_va         (Primary user IB1 GPU VA in [0x00100000..0x001FFFFC])
 *   [12..15] uint32_t ib1_dwords     (Number of 32-bit words in IB1, 1..16384)
 *   [16..19] uint32_t segment_count  (Number of mapped user segments, 1..32)
 *   [20..23] uint32_t flags          (Reserved, 0)
 *
 * Followed by `segment_count` segments:
 *   [0..3]   uint32_t dst_va         (4-byte aligned GPU VA in [0x00100000..0x001FFFFC])
 *   [4..7]   uint32_t byte_len       (Multiple of 4, non-zero, within user VA range)
 *   [8..]    uint8_t  data[byte_len]
 */

#define CSB_MAGIC                0x43534231U
#define CSB_MAX_SEGMENTS         32U
#define CSB_MAX_IB_DWORDS        16384U

/* Type-7 Command Packet Header: [31:28]=0x7, [23:16]=opcode (6-bit), [15:0]=payload_dwords */
#define SQE_PKT7_TAG             0x7U
#define SQE_PKT7_HDR(opc, cnt)   ((0x70000000U) | (((uint32_t)(opc) & 0x3FU) << 16) | ((uint32_t)(cnt) & 0xFFFFU))

/* State Group Control Flags (for PKT_SET_STATE_GROUP word0: [23:16]=flags, [7:0]=slot_id) */
#define SQE_SG_FLAG_ENABLE       0x01U
#define SQE_SG_FLAG_DISABLE      0x02U
#define SQE_SG_FLAG_PINNED       0x04U
#define SQE_MAX_SG_SLOTS         16U

/* Command Packet Opcodes (0x00 .. 0x3F) */
typedef enum {
    PKT_ILLEGAL                 = 0x00,

    /* Queue & Stream Control */
    PKT_NOP                     = 0x01,
    PKT_INDIRECT_BUFFER         = 0x02, /* payload: [gpu_va, dwords] */
    PKT_COND_EXEC               = 0x03, /* payload: [match_val, skip_flag] */
    PKT_SET_PREDICATE           = 0x04, /* payload: [pred_val] */
    PKT_CONTEXT_SWITCH_YIELD    = 0x05, /* payload: [hint_slice] */
    PKT_WAIT_REG_MEM            = 0x06, /* payload: [creg_idx, mask, ref_val] */
    PKT_EVENT_WRITE             = 0x07, /* payload: [dst_va, event_tag] */
    PKT_FENCE_SIGNAL            = 0x08, /* payload: [seq_no] */
    PKT_SET_MARKER              = 0x09, /* payload: [marker_id] */

    /* Deferred Draw-State Group Management */
    PKT_SET_STATE_GROUP         = 0x0A, /* payload: [slot_and_flags, sg_va, sg_dwords] */
    PKT_MASK_STATE_GROUP        = 0x0B, /* payload: [enable_mask, dirty_mask] */
    PKT_CLEAR_STATE_GROUPS      = 0x0C, /* payload: [clear_key] */
    PKT_LATCH_STATE_SUMMARY     = 0x0D, /* payload: [slot_id] */

    /* Graphics Pipeline State */
    PKT_SET_VIEWPORT            = 0x10, /* payload: [vp_idx, xy_packed, wh_packed] */
    PKT_SET_SCISSOR             = 0x11, /* payload: [sc_idx, xy_packed, wh_packed] */
    PKT_SET_RASTER_MODE         = 0x12, /* payload: [raster_bits] */
    PKT_SET_DEPTH_BIAS          = 0x13, /* payload: [const_bias, slope_bias] */
    PKT_SET_DEPTH_STENCIL       = 0x14, /* payload: [ds_ctrl, stencil_ref] */
    PKT_SET_BLEND_CONST         = 0x15, /* payload: [rgba_packed] */
    PKT_SET_BLEND_CTRL          = 0x16, /* payload: [rt_idx, blend_eq] */
    PKT_SET_COLOR_TARGET        = 0x17, /* payload: [rt_va, fmt_msaa] */
    PKT_SET_Z_TARGET            = 0x18, /* payload: [z_va, z_fmt] */
    PKT_SET_MSAA_CONFIG         = 0x19, /* payload: [sample_cnt, sample_mask] */
    PKT_SET_VTX_BINDING         = 0x1A, /* payload: [slot, vtx_va, stride] */
    PKT_SET_IDX_BUFFER          = 0x1B, /* payload: [idx_va, idx_type] */
    PKT_SET_VTX_ATTR            = 0x1C, /* payload: [attr_idx, fmt_offset] */
    PKT_SET_CLIP_CONTROL        = 0x1D, /* payload: [clip_bits] */
    PKT_SET_TESSELLATION        = 0x1E, /* payload: [outer_lvl, inner_lvl] */
    PKT_SET_BINNING_CFG         = 0x1F, /* payload: [tile_wh, bin_mode] */

    /* Shader & Resource Descriptors */
    PKT_LOAD_VS_PROGRAM         = 0x20, /* payload: [prog_id, entry_off] */
    PKT_LOAD_FS_PROGRAM         = 0x21, /* payload: [prog_id, entry_off] */
    PKT_LOAD_CS_PROGRAM         = 0x22, /* payload: [prog_id, entry_off] */
    PKT_SET_PUSH_CONST          = 0x23, /* payload: [stage_idx, c0, c1] */
    PKT_BIND_TEX_DESC           = 0x24, /* payload: [unit, tex_va, dim_fmt] */
    PKT_BIND_SAMPLER_DESC       = 0x25, /* payload: [unit, filter_wrap] */
    PKT_BIND_UBO_RANGE          = 0x26, /* payload: [slot, ubo_va, size_words] */
    PKT_BIND_SSBO_RANGE         = 0x27, /* payload: [slot, ssbo_va, size_words] */
    PKT_SET_LOCAL_WORKGROUP     = 0x28, /* payload: [wg_xyz] */
    PKT_INVALIDATE_ICACHE       = 0x29, /* payload: [scope_mask] */

    /* Draw, Compute & DMA Backend Operations */
    PKT_DRAW_AUTO               = 0x2A, /* payload: [vtx_count] */
    PKT_DRAW_INDEXED            = 0x2B, /* payload: [idx_count, vtx_base] */
    PKT_DRAW_INSTANCED          = 0x2C, /* payload: [vtx_count, inst_count] */
    PKT_DISPATCH_COMPUTE        = 0x2D, /* payload: [groups_x, groups_y, groups_z] */
    PKT_BLIT_2D_RECT            = 0x2E, /* payload: [src_va, dst_va, wh_words] */
    PKT_DMA_FILL_BUFFER         = 0x2F, /* payload: [dst_va, fill_val, word_cnt] */
    PKT_DMA_COPY_BUFFER         = 0x30, /* payload: [src_va, dst_va, word_cnt] */
    PKT_RESOLVE_TILE_BUFFER     = 0x31, /* payload: [resolve_va, resolve_mode] */

    /* Telemetry & Counters */
    PKT_PERF_SAMPLE             = 0x32, /* payload: [cntr_sel, weight] */
    PKT_TIMESTAMP_WRITE         = 0x33, /* payload: [dst_va, clock_sel] */
    PKT_ACCUM_OCCLUSION         = 0x34, /* payload: [sample_delta] */
    PKT_PIPELINE_STAT_SNAP      = 0x35, /* payload: [stat_mask] */

    /* Ring-0 Supervisor Control Packets */
    PKT_IOMMU_TTBR_UPDATE       = 0x38, /* payload: [ttbr0_lo, ttbr0_hi, asid] */
    PKT_APERTURE_WIN_CFG        = 0x39, /* payload: [base_addr, limit_addr] */
    PKT_TRAP_VECTOR_SET         = 0x3A, /* payload: [trap_vec_addr] */
    PKT_PREEMPT_RING_CFG        = 0x3B, /* payload: [save_area_pa] */
    PKT_RING_BOOTSTRAP_IB1      = 0x3C, /* payload: [ib1_va, ib1_dwords] */
    PKT_RING_COMPLETE           = 0x3D  /* payload: [] */
} sqe_pkt_opc_t;

#ifdef __cplusplus
}
#endif

#endif /* SQE_PKT_H */
