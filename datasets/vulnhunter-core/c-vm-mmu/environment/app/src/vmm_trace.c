#include "vmm_trace.h"

#include <sched.h>
#include <stdlib.h>
#include <string.h>

#define VMM_MAX_TOTAL_OPS 300000ULL

typedef struct {
    uint32_t         worker_id;
    uint32_t         repeat_count;
    uint32_t         cmd_count;
    vmm_trace_cmd_t *cmds;
} parsed_worker_t;

typedef struct {
    vmm_instance_t        *vm;
    const parsed_worker_t *spec;
    uint32_t               vcpu_slot;
    uint32_t               total_workers;
    _Atomic uint32_t      *ready_count;
    _Atomic int           *start_gate;
    _Atomic int           *abort_flag;
    vmm_status_t           status;
    uint64_t               retired;
} worker_ctx_t;

static void fill_pattern_buffer(uint8_t *buf, size_t len, uint64_t pattern) {
    uint8_t pat_bytes[8];
    for (size_t b = 0; b < 8U; b++) {
        pat_bytes[b] = (uint8_t)((pattern >> (b * 8U)) & 0xFFU);
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = pat_bytes[i & 7U];
    }
}

static void *trace_worker_entry(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    uint8_t scratch[VMM_PAGE_SIZE];

    atomic_fetch_add_explicit(ctx->ready_count, 1U, memory_order_acq_rel);
    while (atomic_load_explicit(ctx->start_gate, memory_order_acquire) == 0) {
        sched_yield();
    }

    ctx->status = VMM_OK;
    ctx->retired = 0ULL;

    for (uint32_t r = 0; r < ctx->spec->repeat_count; r++) {
        if (atomic_load_explicit(ctx->abort_flag, memory_order_relaxed) != 0) {
            break;
        }

        for (uint32_t c = 0; c < ctx->spec->cmd_count; c++) {
            if (atomic_load_explicit(ctx->abort_flag, memory_order_relaxed) != 0) {
                break;
            }

            const vmm_trace_cmd_t *cmd = &ctx->spec->cmds[c];
            vmm_status_t st = VMM_OK;

            switch (cmd->opcode) {
                case VMM_OP_GUEST_LOAD:
                    if (cmd->len == 0U || cmd->len > VMM_PAGE_SIZE) {
                        st = VMM_ERR_INVALID;
                    } else {
                        st = vmm_guest_load(ctx->vm, ctx->vcpu_slot, cmd->gpa, scratch, cmd->len);
                    }
                    break;

                case VMM_OP_GUEST_STORE:
                    if (cmd->len == 0U || cmd->len > VMM_PAGE_SIZE) {
                        st = VMM_ERR_INVALID;
                    } else {
                        fill_pattern_buffer(scratch, cmd->len, cmd->pattern);
                        st = vmm_guest_store(ctx->vm, ctx->vcpu_slot, cmd->gpa, scratch, cmd->len);
                    }
                    break;

                case VMM_OP_HOST_DMA_WRITE:
                    if (cmd->len == 0U || cmd->len > VMM_PAGE_SIZE) {
                        st = VMM_ERR_INVALID;
                    } else {
                        fill_pattern_buffer(scratch, cmd->len, cmd->pattern);
                        st = vmm_host_write_gpa(ctx->vm, cmd->gpa, scratch, cmd->len, false);
                    }
                    break;

                case VMM_OP_HOST_PATCH:
                    if (cmd->len == 0U || cmd->len > VMM_PAGE_SIZE) {
                        st = VMM_ERR_INVALID;
                    } else {
                        fill_pattern_buffer(scratch, cmd->len, cmd->pattern);
                        st = vmm_host_write_gpa(ctx->vm, cmd->gpa, scratch, cmd->len, true);
                    }
                    break;

                case VMM_OP_BALLOON_ZAP:
                    if (cmd->len == 0U || cmd->len > 256U) {
                        st = VMM_ERR_INVALID;
                    } else {
                        st = vmm_balloon_zap_range(ctx->vm, cmd->gpa, cmd->len);
                    }
                    break;

                case VMM_OP_PROTECT_SLOT:
                    st = vmm_protect_slot(ctx->vm, cmd->aux, (uint32_t)cmd->pattern);
                    break;

                default:
                    st = VMM_ERR_FORMAT;
                    break;
            }

            if (st != VMM_OK && !(cmd->flags & VMM_CMD_ALLOW_FAULT)) {
                ctx->status = st;
                atomic_store_explicit(ctx->abort_flag, 1, memory_order_release);
                break;
            }
            ctx->retired++;
        }
    }

    atomic_fetch_sub_explicit(&ctx->vm->active_workers, 1U, memory_order_relaxed);
    return NULL;
}

vmm_status_t vmm_exec_trace_bytes(
    const uint8_t *buf,
    size_t len,
    vmm_trace_summary_t *out_summary
) {
    if (buf == NULL || out_summary == NULL || len < sizeof(vmm_trace_header_t)) {
        return VMM_ERR_FORMAT;
    }

    memset(out_summary, 0, sizeof(*out_summary));

    vmm_trace_header_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    size_t off = sizeof(hdr);

    if (hdr.magic != VMM_TRACE_MAGIC) {
        return VMM_ERR_FORMAT;
    }
    if (hdr.slot_count == 0U || hdr.slot_count > VMM_MAX_SLOTS) {
        return VMM_ERR_FORMAT;
    }
    if (hdr.worker_count == 0U || hdr.worker_count > VMM_TRACE_MAX_WORKERS) {
        return VMM_ERR_FORMAT;
    }

    size_t slots_bytes = (size_t)hdr.slot_count * sizeof(vmm_trace_slot_desc_t);
    if (slots_bytes > len - off) {
        return VMM_ERR_FORMAT;
    }

    vmm_trace_slot_desc_t slot_descs[VMM_MAX_SLOTS];
    memcpy(slot_descs, buf + off, slots_bytes);
    off += slots_bytes;

    parsed_worker_t workers[VMM_TRACE_MAX_WORKERS];
    memset(workers, 0, sizeof(workers));
    uint64_t total_planned_ops = 0ULL;

    for (uint16_t w = 0; w < hdr.worker_count; w++) {
        if (sizeof(vmm_trace_worker_hdr_t) > len - off) {
            for (uint16_t k = 0; k < w; k++) {
                free(workers[k].cmds);
            }
            return VMM_ERR_FORMAT;
        }

        vmm_trace_worker_hdr_t whdr;
        memcpy(&whdr, buf + off, sizeof(whdr));
        off += sizeof(whdr);

        if (whdr.repeat_count == 0U || whdr.repeat_count > VMM_TRACE_MAX_REPEAT ||
            whdr.cmd_count == 0U || whdr.cmd_count > VMM_TRACE_MAX_CMDS) {
            for (uint16_t k = 0; k < w; k++) {
                free(workers[k].cmds);
            }
            return VMM_ERR_FORMAT;
        }

        uint64_t w_ops = (uint64_t)whdr.repeat_count * (uint64_t)whdr.cmd_count;
        total_planned_ops += w_ops;
        if (total_planned_ops > VMM_MAX_TOTAL_OPS) {
            for (uint16_t k = 0; k < w; k++) {
                free(workers[k].cmds);
            }
            return VMM_ERR_BOUNDS;
        }

        size_t cmds_bytes = (size_t)whdr.cmd_count * sizeof(vmm_trace_cmd_t);
        if (cmds_bytes > len - off) {
            for (uint16_t k = 0; k < w; k++) {
                free(workers[k].cmds);
            }
            return VMM_ERR_FORMAT;
        }

        workers[w].worker_id = whdr.worker_id;
        workers[w].repeat_count = whdr.repeat_count;
        workers[w].cmd_count = whdr.cmd_count;
        workers[w].cmds = (vmm_trace_cmd_t *)malloc(cmds_bytes);
        if (workers[w].cmds == NULL) {
            for (uint16_t k = 0; k < w; k++) {
                free(workers[k].cmds);
            }
            return VMM_ERR_NOMEM;
        }
        memcpy(workers[w].cmds, buf + off, cmds_bytes);
        off += cmds_bytes;
    }

    if (off != len) {
        for (uint16_t k = 0; k < hdr.worker_count; k++) {
            free(workers[k].cmds);
        }
        return VMM_ERR_FORMAT;
    }

    vmm_phys_pool_t phys;
    vmm_status_t st = vmm_phys_pool_init(&phys, VMM_DEFAULT_POOL_FRAMES);
    if (st != VMM_OK) {
        for (uint16_t k = 0; k < hdr.worker_count; k++) {
            free(workers[k].cmds);
        }
        return st;
    }

    vmm_image_store_t image;
    st = vmm_image_init(&image, &phys, hdr.image_seed);
    if (st != VMM_OK) {
        vmm_phys_pool_destroy(&phys);
        for (uint16_t k = 0; k < hdr.worker_count; k++) {
            free(workers[k].cmds);
        }
        return st;
    }

    uint64_t baseline_ro = vmm_image_ro_digest(&image);

    vmm_instance_t vm;
    st = vmm_init(&vm, &phys, &image);
    if (st != VMM_OK) {
        vmm_image_destroy(&image);
        vmm_phys_pool_destroy(&phys);
        for (uint16_t k = 0; k < hdr.worker_count; k++) {
            free(workers[k].cmds);
        }
        return st;
    }

    for (uint16_t s = 0; s < hdr.slot_count; s++) {
        st = vmm_map_slot(
            &vm,
            slot_descs[s].slot_id,
            slot_descs[s].base_gpa,
            slot_descs[s].npages,
            slot_descs[s].slot_flags,
            slot_descs[s].image_base_page
        );
        if (st != VMM_OK) {
            vmm_destroy(&vm);
            vmm_image_destroy(&image);
            vmm_phys_pool_destroy(&phys);
            for (uint16_t k = 0; k < hdr.worker_count; k++) {
                free(workers[k].cmds);
            }
            return st;
        }
    }

    atomic_store_explicit(&vm.active_workers, hdr.worker_count, memory_order_release);

    pthread_t threads[VMM_TRACE_MAX_WORKERS];
    worker_ctx_t ctxs[VMM_TRACE_MAX_WORKERS];
    _Atomic uint32_t ready_count = 0U;
    _Atomic int start_gate = 0;
    _Atomic int abort_flag = 0;

    for (uint16_t w = 0; w < hdr.worker_count; w++) {
        ctxs[w].vm = &vm;
        ctxs[w].spec = &workers[w];
        ctxs[w].vcpu_slot = w % VMM_MAX_VCPUS;
        ctxs[w].total_workers = hdr.worker_count;
        ctxs[w].ready_count = &ready_count;
        ctxs[w].start_gate = &start_gate;
        ctxs[w].abort_flag = &abort_flag;
        ctxs[w].status = VMM_OK;
        ctxs[w].retired = 0ULL;

        if (pthread_create(&threads[w], NULL, trace_worker_entry, &ctxs[w]) != 0) {
            atomic_store_explicit(&abort_flag, 1, memory_order_release);
            atomic_store_explicit(&start_gate, 1, memory_order_release);
            for (uint16_t j = 0; j < w; j++) {
                pthread_join(threads[j], NULL);
            }
            vmm_destroy(&vm);
            vmm_image_destroy(&image);
            vmm_phys_pool_destroy(&phys);
            for (uint16_t k = 0; k < hdr.worker_count; k++) {
                free(workers[k].cmds);
            }
            return VMM_ERR_NOMEM;
        }
    }

    while (atomic_load_explicit(&ready_count, memory_order_acquire) < hdr.worker_count) {
        sched_yield();
    }
    atomic_store_explicit(&start_gate, 1, memory_order_release);

    vmm_status_t final_st = VMM_OK;
    uint64_t total_retired = 0ULL;
    for (uint16_t w = 0; w < hdr.worker_count; w++) {
        pthread_join(threads[w], NULL);
        total_retired += ctxs[w].retired;
        if (final_st == VMM_OK && ctxs[w].status != VMM_OK) {
            final_st = ctxs[w].status;
        }
    }

    if (final_st == VMM_OK) {
        out_summary->worker_count = hdr.worker_count;
        out_summary->ops_retired = total_retired;
        out_summary->faults = atomic_load_explicit(&vm.stat_faults, memory_order_relaxed);
        out_summary->cow_splits = atomic_load_explicit(&vm.stat_cow_splits, memory_order_relaxed);
        out_summary->balloon_zaps = atomic_load_explicit(&vm.stat_balloon_zaps, memory_order_relaxed);
        out_summary->guest_digest = vmm_guest_memory_digest(&vm);
        out_summary->image_ro_digest = vmm_image_ro_digest(&image);
        out_summary->baseline_ro_digest = baseline_ro;
    }

    vmm_destroy(&vm);
    vmm_image_destroy(&image);
    vmm_phys_pool_destroy(&phys);
    for (uint16_t k = 0; k < hdr.worker_count; k++) {
        free(workers[k].cmds);
    }

    return final_st;
}
