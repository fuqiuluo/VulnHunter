#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# 1. Write technical analysis report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "file": "src/vmm_pin.c",
  "function": "populate_s2_leaf",
  "summary": "When resolving a COW split on a guest read-only slot (missing VMM_SLOT_WRITE) under VMM_WALK_OVERRIDE, populate_s2_leaf() clears VMM_WALK_WRITE from walk_flags after dropping l2->lock so the subsequent table walk accepts the non-S2PTE_WRITE private PTE. If a concurrent vmm_balloon_zap_range() discards that private PTE before walk_s2_leaf() runs, the next populate_s2_leaf() iteration faults without VMM_FAULT_WRITE, mapping the shared read-only backing image frame and returning it to vmm_host_write_gpa(), corrupting the shared template store. Fix by keeping VMM_WALK_WRITE intact, tracking an internal COW-completed flag reset on every fault attempt, and requiring both that flag and S2PTE_DIRTY in walk_s2_leaf() when following a non-writable PTE under VMM_WALK_OVERRIDE."
}
EOF

# 2. Apply Linus-style FOLL_COW + S2PTE_DIRTY fix in src/vmm_pin.c
cat > "$APP_DIR/src/vmm_pin.c" <<'EOF'
#include "vmm_mmu.h"

#include <stdlib.h>
#include <string.h>

#define VMM_WALK_COW_SPLIT (1U << 8)

static vmm_status_t check_slot_pin_access(const vmm_slot_t *slot, uint32_t walk_flags) {
    if (slot == NULL || !slot->active) {
        return VMM_ERR_UNMAPPED;
    }
    if (!(slot->flags & VMM_SLOT_READ)) {
        return VMM_ERR_PERM;
    }
    if (walk_flags & VMM_WALK_WRITE) {
        bool writable = (slot->flags & VMM_SLOT_WRITE) != 0U;
        bool override_ok = ((walk_flags & VMM_WALK_OVERRIDE) != 0U) && ((slot->flags & VMM_SLOT_COW) != 0U);
        if (!writable && !override_ok) {
            return VMM_ERR_PERM;
        }
    }
    return VMM_OK;
}

static inline bool can_follow_write_s2pte(s2pte_t pte, uint32_t walk_flags) {
    if (pte & S2PTE_WRITE) {
        return true;
    }
    return ((walk_flags & VMM_WALK_OVERRIDE) != 0U) &&
           ((walk_flags & VMM_WALK_COW_SPLIT) != 0U) &&
           ((pte & S2PTE_DIRTY) != 0ULL);
}

static vmm_frame_t *walk_s2_leaf(vmm_instance_t *vm, uint64_t page_gpa, uint32_t walk_flags) {
    vmm_l2_table_t *l2 = vmm_lookup_l2(vm, page_gpa);
    if (l2 == NULL) {
        return NULL;
    }

    size_t l2_idx = vmm_gpa_l2_index(page_gpa);
    pthread_mutex_lock(&l2->lock);

    s2pte_t pte = l2->entries[l2_idx];
    if (!(pte & S2PTE_PRESENT)) {
        pthread_mutex_unlock(&l2->lock);
        return NULL;
    }

    if ((walk_flags & VMM_WALK_WRITE) && !can_follow_write_s2pte(pte, walk_flags)) {
        pthread_mutex_unlock(&l2->lock);
        return NULL;
    }

    vmm_frame_t *frame = vmm_phys_frame(vm->phys, s2pte_pfn(pte));
    if (frame == NULL) {
        pthread_mutex_unlock(&l2->lock);
        return NULL;
    }

    s2pte_t updated = pte | S2PTE_ACCESSED;
    if (walk_flags & VMM_WALK_WRITE) {
        updated |= S2PTE_DIRTY;
    }
    l2->entries[l2_idx] = updated;
    vmm_frame_get(frame);

    pthread_mutex_unlock(&l2->lock);
    return frame;
}

static vmm_status_t populate_s2_leaf(
    vmm_instance_t *vm,
    const vmm_slot_t *slot,
    uint64_t page_gpa,
    uint32_t *walk_flags
) {
    *walk_flags &= ~VMM_WALK_COW_SPLIT;

    uint32_t fault_flags = VMM_FAULT_READ;
    if (*walk_flags & VMM_WALK_WRITE) {
        fault_flags |= VMM_FAULT_WRITE;
    }
    if (*walk_flags & VMM_WALK_OVERRIDE) {
        fault_flags |= VMM_FAULT_OVERRIDE;
    }

    uint32_t outcome = 0U;
    vmm_status_t st = vmm_resolve_s2_fault(vm, slot, page_gpa, fault_flags, &outcome);
    if (st != VMM_OK) {
        return st;
    }

    if (outcome & VMM_FAULT_OUT_COW_SPLIT) {
        vmm_tlb_shootdown_page(vm, page_gpa);
        if (!(slot->flags & VMM_SLOT_WRITE)) {
            *walk_flags |= VMM_WALK_COW_SPLIT;
        }
    }

    return VMM_OK;
}

static vmm_status_t pin_single_gpa(
    vmm_instance_t *vm,
    uint64_t page_gpa,
    uint32_t walk_flags,
    vmm_frame_t **out_frame
) {
    const vmm_slot_t *slot = vmm_find_slot_locked(vm, page_gpa);
    vmm_status_t st = check_slot_pin_access(slot, walk_flags);
    if (st != VMM_OK) {
        return st;
    }

    uint32_t cur_flags = walk_flags;
    for (;;) {
        vmm_frame_t *frame = walk_s2_leaf(vm, page_gpa, cur_flags);
        if (frame != NULL) {
            *out_frame = frame;
            return VMM_OK;
        }

        st = populate_s2_leaf(vm, slot, page_gpa, &cur_flags);
        if (st != VMM_OK) {
            return st;
        }
    }
}

vmm_status_t vmm_pin_gpa_pages(
    vmm_instance_t *vm,
    uint64_t base_gpa,
    uint32_t npages,
    uint32_t walk_flags,
    vmm_frame_t **out_frames
) {
    if (vm == NULL || out_frames == NULL || npages == 0U || npages > VMM_MAX_GPA_PAGES) {
        return VMM_ERR_INVALID;
    }
    if ((base_gpa & VMM_PAGE_OFFSET_MASK) != 0ULL) {
        return VMM_ERR_INVALID;
    }
    uint64_t byte_len = (uint64_t)npages * VMM_PAGE_SIZE;
    if (base_gpa > VMM_MAX_GPA_BYTES || byte_len > VMM_MAX_GPA_BYTES - base_gpa) {
        return VMM_ERR_BOUNDS;
    }

    pthread_rwlock_rdlock(&vm->slots_lock);

    for (uint32_t i = 0; i < npages; i++) {
        uint64_t page_gpa = base_gpa + (uint64_t)i * VMM_PAGE_SIZE;
        vmm_status_t st = pin_single_gpa(vm, page_gpa, walk_flags, &out_frames[i]);
        if (st != VMM_OK) {
            for (uint32_t j = 0; j < i; j++) {
                vmm_frame_put(vm->phys, out_frames[j]);
                out_frames[j] = NULL;
            }
            pthread_rwlock_unlock(&vm->slots_lock);
            return st;
        }
    }

    pthread_rwlock_unlock(&vm->slots_lock);
    return VMM_OK;
}

void vmm_unpin_gpa_pages(vmm_instance_t *vm, vmm_frame_t **frames, uint32_t npages) {
    if (vm == NULL || frames == NULL) {
        return;
    }
    for (uint32_t i = 0; i < npages; i++) {
        if (frames[i] != NULL) {
            vmm_frame_put(vm->phys, frames[i]);
            frames[i] = NULL;
        }
    }
}

vmm_status_t vmm_host_read_gpa(vmm_instance_t *vm, uint64_t gpa, void *dst, size_t len) {
    if (vm == NULL || (dst == NULL && len > 0U)) {
        return VMM_ERR_INVALID;
    }
    if (len == 0U) {
        return VMM_OK;
    }
    if (gpa >= VMM_MAX_GPA_BYTES || len > VMM_MAX_GPA_BYTES - gpa) {
        return VMM_ERR_BOUNDS;
    }

    uint64_t first_page = gpa & VMM_PAGE_MASK;
    uint64_t last_page  = (gpa + len - 1U) & VMM_PAGE_MASK;
    uint32_t npages     = (uint32_t)(((last_page - first_page) >> VMM_PAGE_SHIFT) + 1ULL);

    vmm_frame_t **pinned = (vmm_frame_t **)calloc(npages, sizeof(vmm_frame_t *));
    if (pinned == NULL) {
        return VMM_ERR_NOMEM;
    }

    vmm_status_t st = vmm_pin_gpa_pages(vm, first_page, npages, VMM_WALK_READ, pinned);
    if (st != VMM_OK) {
        free(pinned);
        return st;
    }

    uint8_t *out = (uint8_t *)dst;
    size_t rem = len;
    uint64_t cur = gpa;
    for (uint32_t i = 0; i < npages; i++) {
        size_t off = (size_t)(cur & VMM_PAGE_OFFSET_MASK);
        size_t chunk = VMM_PAGE_SIZE - off;
        if (chunk > rem) {
            chunk = rem;
        }
        memcpy(out, pinned[i]->data + off, chunk);
        out += chunk;
        cur += chunk;
        rem -= chunk;
    }

    vmm_unpin_gpa_pages(vm, pinned, npages);
    free(pinned);
    return VMM_OK;
}

vmm_status_t vmm_host_write_gpa(vmm_instance_t *vm, uint64_t gpa, const void *src, size_t len, bool override_ro) {
    if (vm == NULL || (src == NULL && len > 0U)) {
        return VMM_ERR_INVALID;
    }
    if (len == 0U) {
        return VMM_OK;
    }
    if (gpa >= VMM_MAX_GPA_BYTES || len > VMM_MAX_GPA_BYTES - gpa) {
        return VMM_ERR_BOUNDS;
    }

    uint64_t first_page = gpa & VMM_PAGE_MASK;
    uint64_t last_page  = (gpa + len - 1U) & VMM_PAGE_MASK;
    uint32_t npages     = (uint32_t)(((last_page - first_page) >> VMM_PAGE_SHIFT) + 1ULL);

    vmm_frame_t **pinned = (vmm_frame_t **)calloc(npages, sizeof(vmm_frame_t *));
    if (pinned == NULL) {
        return VMM_ERR_NOMEM;
    }

    uint32_t walk_flags = VMM_WALK_READ | VMM_WALK_WRITE;
    if (override_ro) {
        walk_flags |= VMM_WALK_OVERRIDE;
    }

    vmm_status_t st = vmm_pin_gpa_pages(vm, first_page, npages, walk_flags, pinned);
    if (st != VMM_OK) {
        free(pinned);
        return st;
    }

    const uint8_t *in = (const uint8_t *)src;
    size_t rem = len;
    uint64_t cur = gpa;
    for (uint32_t i = 0; i < npages; i++) {
        size_t off = (size_t)(cur & VMM_PAGE_OFFSET_MASK);
        size_t chunk = VMM_PAGE_SIZE - off;
        if (chunk > rem) {
            chunk = rem;
        }
        memcpy(pinned[i]->data + off, in, chunk);
        in += chunk;
        cur += chunk;
        rem -= chunk;
    }

    vmm_unpin_gpa_pages(vm, pinned, npages);
    free(pinned);
    return VMM_OK;
}
EOF

make -C "$APP_DIR" clean all
