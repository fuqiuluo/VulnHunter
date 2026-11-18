#include "vmm_mmu.h"

#include <stdlib.h>
#include <string.h>

static uint64_t fnv1a_step(uint64_t h, const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)buf[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void flush_tlb_vpn_nowait(vmm_instance_t *vm, uint64_t vpn) {
    for (uint32_t i = 0; i < VMM_MAX_VCPUS; i++) {
        vmm_tlb_t *tlb = &vm->tlbs[i];
        vmm_frame_t *released[VMM_TLB_WAYS];
        uint32_t rel_cnt = 0U;

        pthread_mutex_lock(&tlb->lock);
        for (uint32_t w = 0; w < VMM_TLB_WAYS; w++) {
            if (tlb->entries[w].valid && tlb->entries[w].vpn == vpn) {
                if (tlb->entries[w].frame != NULL) {
                    released[rel_cnt++] = tlb->entries[w].frame;
                }
                tlb->entries[w].valid = false;
                tlb->entries[w].frame = NULL;
            }
        }
        tlb->flush_epoch++;
        pthread_mutex_unlock(&tlb->lock);

        for (uint32_t r = 0; r < rel_cnt; r++) {
            vmm_frame_put(vm->phys, released[r]);
        }
    }
}

vmm_status_t vmm_init(vmm_instance_t *vm, vmm_phys_pool_t *phys, vmm_image_store_t *image) {
    if (vm == NULL || phys == NULL || image == NULL) {
        return VMM_ERR_INVALID;
    }

    memset(vm, 0, sizeof(*vm));
    vm->phys = phys;
    vm->image = image;

    if (pthread_rwlock_init(&vm->slots_lock, NULL) != 0) {
        return VMM_ERR_INVALID;
    }

    vmm_tlb_init_all(vm);
    atomic_init(&vm->mmu_seq, 1ULL);
    atomic_init(&vm->active_workers, 1U);
    atomic_init(&vm->stat_faults, 0ULL);
    atomic_init(&vm->stat_cow_splits, 0ULL);
    atomic_init(&vm->stat_balloon_zaps, 0ULL);
    atomic_init(&vm->stat_tlb_shootdowns, 0ULL);
    return VMM_OK;
}

void vmm_destroy(vmm_instance_t *vm) {
    if (vm == NULL || vm->phys == NULL) {
        return;
    }

    vmm_tlb_destroy_all(vm);

    for (size_t i = 0; i < VMM_L1_ENTRIES; i++) {
        vmm_l2_table_t *l2 = vm->l1[i];
        if (l2 != NULL) {
            for (size_t j = 0; j < VMM_L2_ENTRIES; j++) {
                s2pte_t pte = l2->entries[j];
                if (pte & S2PTE_PRESENT) {
                    vmm_frame_t *f = vmm_phys_frame(vm->phys, s2pte_pfn(pte));
                    vmm_frame_put(vm->phys, f);
                    l2->entries[j] = 0ULL;
                }
            }
            pthread_mutex_destroy(&l2->lock);
            free(l2);
            vm->l1[i] = NULL;
        }
    }

    pthread_rwlock_destroy(&vm->slots_lock);
    vm->phys = NULL;
    vm->image = NULL;
}

const vmm_slot_t *vmm_find_slot_locked(const vmm_instance_t *vm, uint64_t gpa) {
    for (uint32_t i = 0; i < VMM_MAX_SLOTS; i++) {
        const vmm_slot_t *s = &vm->slots[i];
        if (!s->active) {
            continue;
        }
        uint64_t end_gpa = s->base_gpa + (uint64_t)s->npages * VMM_PAGE_SIZE;
        if (gpa >= s->base_gpa && gpa < end_gpa) {
            return s;
        }
    }
    return NULL;
}

vmm_l2_table_t *vmm_lookup_l2(const vmm_instance_t *vm, uint64_t gpa) {
    if (vm == NULL || gpa >= VMM_MAX_GPA_BYTES) {
        return NULL;
    }
    return vm->l1[vmm_gpa_l1_index(gpa)];
}

vmm_status_t vmm_map_slot(
    vmm_instance_t *vm,
    uint32_t slot_id,
    uint64_t base_gpa,
    uint32_t npages,
    uint32_t slot_flags,
    uint32_t image_base_page
) {
    if (vm == NULL || slot_id >= VMM_MAX_SLOTS || npages == 0U || npages > VMM_MAX_GPA_PAGES) {
        return VMM_ERR_INVALID;
    }
    if ((base_gpa & VMM_PAGE_OFFSET_MASK) != 0ULL) {
        return VMM_ERR_INVALID;
    }

    uint64_t byte_len = (uint64_t)npages * VMM_PAGE_SIZE;
    if (base_gpa > VMM_MAX_GPA_BYTES || byte_len > VMM_MAX_GPA_BYTES - base_gpa) {
        return VMM_ERR_BOUNDS;
    }

    if ((slot_flags & VMM_SLOT_READ) == 0U) {
        return VMM_ERR_INVALID;
    }

    if (slot_flags & VMM_SLOT_BACKED) {
        if (image_base_page >= VMM_IMAGE_TOTAL_PAGES ||
            npages > VMM_IMAGE_TOTAL_PAGES - image_base_page) {
            return VMM_ERR_BOUNDS;
        }
        /* Read-only golden boot/template pages [0..VMM_IMAGE_RO_PAGES-1] require COW if writable */
        bool touches_ro_image = (image_base_page < VMM_IMAGE_RO_PAGES);
        if (touches_ro_image && (slot_flags & VMM_SLOT_WRITE) && !(slot_flags & VMM_SLOT_COW)) {
            return VMM_ERR_PERM;
        }
    }

    pthread_rwlock_wrlock(&vm->slots_lock);

    if (vm->slots[slot_id].active) {
        pthread_rwlock_unlock(&vm->slots_lock);
        return VMM_ERR_INVALID;
    }

    uint64_t new_end = base_gpa + byte_len;
    for (uint32_t i = 0; i < VMM_MAX_SLOTS; i++) {
        const vmm_slot_t *s = &vm->slots[i];
        if (!s->active) {
            continue;
        }
        uint64_t s_end = s->base_gpa + (uint64_t)s->npages * VMM_PAGE_SIZE;
        if (base_gpa < s_end && new_end > s->base_gpa) {
            pthread_rwlock_unlock(&vm->slots_lock);
            return VMM_ERR_INVALID;
        }
    }

    /* Pre-allocate L2 page tables covering the slot */
    for (uint32_t p = 0; p < npages; p++) {
        uint64_t gpa = base_gpa + (uint64_t)p * VMM_PAGE_SIZE;
        size_t l1_idx = vmm_gpa_l1_index(gpa);
        if (vm->l1[l1_idx] == NULL) {
            vmm_l2_table_t *l2 = (vmm_l2_table_t *)calloc(1U, sizeof(vmm_l2_table_t));
            if (l2 == NULL) {
                pthread_rwlock_unlock(&vm->slots_lock);
                return VMM_ERR_NOMEM;
            }
            pthread_mutex_init(&l2->lock, NULL);
            vm->l1[l1_idx] = l2;
        }
    }

    vmm_slot_t *dst = &vm->slots[slot_id];
    dst->active = true;
    dst->slot_id = slot_id;
    dst->flags = slot_flags;
    dst->base_gpa = base_gpa;
    dst->npages = npages;
    dst->image_base_page = image_base_page;

    pthread_rwlock_unlock(&vm->slots_lock);
    return VMM_OK;
}

vmm_status_t vmm_protect_slot(vmm_instance_t *vm, uint32_t slot_id, uint32_t new_rw_flags) {
    if (vm == NULL || slot_id >= VMM_MAX_SLOTS) {
        return VMM_ERR_INVALID;
    }
    if ((new_rw_flags & VMM_SLOT_READ) == 0U) {
        return VMM_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&vm->slots_lock);
    vmm_slot_t *slot = &vm->slots[slot_id];
    if (!slot->active) {
        pthread_rwlock_unlock(&vm->slots_lock);
        return VMM_ERR_UNMAPPED;
    }

    uint32_t preserved = slot->flags & (VMM_SLOT_COW | VMM_SLOT_BACKED);
    uint32_t updated_flags = preserved | (new_rw_flags & (VMM_SLOT_READ | VMM_SLOT_WRITE | VMM_SLOT_EXEC));

    if ((updated_flags & VMM_SLOT_BACKED) &&
        slot->image_base_page < VMM_IMAGE_RO_PAGES &&
        (updated_flags & VMM_SLOT_WRITE) &&
        !(updated_flags & VMM_SLOT_COW)) {
        pthread_rwlock_unlock(&vm->slots_lock);
        return VMM_ERR_PERM;
    }

    bool dropping_write = (slot->flags & VMM_SLOT_WRITE) && !(updated_flags & VMM_SLOT_WRITE);
    slot->flags = updated_flags;

    if (dropping_write) {
        for (uint32_t p = 0; p < slot->npages; p++) {
            uint64_t gpa = slot->base_gpa + (uint64_t)p * VMM_PAGE_SIZE;
            vmm_l2_table_t *l2 = vmm_lookup_l2(vm, gpa);
            size_t l2_idx = vmm_gpa_l2_index(gpa);
            pthread_mutex_lock(&l2->lock);
            if (l2->entries[l2_idx] & S2PTE_WRITE) {
                l2->entries[l2_idx] &= ~S2PTE_WRITE;
                atomic_fetch_add_explicit(&vm->mmu_seq, 1ULL, memory_order_release);
            }
            pthread_mutex_unlock(&l2->lock);
        }
        vmm_tlb_shootdown_range(vm, slot->base_gpa, slot->npages);
    }

    pthread_rwlock_unlock(&vm->slots_lock);
    return VMM_OK;
}

vmm_status_t vmm_guest_load(vmm_instance_t *vm, uint32_t vcpu_id, uint64_t gpa, void *dst, size_t len) {
    if (vm == NULL || vcpu_id >= VMM_MAX_VCPUS || (dst == NULL && len > 0U)) {
        return VMM_ERR_INVALID;
    }
    if (len == 0U) {
        return VMM_OK;
    }
    if (gpa >= VMM_MAX_GPA_BYTES || len > VMM_MAX_GPA_BYTES - gpa) {
        return VMM_ERR_BOUNDS;
    }

    uint8_t *out = (uint8_t *)dst;
    size_t rem = len;
    uint64_t cur = gpa;

    pthread_rwlock_rdlock(&vm->slots_lock);

    while (rem > 0U) {
        size_t page_off = (size_t)(cur & VMM_PAGE_OFFSET_MASK);
        size_t chunk = VMM_PAGE_SIZE - page_off;
        if (chunk > rem) {
            chunk = rem;
        }

        /* Hardware TLB + Stage-2 page table walk; trap to slot lookup only on EPT miss/violation */
        vmm_frame_t *frame = vmm_tlb_lookup_pin(vm, vcpu_id, cur, S2PTE_PRESENT | S2PTE_READ);
        while (frame == NULL) {
            vmm_l2_table_t *l2 = vmm_lookup_l2(vm, cur);
            if (l2 != NULL) {
                size_t l2_idx = vmm_gpa_l2_index(cur);
                pthread_mutex_lock(&l2->lock);
                s2pte_t pte = l2->entries[l2_idx];
                if ((pte & (S2PTE_PRESENT | S2PTE_READ)) == (S2PTE_PRESENT | S2PTE_READ)) {
                    s2pte_t new_pte = pte | S2PTE_ACCESSED;
                    l2->entries[l2_idx] = new_pte;
                    frame = vmm_phys_frame(vm->phys, s2pte_pfn(new_pte));
                    vmm_frame_get(frame);
                    uint64_t seq = atomic_load_explicit(&vm->mmu_seq, memory_order_relaxed);
                    pthread_mutex_unlock(&l2->lock);

                    vmm_tlb_insert(vm, vcpu_id, cur & VMM_PAGE_MASK, new_pte, frame, seq);
                    break;
                }
                pthread_mutex_unlock(&l2->lock);
            }

            const vmm_slot_t *slot = vmm_find_slot_locked(vm, cur);
            if (slot == NULL) {
                pthread_rwlock_unlock(&vm->slots_lock);
                return VMM_ERR_UNMAPPED;
            }
            if (!(slot->flags & VMM_SLOT_READ)) {
                pthread_rwlock_unlock(&vm->slots_lock);
                return VMM_ERR_PERM;
            }

            uint32_t outcome = 0U;
            vmm_status_t st = vmm_resolve_s2_fault(vm, slot, cur & VMM_PAGE_MASK, VMM_FAULT_READ, &outcome);
            if (st != VMM_OK) {
                pthread_rwlock_unlock(&vm->slots_lock);
                return st;
            }
        }

        memcpy(out, frame->data + page_off, chunk);
        vmm_frame_put(vm->phys, frame);

        out += chunk;
        cur += chunk;
        rem -= chunk;
    }

    pthread_rwlock_unlock(&vm->slots_lock);
    return VMM_OK;
}

vmm_status_t vmm_guest_store(vmm_instance_t *vm, uint32_t vcpu_id, uint64_t gpa, const void *src, size_t len) {
    if (vm == NULL || vcpu_id >= VMM_MAX_VCPUS || (src == NULL && len > 0U)) {
        return VMM_ERR_INVALID;
    }
    if (len == 0U) {
        return VMM_OK;
    }
    if (gpa >= VMM_MAX_GPA_BYTES || len > VMM_MAX_GPA_BYTES - gpa) {
        return VMM_ERR_BOUNDS;
    }

    const uint8_t *in = (const uint8_t *)src;
    size_t rem = len;
    uint64_t cur = gpa;

    pthread_rwlock_rdlock(&vm->slots_lock);

    while (rem > 0U) {
        size_t page_off = (size_t)(cur & VMM_PAGE_OFFSET_MASK);
        size_t chunk = VMM_PAGE_SIZE - page_off;
        if (chunk > rem) {
            chunk = rem;
        }

        /* Hardware TLB + Stage-2 page table walk; trap to EPT fault handler when !S2PTE_WRITE */
        vmm_frame_t *frame = vmm_tlb_lookup_pin(vm, vcpu_id, cur, S2PTE_PRESENT | S2PTE_WRITE);
        while (frame == NULL) {
            vmm_l2_table_t *l2 = vmm_lookup_l2(vm, cur);
            if (l2 != NULL) {
                size_t l2_idx = vmm_gpa_l2_index(cur);
                pthread_mutex_lock(&l2->lock);
                s2pte_t pte = l2->entries[l2_idx];
                if ((pte & (S2PTE_PRESENT | S2PTE_WRITE)) == (S2PTE_PRESENT | S2PTE_WRITE)) {
                    s2pte_t new_pte = pte | S2PTE_ACCESSED | S2PTE_DIRTY;
                    l2->entries[l2_idx] = new_pte;
                    frame = vmm_phys_frame(vm->phys, s2pte_pfn(new_pte));
                    vmm_frame_get(frame);
                    uint64_t seq = atomic_load_explicit(&vm->mmu_seq, memory_order_relaxed);
                    pthread_mutex_unlock(&l2->lock);

                    vmm_tlb_insert(vm, vcpu_id, cur & VMM_PAGE_MASK, new_pte, frame, seq);
                    break;
                }
                pthread_mutex_unlock(&l2->lock);
            }

            const vmm_slot_t *slot = vmm_find_slot_locked(vm, cur);
            if (slot == NULL) {
                pthread_rwlock_unlock(&vm->slots_lock);
                return VMM_ERR_UNMAPPED;
            }
            if (!(slot->flags & VMM_SLOT_WRITE)) {
                pthread_rwlock_unlock(&vm->slots_lock);
                return VMM_ERR_PERM;
            }

            uint32_t outcome = 0U;
            vmm_status_t st = vmm_resolve_s2_fault(vm, slot, cur & VMM_PAGE_MASK, VMM_FAULT_WRITE, &outcome);
            if (st != VMM_OK) {
                pthread_rwlock_unlock(&vm->slots_lock);
                return st;
            }
            if (outcome & VMM_FAULT_OUT_COW_SPLIT) {
                vmm_tlb_shootdown_page(vm, cur & VMM_PAGE_MASK);
            }
        }

        memcpy(frame->data + page_off, in, chunk);
        vmm_frame_put(vm->phys, frame);

        in += chunk;
        cur += chunk;
        rem -= chunk;
    }

    pthread_rwlock_unlock(&vm->slots_lock);
    return VMM_OK;
}

vmm_status_t vmm_balloon_zap_range(vmm_instance_t *vm, uint64_t base_gpa, uint32_t npages) {
    if (vm == NULL || npages == 0U || npages > VMM_MAX_GPA_PAGES) {
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

    for (uint32_t p = 0; p < npages; p++) {
        uint64_t gpa = base_gpa + (uint64_t)p * VMM_PAGE_SIZE;
        if (vmm_find_slot_locked(vm, gpa) == NULL) {
            pthread_rwlock_unlock(&vm->slots_lock);
            return VMM_ERR_UNMAPPED;
        }
    }

    for (uint32_t p = 0; p < npages; p++) {
        uint64_t gpa = base_gpa + (uint64_t)p * VMM_PAGE_SIZE;
        vmm_l2_table_t *l2 = vmm_lookup_l2(vm, gpa);
        size_t l2_idx = vmm_gpa_l2_index(gpa);
        vmm_frame_t *old_frame = NULL;

        pthread_mutex_lock(&l2->lock);
        s2pte_t old_pte = l2->entries[l2_idx];
        if (old_pte & S2PTE_PRESENT) {
            l2->entries[l2_idx] = 0ULL;
            atomic_fetch_add_explicit(&vm->mmu_seq, 1ULL, memory_order_release);
            atomic_fetch_add_explicit(&vm->stat_balloon_zaps, 1ULL, memory_order_relaxed);
            old_frame = vmm_phys_frame(vm->phys, s2pte_pfn(old_pte));
        }
        pthread_mutex_unlock(&l2->lock);

        if (old_frame != NULL) {
            flush_tlb_vpn_nowait(vm, gpa >> VMM_PAGE_SHIFT);
            vmm_frame_put(vm->phys, old_frame);
        }
    }

    pthread_rwlock_unlock(&vm->slots_lock);
    return VMM_OK;
}

uint64_t vmm_guest_memory_digest(vmm_instance_t *vm) {
    if (vm == NULL) {
        return 0ULL;
    }

    uint8_t zero_page[VMM_PAGE_SIZE];
    memset(zero_page, 0, sizeof(zero_page));

    uint64_t h = 14695981039346656037ULL;
    pthread_rwlock_rdlock(&vm->slots_lock);

    for (uint32_t sid = 0; sid < VMM_MAX_SLOTS; sid++) {
        const vmm_slot_t *s = &vm->slots[sid];
        if (!s->active || !(s->flags & VMM_SLOT_READ)) {
            continue;
        }
        for (uint32_t p = 0; p < s->npages; p++) {
            uint64_t gpa = s->base_gpa + (uint64_t)p * VMM_PAGE_SIZE;
            vmm_l2_table_t *l2 = vmm_lookup_l2(vm, gpa);
            size_t l2_idx = vmm_gpa_l2_index(gpa);

            pthread_mutex_lock(&l2->lock);
            s2pte_t pte = l2->entries[l2_idx];
            if (pte & S2PTE_PRESENT) {
                const vmm_frame_t *f = vmm_phys_frame(vm->phys, s2pte_pfn(pte));
                h = fnv1a_step(h, f->data, VMM_PAGE_SIZE);
            } else if (s->flags & VMM_SLOT_BACKED) {
                uint32_t bpfn = vmm_image_page_pfn(vm->image, s->image_base_page + p);
                const vmm_frame_t *bf = vmm_phys_frame(vm->phys, bpfn);
                h = fnv1a_step(h, bf->data, VMM_PAGE_SIZE);
            } else {
                h = fnv1a_step(h, zero_page, VMM_PAGE_SIZE);
            }
            pthread_mutex_unlock(&l2->lock);
        }
    }

    pthread_rwlock_unlock(&vm->slots_lock);
    return h;
}
