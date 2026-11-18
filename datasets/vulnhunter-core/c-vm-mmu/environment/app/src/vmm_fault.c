#include "vmm_mmu.h"

#include <string.h>

static uint32_t resolve_slot_backing_pfn(
    const vmm_instance_t *vm,
    const vmm_slot_t *slot,
    uint64_t page_gpa
) {
    uint32_t page_offset_idx = (uint32_t)((page_gpa - slot->base_gpa) >> VMM_PAGE_SHIFT);
    return vmm_image_page_pfn(vm->image, slot->image_base_page + page_offset_idx);
}

vmm_status_t vmm_resolve_s2_fault(
    vmm_instance_t *vm,
    const vmm_slot_t *slot,
    uint64_t gpa,
    uint32_t fault_flags,
    uint32_t *outcome
) {
    if (outcome != NULL) {
        *outcome = VMM_FAULT_OUT_NOP;
    }
    if (vm == NULL || slot == NULL || !slot->active) {
        return VMM_ERR_INVALID;
    }

    uint64_t page_gpa = gpa & VMM_PAGE_MASK;
    vmm_l2_table_t *l2 = vmm_lookup_l2(vm, page_gpa);
    if (l2 == NULL) {
        return VMM_ERR_UNMAPPED;
    }
    size_t l2_idx = vmm_gpa_l2_index(page_gpa);
    uint64_t exec_attr = (slot->flags & VMM_SLOT_EXEC) ? S2PTE_EXEC : 0ULL;

    /* Read fault path */
    if (!(fault_flags & VMM_FAULT_WRITE)) {
        if (!(slot->flags & VMM_SLOT_READ)) {
            return VMM_ERR_PERM;
        }

        pthread_mutex_lock(&l2->lock);
        s2pte_t pte = l2->entries[l2_idx];
        if (pte & S2PTE_PRESENT) {
            pthread_mutex_unlock(&l2->lock);
            return VMM_OK;
        }

        if (slot->flags & VMM_SLOT_BACKED) {
            uint32_t bpfn = resolve_slot_backing_pfn(vm, slot, page_gpa);
            vmm_frame_t *bframe = vmm_phys_frame(vm->phys, bpfn);
            if (bframe == NULL) {
                pthread_mutex_unlock(&l2->lock);
                return VMM_ERR_INVALID;
            }
            vmm_frame_get(bframe);
            l2->entries[l2_idx] = s2pte_make(bpfn, S2PTE_PRESENT | S2PTE_READ | exec_attr);
        } else {
            vmm_frame_t *zframe = vmm_frame_alloc(vm->phys);
            if (zframe == NULL) {
                pthread_mutex_unlock(&l2->lock);
                return VMM_ERR_NOMEM;
            }
            l2->entries[l2_idx] = s2pte_make(zframe->pfn, S2PTE_PRESENT | S2PTE_READ | exec_attr);
        }

        atomic_fetch_add_explicit(&vm->stat_faults, 1ULL, memory_order_relaxed);
        pthread_mutex_unlock(&l2->lock);

        if (outcome != NULL) {
            *outcome = VMM_FAULT_OUT_POPULATED;
        }
        return VMM_OK;
    }

    /* Write fault path */
    bool guest_writable = (slot->flags & VMM_SLOT_WRITE) != 0U;
    bool override_cow   = ((fault_flags & VMM_FAULT_OVERRIDE) != 0U) && ((slot->flags & VMM_SLOT_COW) != 0U);
    if (!guest_writable && !override_cow) {
        return VMM_ERR_PERM;
    }

    /* Shared write-through image slot (writable without COW) */
    if ((slot->flags & VMM_SLOT_BACKED) && !(slot->flags & VMM_SLOT_COW)) {
        pthread_mutex_lock(&l2->lock);
        s2pte_t pte = l2->entries[l2_idx];
        if (!(pte & S2PTE_PRESENT)) {
            uint32_t bpfn = resolve_slot_backing_pfn(vm, slot, page_gpa);
            vmm_frame_t *bframe = vmm_phys_frame(vm->phys, bpfn);
            if (bframe == NULL) {
                pthread_mutex_unlock(&l2->lock);
                return VMM_ERR_INVALID;
            }
            vmm_frame_get(bframe);
            l2->entries[l2_idx] = s2pte_make(
                bpfn,
                S2PTE_PRESENT | S2PTE_READ | S2PTE_WRITE | S2PTE_ACCESSED | S2PTE_DIRTY | exec_attr
            );
        } else {
            l2->entries[l2_idx] = pte | S2PTE_WRITE | S2PTE_ACCESSED | S2PTE_DIRTY;
        }
        atomic_fetch_add_explicit(&vm->stat_faults, 1ULL, memory_order_relaxed);
        pthread_mutex_unlock(&l2->lock);

        if (outcome != NULL) {
            *outcome = VMM_FAULT_OUT_MKWRITE;
        }
        return VMM_OK;
    }

    /* Anonymous non-backed slot */
    if (!(slot->flags & VMM_SLOT_BACKED)) {
        pthread_mutex_lock(&l2->lock);
        s2pte_t pte = l2->entries[l2_idx];
        uint64_t write_attr = guest_writable ? S2PTE_WRITE : 0ULL;

        if (!(pte & S2PTE_PRESENT)) {
            vmm_frame_t *aframe = vmm_frame_alloc(vm->phys);
            if (aframe == NULL) {
                pthread_mutex_unlock(&l2->lock);
                return VMM_ERR_NOMEM;
            }
            l2->entries[l2_idx] = s2pte_make(
                aframe->pfn,
                S2PTE_PRESENT | S2PTE_READ | S2PTE_ACCESSED | S2PTE_DIRTY | write_attr | exec_attr
            );
            atomic_fetch_add_explicit(&vm->stat_faults, 1ULL, memory_order_relaxed);
            pthread_mutex_unlock(&l2->lock);
            if (outcome != NULL) {
                *outcome = guest_writable ? VMM_FAULT_OUT_POPULATED : VMM_FAULT_OUT_COW_SPLIT;
            }
            return VMM_OK;
        }

        l2->entries[l2_idx] = pte | S2PTE_ACCESSED | S2PTE_DIRTY | write_attr;
        pthread_mutex_unlock(&l2->lock);
        if (outcome != NULL) {
            *outcome = guest_writable ? VMM_FAULT_OUT_MKWRITE : VMM_FAULT_OUT_COW_SPLIT;
        }
        return VMM_OK;
    }

    /* Copy-on-write image-backed slot */
    vmm_frame_t *priv_frame = vmm_frame_alloc(vm->phys);
    if (priv_frame == NULL) {
        return VMM_ERR_NOMEM;
    }

    pthread_mutex_lock(&l2->lock);
    s2pte_t pte = l2->entries[l2_idx];

    /* Already split and guest-writable */
    if ((pte & S2PTE_PRESENT) && (pte & S2PTE_WRITE)) {
        l2->entries[l2_idx] = pte | S2PTE_ACCESSED | S2PTE_DIRTY;
        pthread_mutex_unlock(&l2->lock);
        vmm_frame_put(vm->phys, priv_frame);
        return VMM_OK;
    }

    vmm_frame_t *old_mapped = NULL;
    const vmm_frame_t *copy_src = NULL;

    if (pte & S2PTE_PRESENT) {
        old_mapped = vmm_phys_frame(vm->phys, s2pte_pfn(pte));
        copy_src = old_mapped;
    } else {
        uint32_t bpfn = resolve_slot_backing_pfn(vm, slot, page_gpa);
        copy_src = vmm_phys_frame(vm->phys, bpfn);
    }

    if (copy_src == NULL) {
        pthread_mutex_unlock(&l2->lock);
        vmm_frame_put(vm->phys, priv_frame);
        return VMM_ERR_INVALID;
    }

    memcpy(priv_frame->data, copy_src->data, VMM_PAGE_SIZE);

    uint64_t new_attr = S2PTE_PRESENT | S2PTE_READ | S2PTE_ACCESSED | S2PTE_DIRTY | exec_attr;
    if (guest_writable) {
        new_attr |= S2PTE_WRITE;
    }

    l2->entries[l2_idx] = s2pte_make(priv_frame->pfn, new_attr);
    atomic_fetch_add_explicit(&vm->mmu_seq, 1ULL, memory_order_release);
    atomic_fetch_add_explicit(&vm->stat_faults, 1ULL, memory_order_relaxed);
    atomic_fetch_add_explicit(&vm->stat_cow_splits, 1ULL, memory_order_relaxed);
    pthread_mutex_unlock(&l2->lock);

    if (old_mapped != NULL) {
        vmm_frame_put(vm->phys, old_mapped);
    }

    if (outcome != NULL) {
        *outcome = VMM_FAULT_OUT_COW_SPLIT;
    }
    return VMM_OK;
}
