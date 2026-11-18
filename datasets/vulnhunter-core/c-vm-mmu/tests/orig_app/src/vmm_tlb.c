#include "vmm_mmu.h"

#include <sched.h>
#include <string.h>

void vmm_tlb_init_all(vmm_instance_t *vm) {
    for (uint32_t i = 0; i < VMM_MAX_VCPUS; i++) {
        vmm_tlb_t *tlb = &vm->tlbs[i];
        memset(tlb, 0, sizeof(*tlb));
        pthread_mutex_init(&tlb->lock, NULL);
    }
}

void vmm_tlb_destroy_all(vmm_instance_t *vm) {
    for (uint32_t i = 0; i < VMM_MAX_VCPUS; i++) {
        vmm_tlb_t *tlb = &vm->tlbs[i];
        pthread_mutex_lock(&tlb->lock);
        for (uint32_t w = 0; w < VMM_TLB_WAYS; w++) {
            if (tlb->entries[w].valid && tlb->entries[w].frame != NULL) {
                vmm_frame_put(vm->phys, tlb->entries[w].frame);
                tlb->entries[w].frame = NULL;
                tlb->entries[w].valid = false;
            }
        }
        pthread_mutex_unlock(&tlb->lock);
        pthread_mutex_destroy(&tlb->lock);
    }
}

vmm_frame_t *vmm_tlb_lookup_pin(vmm_instance_t *vm, uint32_t vcpu_id, uint64_t gpa, uint64_t req_attr) {
    if (vm == NULL || vcpu_id >= VMM_MAX_VCPUS) {
        return NULL;
    }

    uint64_t vpn = gpa >> VMM_PAGE_SHIFT;
    vmm_tlb_t *tlb = &vm->tlbs[vcpu_id];
    vmm_frame_t *pinned = NULL;

    pthread_mutex_lock(&tlb->lock);
    for (uint32_t w = 0; w < VMM_TLB_WAYS; w++) {
        vmm_tlb_entry_t *ent = &tlb->entries[w];
        if (ent->valid && ent->vpn == vpn) {
            if ((ent->pte_attr & req_attr) == req_attr && ent->frame != NULL) {
                vmm_frame_get(ent->frame);
                pinned = ent->frame;
                tlb->hits++;
            } else {
                tlb->misses++;
            }
            pthread_mutex_unlock(&tlb->lock);
            return pinned;
        }
    }
    tlb->misses++;
    pthread_mutex_unlock(&tlb->lock);
    return NULL;
}

void vmm_tlb_insert(
    vmm_instance_t *vm,
    uint32_t vcpu_id,
    uint64_t gpa,
    s2pte_t pte,
    vmm_frame_t *frame,
    uint64_t observed_seq
) {
    if (vm == NULL || vcpu_id >= VMM_MAX_VCPUS || frame == NULL) {
        return;
    }

    uint64_t vpn = gpa >> VMM_PAGE_SHIFT;
    vmm_tlb_t *tlb = &vm->tlbs[vcpu_id];

    pthread_mutex_lock(&tlb->lock);
    if (atomic_load_explicit(&vm->mmu_seq, memory_order_acquire) != observed_seq) {
        pthread_mutex_unlock(&tlb->lock);
        return;
    }

    uint32_t target_way = VMM_TLB_WAYS;
    for (uint32_t w = 0; w < VMM_TLB_WAYS; w++) {
        if (tlb->entries[w].valid && tlb->entries[w].vpn == vpn) {
            target_way = w;
            break;
        }
        if (!tlb->entries[w].valid && target_way == VMM_TLB_WAYS) {
            target_way = w;
        }
    }

    if (target_way == VMM_TLB_WAYS) {
        target_way = tlb->next_way;
        tlb->next_way = (tlb->next_way + 1U) % VMM_TLB_WAYS;
    }

    vmm_tlb_entry_t *ent = &tlb->entries[target_way];
    vmm_frame_t *old_frame = ent->valid ? ent->frame : NULL;

    vmm_frame_get(frame);
    ent->valid = true;
    ent->vpn = vpn;
    ent->pte_attr = pte & 0xFFFULL;
    ent->frame = frame;
    pthread_mutex_unlock(&tlb->lock);

    if (old_frame != NULL) {
        vmm_frame_put(vm->phys, old_frame);
    }
}

void vmm_tlb_shootdown_page(vmm_instance_t *vm, uint64_t gpa) {
    if (vm == NULL) {
        return;
    }

    uint64_t vpn = gpa >> VMM_PAGE_SHIFT;
    atomic_fetch_add_explicit(&vm->stat_tlb_shootdowns, 1ULL, memory_order_relaxed);

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

    if (atomic_load_explicit(&vm->active_workers, memory_order_relaxed) > 1U) {
        sched_yield();
    }
}

void vmm_tlb_shootdown_range(vmm_instance_t *vm, uint64_t base_gpa, uint32_t npages) {
    if (vm == NULL || npages == 0U) {
        return;
    }

    uint64_t start_vpn = base_gpa >> VMM_PAGE_SHIFT;
    uint64_t end_vpn = start_vpn + npages;
    atomic_fetch_add_explicit(&vm->stat_tlb_shootdowns, 1ULL, memory_order_relaxed);

    for (uint32_t i = 0; i < VMM_MAX_VCPUS; i++) {
        vmm_tlb_t *tlb = &vm->tlbs[i];
        vmm_frame_t *released[VMM_TLB_WAYS];
        uint32_t rel_cnt = 0U;

        pthread_mutex_lock(&tlb->lock);
        for (uint32_t w = 0; w < VMM_TLB_WAYS; w++) {
            if (tlb->entries[w].valid &&
                tlb->entries[w].vpn >= start_vpn &&
                tlb->entries[w].vpn < end_vpn) {
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

    if (atomic_load_explicit(&vm->active_workers, memory_order_relaxed) > 1U) {
        sched_yield();
    }
}
