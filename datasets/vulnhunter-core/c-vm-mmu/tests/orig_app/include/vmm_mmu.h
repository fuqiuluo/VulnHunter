#ifndef VMM_MMU_H
#define VMM_MMU_H

#include "vmm_types.h"

#include <pthread.h>
#include <stdatomic.h>

typedef struct vmm_frame {
    _Atomic uint32_t refcount;
    uint32_t         pfn;
    uint8_t          data[VMM_PAGE_SIZE];
} vmm_frame_t;

typedef struct vmm_phys_pool {
    vmm_frame_t     *frames;
    uint32_t        *free_stack;
    uint32_t         total_frames;
    uint32_t         free_top;
    pthread_mutex_t  lock;
} vmm_phys_pool_t;

typedef struct vmm_image_store {
    vmm_phys_pool_t *phys;
    uint32_t         seed;
    uint32_t         page_pfns[VMM_IMAGE_TOTAL_PAGES];
} vmm_image_store_t;

typedef struct vmm_slot {
    bool             active;
    uint32_t         slot_id;
    uint32_t         flags;
    uint64_t         base_gpa;
    uint32_t         npages;
    uint32_t         image_base_page;
} vmm_slot_t;

typedef struct vmm_l2_table {
    pthread_mutex_t  lock;
    s2pte_t          entries[VMM_L2_ENTRIES];
} vmm_l2_table_t;

typedef struct vmm_tlb_entry {
    bool             valid;
    uint64_t         vpn;
    uint64_t         pte_attr;
    vmm_frame_t     *frame;
} vmm_tlb_entry_t;

typedef struct vmm_tlb {
    pthread_mutex_t  lock;
    uint32_t         next_way;
    uint64_t         flush_epoch;
    uint64_t         hits;
    uint64_t         misses;
    vmm_tlb_entry_t  entries[VMM_TLB_WAYS];
} vmm_tlb_t;

typedef struct vmm_instance {
    vmm_phys_pool_t   *phys;
    vmm_image_store_t *image;
    pthread_rwlock_t   slots_lock;
    vmm_slot_t         slots[VMM_MAX_SLOTS];
    vmm_l2_table_t    *l1[VMM_L1_ENTRIES];
    vmm_tlb_t          tlbs[VMM_MAX_VCPUS];

    _Atomic uint64_t   mmu_seq;
    _Atomic uint32_t   active_workers;
    _Atomic uint64_t   stat_faults;
    _Atomic uint64_t   stat_cow_splits;
    _Atomic uint64_t   stat_balloon_zaps;
    _Atomic uint64_t   stat_tlb_shootdowns;
} vmm_instance_t;

/* Physical frame pool */
vmm_status_t vmm_phys_pool_init(vmm_phys_pool_t *pool, uint32_t total_frames);
void         vmm_phys_pool_destroy(vmm_phys_pool_t *pool);
vmm_frame_t *vmm_phys_frame(vmm_phys_pool_t *pool, uint32_t pfn);
vmm_frame_t *vmm_frame_alloc(vmm_phys_pool_t *pool);
void         vmm_frame_get(vmm_frame_t *frame);
void         vmm_frame_put(vmm_phys_pool_t *pool, vmm_frame_t *frame);
uint32_t     vmm_phys_free_count(vmm_phys_pool_t *pool);

/* Base image backing store */
vmm_status_t vmm_image_init(vmm_image_store_t *img, vmm_phys_pool_t *phys, uint32_t seed);
void         vmm_image_destroy(vmm_image_store_t *img);
uint32_t     vmm_image_page_pfn(const vmm_image_store_t *img, uint32_t page_idx);
uint64_t     vmm_image_ro_digest(const vmm_image_store_t *img);
uint64_t     vmm_image_full_digest(const vmm_image_store_t *img);

/* Per-vCPU software TLB */
void         vmm_tlb_init_all(vmm_instance_t *vm);
void         vmm_tlb_destroy_all(vmm_instance_t *vm);
vmm_frame_t *vmm_tlb_lookup_pin(vmm_instance_t *vm, uint32_t vcpu_id, uint64_t gpa, uint64_t req_attr);
void         vmm_tlb_insert(vmm_instance_t *vm, uint32_t vcpu_id, uint64_t gpa, s2pte_t pte, vmm_frame_t *frame, uint64_t observed_seq);
void         vmm_tlb_shootdown_page(vmm_instance_t *vm, uint64_t gpa);
void         vmm_tlb_shootdown_range(vmm_instance_t *vm, uint64_t base_gpa, uint32_t npages);

/* VM Stage-2 MMU core */
vmm_status_t vmm_init(vmm_instance_t *vm, vmm_phys_pool_t *phys, vmm_image_store_t *image);
void         vmm_destroy(vmm_instance_t *vm);
vmm_status_t vmm_map_slot(
    vmm_instance_t *vm,
    uint32_t slot_id,
    uint64_t base_gpa,
    uint32_t npages,
    uint32_t slot_flags,
    uint32_t image_base_page
);
vmm_status_t vmm_protect_slot(vmm_instance_t *vm, uint32_t slot_id, uint32_t new_rw_flags);
const vmm_slot_t *vmm_find_slot_locked(const vmm_instance_t *vm, uint64_t gpa);
vmm_l2_table_t   *vmm_lookup_l2(const vmm_instance_t *vm, uint64_t gpa);

static inline size_t vmm_gpa_l1_index(uint64_t gpa) {
    return (size_t)((gpa >> (VMM_PAGE_SHIFT + VMM_L2_BITS)) & (VMM_L1_ENTRIES - 1U));
}

static inline size_t vmm_gpa_l2_index(uint64_t gpa) {
    return (size_t)((gpa >> VMM_PAGE_SHIFT) & (VMM_L2_ENTRIES - 1U));
}

/* Guest memory accesses and balloon reclaim */
vmm_status_t vmm_guest_load(vmm_instance_t *vm, uint32_t vcpu_id, uint64_t gpa, void *dst, size_t len);
vmm_status_t vmm_guest_store(vmm_instance_t *vm, uint32_t vcpu_id, uint64_t gpa, const void *src, size_t len);
vmm_status_t vmm_balloon_zap_range(vmm_instance_t *vm, uint64_t base_gpa, uint32_t npages);
uint64_t     vmm_guest_memory_digest(vmm_instance_t *vm);

/* Stage-2 EPT/NPT violation resolution */
vmm_status_t vmm_resolve_s2_fault(
    vmm_instance_t *vm,
    const vmm_slot_t *slot,
    uint64_t gpa,
    uint32_t fault_flags,
    uint32_t *outcome
);

/* Host DMA and live-patch GPA pinning */
vmm_status_t vmm_pin_gpa_pages(
    vmm_instance_t *vm,
    uint64_t base_gpa,
    uint32_t npages,
    uint32_t walk_flags,
    vmm_frame_t **out_frames
);
void         vmm_unpin_gpa_pages(vmm_instance_t *vm, vmm_frame_t **frames, uint32_t npages);
vmm_status_t vmm_host_read_gpa(vmm_instance_t *vm, uint64_t gpa, void *dst, size_t len);
vmm_status_t vmm_host_write_gpa(vmm_instance_t *vm, uint64_t gpa, const void *src, size_t len, bool override_ro);

#endif /* VMM_MMU_H */
