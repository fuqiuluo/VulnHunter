#ifndef VMM_TYPES_H
#define VMM_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VMM_PAGE_SHIFT          12U
#define VMM_PAGE_SIZE           (1U << VMM_PAGE_SHIFT)
#define VMM_PAGE_OFFSET_MASK    (VMM_PAGE_SIZE - 1U)
#define VMM_PAGE_MASK           (~(uint64_t)VMM_PAGE_OFFSET_MASK)

#define VMM_L1_BITS             6U
#define VMM_L2_BITS             6U
#define VMM_L1_ENTRIES          (1U << VMM_L1_BITS)
#define VMM_L2_ENTRIES          (1U << VMM_L2_BITS)
#define VMM_MAX_GPA_PAGES       (VMM_L1_ENTRIES * VMM_L2_ENTRIES)
#define VMM_MAX_GPA_BYTES       ((uint64_t)VMM_MAX_GPA_PAGES * VMM_PAGE_SIZE)

#define VMM_MAX_SLOTS           16U
#define VMM_MAX_VCPUS           8U
#define VMM_TLB_WAYS            16U

#define VMM_IMAGE_RO_PAGES      96U
#define VMM_IMAGE_RW_PAGES      32U
#define VMM_IMAGE_TOTAL_PAGES   (VMM_IMAGE_RO_PAGES + VMM_IMAGE_RW_PAGES)
#define VMM_DEFAULT_POOL_FRAMES 2048U

typedef enum {
    VMM_OK           =  0,
    VMM_ERR_INVALID  = -1,
    VMM_ERR_UNMAPPED = -2,
    VMM_ERR_PERM     = -3,
    VMM_ERR_NOMEM    = -4,
    VMM_ERR_FORMAT   = -5,
    VMM_ERR_BOUNDS   = -6,
} vmm_status_t;

typedef uint64_t s2pte_t;

#define S2PTE_PRESENT           (1ULL << 0)
#define S2PTE_READ              (1ULL << 1)
#define S2PTE_WRITE             (1ULL << 2)
#define S2PTE_EXEC              (1ULL << 3)
#define S2PTE_USER              (1ULL << 4)
#define S2PTE_ACCESSED          (1ULL << 5)
#define S2PTE_DIRTY             (1ULL << 6)
#define S2PTE_PFN_SHIFT         12U
#define S2PTE_PFN_MASK          (0xFFFFFULL << S2PTE_PFN_SHIFT)

static inline s2pte_t s2pte_make(uint32_t pfn, uint64_t attr) {
    return (((uint64_t)pfn << S2PTE_PFN_SHIFT) & S2PTE_PFN_MASK) | (attr & 0xFFFULL);
}

static inline uint32_t s2pte_pfn(s2pte_t pte) {
    return (uint32_t)((pte & S2PTE_PFN_MASK) >> S2PTE_PFN_SHIFT);
}

/* Guest physical memory slot attributes */
#define VMM_SLOT_READ           (1U << 0)
#define VMM_SLOT_WRITE          (1U << 1)
#define VMM_SLOT_EXEC           (1U << 2)
#define VMM_SLOT_COW            (1U << 3)
#define VMM_SLOT_BACKED         (1U << 4)

/* Stage-2 fault request flags */
#define VMM_FAULT_READ          (1U << 0)
#define VMM_FAULT_WRITE         (1U << 1)
#define VMM_FAULT_OVERRIDE      (1U << 2)

/* Stage-2 fault resolution outcomes */
#define VMM_FAULT_OUT_NOP       0U
#define VMM_FAULT_OUT_POPULATED (1U << 0)
#define VMM_FAULT_OUT_COW_SPLIT (1U << 1)
#define VMM_FAULT_OUT_MKWRITE   (1U << 2)

/* Host GPA pin / walk flags */
#define VMM_WALK_READ           (1U << 0)
#define VMM_WALK_WRITE          (1U << 1)
#define VMM_WALK_OVERRIDE       (1U << 2)

#endif /* VMM_TYPES_H */
