#include "vmm_mmu.h"

#include <stdlib.h>
#include <string.h>

vmm_status_t vmm_phys_pool_init(vmm_phys_pool_t *pool, uint32_t total_frames) {
    if (pool == NULL || total_frames <= VMM_IMAGE_TOTAL_PAGES + 16U) {
        return VMM_ERR_INVALID;
    }

    memset(pool, 0, sizeof(*pool));
    pool->frames = (vmm_frame_t *)calloc(total_frames, sizeof(vmm_frame_t));
    if (pool->frames == NULL) {
        return VMM_ERR_NOMEM;
    }

    pool->free_stack = (uint32_t *)calloc(total_frames, sizeof(uint32_t));
    if (pool->free_stack == NULL) {
        free(pool->frames);
        pool->frames = NULL;
        return VMM_ERR_NOMEM;
    }

    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool->free_stack);
        free(pool->frames);
        memset(pool, 0, sizeof(*pool));
        return VMM_ERR_INVALID;
    }

    pool->total_frames = total_frames;
    pool->free_top = 0;

    /* PFN 0 is reserved as an invalid sentinel; push PFNs [1..total_frames-1] in reverse */
    atomic_init(&pool->frames[0].refcount, 1U);
    pool->frames[0].pfn = 0U;

    for (uint32_t i = total_frames - 1U; i >= 1U; i--) {
        atomic_init(&pool->frames[i].refcount, 0U);
        pool->frames[i].pfn = i;
        pool->free_stack[pool->free_top++] = i;
    }

    return VMM_OK;
}

void vmm_phys_pool_destroy(vmm_phys_pool_t *pool) {
    if (pool == NULL || pool->frames == NULL) {
        return;
    }
    pthread_mutex_destroy(&pool->lock);
    free(pool->free_stack);
    free(pool->frames);
    memset(pool, 0, sizeof(*pool));
}

vmm_frame_t *vmm_phys_frame(vmm_phys_pool_t *pool, uint32_t pfn) {
    if (pool == NULL || pfn == 0U || pfn >= pool->total_frames) {
        return NULL;
    }
    return &pool->frames[pfn];
}

vmm_frame_t *vmm_frame_alloc(vmm_phys_pool_t *pool) {
    if (pool == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&pool->lock);
    if (pool->free_top == 0U) {
        pthread_mutex_unlock(&pool->lock);
        return NULL;
    }
    uint32_t pfn = pool->free_stack[--pool->free_top];
    pthread_mutex_unlock(&pool->lock);

    vmm_frame_t *frame = &pool->frames[pfn];
    memset(frame->data, 0, VMM_PAGE_SIZE);
    atomic_store_explicit(&frame->refcount, 1U, memory_order_release);
    return frame;
}

void vmm_frame_get(vmm_frame_t *frame) {
    if (frame != NULL) {
        atomic_fetch_add_explicit(&frame->refcount, 1U, memory_order_relaxed);
    }
}

void vmm_frame_put(vmm_phys_pool_t *pool, vmm_frame_t *frame) {
    if (pool == NULL || frame == NULL || frame->pfn == 0U) {
        return;
    }

    uint32_t prev = atomic_fetch_sub_explicit(&frame->refcount, 1U, memory_order_acq_rel);
    if (prev == 1U) {
        memset(frame->data, 0, VMM_PAGE_SIZE);
        pthread_mutex_lock(&pool->lock);
        pool->free_stack[pool->free_top++] = frame->pfn;
        pthread_mutex_unlock(&pool->lock);
    }
}

uint32_t vmm_phys_free_count(vmm_phys_pool_t *pool) {
    if (pool == NULL) {
        return 0U;
    }
    pthread_mutex_lock(&pool->lock);
    uint32_t count = pool->free_top;
    pthread_mutex_unlock(&pool->lock);
    return count;
}
