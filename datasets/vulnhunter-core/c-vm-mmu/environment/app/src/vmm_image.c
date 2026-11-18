#include "vmm_mmu.h"

#include <string.h>

static uint64_t splitmix64_next(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint64_t fnv1a_update(uint64_t hash, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

vmm_status_t vmm_image_init(vmm_image_store_t *img, vmm_phys_pool_t *phys, uint32_t seed) {
    if (img == NULL || phys == NULL) {
        return VMM_ERR_INVALID;
    }

    memset(img, 0, sizeof(*img));
    img->phys = phys;
    img->seed = seed;

    for (uint32_t i = 0; i < VMM_IMAGE_TOTAL_PAGES; i++) {
        vmm_frame_t *frame = vmm_frame_alloc(phys);
        if (frame == NULL) {
            vmm_image_destroy(img);
            return VMM_ERR_NOMEM;
        }
        img->page_pfns[i] = frame->pfn;

        uint64_t prng = ((uint64_t)seed << 32) ^ ((uint64_t)i * 0x517CC1B727220A95ULL) ^ 0x4D4D55494D473031ULL;
        for (size_t off = 0; off < VMM_PAGE_SIZE; off += sizeof(uint64_t)) {
            uint64_t word = splitmix64_next(&prng);
            memcpy(frame->data + off, &word, sizeof(uint64_t));
        }
    }

    return VMM_OK;
}

void vmm_image_destroy(vmm_image_store_t *img) {
    if (img == NULL || img->phys == NULL) {
        return;
    }
    for (uint32_t i = 0; i < VMM_IMAGE_TOTAL_PAGES; i++) {
        if (img->page_pfns[i] != 0U) {
            vmm_frame_t *f = vmm_phys_frame(img->phys, img->page_pfns[i]);
            vmm_frame_put(img->phys, f);
            img->page_pfns[i] = 0U;
        }
    }
    img->phys = NULL;
}

uint32_t vmm_image_page_pfn(const vmm_image_store_t *img, uint32_t page_idx) {
    if (img == NULL || page_idx >= VMM_IMAGE_TOTAL_PAGES) {
        return 0U;
    }
    return img->page_pfns[page_idx];
}

uint64_t vmm_image_ro_digest(const vmm_image_store_t *img) {
    if (img == NULL || img->phys == NULL) {
        return 0ULL;
    }
    uint64_t h = 14695981039346656037ULL;
    for (uint32_t i = 0; i < VMM_IMAGE_RO_PAGES; i++) {
        const vmm_frame_t *f = vmm_phys_frame(img->phys, img->page_pfns[i]);
        if (f != NULL) {
            h = fnv1a_update(h, f->data, VMM_PAGE_SIZE);
        }
    }
    return h;
}

uint64_t vmm_image_full_digest(const vmm_image_store_t *img) {
    if (img == NULL || img->phys == NULL) {
        return 0ULL;
    }
    uint64_t h = 14695981039346656037ULL;
    for (uint32_t i = 0; i < VMM_IMAGE_TOTAL_PAGES; i++) {
        const vmm_frame_t *f = vmm_phys_frame(img->phys, img->page_pfns[i]);
        if (f != NULL) {
            h = fnv1a_update(h, f->data, VMM_PAGE_SIZE);
        }
    }
    return h;
}
