#include "vmm_trace.h"

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern vmm_status_t __real_vmm_resolve_s2_fault(
    vmm_instance_t *vm,
    const vmm_slot_t *slot,
    uint64_t gpa,
    uint32_t fault_flags,
    uint32_t *outcome
);

typedef enum {
    HOOK_NONE          = 0,
    HOOK_ZAP_ONLY      = 1,
    HOOK_ZAP_AND_READ  = 2,
} hook_mode_t;

typedef struct {
    _Atomic int      mode;
    _Atomic int      armed;
    _Atomic int      req_cmd;   /* 0=idle, 1=zap, 2=zap+read, 99=quit */
    _Atomic int      req_done;
    pthread_t        target_tid;
    vmm_instance_t  *vm;
    uint64_t         gpa;
} fault_hook_ctl_t;

static fault_hook_ctl_t g_hook;

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void *hook_helper_thread(void *arg) {
    (void)arg;
    uint8_t dummy[64];

    for (;;) {
        int cmd = atomic_load_explicit(&g_hook.req_cmd, memory_order_acquire);
        if (cmd == 0) {
            sched_yield();
            continue;
        }
        if (cmd == 99) {
            atomic_store_explicit(&g_hook.req_cmd, 0, memory_order_release);
            break;
        }

        vmm_instance_t *vm = g_hook.vm;
        uint64_t page_gpa = g_hook.gpa & VMM_PAGE_MASK;

        if (cmd == 1) {
            (void)vmm_balloon_zap_range(vm, page_gpa, 1U);
        } else if (cmd == 2) {
            (void)vmm_balloon_zap_range(vm, page_gpa, 1U);
            (void)vmm_guest_load(vm, 1U, page_gpa, dummy, sizeof(dummy));
        }

        atomic_store_explicit(&g_hook.req_cmd, 0, memory_order_release);
        atomic_store_explicit(&g_hook.req_done, 1, memory_order_release);
    }
    return NULL;
}

vmm_status_t __wrap_vmm_resolve_s2_fault(
    vmm_instance_t *vm,
    const vmm_slot_t *slot,
    uint64_t gpa,
    uint32_t fault_flags,
    uint32_t *outcome
) {
    uint32_t local_out = 0U;
    uint32_t *out_ptr = (outcome != NULL) ? outcome : &local_out;

    vmm_status_t st = __real_vmm_resolve_s2_fault(vm, slot, gpa, fault_flags, out_ptr);
    if (st != VMM_OK) {
        return st;
    }

    int mode = atomic_load_explicit(&g_hook.mode, memory_order_acquire);
    if (mode != HOOK_NONE &&
        (fault_flags & VMM_FAULT_OVERRIDE) != 0U &&
        (*out_ptr & VMM_FAULT_OUT_COW_SPLIT) != 0U &&
        pthread_equal(pthread_self(), g_hook.target_tid)) {
        if (atomic_exchange_explicit(&g_hook.armed, 0, memory_order_acq_rel) == 1) {
            g_hook.vm = vm;
            g_hook.gpa = gpa;
            atomic_store_explicit(&g_hook.req_done, 0, memory_order_release);
            atomic_store_explicit(
                &g_hook.req_cmd,
                (mode == HOOK_ZAP_AND_READ) ? 2 : 1,
                memory_order_release
            );

            /* Wait up to 3 ms so serialized-lock fixes never deadlock */
            uint64_t deadline = monotonic_ns() + 3000000ULL;
            while (atomic_load_explicit(&g_hook.req_done, memory_order_acquire) == 0 &&
                   monotonic_ns() < deadline) {
                sched_yield();
            }
        }
    }

    return st;
}

static int run_hooked_check(hook_mode_t mode, const char **err_msg) {
    vmm_phys_pool_t phys;
    if (vmm_phys_pool_init(&phys, VMM_DEFAULT_POOL_FRAMES) != VMM_OK) {
        *err_msg = "phys_pool_init failed";
        return 0;
    }

    vmm_image_store_t img;
    if (vmm_image_init(&img, &phys, 0x51952016U + (uint32_t)mode) != VMM_OK) {
        vmm_phys_pool_destroy(&phys);
        *err_msg = "image_init failed";
        return 0;
    }

    uint32_t free_baseline = vmm_phys_free_count(&phys);
    uint64_t ro_baseline = vmm_image_ro_digest(&img);

    vmm_instance_t vm;
    if (vmm_init(&vm, &phys, &img) != VMM_OK) {
        vmm_image_destroy(&img);
        vmm_phys_pool_destroy(&phys);
        *err_msg = "vmm_init failed";
        return 0;
    }

    if (vmm_map_slot(&vm, 0U, 0x20000ULL, 4U,
                     VMM_SLOT_READ | VMM_SLOT_EXEC | VMM_SLOT_COW | VMM_SLOT_BACKED,
                     8U) != VMM_OK) {
        vmm_destroy(&vm);
        vmm_image_destroy(&img);
        vmm_phys_pool_destroy(&phys);
        *err_msg = "map_slot failed";
        return 0;
    }

    memset(&g_hook, 0, sizeof(g_hook));
    g_hook.target_tid = pthread_self();
    atomic_store_explicit(&g_hook.mode, (int)mode, memory_order_release);

    pthread_t helper;
    pthread_create(&helper, NULL, hook_helper_thread, NULL);

    uint8_t patch_payload[128];
    memset(patch_payload, (mode == HOOK_ZAP_AND_READ) ? 0xCC : 0xAA, sizeof(patch_payload));

    int ok = 1;
    for (int iter = 0; iter < 8; iter++) {
        /* Pre-fault clean read PTE on odd iterations to cover both present and non-present starts */
        if ((iter & 1) != 0) {
            uint8_t pre[16];
            (void)vmm_guest_load(&vm, 0U, 0x20000ULL, pre, sizeof(pre));
        } else {
            (void)vmm_balloon_zap_range(&vm, 0x20000ULL, 1U);
        }

        atomic_store_explicit(&g_hook.armed, 1, memory_order_release);
        vmm_status_t st = vmm_host_write_gpa(&vm, 0x20020ULL, patch_payload, sizeof(patch_payload), true);
        while (atomic_load_explicit(&g_hook.req_cmd, memory_order_acquire) != 0) {
            sched_yield();
        }
        if (st != VMM_OK) {
            *err_msg = "vmm_host_write_gpa override failed under concurrent reclaim";
            ok = 0;
            break;
        }
        if (vmm_image_ro_digest(&img) != ro_baseline) {
            *err_msg = (mode == HOOK_ZAP_AND_READ)
                ? "RO image corrupted under 3-way COW split + zap + clean read refault"
                : "RO image corrupted under 2-way COW split + zap";
            ok = 0;
            break;
        }
    }

    atomic_store_explicit(&g_hook.mode, HOOK_NONE, memory_order_release);
    atomic_store_explicit(&g_hook.req_cmd, 99, memory_order_release);
    pthread_join(helper, NULL);

    vmm_destroy(&vm);
    if (ok && vmm_phys_free_count(&phys) != free_baseline) {
        *err_msg = "physical frame leak detected after hooked test";
        ok = 0;
    }

    vmm_image_destroy(&img);
    vmm_phys_pool_destroy(&phys);
    return ok;
}

typedef struct {
    vmm_instance_t  *vm;
    _Atomic int     *start_gate;
    int              role;
    uint32_t         iters;
} stress_arg_t;

static void *stress_worker(void *raw) {
    stress_arg_t *arg = (stress_arg_t *)raw;
    uint8_t buf[96];
    memset(buf, 0x5A + arg->role, sizeof(buf));

    while (atomic_load_explicit(arg->start_gate, memory_order_acquire) == 0) {
        sched_yield();
    }

    for (uint32_t i = 0; i < arg->iters; i++) {
        if (arg->role == 0) {
            /* Cross-page and in-page override live patches on guest-RO COW slot */
            uint64_t gpa = (i & 3U) == 0U ? 0x40FE0ULL : 0x40040ULL;
            (void)vmm_host_write_gpa(arg->vm, gpa, buf, 64U, true);
        } else if (arg->role == 1) {
            (void)vmm_balloon_zap_range(arg->vm, 0x40000ULL, 2U);
        } else {
            uint8_t rd[64];
            (void)vmm_guest_load(arg->vm, (uint32_t)(arg->role & 7), 0x40000ULL, rd, sizeof(rd));
            (void)vmm_guest_load(arg->vm, (uint32_t)(arg->role & 7), 0x41000ULL, rd, sizeof(rd));
        }
    }

    atomic_fetch_sub_explicit(&arg->vm->active_workers, 1U, memory_order_relaxed);
    return NULL;
}

static int run_pthread_stress_suite(const char **err_msg) {
    vmm_phys_pool_t phys;
    if (vmm_phys_pool_init(&phys, VMM_DEFAULT_POOL_FRAMES) != VMM_OK) {
        *err_msg = "phys_pool_init failed";
        return 0;
    }

    vmm_image_store_t img;
    if (vmm_image_init(&img, &phys, 0xA5A5F00DU) != VMM_OK) {
        vmm_phys_pool_destroy(&phys);
        *err_msg = "image_init failed";
        return 0;
    }

    uint32_t free_baseline = vmm_phys_free_count(&phys);
    uint64_t ro_baseline = vmm_image_ro_digest(&img);

    vmm_instance_t vm;
    if (vmm_init(&vm, &phys, &img) != VMM_OK) {
        vmm_image_destroy(&img);
        vmm_phys_pool_destroy(&phys);
        *err_msg = "vmm_init failed";
        return 0;
    }

    if (vmm_map_slot(&vm, 0U, 0x40000ULL, 4U,
                     VMM_SLOT_READ | VMM_SLOT_EXEC | VMM_SLOT_COW | VMM_SLOT_BACKED,
                     16U) != VMM_OK) {
        vmm_destroy(&vm);
        vmm_image_destroy(&img);
        vmm_phys_pool_destroy(&phys);
        *err_msg = "map_slot failed";
        return 0;
    }

    pthread_t tids[4];
    stress_arg_t args[4];
    _Atomic int gate = 0;

    atomic_store_explicit(&vm.active_workers, 4U, memory_order_release);
    uint32_t counts[4] = { 2500U, 9000U, 9000U, 9000U };
    for (int i = 0; i < 4; i++) {
        args[i].vm = &vm;
        args[i].start_gate = &gate;
        args[i].role = i;
        args[i].iters = counts[i];
        pthread_create(&tids[i], NULL, stress_worker, &args[i]);
    }

    atomic_store_explicit(&gate, 1, memory_order_release);
    for (int i = 0; i < 4; i++) {
        pthread_join(tids[i], NULL);
    }

    int ok = 1;
    if (vmm_image_ro_digest(&img) != ro_baseline) {
        *err_msg = "RO image corrupted during 4-thread pthread stress";
        ok = 0;
    }

    vmm_destroy(&vm);
    if (ok && vmm_phys_free_count(&phys) != free_baseline) {
        *err_msg = "physical frame leak detected after pthread stress";
        ok = 0;
    }

    vmm_image_destroy(&img);
    vmm_phys_pool_destroy(&phys);
    return ok;
}

static int run_functional_invariants(const char **err_msg) {
    vmm_phys_pool_t phys;
    if (vmm_phys_pool_init(&phys, VMM_DEFAULT_POOL_FRAMES) != VMM_OK) {
        *err_msg = "phys_pool_init failed";
        return 0;
    }

    vmm_image_store_t img;
    if (vmm_image_init(&img, &phys, 0x13572468U) != VMM_OK) {
        vmm_phys_pool_destroy(&phys);
        *err_msg = "image_init failed";
        return 0;
    }

    uint32_t free_baseline = vmm_phys_free_count(&phys);
    uint64_t ro_baseline = vmm_image_ro_digest(&img);
    uint64_t full_baseline = vmm_image_full_digest(&img);

    vmm_instance_t vm;
    if (vmm_init(&vm, &phys, &img) != VMM_OK) {
        vmm_image_destroy(&img);
        vmm_phys_pool_destroy(&phys);
        *err_msg = "vmm_init failed";
        return 0;
    }

    /* Slot 0: Guest RO + COW backed (boot text) */
    if (vmm_map_slot(&vm, 0U, 0x10000ULL, 2U,
                     VMM_SLOT_READ | VMM_SLOT_EXEC | VMM_SLOT_COW | VMM_SLOT_BACKED,
                     4U) != VMM_OK ||
        /* Slot 1: Pure RO backed without COW (immutable ROM) */
        vmm_map_slot(&vm, 1U, 0x30000ULL, 2U,
                     VMM_SLOT_READ | VMM_SLOT_BACKED,
                     20U) != VMM_OK ||
        /* Slot 2: Guest RW + COW backed (private data overlay) */
        vmm_map_slot(&vm, 2U, 0x50000ULL, 2U,
                     VMM_SLOT_READ | VMM_SLOT_WRITE | VMM_SLOT_COW | VMM_SLOT_BACKED,
                     30U) != VMM_OK ||
        /* Slot 3: Shared RW backed in RW image partition [96..127] */
        vmm_map_slot(&vm, 3U, 0x70000ULL, 2U,
                     VMM_SLOT_READ | VMM_SLOT_WRITE | VMM_SLOT_BACKED,
                     VMM_IMAGE_RO_PAGES) != VMM_OK) {
        vmm_destroy(&vm);
        vmm_image_destroy(&img);
        vmm_phys_pool_destroy(&phys);
        *err_msg = "slot setup failed";
        return 0;
    }

    uint8_t orig_bytes[32];
    if (vmm_guest_load(&vm, 0U, 0x10080ULL, orig_bytes, sizeof(orig_bytes)) != VMM_OK) {
        *err_msg = "initial guest_load failed";
        goto fail;
    }

    /* 1. Override live-patch on guest-RO COW slot must succeed */
    uint8_t patch_bytes[32];
    for (size_t i = 0; i < sizeof(patch_bytes); i++) {
        patch_bytes[i] = (uint8_t)(0xE0U + i);
    }
    if (vmm_host_write_gpa(&vm, 0x10080ULL, patch_bytes, sizeof(patch_bytes), true) != VMM_OK) {
        *err_msg = "legitimate override live-patch failed on RO COW slot";
        goto fail;
    }

    uint8_t check_buf[32];
    if (vmm_guest_load(&vm, 0U, 0x10080ULL, check_buf, sizeof(check_buf)) != VMM_OK ||
        memcmp(check_buf, patch_bytes, sizeof(patch_bytes)) != 0) {
        *err_msg = "guest_load did not observe override patch bytes";
        goto fail;
    }

    /* 2. Second consecutive override patch on already-split RO COW page must preserve prior bytes */
    uint8_t patch2[8] = { 0x90, 0x90, 0xCC, 0x90, 0x0F, 0x1F, 0x40, 0x00 };
    if (vmm_host_write_gpa(&vm, 0x10088ULL, patch2, sizeof(patch2), true) != VMM_OK) {
        *err_msg = "second consecutive override patch failed";
        goto fail;
    }
    if (vmm_guest_load(&vm, 0U, 0x10080ULL, check_buf, sizeof(check_buf)) != VMM_OK ||
        memcmp(check_buf, patch_bytes, 8U) != 0 ||
        memcmp(check_buf + 8U, patch2, 8U) != 0) {
        *err_msg = "consecutive override patches lost earlier patch bytes";
        goto fail;
    }

    /* 3. Guest store & non-override DMA on RO COW slot MUST still trap with VMM_ERR_PERM */
    uint8_t rogue[16];
    memset(rogue, 0x77, sizeof(rogue));
    if (vmm_guest_store(&vm, 0U, 0x10080ULL, rogue, sizeof(rogue)) != VMM_ERR_PERM) {
        *err_msg = "guest_store succeeded on RO COW slot after override patch (S2PTE_WRITE leaked)";
        goto fail;
    }
    if (vmm_host_write_gpa(&vm, 0x10080ULL, rogue, sizeof(rogue), false) != VMM_ERR_PERM) {
        *err_msg = "non-override host DMA write succeeded on RO COW slot";
        goto fail;
    }

    /* 4. Non-COW pure RO slot must reject even override writes */
    if (vmm_host_write_gpa(&vm, 0x30000ULL, patch_bytes, sizeof(patch_bytes), true) != VMM_ERR_PERM) {
        *err_msg = "override write succeeded on non-COW ROM slot";
        goto fail;
    }

    /* 5. Balloon reclaim on patched COW page must revert guest view to backing image */
    if (vmm_balloon_zap_range(&vm, 0x10000ULL, 1U) != VMM_OK) {
        *err_msg = "vmm_balloon_zap_range failed";
        goto fail;
    }
    if (vmm_guest_load(&vm, 0U, 0x10080ULL, check_buf, sizeof(check_buf)) != VMM_OK ||
        memcmp(check_buf, orig_bytes, sizeof(orig_bytes)) != 0) {
        *err_msg = "guest_load after balloon zap did not revert to clean backing image";
        goto fail;
    }

    /* 6. Guest RW COW slot + protect_slot demotion */
    if (vmm_guest_store(&vm, 1U, 0x50100ULL, patch_bytes, sizeof(patch_bytes)) != VMM_OK) {
        *err_msg = "guest_store on RW COW slot failed";
        goto fail;
    }
    if (vmm_protect_slot(&vm, 2U, VMM_SLOT_READ) != VMM_OK) {
        *err_msg = "vmm_protect_slot failed";
        goto fail;
    }
    if (vmm_guest_store(&vm, 1U, 0x50100ULL, rogue, sizeof(rogue)) != VMM_ERR_PERM) {
        *err_msg = "guest_store succeeded after vmm_protect_slot dropped VMM_SLOT_WRITE";
        goto fail;
    }

    /* 7. Shared RW slot writes through to RW partition without touching RO partition */
    if (vmm_guest_store(&vm, 2U, 0x70000ULL, patch_bytes, sizeof(patch_bytes)) != VMM_OK) {
        *err_msg = "guest_store on shared RW slot failed";
        goto fail;
    }
    if (vmm_image_ro_digest(&img) != ro_baseline) {
        *err_msg = "RO image digest changed during functional suite";
        goto fail;
    }
    if (vmm_image_full_digest(&img) == full_baseline) {
        *err_msg = "shared RW image partition did not reflect write-through store";
        goto fail;
    }

    vmm_destroy(&vm);
    if (vmm_phys_free_count(&phys) != free_baseline) {
        vmm_image_destroy(&img);
        vmm_phys_pool_destroy(&phys);
        *err_msg = "physical frame leak detected after functional suite";
        return 0;
    }

    vmm_image_destroy(&img);
    vmm_phys_pool_destroy(&phys);
    return 1;

fail:
    vmm_destroy(&vm);
    vmm_image_destroy(&img);
    vmm_phys_pool_destroy(&phys);
    return 0;
}

static int cmd_trace(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return 2;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 2;
    }
    long sz = ftell(fp);
    if (sz <= 0 || sz > 2 * 1024 * 1024) {
        fclose(fp);
        return 2;
    }
    rewind(fp);

    uint8_t *raw = (uint8_t *)malloc((size_t)sz);
    if (raw == NULL) {
        fclose(fp);
        return 2;
    }
    size_t n = fread(raw, 1U, (size_t)sz, fp);
    fclose(fp);
    if (n != (size_t)sz) {
        free(raw);
        return 2;
    }

    atomic_store_explicit(&g_hook.mode, HOOK_NONE, memory_order_release);

    vmm_trace_summary_t sum;
    vmm_status_t st = vmm_exec_trace_bytes(raw, n, &sum);
    free(raw);

    int corrupted = (st == VMM_OK && sum.image_ro_digest != sum.baseline_ro_digest) ? 1 : 0;

    printf("{"
           "\"status\": %d, "
           "\"ro_corrupted\": %d, "
           "\"ops\": %" PRIu64 ", "
           "\"faults\": %" PRIu64 ", "
           "\"splits\": %" PRIu64 ", "
           "\"zaps\": %" PRIu64 ", "
           "\"guest_digest\": \"%016" PRIx64 "\", "
           "\"img_digest\": \"%016" PRIx64 "\", "
           "\"baseline_ro_digest\": \"%016" PRIx64 "\""
           "}\n",
           (int)st,
           corrupted,
           sum.ops_retired,
           sum.faults,
           sum.cow_splits,
           sum.balloon_zaps,
           sum.guest_digest,
           sum.image_ro_digest,
           sum.baseline_ro_digest);
    return 0;
}

static int cmd_audit(void) {
    const char *err = "ok";
    int ok_hook2 = run_hooked_check(HOOK_ZAP_ONLY, &err);
    if (!ok_hook2) {
        printf("{\"passed\": false, \"stage\": \"hook_2way_zap\", \"error\": \"%s\"}\n", err);
        return 0;
    }

    int ok_hook3 = run_hooked_check(HOOK_ZAP_AND_READ, &err);
    if (!ok_hook3) {
        printf("{\"passed\": false, \"stage\": \"hook_3way_zap_refault\", \"error\": \"%s\"}\n", err);
        return 0;
    }

    int ok_stress = run_pthread_stress_suite(&err);
    if (!ok_stress) {
        printf("{\"passed\": false, \"stage\": \"pthread_4way_stress\", \"error\": \"%s\"}\n", err);
        return 0;
    }

    int ok_func = run_functional_invariants(&err);
    if (!ok_func) {
        printf("{\"passed\": false, \"stage\": \"functional_invariants\", \"error\": \"%s\"}\n", err);
        return 0;
    }

    printf("{\"passed\": true, \"stage\": \"all\", \"error\": \"none\"}\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "trace") == 0) {
        return cmd_trace(argv[2]);
    }
    if (argc == 2 && strcmp(argv[1], "audit") == 0) {
        return cmd_audit();
    }
    fprintf(stderr, "Usage: %s [trace <file> | audit]\n", argv[0]);
    return 2;
}
