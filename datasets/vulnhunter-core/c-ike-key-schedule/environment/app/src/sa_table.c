#include "kex_engine.h"
#include <stdlib.h>
#include <string.h>

ChildSa *kex_child_sa_alloc(void) {
    ChildSa *csa = (ChildSa *)calloc(1u, sizeof(ChildSa));
    if (csa == NULL) return NULL;
    csa->magic = KEX_CHILD_MAGIC;
    csa->refcnt = 1;
    return csa;
}

void kex_child_sa_ref(ChildSa *csa) {
    if (csa == NULL) return;
    if (csa->magic != KEX_CHILD_MAGIC || csa->refcnt <= 0) abort();
    csa->refcnt++;
}

void kex_child_sa_unref(ChildSa *csa) {
    if (csa == NULL) return;
    if (csa->magic != KEX_CHILD_MAGIC || csa->refcnt <= 0) abort();
    csa->refcnt--;
    if (csa->refcnt == 0) {
        kex_secure_zero(csa, sizeof(*csa));
        free(csa);
    }
}

KexSa *kex_table_find_sa(KexEngine *eng, uint64_t init_spi, uint64_t resp_spi) {
    for (size_t i = 0; i < KEX_MAX_SAS; i++) {
        KexSa *sa = &eng->slots[i];
        if (!sa->in_use || sa->state == KEX_STATE_DELETED) continue;
        if (sa->init_spi == init_spi && (resp_spi == 0 || sa->resp_spi == resp_spi)) return sa;
    }
    return NULL;
}

KexSa *kex_table_alloc_sa(KexEngine *eng, uint64_t init_spi, uint64_t resp_spi) {
    if (kex_table_find_sa(eng, init_spi, resp_spi) != NULL) return NULL;
    for (size_t i = 0; i < KEX_MAX_SAS; i++) {
        KexSa *sa = &eng->slots[i];
        if (!sa->in_use) {
            memset(sa, 0, sizeof(*sa));
            sa->in_use = true;
            sa->init_spi = init_spi;
            sa->resp_spi = resp_spi;
            sa->state = KEX_STATE_IDLE;
            kex_frag_init(&sa->frag);
            return sa;
        }
    }
    return NULL;
}

void kex_table_release_sa(KexSa *sa) {
    if (sa == NULL || !sa->in_use) return;
    kex_frag_reset(&sa->frag);
    if (sa->active_child != NULL) { kex_child_sa_unref(sa->active_child); sa->active_child = NULL; }
    if (sa->pending_rekey != NULL) { kex_child_sa_unref(sa->pending_rekey); sa->pending_rekey = NULL; }
    if (sa->collision_peer != NULL) { kex_child_sa_unref(sa->collision_peer); sa->collision_peer = NULL; }
    kex_secure_zero(sa, sizeof(*sa));
}

uint32_t kex_table_count_established(const KexEngine *eng) {
    uint32_t count = 0;
    for (size_t i = 0; i < KEX_MAX_SAS; i++) {
        if (eng->slots[i].in_use && eng->slots[i].state == KEX_STATE_ESTABLISHED) count++;
    }
    return count;
}

void kex_table_compute_digest(const KexEngine *eng, uint8_t out_digest[KEX_HASH_LEN]) {
    KexSha256Ctx sh;
    kex_sha256_init(&sh);
    kex_sha256_update(&sh, eng->probe_acc, KEX_HASH_LEN);
    for (size_t i = 0; i < KEX_MAX_SAS; i++) {
        const KexSa *sa = &eng->slots[i];
        if (!sa->in_use || sa->state != KEX_STATE_ESTABLISHED) continue;
        uint8_t meta[24];
        kex_put_be64(meta + 0, sa->init_spi);
        kex_put_be64(meta + 8u, sa->resp_spi);
        kex_put_be16(meta + 16u, sa->policy_flags);
        kex_put_be16(meta + 18u, sa->completed_kem_rounds);
        kex_put_be32(meta + 20u, sa->peer_id);
        kex_sha256_update(&sh, meta, sizeof(meta));
        kex_sha256_update(&sh, sa->sk_d, KEX_HASH_LEN);
        if (sa->active_child != NULL) {
            if (sa->active_child->magic != KEX_CHILD_MAGIC || !sa->active_child->established) abort();
            uint8_t cmeta[8];
            kex_put_be32(cmeta + 0, sa->active_child->child_spi_in);
            kex_put_be32(cmeta + 4u, sa->active_child->child_spi_out);
            kex_sha256_update(&sh, cmeta, sizeof(cmeta));
            kex_sha256_update(&sh, sa->active_child->sk_child_i, KEX_HASH_LEN);
            kex_sha256_update(&sh, sa->active_child->sk_child_r, KEX_HASH_LEN);
        }
    }
    kex_sha256_final(&sh, out_digest);
}
