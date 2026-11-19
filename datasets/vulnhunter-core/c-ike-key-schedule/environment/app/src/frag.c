#include "kex_engine.h"
#include <stdlib.h>
#include <string.h>

void kex_frag_init(KexFragCtx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void kex_frag_reset(KexFragCtx *ctx) {
    if (ctx->slots != NULL) {
        for (uint16_t i = 0; i < ctx->total_frags; i++) {
            if (ctx->slots[i] != NULL) {
                kex_secure_zero(ctx->slots[i], ctx->slot_lens[i]);
                free(ctx->slots[i]);
            }
        }
        free(ctx->slots);
    }
    free(ctx->slot_lens);
    memset(ctx, 0, sizeof(*ctx));
}

int kex_frag_collect(KexSa *sa, const uint8_t *raw_pkt, size_t raw_len, const KexHeader *hdr, uint8_t *plain_out, size_t plain_cap, size_t *plain_len_out, uint8_t *inner_first_out) {
    if (hdr->first_unit != KEX_UNIT_SKF || (hdr->flags & KEX_FLAG_FRAGMENTED) == 0) return KEX_ERR_PROTO;
    if (hdr->msg_id < sa->expected_peer_msg_id) return KEX_ERR_STATE;

    KexUnitIter it;
    KexUnitView u;
    kex_unit_iter_init(&it, raw_pkt + KEX_HDR_LEN, raw_len - KEX_HDR_LEN);
    int rc = kex_unit_iter_next(&it, &u);
    if (rc != 1 || u.unit_type != KEX_UNIT_SKF || it.offset != it.len) return KEX_ERR_WIRE;
    if (u.body_len < 8u + KEX_AEAD_IV_LEN + KEX_AEAD_TAG_LEN) return KEX_ERR_WIRE;

    uint16_t frag_num = kex_get_be16(u.body + 0);
    uint16_t total_frags = kex_get_be16(u.body + 2u);
    uint8_t inner_first = u.body[4];
    if (total_frags == 0 || total_frags > KEX_MAX_FRAGS || frag_num > KEX_MAX_FRAGS) return KEX_ERR_PROTO;

    uint8_t aad[KEX_HDR_LEN + 8u], dec_buf[KEX_MAX_PKT_LEN];
    size_t dec_len = 0;
    memcpy(aad, raw_pkt, KEX_HDR_LEN);
    memcpy(aad + KEX_HDR_LEN, u.body, 8u);
    rc = kex_aead_open(sa->sk_ei, sa->sk_ai, aad, sizeof(aad), u.body + 8u, u.body_len - 8u, dec_buf, &dec_len);
    if (rc != KEX_OK) return rc;

    KexFragCtx *ctx = &sa->frag;
    if (ctx->active && (ctx->msg_id != hdr->msg_id || ctx->exch_type != hdr->exch_type)) {
        kex_frag_reset(ctx);
    }
    if (!ctx->active) {
        ctx->slots = (uint8_t **)calloc(total_frags, sizeof(uint8_t *));
        ctx->slot_lens = (size_t *)calloc(total_frags, sizeof(size_t));
        if (ctx->slots == NULL || ctx->slot_lens == NULL) {
            kex_frag_reset(ctx);
            kex_secure_zero(dec_buf, dec_len);
            return KEX_ERR_NOMEM;
        }
        ctx->active = true;
        ctx->msg_id = hdr->msg_id;
        ctx->exch_type = hdr->exch_type;
        ctx->total_frags = total_frags;
    }

    ctx->total_frags = total_frags;
    uint16_t idx = (uint16_t)(frag_num - 1u);
    if (frag_num == 1u) ctx->inner_first_unit = inner_first;

    uint8_t *chunk = NULL;
    if (dec_len > 0) {
        chunk = (uint8_t *)malloc(dec_len);
        if (chunk == NULL) {
            kex_secure_zero(dec_buf, dec_len);
            return KEX_ERR_NOMEM;
        }
        memcpy(chunk, dec_buf, dec_len);
    }
    kex_secure_zero(dec_buf, dec_len);

    ctx->slots[idx] = chunk;
    ctx->slot_lens[idx] = dec_len;
    if (idx < 32u) ctx->seen_mask |= (1u << idx);
    ctx->total_bytes += dec_len;
    ctx->received_count++;

    if (ctx->received_count < ctx->total_frags) return KEX_OK_PENDING;
    if (ctx->total_bytes > plain_cap) {
        kex_frag_reset(ctx);
        return KEX_ERR_WIRE;
    }

    size_t pos = 0;
    for (uint16_t i = 0; i < ctx->total_frags; i++) {
        if (ctx->slot_lens[i] > 0 && ctx->slots[i] != NULL) {
            memcpy(plain_out + pos, ctx->slots[i], ctx->slot_lens[i]);
            pos += ctx->slot_lens[i];
        }
    }
    *plain_len_out = pos;
    *inner_first_out = ctx->inner_first_unit;
    kex_frag_reset(ctx);
    return KEX_OK;
}
