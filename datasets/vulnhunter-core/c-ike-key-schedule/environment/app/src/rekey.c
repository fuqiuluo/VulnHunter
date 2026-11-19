#include "kex_engine.h"
#include <string.h>

static void rekey_compute_min_nonce(ChildSa *csa) {
    const uint8_t *src = (memcmp(csa->nonce_i, csa->nonce_r, KEX_NONCE_LEN) <= 0) ? csa->nonce_i : csa->nonce_r;
    memcpy(csa->min_nonce, src, KEX_NONCE_LEN);
}

static int rekey_compare_collision(const ChildSa *local_cand, const ChildSa *peer_cand) {
    return memcmp(local_cand->min_nonce, peer_cand->min_nonce, KEX_NONCE_LEN);
}

static uint32_t draw_child_spi(KexDrbg *drbg) {
    uint8_t raw[4];
    kex_drbg_generate(drbg, raw, sizeof(raw));
    uint32_t spi = kex_get_be32(raw);
    return spi != 0 ? spi : 0x01000001u;
}

static void kex_rekey_abort(KexSa *sa, ChildSa *cand) {
    (void)sa;
    if (cand != NULL) kex_child_sa_unref(cand);
}

int kex_child_establish_initial(KexSa *sa) {
    ChildSa *csa = kex_child_sa_alloc();
    if (csa == NULL) return KEX_ERR_NOMEM;
    csa->child_spi_in = sa->initial_local_child_spi;
    csa->child_spi_out = sa->initial_peer_child_spi;
    memcpy(csa->nonce_i, sa->nonce_i, KEX_NONCE_LEN);
    memcpy(csa->nonce_r, sa->nonce_r, KEX_NONCE_LEN);
    rekey_compute_min_nonce(csa);
    kex_derive_child_keys(sa, csa, NULL);
    csa->established = true;
    if (sa->active_child != NULL) kex_child_sa_unref(sa->active_child);
    sa->active_child = csa;
    return KEX_OK;
}

int kex_rekey_init_local(KexEngine *eng, KexSa *sa, bool use_pfs, uint32_t override_spi, const uint8_t *override_nonce, uint8_t *out_pkt, size_t cap, size_t *out_len) {
    if (sa->state != KEX_STATE_ESTABLISHED || sa->active_child == NULL || sa->pending_rekey != NULL) return KEX_ERR_STATE;

    ChildSa *cand = kex_child_sa_alloc();
    if (cand == NULL) return KEX_ERR_NOMEM;
    cand->rekey_of_spi = sa->active_child->child_spi_in;
    cand->child_spi_in = (override_spi != 0) ? override_spi : draw_child_spi(&eng->drbg);
    if (override_nonce != NULL) memcpy(cand->nonce_i, override_nonce, KEX_NONCE_LEN);
    else kex_drbg_generate(&eng->drbg, cand->nonce_i, KEX_NONCE_LEN);

    uint8_t pfs_pub[KEX_DH_LEN];
    if (use_pfs) {
        cand->has_pfs = true;
        (void)kex_dh_keypair(&eng->drbg, cand->pfs_priv, pfs_pub);
    }

    uint8_t plain[256];
    size_t plain_len = 0;
    KexProposal prop = { use_pfs ? KEX_DH_MODP256 : 0u, KEX_PRF_HMAC_SHA256, KEX_AEAD_SHA256_128, sa->policy_flags, cand->child_spi_in, 0u, 0u };
    if (kex_append_notify(plain, sizeof(plain), &plain_len, KEX_NOTIFY_REKEY_SA, KEX_PROTO_CHILD, sa->active_child->child_spi_in) != KEX_OK ||
        kex_append_proposal(plain, sizeof(plain), &plain_len, &prop) != KEX_OK ||
        kex_append_nonce(plain, sizeof(plain), &plain_len, cand->nonce_i) != KEX_OK ||
        (use_pfs && kex_append_ke(plain, sizeof(plain), &plain_len, KEX_DH_MODP256, pfs_pub) != KEX_OK)) {
        kex_child_sa_unref(cand);
        return KEX_ERR_WIRE;
    }

    uint32_t msg_id = sa->next_local_msg_id++;
    KexHeader hdr = { sa->init_spi, sa->resp_spi, KEX_VERSION_20, KEX_EXCH_CREATE_CHILD, 0u, KEX_UNIT_SK, msg_id, 0u };
    int rc = kex_wrap_encrypted_packet(&eng->drbg, sa->sk_er, sa->sk_ar, &hdr, KEX_UNIT_NOTIFY, plain, plain_len, out_pkt, cap, out_len);
    if (rc != KEX_OK) {
        kex_child_sa_unref(cand);
        return rc;
    }
    sa->pending_rekey = cand;
    sa->pending_rekey_msg_id = msg_id;
    kex_engine_record_tx(eng, out_pkt, *out_len);
    return KEX_OK;
}

int kex_rekey_handle_request(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len, uint8_t *out_pkt, size_t cap, size_t *out_len) {
    if (sa->state != KEX_STATE_ESTABLISHED || sa->active_child == NULL || hdr->msg_id != sa->expected_peer_msg_id) return KEX_ERR_STATE;

    bool seen_rekey = false, seen_prop = false, seen_nonce = false, seen_ke = false;
    uint32_t target_spi = 0;
    KexProposal prop;
    uint8_t peer_nonce[KEX_NONCE_LEN], peer_ke[KEX_DH_LEN];

    KexUnitIter it;
    KexUnitView u;
    kex_unit_iter_init(&it, plain, plain_len);
    while (true) {
        int rc = kex_unit_iter_next(&it, &u);
        if (rc < 0) return rc;
        if (rc == 0) break;
        if (u.unit_type == KEX_UNIT_NOTIFY && u.body_len >= 8u && kex_get_be16(u.body) == KEX_NOTIFY_REKEY_SA) {
            target_spi = kex_get_be32(u.body + 4u);
            seen_rekey = true;
        } else if (u.unit_type == KEX_UNIT_SA_PROPOSAL) {
            if (kex_parse_proposal(&u, &prop) != KEX_OK) return KEX_ERR_WIRE;
            seen_prop = true;
        } else if (u.unit_type == KEX_UNIT_NONCE && u.body_len == KEX_NONCE_LEN) {
            memcpy(peer_nonce, u.body, KEX_NONCE_LEN);
            seen_nonce = true;
        } else if (u.unit_type == KEX_UNIT_KE_CLASSIC && u.body_len == 4u + KEX_DH_LEN) {
            if (kex_get_be16(u.body) != KEX_DH_MODP256) return KEX_ERR_PROPOSAL;
            memcpy(peer_ke, u.body + 4u, KEX_DH_LEN);
            seen_ke = true;
        }
    }

    if (!seen_rekey || !seen_prop || !seen_nonce || prop.child_spi == 0) return KEX_ERR_PROTO;
    if (target_spi != sa->active_child->child_spi_in && target_spi != sa->active_child->child_spi_out) return KEX_ERR_STATE;
    if ((prop.dh_group == KEX_DH_MODP256) != seen_ke || (prop.dh_group != 0u && prop.dh_group != KEX_DH_MODP256)) return KEX_ERR_PROPOSAL;

    if (sa->collision_peer != NULL) {
        uint8_t nbuf[32];
        size_t nlen = 0;
        (void)kex_append_notify(nbuf, sizeof(nbuf), &nlen, KEX_NOTIFY_TEMP_FAILURE, KEX_PROTO_CHILD, 0u);
        KexHeader rhdr = *hdr;
        rhdr.flags = KEX_FLAG_RESPONSE;
        int wrc = kex_wrap_encrypted_packet(&eng->drbg, sa->sk_er, sa->sk_ar, &rhdr, KEX_UNIT_NOTIFY, nbuf, nlen, out_pkt, cap, out_len);
        if (wrc == KEX_OK) sa->expected_peer_msg_id++;
        return wrc;
    }

    uint8_t pfs_priv[KEX_DH_LEN], pfs_pub[KEX_DH_LEN], pfs_ss[KEX_DH_LEN];
    if (seen_ke) {
        (void)kex_dh_keypair(&eng->drbg, pfs_priv, pfs_pub);
        if (kex_dh_shared(pfs_priv, peer_ke, pfs_ss) != KEX_OK) {
            kex_secure_zero(pfs_priv, sizeof(pfs_priv));
            return KEX_ERR_CRYPTO;
        }
        kex_secure_zero(pfs_priv, sizeof(pfs_priv));
    }

    ChildSa *peer_cand = kex_child_sa_alloc();
    if (peer_cand == NULL) return KEX_ERR_NOMEM;
    peer_cand->rekey_of_spi = sa->active_child->child_spi_in;
    peer_cand->child_spi_in = draw_child_spi(&eng->drbg);
    peer_cand->child_spi_out = prop.child_spi;
    memcpy(peer_cand->nonce_i, peer_nonce, KEX_NONCE_LEN);
    kex_drbg_generate(&eng->drbg, peer_cand->nonce_r, KEX_NONCE_LEN);
    rekey_compute_min_nonce(peer_cand);
    kex_derive_child_keys(sa, peer_cand, seen_ke ? pfs_ss : NULL);
    peer_cand->established = true;
    kex_secure_zero(pfs_ss, sizeof(pfs_ss));

    uint8_t rplain[256];
    size_t rplain_len = 0;
    KexProposal rprop = prop;
    rprop.child_spi = peer_cand->child_spi_in;
    if (kex_append_proposal(rplain, sizeof(rplain), &rplain_len, &rprop) != KEX_OK ||
        kex_append_nonce(rplain, sizeof(rplain), &rplain_len, peer_cand->nonce_r) != KEX_OK ||
        (seen_ke && kex_append_ke(rplain, sizeof(rplain), &rplain_len, KEX_DH_MODP256, pfs_pub) != KEX_OK)) {
        kex_child_sa_unref(peer_cand);
        return KEX_ERR_WIRE;
    }

    KexHeader rhdr = { sa->init_spi, sa->resp_spi, KEX_VERSION_20, KEX_EXCH_CREATE_CHILD, KEX_FLAG_RESPONSE, KEX_UNIT_SK, hdr->msg_id, 0u };
    int rc = kex_wrap_encrypted_packet(&eng->drbg, sa->sk_er, sa->sk_ar, &rhdr, KEX_UNIT_SA_PROPOSAL, rplain, rplain_len, out_pkt, cap, out_len);
    if (rc != KEX_OK) {
        kex_child_sa_unref(peer_cand);
        return rc;
    }

    sa->expected_peer_msg_id++;
    if (sa->pending_rekey != NULL) {
        sa->collision_peer = peer_cand;
        sa->collision_detected = true;
    } else {
        ChildSa *old = sa->active_child;
        sa->active_child = peer_cand;
        kex_child_sa_unref(old);
    }
    return KEX_OK;
}

int kex_rekey_handle_response(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len) {
    (void)eng;
    if (sa->state != KEX_STATE_ESTABLISHED || sa->pending_rekey == NULL || hdr->msg_id != sa->pending_rekey_msg_id) return KEX_ERR_STATE;

    ChildSa *local_cand = sa->pending_rekey;
    ChildSa *old_active = sa->active_child;
    sa->active_child = local_cand;
    sa->pending_rekey = NULL;

    bool seen_prop = false, seen_nonce = false, seen_ke = false;
    KexProposal prop;
    uint8_t peer_nonce[KEX_NONCE_LEN], peer_ke[KEX_DH_LEN];

    KexUnitIter it;
    KexUnitView u;
    kex_unit_iter_init(&it, plain, plain_len);
    while (true) {
        int rc = kex_unit_iter_next(&it, &u);
        if (rc < 0) {
            kex_rekey_abort(sa, local_cand);
            return rc;
        }
        if (rc == 0) break;
        if (u.unit_type == KEX_UNIT_NOTIFY && u.body_len >= 8u) {
            uint16_t ntype = kex_get_be16(u.body);
            if (ntype == KEX_NOTIFY_TEMP_FAILURE || ntype == KEX_NOTIFY_NO_PROPOSAL_CHOSEN) {
                kex_rekey_abort(sa, local_cand);
                return KEX_OK;
            }
        } else if (u.unit_type == KEX_UNIT_SA_PROPOSAL) {
            if (kex_parse_proposal(&u, &prop) != KEX_OK) {
                kex_rekey_abort(sa, local_cand);
                return KEX_ERR_WIRE;
            }
            seen_prop = true;
        } else if (u.unit_type == KEX_UNIT_NONCE && u.body_len == KEX_NONCE_LEN) {
            memcpy(peer_nonce, u.body, KEX_NONCE_LEN);
            seen_nonce = true;
        } else if (u.unit_type == KEX_UNIT_KE_CLASSIC && u.body_len == 4u + KEX_DH_LEN) {
            if (kex_get_be16(u.body) != KEX_DH_MODP256) {
                kex_rekey_abort(sa, local_cand);
                return KEX_ERR_PROPOSAL;
            }
            memcpy(peer_ke, u.body + 4u, KEX_DH_LEN);
            seen_ke = true;
        }
    }

    if (!seen_prop || !seen_nonce || prop.child_spi == 0 || local_cand->has_pfs != seen_ke) {
        kex_rekey_abort(sa, local_cand);
        return KEX_ERR_PROTO;
    }

    uint8_t pfs_ss[KEX_DH_LEN];
    if (local_cand->has_pfs && kex_dh_shared(local_cand->pfs_priv, peer_ke, pfs_ss) != KEX_OK) {
        kex_rekey_abort(sa, local_cand);
        return KEX_ERR_CRYPTO;
    }

    local_cand->child_spi_out = prop.child_spi;
    memcpy(local_cand->nonce_r, peer_nonce, KEX_NONCE_LEN);
    rekey_compute_min_nonce(local_cand);
    kex_derive_child_keys(sa, local_cand, local_cand->has_pfs ? pfs_ss : NULL);
    local_cand->established = true;
    kex_secure_zero(pfs_ss, sizeof(pfs_ss));

    if (sa->collision_detected && sa->collision_peer != NULL) {
        ChildSa *peer_cand = sa->collision_peer;
        sa->collision_peer = NULL;
        sa->collision_detected = false;
        if (rekey_compare_collision(local_cand, peer_cand) >= 0) {
            kex_child_sa_unref(peer_cand);
            kex_child_sa_unref(old_active);
        } else {
            kex_rekey_abort(sa, local_cand);
            kex_child_sa_unref(old_active);
        }
    } else {
        kex_child_sa_unref(old_active);
    }
    return KEX_OK;
}

int kex_handle_informational(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len, uint8_t *out_pkt, size_t cap, size_t *out_len) {
    if (sa->state != KEX_STATE_ESTABLISHED || hdr->msg_id != sa->expected_peer_msg_id) return KEX_ERR_STATE;

    bool delete_ike = false;
    uint32_t deleted_child_spi = 0;
    KexUnitIter it;
    KexUnitView u;
    kex_unit_iter_init(&it, plain, plain_len);
    while (true) {
        int rc = kex_unit_iter_next(&it, &u);
        if (rc < 0) return rc;
        if (rc == 0) break;
        if (u.unit_type == KEX_UNIT_DELETE) {
            if (u.body_len != 8u) return KEX_ERR_WIRE;
            uint16_t proto = kex_get_be16(u.body), count = kex_get_be16(u.body + 2u);
            uint32_t spi = kex_get_be32(u.body + 4u);
            if (proto == KEX_PROTO_IKE) delete_ike = true;
            else if (proto == KEX_PROTO_CHILD && count == 1u && sa->active_child != NULL &&
                     (sa->active_child->child_spi_in == spi || sa->active_child->child_spi_out == spi)) {
                deleted_child_spi = sa->active_child->child_spi_in;
                kex_child_sa_unref(sa->active_child);
                sa->active_child = NULL;
            }
        }
    }

    uint8_t rplain[32];
    size_t rplain_len = 0;
    uint8_t inner_first = 0;
    if (deleted_child_spi != 0) {
        uint8_t del_body[8];
        kex_put_be16(del_body + 0, KEX_PROTO_CHILD);
        kex_put_be16(del_body + 2u, 1u);
        kex_put_be32(del_body + 4u, deleted_child_spi);
        (void)kex_append_unit(rplain, sizeof(rplain), &rplain_len, KEX_UNIT_DELETE, 0, del_body, sizeof(del_body));
        inner_first = KEX_UNIT_DELETE;
    }

    KexHeader rhdr = { sa->init_spi, sa->resp_spi, KEX_VERSION_20, KEX_EXCH_INFORMATIONAL, KEX_FLAG_RESPONSE, KEX_UNIT_SK, hdr->msg_id, 0u };
    int rc = kex_wrap_encrypted_packet(&eng->drbg, sa->sk_er, sa->sk_ar, &rhdr, inner_first, rplain, rplain_len, out_pkt, cap, out_len);
    if (rc != KEX_OK) return rc;
    sa->expected_peer_msg_id++;
    if (delete_ike) kex_table_release_sa(sa);
    return KEX_OK;
}
