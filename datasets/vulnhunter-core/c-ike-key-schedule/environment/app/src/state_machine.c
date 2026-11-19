#include "kex_engine.h"
#include <string.h>

uint16_t kex_kem_required_rounds(uint16_t kem_alg) {
    switch (kem_alg) {
    case KEX_KEM_NONE:        return 0u;
    case KEX_KEM_MLKEM768:    return 1u;
    case KEX_KEM_HYBRID_DUAL: return 2u;
    default:                  return 0xffffu;
    }
}

static bool valid_policy_combo(uint16_t policy_flags, uint16_t kem_alg) {
    uint16_t rounds = kex_kem_required_rounds(kem_alg);
    if (rounds == 0xffffu) return false;
    if (policy_flags == KEX_POLICY_CLASSIC_ONLY) return kem_alg == KEX_KEM_NONE;
    if (policy_flags == KEX_POLICY_HYBRID_OPTIONAL) return true;
    if (policy_flags == KEX_POLICY_HYBRID_REQUIRED) return rounds >= 1u;
    return false;
}

static int handle_sa_init(KexEngine *eng, const uint8_t *raw_pkt, size_t raw_len, const KexHeader *hdr, uint8_t *resp_out, size_t resp_cap, size_t *resp_len) {
    if (hdr->resp_spi != 0 || hdr->msg_id != 0 || hdr->flags != KEX_FLAG_INITIATOR) return KEX_ERR_PROTO;

    bool seen_prop = false, seen_ke = false, seen_nonce = false;
    KexProposal prop;
    uint8_t peer_pub[KEX_DH_LEN], peer_nonce[KEX_NONCE_LEN];

    KexUnitIter it;
    KexUnitView u;
    kex_unit_iter_init(&it, raw_pkt + KEX_HDR_LEN, raw_len - KEX_HDR_LEN);
    while (true) {
        int rc = kex_unit_iter_next(&it, &u);
        if (rc < 0) return rc;
        if (rc == 0) break;
        if (u.unit_type == KEX_UNIT_SA_PROPOSAL) {
            if (kex_parse_proposal(&u, &prop) != KEX_OK) return KEX_ERR_WIRE;
            seen_prop = true;
        } else if (u.unit_type == KEX_UNIT_KE_CLASSIC) {
            if (u.body_len != 4u + KEX_DH_LEN || kex_get_be16(u.body) != KEX_DH_MODP256) return KEX_ERR_PROPOSAL;
            memcpy(peer_pub, u.body + 4u, KEX_DH_LEN);
            seen_ke = true;
        } else if (u.unit_type == KEX_UNIT_NONCE) {
            if (u.body_len != KEX_NONCE_LEN) return KEX_ERR_WIRE;
            memcpy(peer_nonce, u.body, KEX_NONCE_LEN);
            seen_nonce = true;
        }
    }

    if (!seen_prop || !seen_ke || !seen_nonce) return KEX_ERR_PROTO;
    if (prop.dh_group != KEX_DH_MODP256 || prop.prf_alg != KEX_PRF_HMAC_SHA256 ||
        prop.aead_alg != KEX_AEAD_SHA256_128 || prop.child_spi == 0 ||
        !valid_policy_combo(prop.policy_flags, prop.kem_alg)) return KEX_ERR_PROPOSAL;

    uint8_t spi_raw[8], dh_priv[KEX_DH_LEN], dh_pub[KEX_DH_LEN], dh_shared[KEX_DH_LEN], nonce_r[KEX_NONCE_LEN], cspi_raw[4];
    kex_drbg_generate(&eng->drbg, spi_raw, sizeof(spi_raw));
    uint64_t resp_spi = kex_get_be64(spi_raw);
    if (resp_spi == 0) resp_spi = 0x0102030405060708ULL;

    (void)kex_dh_keypair(&eng->drbg, dh_priv, dh_pub);
    if (kex_dh_shared(dh_priv, peer_pub, dh_shared) != KEX_OK) {
        kex_secure_zero(dh_priv, sizeof(dh_priv));
        return KEX_ERR_CRYPTO;
    }
    kex_secure_zero(dh_priv, sizeof(dh_priv));

    kex_drbg_generate(&eng->drbg, nonce_r, sizeof(nonce_r));
    kex_drbg_generate(&eng->drbg, cspi_raw, sizeof(cspi_raw));
    uint32_t local_cspi = kex_get_be32(cspi_raw);
    if (local_cspi == 0) local_cspi = 0x01000001u;

    KexSa *sa = kex_table_alloc_sa(eng, hdr->init_spi, resp_spi);
    if (sa == NULL) {
        kex_secure_zero(dh_shared, sizeof(dh_shared));
        return KEX_ERR_NOMEM;
    }

    sa->policy_flags = prop.policy_flags;
    sa->kem_alg = prop.kem_alg;
    sa->required_kem_rounds = kex_kem_required_rounds(prop.kem_alg);
    sa->initial_peer_child_spi = prop.child_spi;
    sa->initial_local_child_spi = local_cspi;
    sa->expected_peer_msg_id = 1u;
    memcpy(sa->nonce_i, peer_nonce, KEX_NONCE_LEN);
    memcpy(sa->nonce_r, nonce_r, KEX_NONCE_LEN);
    memcpy(sa->dh_shared, dh_shared, KEX_DH_LEN);
    kex_secure_zero(dh_shared, sizeof(dh_shared));
    kex_derive_init_keys(sa);

    size_t off = KEX_HDR_LEN;
    KexProposal rprop = prop;
    rprop.child_spi = local_cspi;
    if (resp_cap < KEX_HDR_LEN ||
        kex_append_proposal(resp_out, resp_cap, &off, &rprop) != KEX_OK ||
        kex_append_ke(resp_out, resp_cap, &off, KEX_DH_MODP256, dh_pub) != KEX_OK ||
        kex_append_nonce(resp_out, resp_cap, &off, sa->nonce_r) != KEX_OK) {
        kex_table_release_sa(sa);
        return KEX_ERR_WIRE;
    }

    KexHeader rhdr = { sa->init_spi, sa->resp_spi, KEX_VERSION_20, KEX_EXCH_SA_INIT, KEX_FLAG_RESPONSE, KEX_UNIT_SA_PROPOSAL, 0u, (uint32_t)off };
    kex_write_header(resp_out, &rhdr);
    *resp_len = off;
    kex_sha256(raw_pkt, raw_len, sa->init_req_hash);
    kex_sha256(resp_out, *resp_len, sa->init_resp_hash);
    sa->state = KEX_STATE_INIT_DONE;
    return KEX_OK;
}

static int handle_intermediate(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len, uint8_t *resp_out, size_t resp_cap, size_t *resp_len) {
    if (sa->state != KEX_STATE_INIT_DONE || sa->required_kem_rounds == 0u || sa->completed_kem_rounds >= sa->required_kem_rounds) return KEX_ERR_STATE;
    if ((hdr->flags & KEX_FLAG_RESPONSE) != 0 || hdr->msg_id != sa->expected_peer_msg_id) return KEX_ERR_STATE;

    bool seen_kem = false;
    uint16_t round_num = 0, kem_alg = 0;
    uint8_t peer_pk[KEX_DH_LEN];

    KexUnitIter it;
    KexUnitView u;
    kex_unit_iter_init(&it, plain, plain_len);
    while (true) {
        int rc = kex_unit_iter_next(&it, &u);
        if (rc < 0) return rc;
        if (rc == 0) break;
        if (u.unit_type == KEX_UNIT_KEM_DATA) {
            if (seen_kem || u.body_len != 4u + KEX_DH_LEN) return KEX_ERR_PROTO;
            round_num = kex_get_be16(u.body + 0);
            kem_alg = kex_get_be16(u.body + 2u);
            memcpy(peer_pk, u.body + 4u, KEX_DH_LEN);
            seen_kem = true;
        } else if (u.unit_type != KEX_UNIT_NOTIFY) {
            return KEX_ERR_PROTO;
        }
    }

    uint16_t expected_round = (uint16_t)(sa->completed_kem_rounds + 1u);
    if (!seen_kem || round_num != expected_round || kem_alg != sa->kem_alg) return KEX_ERR_PROTO;

    uint8_t kem_ct[KEX_DH_LEN], pq_ss[KEX_HASH_LEN], rplain[128];
    size_t rplain_len = 0;
    int krc = kex_kem_encaps(&eng->drbg, round_num, peer_pk, kem_ct, pq_ss);
    if (krc != KEX_OK) return krc;
    if (kex_append_kem(rplain, sizeof(rplain), &rplain_len, round_num, sa->kem_alg, kem_ct) != KEX_OK) {
        kex_secure_zero(pq_ss, sizeof(pq_ss));
        return KEX_ERR_WIRE;
    }

    KexHeader rhdr = { sa->init_spi, sa->resp_spi, KEX_VERSION_20, KEX_EXCH_INTERMEDIATE, KEX_FLAG_RESPONSE, KEX_UNIT_SK, hdr->msg_id, 0u };
    int wrc = kex_wrap_encrypted_packet(&eng->drbg, sa->sk_er, sa->sk_ar, &rhdr, KEX_UNIT_KEM_DATA, rplain, rplain_len, resp_out, resp_cap, resp_len);
    if (wrc != KEX_OK) {
        kex_secure_zero(pq_ss, sizeof(pq_ss));
        return wrc;
    }

    kex_reseed_hybrid_keys(sa, round_num, pq_ss);
    kex_secure_zero(pq_ss, sizeof(pq_ss));
    sa->completed_kem_rounds++;
    sa->expected_peer_msg_id++;
    if (sa->completed_kem_rounds == sa->required_kem_rounds) {
        sa->hybrid_completed = true;
        sa->state = KEX_STATE_INTERMEDIATE_DONE;
    }
    return KEX_OK;
}

static int handle_auth(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len, uint8_t *resp_out, size_t resp_cap, size_t *resp_len) {
    if (sa->state != KEX_STATE_INIT_DONE && sa->state != KEX_STATE_INTERMEDIATE_DONE) return KEX_ERR_STATE;
    if ((hdr->flags & KEX_FLAG_RESPONSE) != 0 || hdr->msg_id != sa->expected_peer_msg_id) return KEX_ERR_STATE;

    bool seen_id = false, seen_auth = false;
    uint32_t peer_id = 0;
    uint8_t peer_mac[KEX_HASH_LEN];

    KexUnitIter it;
    KexUnitView u;
    kex_unit_iter_init(&it, plain, plain_len);
    while (true) {
        int rc = kex_unit_iter_next(&it, &u);
        if (rc < 0) return rc;
        if (rc == 0) break;
        if (u.unit_type == KEX_UNIT_ID) {
            if (u.body_len != 8u || kex_get_be32(u.body) != 1u) return KEX_ERR_WIRE;
            peer_id = kex_get_be32(u.body + 4u);
            seen_id = true;
        } else if (u.unit_type == KEX_UNIT_AUTH) {
            if (u.body_len != 4u + KEX_HASH_LEN || kex_get_be16(u.body) != KEX_AUTH_METHOD_PSK) return KEX_ERR_AUTH;
            memcpy(peer_mac, u.body + 4u, KEX_HASH_LEN);
            seen_auth = true;
        } else if (u.unit_type == KEX_UNIT_SA_PROPOSAL) {
            KexProposal cprop;
            if (kex_parse_proposal(&u, &cprop) != KEX_OK) return KEX_ERR_WIRE;
            if (cprop.child_spi != 0) sa->initial_peer_child_spi = cprop.child_spi;
        } else if (u.unit_type != KEX_UNIT_NOTIFY) {
            return KEX_ERR_PROTO;
        }
    }

    if (!seen_id || !seen_auth || peer_id == 0) return KEX_ERR_PROTO;

    uint8_t expected_mac[KEX_HASH_LEN], resp_mac[KEX_HASH_LEN], rplain[256];
    size_t rplain_len = 0;
    kex_compute_auth_mac(sa->sk_pi, eng->psk, sa->init_req_hash, sa->nonce_r, peer_id, NULL, NULL, 0u, expected_mac);
    if (kex_ct_memcmp(peer_mac, expected_mac, KEX_HASH_LEN) != 0) return KEX_ERR_AUTH;

    int crc = kex_child_establish_initial(sa);
    if (crc != KEX_OK) return crc;

    kex_compute_auth_mac(sa->sk_pr, eng->psk, sa->init_resp_hash, sa->nonce_i, eng->server_id, NULL, NULL, 0u, resp_mac);
    KexProposal rprop = { 0u, KEX_PRF_HMAC_SHA256, KEX_AEAD_SHA256_128, sa->policy_flags, sa->initial_local_child_spi, sa->kem_alg, 0u };
    if (kex_append_id(rplain, sizeof(rplain), &rplain_len, eng->server_id) != KEX_OK ||
        kex_append_auth(rplain, sizeof(rplain), &rplain_len, resp_mac) != KEX_OK ||
        kex_append_proposal(rplain, sizeof(rplain), &rplain_len, &rprop) != KEX_OK) return KEX_ERR_WIRE;

    KexHeader rhdr = { sa->init_spi, sa->resp_spi, KEX_VERSION_20, KEX_EXCH_AUTH, KEX_FLAG_RESPONSE, KEX_UNIT_SK, hdr->msg_id, 0u };
    int wrc = kex_wrap_encrypted_packet(&eng->drbg, sa->sk_er, sa->sk_ar, &rhdr, KEX_UNIT_ID, rplain, rplain_len, resp_out, resp_cap, resp_len);
    if (wrc != KEX_OK) return wrc;

    sa->peer_id = peer_id;
    sa->expected_peer_msg_id++;
    sa->state = KEX_STATE_ESTABLISHED;
    return KEX_OK;
}

int kex_process_packet(KexEngine *eng, const uint8_t *pkt, size_t pkt_len, uint8_t *resp_out, size_t resp_cap, size_t *resp_len) {
    *resp_len = 0;
    KexHeader hdr;
    int rc = kex_parse_header(pkt, pkt_len, &hdr);
    if (rc != KEX_OK) return rc;
    if ((hdr.flags & KEX_FLAG_INITIATOR) == 0) return KEX_ERR_PROTO;

    if (hdr.exch_type == KEX_EXCH_SA_INIT) {
        rc = handle_sa_init(eng, pkt, pkt_len, &hdr, resp_out, resp_cap, resp_len);
        if (rc == KEX_OK && *resp_len > 0) kex_engine_record_tx(eng, resp_out, *resp_len);
        return rc;
    }

    if (hdr.resp_spi == 0) return KEX_ERR_PROTO;
    KexSa *sa = kex_table_find_sa(eng, hdr.init_spi, hdr.resp_spi);
    if (sa == NULL) return KEX_ERR_STATE;

    uint8_t plain[KEX_MAX_PKT_LEN];
    size_t plain_len = 0;
    uint8_t inner_first = 0;

    if ((hdr.flags & KEX_FLAG_FRAGMENTED) != 0) {
        rc = kex_frag_collect(sa, pkt, pkt_len, &hdr, plain, sizeof(plain), &plain_len, &inner_first);
        if (rc == KEX_OK_PENDING || rc < 0) return rc;
    } else {
        rc = kex_unwrap_encrypted_packet(sa->sk_ei, sa->sk_ai, pkt, pkt_len, &hdr, &inner_first, plain, &plain_len);
        if (rc != KEX_OK) return rc;
    }
    (void)inner_first;

    switch (hdr.exch_type) {
    case KEX_EXCH_INTERMEDIATE:
        rc = handle_intermediate(eng, sa, &hdr, plain, plain_len, resp_out, resp_cap, resp_len);
        break;
    case KEX_EXCH_AUTH:
        rc = handle_auth(eng, sa, &hdr, plain, plain_len, resp_out, resp_cap, resp_len);
        break;
    case KEX_EXCH_CREATE_CHILD:
        rc = ((hdr.flags & KEX_FLAG_RESPONSE) != 0)
            ? kex_rekey_handle_response(eng, sa, &hdr, plain, plain_len)
            : kex_rekey_handle_request(eng, sa, &hdr, plain, plain_len, resp_out, resp_cap, resp_len);
        break;
    case KEX_EXCH_INFORMATIONAL:
        rc = kex_handle_informational(eng, sa, &hdr, plain, plain_len, resp_out, resp_cap, resp_len);
        break;
    default:
        rc = KEX_ERR_PROTO;
        break;
    }

    kex_secure_zero(plain, plain_len);
    if (rc == KEX_OK && *resp_len > 0) kex_engine_record_tx(eng, resp_out, *resp_len);
    return rc;
}
