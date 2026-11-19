#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "src/state_machine.c",
    "src/rekey.c",
    "src/frag.c"
  ],
  "findings": [
    {
      "file": "src/state_machine.c",
      "function": "handle_intermediate / handle_auth",
      "description": "Enforced completion of negotiated mandatory and multi-round KEX_INTERMEDIATE exchanges prior to KEX_AUTH, and bound intermediate request/response transcripts (int_auth_i, int_auth_r) into peer and responder AUTH MAC calculations."
    },
    {
      "file": "src/rekey.c",
      "function": "kex_rekey_handle_response / kex_rekey_abort",
      "description": "Deferred installing local_cand onto sa->active_child until response validation and simultaneous-rekey nonce tie-breaking complete, promoting collision_peer when local_cand loses or aborts during a collision and preserving old_active on non-colliding aborts."
    },
    {
      "file": "src/frag.c",
      "function": "kex_frag_collect",
      "description": "Rejected zero or out-of-range fragment numbers (frag_num < 1 or frag_num > total_frags), rejected mid-reassembly total_frags mutations, and ignored duplicate already-seen fragments idempotently."
    }
  ],
  "summary": "Hardened mandatory hybrid KEX_INTERMEDIATE state enforcement and RFC 9242 IntAuth transcript binding in state_machine.c, fixed ChildSa pointer rollback and collision tie-breaker lifetime handling in rekey.c, and enforced strict fragment bounds, total_frags consistency, and duplicate suppression in frag.c."
}
EOF

python3 - "$APP_DIR" <<'PY'
from pathlib import Path
import sys

app = Path(sys.argv[1])

# 1. Patch src/state_machine.c
sm_path = app / "src" / "state_machine.c"
sm = sm_path.read_text(encoding="utf-8")

old_int = """    int wrc = kex_wrap_encrypted_packet(&eng->drbg, sa->sk_er, sa->sk_ar, &rhdr, KEX_UNIT_KEM_DATA, rplain, rplain_len, resp_out, resp_cap, resp_len);
    if (wrc != KEX_OK) {
        kex_secure_zero(pq_ss, sizeof(pq_ss));
        return wrc;
    }

    kex_reseed_hybrid_keys(sa, round_num, pq_ss);"""

new_int = """    int wrc = kex_wrap_encrypted_packet(&eng->drbg, sa->sk_er, sa->sk_ar, &rhdr, KEX_UNIT_KEM_DATA, rplain, rplain_len, resp_out, resp_cap, resp_len);
    if (wrc != KEX_OK) {
        kex_secure_zero(pq_ss, sizeof(pq_ss));
        return wrc;
    }

    kex_update_int_auth(sa->int_auth_i, hdr, plain, plain_len);
    kex_update_int_auth(sa->int_auth_r, &rhdr, rplain, rplain_len);
    kex_reseed_hybrid_keys(sa, round_num, pq_ss);"""

assert old_int in sm, "handle_intermediate block not found"
sm = sm.replace(old_int, new_int, 1)

old_auth_state = """static int handle_auth(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len, uint8_t *resp_out, size_t resp_cap, size_t *resp_len) {
    if (sa->state != KEX_STATE_INIT_DONE && sa->state != KEX_STATE_INTERMEDIATE_DONE) return KEX_ERR_STATE;"""

new_auth_state = """static int handle_auth(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len, uint8_t *resp_out, size_t resp_cap, size_t *resp_len) {
    if (sa->state != KEX_STATE_INIT_DONE && sa->state != KEX_STATE_INTERMEDIATE_DONE) return KEX_ERR_STATE;
    if ((sa->policy_flags & KEX_POLICY_HYBRID_REQUIRED) != 0 &&
        (sa->state != KEX_STATE_INTERMEDIATE_DONE || !sa->hybrid_completed || sa->completed_kem_rounds != sa->required_kem_rounds)) {
        return KEX_ERR_STATE;
    }
    if (sa->completed_kem_rounds > 0u &&
        (sa->state != KEX_STATE_INTERMEDIATE_DONE || sa->completed_kem_rounds != sa->required_kem_rounds)) {
        return KEX_ERR_STATE;
    }"""

assert old_auth_state in sm, "handle_auth state check not found"
sm = sm.replace(old_auth_state, new_auth_state, 1)

old_auth_macs = """    kex_compute_auth_mac(sa->sk_pi, eng->psk, sa->init_req_hash, sa->nonce_r, peer_id, NULL, NULL, 0u, expected_mac);
    if (kex_ct_memcmp(peer_mac, expected_mac, KEX_HASH_LEN) != 0) return KEX_ERR_AUTH;

    int crc = kex_child_establish_initial(sa);
    if (crc != KEX_OK) return crc;

    kex_compute_auth_mac(sa->sk_pr, eng->psk, sa->init_resp_hash, sa->nonce_i, eng->server_id, NULL, NULL, 0u, resp_mac);"""

new_auth_macs = """    kex_compute_auth_mac(sa->sk_pi, eng->psk, sa->init_req_hash, sa->nonce_r, peer_id, sa->int_auth_i, sa->int_auth_r, sa->completed_kem_rounds, expected_mac);
    if (kex_ct_memcmp(peer_mac, expected_mac, KEX_HASH_LEN) != 0) return KEX_ERR_AUTH;

    int crc = kex_child_establish_initial(sa);
    if (crc != KEX_OK) return crc;

    kex_compute_auth_mac(sa->sk_pr, eng->psk, sa->init_resp_hash, sa->nonce_i, eng->server_id, sa->int_auth_i, sa->int_auth_r, sa->completed_kem_rounds, resp_mac);"""

assert old_auth_macs in sm, "handle_auth mac block not found"
sm = sm.replace(old_auth_macs, new_auth_macs, 1)
sm_path.write_text(sm, encoding="utf-8")

# 2. Patch src/rekey.c
rk_path = app / "src" / "rekey.c"
rk = rk_path.read_text(encoding="utf-8")

old_abort = """static void kex_rekey_abort(KexSa *sa, ChildSa *cand) {
    (void)sa;
    if (cand != NULL) kex_child_sa_unref(cand);
}"""

new_abort = """static void kex_rekey_abort(KexSa *sa, ChildSa *cand) {
    if (cand != NULL) kex_child_sa_unref(cand);
    if (sa != NULL && sa->collision_detected && sa->collision_peer != NULL) {
        ChildSa *prev = sa->active_child;
        sa->active_child = sa->collision_peer;
        sa->collision_peer = NULL;
        sa->collision_detected = false;
        if (prev != NULL) kex_child_sa_unref(prev);
    }
}"""

assert old_abort in rk, "kex_rekey_abort not found"
rk = rk.replace(old_abort, new_abort, 1)

old_resp_head = """    ChildSa *local_cand = sa->pending_rekey;
    ChildSa *old_active = sa->active_child;
    sa->active_child = local_cand;
    sa->pending_rekey = NULL;"""

new_resp_head = """    ChildSa *local_cand = sa->pending_rekey;
    ChildSa *old_active = sa->active_child;
    sa->pending_rekey = NULL;"""

assert old_resp_head in rk, "kex_rekey_handle_response head not found"
rk = rk.replace(old_resp_head, new_resp_head, 1)

old_resp_tail = """    if (sa->collision_detected && sa->collision_peer != NULL) {
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
    }"""

new_resp_tail = """    if (sa->collision_detected && sa->collision_peer != NULL) {
        ChildSa *peer_cand = sa->collision_peer;
        sa->collision_peer = NULL;
        sa->collision_detected = false;
        if (rekey_compare_collision(local_cand, peer_cand) >= 0) {
            sa->active_child = local_cand;
            kex_child_sa_unref(peer_cand);
            kex_child_sa_unref(old_active);
        } else {
            sa->active_child = peer_cand;
            kex_child_sa_unref(local_cand);
            kex_child_sa_unref(old_active);
        }
    } else {
        sa->active_child = local_cand;
        kex_child_sa_unref(old_active);
    }"""

assert old_resp_tail in rk, "kex_rekey_handle_response tail not found"
rk = rk.replace(old_resp_tail, new_resp_tail, 1)
rk_path.write_text(rk, encoding="utf-8")

# 3. Patch src/frag.c
fg_path = app / "src" / "frag.c"
fg = fg_path.read_text(encoding="utf-8")

old_frag_bounds = """    if (total_frags == 0 || total_frags > KEX_MAX_FRAGS || frag_num > KEX_MAX_FRAGS) return KEX_ERR_PROTO;"""
new_frag_bounds = """    if (frag_num == 0 || total_frags == 0 || total_frags > KEX_MAX_FRAGS || frag_num > total_frags) return KEX_ERR_PROTO;"""
assert old_frag_bounds in fg, "frag bounds check not found"
fg = fg.replace(old_frag_bounds, new_frag_bounds, 1)

old_frag_store = """    if (!ctx->active) {
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
    if (frag_num == 1u) ctx->inner_first_unit = inner_first;"""

new_frag_store = """    if (!ctx->active) {
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
    } else if (total_frags != ctx->total_frags) {
        kex_secure_zero(dec_buf, dec_len);
        return KEX_ERR_PROTO;
    }

    uint16_t idx = (uint16_t)(frag_num - 1u);
    uint32_t bit = (1u << idx);
    if ((ctx->seen_mask & bit) != 0u || ctx->slots[idx] != NULL) {
        kex_secure_zero(dec_buf, dec_len);
        return KEX_OK_PENDING;
    }
    if (frag_num == 1u) ctx->inner_first_unit = inner_first;"""

assert old_frag_store in fg, "frag store block not found"
fg = fg.replace(old_frag_store, new_frag_store, 1)
fg_path.write_text(fg, encoding="utf-8")
PY

make -C "$APP_DIR" clean all
