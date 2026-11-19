#include "kex_engine.h"
#include <string.h>

uint16_t kex_get_be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
uint32_t kex_get_be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
uint64_t kex_get_be64(const uint8_t *p) { return ((uint64_t)kex_get_be32(p) << 32) | kex_get_be32(p + 4u); }

void kex_put_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xffu); }
void kex_put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu); p[3] = (uint8_t)(v & 0xffu);
}
void kex_put_be64(uint8_t *p, uint64_t v) {
    kex_put_be32(p, (uint32_t)(v >> 32));
    kex_put_be32(p + 4u, (uint32_t)(v & 0xffffffffu));
}

bool kex_known_unit_type(uint8_t unit_type) {
    switch (unit_type) {
    case KEX_UNIT_SA_PROPOSAL: case KEX_UNIT_KE_CLASSIC: case KEX_UNIT_KEM_DATA:
    case KEX_UNIT_NONCE: case KEX_UNIT_ID: case KEX_UNIT_AUTH:
    case KEX_UNIT_NOTIFY: case KEX_UNIT_DELETE: case KEX_UNIT_SK: case KEX_UNIT_SKF:
        return true;
    default:
        return false;
    }
}

int kex_parse_header(const uint8_t *buf, size_t len, KexHeader *hdr) {
    if (buf == NULL || hdr == NULL || len < KEX_HDR_LEN || len > KEX_MAX_PKT_LEN) return KEX_ERR_WIRE;
    hdr->init_spi = kex_get_be64(buf + 0);
    hdr->resp_spi = kex_get_be64(buf + 8u);
    hdr->version = buf[16];
    hdr->exch_type = buf[17];
    hdr->flags = buf[18];
    hdr->first_unit = buf[19];
    hdr->msg_id = kex_get_be32(buf + 20u);
    hdr->total_len = kex_get_be32(buf + 24u);
    if (hdr->version != KEX_VERSION_20 || hdr->total_len != len || hdr->init_spi == 0) return KEX_ERR_WIRE;
    return KEX_OK;
}

void kex_write_header(uint8_t *buf, const KexHeader *hdr) {
    kex_put_be64(buf + 0, hdr->init_spi);
    kex_put_be64(buf + 8u, hdr->resp_spi);
    buf[16] = hdr->version;
    buf[17] = hdr->exch_type;
    buf[18] = hdr->flags;
    buf[19] = hdr->first_unit;
    kex_put_be32(buf + 20u, hdr->msg_id);
    kex_put_be32(buf + 24u, hdr->total_len);
}

void kex_unit_iter_init(KexUnitIter *it, const uint8_t *buf, size_t len) {
    it->buf = buf; it->len = len; it->offset = 0;
}

int kex_unit_iter_next(KexUnitIter *it, KexUnitView *view) {
    if (it->offset == it->len) return 0;
    if (it->len - it->offset < 4u) return KEX_ERR_WIRE;
    const uint8_t *p = it->buf + it->offset;
    uint8_t utype = p[0], crit = p[1];
    uint16_t ulen = kex_get_be16(p + 2u);
    if (ulen < 4u || (size_t)ulen > it->len - it->offset) return KEX_ERR_WIRE;
    if (!kex_known_unit_type(utype) && (crit & 0x01u) != 0) return KEX_ERR_PROTO;
    view->unit_type = utype;
    view->critical = crit;
    view->body_len = (uint16_t)(ulen - 4u);
    view->body = p + 4u;
    it->offset += ulen;
    return 1;
}

int kex_append_unit(uint8_t *buf, size_t cap, size_t *off, uint8_t unit_type, uint8_t critical, const uint8_t *body, uint16_t body_len) {
    size_t total = 4u + (size_t)body_len;
    if (*off + total > cap || total > 0xffffu) return KEX_ERR_WIRE;
    buf[*off + 0] = unit_type;
    buf[*off + 1] = critical;
    kex_put_be16(buf + *off + 2u, (uint16_t)total);
    if (body_len > 0 && body != NULL) memcpy(buf + *off + 4u, body, body_len);
    *off += total;
    return KEX_OK;
}

int kex_parse_proposal(const KexUnitView *u, KexProposal *prop) {
    if (u->body_len != 16u) return KEX_ERR_WIRE;
    prop->dh_group = kex_get_be16(u->body + 0);
    prop->prf_alg = kex_get_be16(u->body + 2u);
    prop->aead_alg = kex_get_be16(u->body + 4u);
    prop->policy_flags = kex_get_be16(u->body + 6u);
    prop->child_spi = kex_get_be32(u->body + 8u);
    prop->kem_alg = kex_get_be16(u->body + 12u);
    prop->reserved = kex_get_be16(u->body + 14u);
    return KEX_OK;
}

int kex_append_proposal(uint8_t *buf, size_t cap, size_t *off, const KexProposal *prop) {
    uint8_t b[16];
    kex_put_be16(b + 0, prop->dh_group);
    kex_put_be16(b + 2u, prop->prf_alg);
    kex_put_be16(b + 4u, prop->aead_alg);
    kex_put_be16(b + 6u, prop->policy_flags);
    kex_put_be32(b + 8u, prop->child_spi);
    kex_put_be16(b + 12u, prop->kem_alg);
    kex_put_be16(b + 14u, prop->reserved);
    return kex_append_unit(buf, cap, off, KEX_UNIT_SA_PROPOSAL, 0, b, sizeof(b));
}

int kex_append_ke(uint8_t *buf, size_t cap, size_t *off, uint16_t dh_group, const uint8_t pub[KEX_DH_LEN]) {
    uint8_t b[36];
    kex_put_be16(b + 0, dh_group);
    kex_put_be16(b + 2u, 0);
    memcpy(b + 4u, pub, KEX_DH_LEN);
    return kex_append_unit(buf, cap, off, KEX_UNIT_KE_CLASSIC, 0, b, sizeof(b));
}

int kex_append_kem(uint8_t *buf, size_t cap, size_t *off, uint16_t round_num, uint16_t kem_alg, const uint8_t blob[KEX_DH_LEN]) {
    uint8_t b[36];
    kex_put_be16(b + 0, round_num);
    kex_put_be16(b + 2u, kem_alg);
    memcpy(b + 4u, blob, KEX_DH_LEN);
    return kex_append_unit(buf, cap, off, KEX_UNIT_KEM_DATA, 0, b, sizeof(b));
}

int kex_append_nonce(uint8_t *buf, size_t cap, size_t *off, const uint8_t nonce[KEX_NONCE_LEN]) {
    return kex_append_unit(buf, cap, off, KEX_UNIT_NONCE, 0, nonce, KEX_NONCE_LEN);
}

int kex_append_id(uint8_t *buf, size_t cap, size_t *off, uint32_t id_val) {
    uint8_t b[8];
    kex_put_be32(b + 0, 1u);
    kex_put_be32(b + 4u, id_val);
    return kex_append_unit(buf, cap, off, KEX_UNIT_ID, 0, b, sizeof(b));
}

int kex_append_auth(uint8_t *buf, size_t cap, size_t *off, const uint8_t mac[KEX_HASH_LEN]) {
    uint8_t b[36];
    kex_put_be16(b + 0, KEX_AUTH_METHOD_PSK);
    kex_put_be16(b + 2u, 0);
    memcpy(b + 4u, mac, KEX_HASH_LEN);
    return kex_append_unit(buf, cap, off, KEX_UNIT_AUTH, 0, b, sizeof(b));
}

int kex_append_notify(uint8_t *buf, size_t cap, size_t *off, uint16_t notify_type, uint8_t proto_id, uint32_t aux_u32) {
    uint8_t b[8];
    kex_put_be16(b + 0, notify_type);
    b[2] = proto_id;
    b[3] = (aux_u32 != 0) ? 4u : 0u;
    kex_put_be32(b + 4u, aux_u32);
    return kex_append_unit(buf, cap, off, KEX_UNIT_NOTIFY, 0, b, sizeof(b));
}

int kex_wrap_encrypted_packet(KexDrbg *drbg, const uint8_t sk_e[KEX_HASH_LEN], const uint8_t sk_a[KEX_HASH_LEN], KexHeader *hdr, uint8_t inner_first, const uint8_t *plain, size_t plain_len, uint8_t *out_pkt, size_t cap, size_t *out_len) {
    size_t sk_body_len = 4u + KEX_AEAD_IV_LEN + plain_len + KEX_AEAD_TAG_LEN;
    size_t total_len = KEX_HDR_LEN + 4u + sk_body_len;
    if (total_len > cap || sk_body_len + 4u > 0xffffu) return KEX_ERR_WIRE;

    uint8_t iv[KEX_AEAD_IV_LEN];
    kex_drbg_generate(drbg, iv, sizeof(iv));
    hdr->first_unit = KEX_UNIT_SK;
    hdr->total_len = (uint32_t)total_len;
    kex_write_header(out_pkt, hdr);

    out_pkt[KEX_HDR_LEN + 0] = KEX_UNIT_SK;
    out_pkt[KEX_HDR_LEN + 1] = 0;
    kex_put_be16(out_pkt + KEX_HDR_LEN + 2u, (uint16_t)(4u + sk_body_len));
    uint8_t *sk_body = out_pkt + KEX_HDR_LEN + 4u;
    sk_body[0] = inner_first; sk_body[1] = 0; sk_body[2] = 0; sk_body[3] = 0;

    size_t sealed_len = 0;
    int rc = kex_aead_seal(sk_e, sk_a, out_pkt, KEX_HDR_LEN, iv, plain, plain_len, sk_body + 4u, &sealed_len);
    if (rc != KEX_OK) return rc;
    *out_len = total_len;
    return KEX_OK;
}

int kex_unwrap_encrypted_packet(const uint8_t sk_e[KEX_HASH_LEN], const uint8_t sk_a[KEX_HASH_LEN], const uint8_t *raw_pkt, size_t raw_len, const KexHeader *hdr, uint8_t *inner_first_out, uint8_t *plain_out, size_t *plain_len) {
    if ((hdr->flags & KEX_FLAG_FRAGMENTED) != 0) return KEX_ERR_PROTO;
    KexUnitIter it;
    KexUnitView u;
    kex_unit_iter_init(&it, raw_pkt + KEX_HDR_LEN, raw_len - KEX_HDR_LEN);
    bool seen_sk = false;
    while (true) {
        int rc = kex_unit_iter_next(&it, &u);
        if (rc < 0) return rc;
        if (rc == 0) break;
        if (seen_sk) return KEX_ERR_PROTO;
        if (u.unit_type == KEX_UNIT_SK) {
            if (u.body_len < 4u + KEX_AEAD_IV_LEN + KEX_AEAD_TAG_LEN) return KEX_ERR_WIRE;
            *inner_first_out = u.body[0];
            int dec_rc = kex_aead_open(sk_e, sk_a, raw_pkt, KEX_HDR_LEN, u.body + 4u, u.body_len - 4u, plain_out, plain_len);
            if (dec_rc != KEX_OK) return dec_rc;
            seen_sk = true;
        } else if (u.unit_type != KEX_UNIT_NOTIFY) {
            return KEX_ERR_PROTO;
        }
    }
    return seen_sk ? KEX_OK : KEX_ERR_PROTO;
}
