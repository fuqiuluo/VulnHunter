#include "kex_engine.h"
#include <string.h>

#define KEX_MOD_C_CLASSIC  189u
#define KEX_MOD_C_KEM_R1   357u
#define KEX_MOD_C_KEM_R2   617u

typedef struct { uint64_t w[4]; } KexU256;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static inline uint32_t rotr32(uint32_t x, unsigned int n) { return (x >> n) | (x << (32u - n)); }

void kex_secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0) *p++ = 0;
}

int kex_ct_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a, *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(pa[i] ^ pb[i]);
    return diff != 0 ? 1 : 0;
}

static void sha256_transform(uint32_t st[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = kex_get_be32(block + (size_t)i * 4u);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ ((~e) & g)) + SHA256_K[i] + w[i];
        uint32_t t2 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

void kex_sha256_init(KexSha256Ctx *ctx) {
    static const uint32_t iv[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    memcpy(ctx->state, iv, sizeof(iv));
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void kex_sha256_update(KexSha256Ctx *ctx, const uint8_t *data, size_t len) {
    if (len == 0 || data == NULL) return;
    size_t idx = (size_t)((ctx->bitcount >> 3) & 63u), i = 0;
    ctx->bitcount += (uint64_t)len * 8u;
    if (idx > 0) {
        size_t take = (64u - idx < len) ? (64u - idx) : len;
        memcpy(ctx->buffer + idx, data, take);
        idx += take; i += take;
        if (idx == 64u) sha256_transform(ctx->state, ctx->buffer);
    }
    for (; i + 64u <= len; i += 64u) sha256_transform(ctx->state, data + i);
    if (i < len) memcpy(ctx->buffer, data + i, len - i);
}

void kex_sha256_final(KexSha256Ctx *ctx, uint8_t out[KEX_HASH_LEN]) {
    size_t idx = (size_t)((ctx->bitcount >> 3) & 63u);
    ctx->buffer[idx++] = 0x80u;
    if (idx > 56u) { memset(ctx->buffer + idx, 0, 64u - idx); sha256_transform(ctx->state, ctx->buffer); idx = 0; }
    memset(ctx->buffer + idx, 0, 56u - idx);
    kex_put_be64(ctx->buffer + 56u, ctx->bitcount);
    sha256_transform(ctx->state, ctx->buffer);
    for (int i = 0; i < 8; i++) kex_put_be32(out + (size_t)i * 4u, ctx->state[i]);
    kex_secure_zero(ctx, sizeof(*ctx));
}

void kex_sha256(const uint8_t *data, size_t len, uint8_t out[KEX_HASH_LEN]) {
    KexSha256Ctx ctx;
    kex_sha256_init(&ctx); kex_sha256_update(&ctx, data, len); kex_sha256_final(&ctx, out);
}

void kex_hmac_init(KexHmacCtx *ctx, const uint8_t *key, size_t key_len) {
    uint8_t k_pad[64] = {0}, tk[KEX_HASH_LEN], block[64];
    if (key_len > 64u) { kex_sha256(key, key_len, tk); memcpy(k_pad, tk, KEX_HASH_LEN); kex_secure_zero(tk, sizeof(tk)); }
    else if (key_len > 0 && key != NULL) memcpy(k_pad, key, key_len);
    for (size_t i = 0; i < 64u; i++) block[i] = (uint8_t)(k_pad[i] ^ 0x36u);
    kex_sha256_init(&ctx->inner); kex_sha256_update(&ctx->inner, block, 64u);
    for (size_t i = 0; i < 64u; i++) block[i] = (uint8_t)(k_pad[i] ^ 0x5cu);
    kex_sha256_init(&ctx->outer); kex_sha256_update(&ctx->outer, block, 64u);
    kex_secure_zero(k_pad, sizeof(k_pad)); kex_secure_zero(block, sizeof(block));
}

void kex_hmac_update(KexHmacCtx *ctx, const uint8_t *data, size_t len) { kex_sha256_update(&ctx->inner, data, len); }

void kex_hmac_final(KexHmacCtx *ctx, uint8_t out[KEX_HASH_LEN]) {
    uint8_t inner_digest[KEX_HASH_LEN];
    kex_sha256_final(&ctx->inner, inner_digest);
    kex_sha256_update(&ctx->outer, inner_digest, KEX_HASH_LEN);
    kex_sha256_final(&ctx->outer, out);
    kex_secure_zero(inner_digest, sizeof(inner_digest));
}

void kex_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t out[KEX_HASH_LEN]) {
    KexHmacCtx ctx;
    kex_hmac_init(&ctx, key, key_len); kex_hmac_update(&ctx, data, len); kex_hmac_final(&ctx, out);
}

void kex_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk[KEX_HASH_LEN]) {
    static const uint8_t zero_salt[KEX_HASH_LEN] = {0};
    kex_hmac_sha256((salt == NULL || salt_len == 0) ? zero_salt : salt, (salt == NULL || salt_len == 0) ? KEX_HASH_LEN : salt_len, ikm, ikm_len, prk);
}

int kex_hkdf_expand(const uint8_t prk[KEX_HASH_LEN], const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    if (okm_len > 255u * KEX_HASH_LEN) return KEX_ERR_CRYPTO;
    uint8_t t[KEX_HASH_LEN], ctr = 1;
    size_t t_len = 0, pos = 0;
    while (pos < okm_len) {
        KexHmacCtx hm;
        kex_hmac_init(&hm, prk, KEX_HASH_LEN);
        if (t_len > 0) kex_hmac_update(&hm, t, t_len);
        if (info_len > 0 && info != NULL) kex_hmac_update(&hm, info, info_len);
        kex_hmac_update(&hm, &ctr, 1u);
        kex_hmac_final(&hm, t);
        t_len = KEX_HASH_LEN;
        size_t copy = (okm_len - pos > KEX_HASH_LEN) ? KEX_HASH_LEN : (okm_len - pos);
        memcpy(okm + pos, t, copy);
        pos += copy; ctr++;
    }
    kex_secure_zero(t, sizeof(t));
    return KEX_OK;
}

void kex_drbg_init(KexDrbg *drbg, uint32_t seed) { drbg->seed = seed; drbg->counter = 0; }

void kex_drbg_generate(KexDrbg *drbg, uint8_t *out, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        uint8_t msg[8], blk[KEX_HASH_LEN];
        kex_put_be32(msg, drbg->seed);
        kex_put_be32(msg + 4u, drbg->counter++);
        kex_hmac_sha256((const uint8_t *)"KEX-DRBG-V2", 11u, msg, sizeof(msg), blk);
        size_t copy = (len - pos > KEX_HASH_LEN) ? KEX_HASH_LEN : (len - pos);
        memcpy(out + pos, blk, copy);
        pos += copy;
        kex_secure_zero(blk, sizeof(blk));
    }
}

static KexU256 u256_from_be(const uint8_t b[32]) {
    KexU256 r = {{kex_get_be64(b + 24), kex_get_be64(b + 16), kex_get_be64(b + 8), kex_get_be64(b + 0)}};
    return r;
}

static void u256_to_be(KexU256 v, uint8_t b[32]) {
    kex_put_be64(b + 0, v.w[3]); kex_put_be64(b + 8, v.w[2]); kex_put_be64(b + 16, v.w[1]); kex_put_be64(b + 24, v.w[0]);
}

static int u256_cmp(KexU256 a, KexU256 b) {
    for (int i = 3; i >= 0; i--) if (a.w[i] != b.w[i]) return a.w[i] < b.w[i] ? -1 : 1;
    return 0;
}

static uint64_t u256_add_raw(KexU256 a, KexU256 b, KexU256 *out) {
    uint64_t cy = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t s1 = a.w[i] + b.w[i], c1 = (s1 < a.w[i]) ? 1u : 0u;
        uint64_t s2 = s1 + cy, c2 = (s2 < s1) ? 1u : 0u;
        out->w[i] = s2; cy = c1 + c2;
    }
    return cy;
}

static KexU256 u256_addmod(KexU256 a, KexU256 b, uint64_t c) {
    KexU256 s, c_val = {{c, 0, 0, 0}}, p_val = {{(uint64_t)(0ULL - c), ~0ULL, ~0ULL, ~0ULL}};
    if (u256_add_raw(a, b, &s) != 0 || u256_cmp(s, p_val) >= 0) (void)u256_add_raw(s, c_val, &s);
    return s;
}

static KexU256 u256_mulmod(KexU256 a, KexU256 b, uint64_t c) {
    KexU256 res = {{0, 0, 0, 0}};
    for (int bit = 255; bit >= 0; bit--) {
        res = u256_addmod(res, res, c);
        if ((b.w[bit / 64] >> (bit % 64)) & 1ULL) res = u256_addmod(res, a, c);
    }
    return res;
}

static KexU256 u256_powmod(KexU256 base, KexU256 exp, uint64_t c) {
    KexU256 res = {{1u, 0, 0, 0}};
    for (int bit = 255; bit >= 0; bit--) {
        res = u256_mulmod(res, res, c);
        if ((exp.w[bit / 64] >> (bit % 64)) & 1ULL) res = u256_mulmod(res, base, c);
    }
    return res;
}

static bool u256_valid_pub(KexU256 pub, uint64_t c) {
    KexU256 one = {{1u, 0, 0, 0}}, pm1 = {{(uint64_t)(0ULL - c - 1u), ~0ULL, ~0ULL, ~0ULL}};
    return u256_cmp(pub, one) > 0 && u256_cmp(pub, pm1) < 0;
}

void kex_clamp_scalar(uint8_t scalar[KEX_DH_LEN]) { scalar[0] &= 0x7fu; scalar[31] |= 0x02u; }

int kex_dh_keypair(KexDrbg *drbg, uint8_t priv_out[KEX_DH_LEN], uint8_t pub_out[KEX_DH_LEN]) {
    kex_drbg_generate(drbg, priv_out, KEX_DH_LEN);
    kex_clamp_scalar(priv_out);
    KexU256 g = {{5u, 0, 0, 0}};
    u256_to_be(u256_powmod(g, u256_from_be(priv_out), KEX_MOD_C_CLASSIC), pub_out);
    return KEX_OK;
}

int kex_dh_shared(const uint8_t priv[KEX_DH_LEN], const uint8_t peer_pub[KEX_DH_LEN], uint8_t shared_out[KEX_DH_LEN]) {
    KexU256 pk = u256_from_be(peer_pub);
    if (!u256_valid_pub(pk, KEX_MOD_C_CLASSIC)) return KEX_ERR_CRYPTO;
    u256_to_be(u256_powmod(pk, u256_from_be(priv), KEX_MOD_C_CLASSIC), shared_out);
    return KEX_OK;
}

int kex_kem_encaps(KexDrbg *drbg, uint16_t round_num, const uint8_t peer_pk[KEX_DH_LEN], uint8_t ct_out[KEX_DH_LEN], uint8_t ss_out[KEX_HASH_LEN]) {
    uint64_t mod_c = (round_num == 1u) ? KEX_MOD_C_KEM_R1 : (round_num == 2u ? KEX_MOD_C_KEM_R2 : 0u);
    KexU256 pk = u256_from_be(peer_pk), g = {{5u, 0, 0, 0}};
    if (mod_c == 0u || !u256_valid_pub(pk, mod_c)) return KEX_ERR_CRYPTO;
    uint8_t eph_bytes[KEX_DH_LEN], dh_bytes[KEX_DH_LEN], rnd_be[2];
    kex_drbg_generate(drbg, eph_bytes, KEX_DH_LEN);
    kex_clamp_scalar(eph_bytes);
    KexU256 eph = u256_from_be(eph_bytes);
    u256_to_be(u256_powmod(g, eph, mod_c), ct_out);
    u256_to_be(u256_powmod(pk, eph, mod_c), dh_bytes);
    kex_put_be16(rnd_be, round_num);
    KexSha256Ctx sh;
    kex_sha256_init(&sh);
    kex_sha256_update(&sh, (const uint8_t *)"KEX-KEM-V2", 10u);
    kex_sha256_update(&sh, rnd_be, 2u);
    kex_sha256_update(&sh, peer_pk, KEX_DH_LEN);
    kex_sha256_update(&sh, ct_out, KEX_DH_LEN);
    kex_sha256_update(&sh, dh_bytes, KEX_DH_LEN);
    kex_sha256_final(&sh, ss_out);
    kex_secure_zero(eph_bytes, sizeof(eph_bytes)); kex_secure_zero(dh_bytes, sizeof(dh_bytes));
    return KEX_OK;
}

static void stream_xor(const uint8_t sk_e[KEX_HASH_LEN], const uint8_t iv[KEX_AEAD_IV_LEN], const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t blk = 0;
    for (size_t pos = 0; pos < len;) {
        uint8_t seed[12], ks[KEX_HASH_LEN];
        memcpy(seed, iv, KEX_AEAD_IV_LEN);
        kex_put_be32(seed + 8u, blk++);
        kex_hmac_sha256(sk_e, KEX_HASH_LEN, seed, sizeof(seed), ks);
        size_t chunk = (len - pos > KEX_HASH_LEN) ? KEX_HASH_LEN : (len - pos);
        for (size_t i = 0; i < chunk; i++) out[pos + i] = (uint8_t)(in[pos + i] ^ ks[i]);
        pos += chunk;
        kex_secure_zero(ks, sizeof(ks));
    }
}

static void compute_aead_tag(const uint8_t sk_a[KEX_HASH_LEN], const uint8_t *aad, size_t aad_len, const uint8_t iv[KEX_AEAD_IV_LEN], const uint8_t *ct, size_t ct_len, uint8_t tag_out[KEX_AEAD_TAG_LEN]) {
    uint8_t len_be[4], full_mac[KEX_HASH_LEN];
    KexHmacCtx hm;
    kex_hmac_init(&hm, sk_a, KEX_HASH_LEN);
    kex_put_be32(len_be, (uint32_t)aad_len); kex_hmac_update(&hm, len_be, 4u); kex_hmac_update(&hm, aad, aad_len);
    kex_hmac_update(&hm, iv, KEX_AEAD_IV_LEN);
    kex_put_be32(len_be, (uint32_t)ct_len); kex_hmac_update(&hm, len_be, 4u); kex_hmac_update(&hm, ct, ct_len);
    kex_hmac_final(&hm, full_mac);
    memcpy(tag_out, full_mac, KEX_AEAD_TAG_LEN);
    kex_secure_zero(full_mac, sizeof(full_mac));
}

int kex_aead_seal(const uint8_t sk_e[KEX_HASH_LEN], const uint8_t sk_a[KEX_HASH_LEN], const uint8_t *aad, size_t aad_len, const uint8_t iv[KEX_AEAD_IV_LEN], const uint8_t *plain, size_t plain_len, uint8_t *out, size_t *out_len) {
    memcpy(out, iv, KEX_AEAD_IV_LEN);
    if (plain_len > 0) stream_xor(sk_e, iv, plain, out + KEX_AEAD_IV_LEN, plain_len);
    compute_aead_tag(sk_a, aad, aad_len, iv, out + KEX_AEAD_IV_LEN, plain_len, out + KEX_AEAD_IV_LEN + plain_len);
    *out_len = KEX_AEAD_IV_LEN + plain_len + KEX_AEAD_TAG_LEN;
    return KEX_OK;
}

int kex_aead_open(const uint8_t sk_e[KEX_HASH_LEN], const uint8_t sk_a[KEX_HASH_LEN], const uint8_t *aad, size_t aad_len, const uint8_t *enc, size_t enc_len, uint8_t *plain_out, size_t *plain_len) {
    if (enc_len < KEX_AEAD_IV_LEN + KEX_AEAD_TAG_LEN) return KEX_ERR_AUTH;
    size_t ct_len = enc_len - KEX_AEAD_IV_LEN - KEX_AEAD_TAG_LEN;
    uint8_t exp_tag[KEX_AEAD_TAG_LEN];
    compute_aead_tag(sk_a, aad, aad_len, enc, enc + KEX_AEAD_IV_LEN, ct_len, exp_tag);
    if (kex_ct_memcmp(enc + KEX_AEAD_IV_LEN + ct_len, exp_tag, KEX_AEAD_TAG_LEN) != 0) return KEX_ERR_AUTH;
    if (ct_len > 0) stream_xor(sk_e, enc, enc + KEX_AEAD_IV_LEN, plain_out, ct_len);
    *plain_len = ct_len;
    return KEX_OK;
}

static void assign_sa_keystream(KexSa *sa, const uint8_t ks[224]) {
    memcpy(sa->sk_d, ks + 0, 32u); memcpy(sa->sk_ai, ks + 32u, 32u); memcpy(sa->sk_ar, ks + 64u, 32u);
    memcpy(sa->sk_ei, ks + 96u, 32u); memcpy(sa->sk_er, ks + 128u, 32u); memcpy(sa->sk_pi, ks + 160u, 32u); memcpy(sa->sk_pr, ks + 192u, 32u);
}

void kex_derive_init_keys(KexSa *sa) {
    uint8_t salt[64], skeyseed[KEX_HASH_LEN], info[92], ks[224];
    memcpy(salt, sa->nonce_i, 32u); memcpy(salt + 32u, sa->nonce_r, 32u);
    kex_hkdf_extract(salt, sizeof(salt), sa->dh_shared, KEX_DH_LEN, skeyseed);
    memcpy(info, "KEX-IKE-KEYS", 12u); memcpy(info + 12u, sa->nonce_i, 32u); memcpy(info + 44u, sa->nonce_r, 32u);
    kex_put_be64(info + 76u, sa->init_spi); kex_put_be64(info + 84u, sa->resp_spi);
    (void)kex_hkdf_expand(skeyseed, info, sizeof(info), ks, sizeof(ks));
    assign_sa_keystream(sa, ks);
    kex_secure_zero(skeyseed, sizeof(skeyseed)); kex_secure_zero(ks, sizeof(ks));
}

void kex_reseed_hybrid_keys(KexSa *sa, uint16_t round_num, const uint8_t pq_ss[KEX_HASH_LEN]) {
    uint8_t ikm[96], skeyseed[KEX_HASH_LEN], info[94], ks[224];
    memcpy(sa->pq_shared, pq_ss, KEX_HASH_LEN);
    memcpy(ikm, pq_ss, 32u); memcpy(ikm + 32u, sa->nonce_i, 32u); memcpy(ikm + 64u, sa->nonce_r, 32u);
    kex_hkdf_extract(sa->sk_d, KEX_HASH_LEN, ikm, sizeof(ikm), skeyseed);
    memcpy(info, "KEX-HYB-KEYS", 12u); kex_put_be16(info + 12u, round_num);
    memcpy(info + 14u, sa->nonce_i, 32u); memcpy(info + 46u, sa->nonce_r, 32u);
    kex_put_be64(info + 78u, sa->init_spi); kex_put_be64(info + 86u, sa->resp_spi);
    (void)kex_hkdf_expand(skeyseed, info, sizeof(info), ks, sizeof(ks));
    assign_sa_keystream(sa, ks);
    kex_secure_zero(ikm, sizeof(ikm)); kex_secure_zero(skeyseed, sizeof(skeyseed)); kex_secure_zero(ks, sizeof(ks));
}

void kex_derive_child_keys(const KexSa *sa, ChildSa *csa, const uint8_t *pfs_shared) {
    uint8_t ikm[96], prk[KEX_HASH_LEN], info[20], keymat[64];
    size_t ikm_len = 0;
    if (pfs_shared != NULL) { memcpy(ikm, pfs_shared, 32u); ikm_len += 32u; }
    memcpy(ikm + ikm_len, csa->nonce_i, 32u); memcpy(ikm + ikm_len + 32u, csa->nonce_r, 32u); ikm_len += 64u;
    kex_hkdf_extract(sa->sk_d, KEX_HASH_LEN, ikm, ikm_len, prk);
    memcpy(info, "KEX-CHILD-V2", 12u); kex_put_be32(info + 12u, csa->child_spi_in); kex_put_be32(info + 16u, csa->child_spi_out);
    (void)kex_hkdf_expand(prk, info, sizeof(info), keymat, sizeof(keymat));
    memcpy(csa->sk_child_i, keymat, 32u); memcpy(csa->sk_child_r, keymat + 32u, 32u);
    kex_secure_zero(prk, sizeof(prk)); kex_secure_zero(keymat, sizeof(keymat));
}

void kex_update_int_auth(uint8_t int_auth[KEX_HASH_LEN], const KexHeader *hdr, const uint8_t *inner_units, size_t inner_len) {
    uint8_t meta[28];
    KexSha256Ctx sh;
    kex_put_be64(meta + 0, hdr->init_spi); kex_put_be64(meta + 8, hdr->resp_spi);
    meta[16] = hdr->version; meta[17] = hdr->exch_type;
    meta[18] = (uint8_t)(hdr->flags & (KEX_FLAG_INITIATOR | KEX_FLAG_RESPONSE)); meta[19] = 0;
    kex_put_be32(meta + 20, hdr->msg_id); kex_put_be32(meta + 24, (uint32_t)inner_len);
    kex_sha256_init(&sh);
    kex_sha256_update(&sh, int_auth, KEX_HASH_LEN);
    kex_sha256_update(&sh, meta, sizeof(meta));
    if (inner_len > 0 && inner_units != NULL) kex_sha256_update(&sh, inner_units, inner_len);
    kex_sha256_final(&sh, int_auth);
}

void kex_compute_auth_mac(const uint8_t sk_p[KEX_HASH_LEN], const uint8_t psk[KEX_HASH_LEN], const uint8_t init_octets_hash[KEX_HASH_LEN], const uint8_t peer_nonce[KEX_NONCE_LEN], uint32_t id_val, const uint8_t *int_auth_i, const uint8_t *int_auth_r, uint16_t int_rounds, uint8_t out_mac[KEX_HASH_LEN]) {
    uint8_t id_buf[8], id_prf[KEX_HASH_LEN];
    KexHmacCtx hm;
    kex_put_be32(id_buf, 1u); kex_put_be32(id_buf + 4u, id_val);
    kex_hmac_sha256(sk_p, KEX_HASH_LEN, id_buf, sizeof(id_buf), id_prf);
    kex_hmac_init(&hm, psk, KEX_HASH_LEN);
    kex_hmac_update(&hm, init_octets_hash, KEX_HASH_LEN);
    kex_hmac_update(&hm, peer_nonce, KEX_NONCE_LEN);
    kex_hmac_update(&hm, id_prf, KEX_HASH_LEN);
    if (int_rounds > 0 && int_auth_i != NULL && int_auth_r != NULL) {
        uint8_t int_prf[KEX_HASH_LEN], int_blk[66];
        memcpy(int_blk, int_auth_i, KEX_HASH_LEN); memcpy(int_blk + 32u, int_auth_r, KEX_HASH_LEN);
        kex_put_be16(int_blk + 64u, int_rounds);
        kex_hmac_sha256(sk_p, KEX_HASH_LEN, int_blk, sizeof(int_blk), int_prf);
        kex_hmac_update(&hm, int_prf, KEX_HASH_LEN);
        kex_secure_zero(int_prf, sizeof(int_prf));
    }
    kex_hmac_final(&hm, out_mac);
    kex_secure_zero(id_prf, sizeof(id_prf));
}
