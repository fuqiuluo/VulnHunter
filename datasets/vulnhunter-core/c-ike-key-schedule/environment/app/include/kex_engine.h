#ifndef KEX_ENGINE_H
#define KEX_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KEX_TRACE_MAGIC   0x4B455831u
#define KEX_CHILD_MAGIC   0x43534132u
#define KEX_VERSION_20    0x20u
#define KEX_HDR_LEN       28u
#define KEX_HASH_LEN      32u
#define KEX_NONCE_LEN     32u
#define KEX_DH_LEN        32u
#define KEX_AEAD_IV_LEN   8u
#define KEX_AEAD_TAG_LEN  16u
#define KEX_MAX_PKT_LEN   65536u
#define KEX_MAX_FRAGS     32u
#define KEX_MAX_SAS       64u

#define KEX_OK             0
#define KEX_OK_PENDING     1
#define KEX_ERR_IO        -1
#define KEX_ERR_WIRE      -2
#define KEX_ERR_PROTO     -3
#define KEX_ERR_STATE     -4
#define KEX_ERR_AUTH      -5
#define KEX_ERR_CRYPTO    -6
#define KEX_ERR_PROPOSAL  -7
#define KEX_ERR_NOMEM     -8

#define KEX_EXCH_SA_INIT       34u
#define KEX_EXCH_AUTH          35u
#define KEX_EXCH_CREATE_CHILD  36u
#define KEX_EXCH_INFORMATIONAL 37u
#define KEX_EXCH_INTERMEDIATE  43u

#define KEX_FLAG_INITIATOR   0x08u
#define KEX_FLAG_RESPONSE    0x20u
#define KEX_FLAG_FRAGMENTED  0x40u

#define KEX_UNIT_SA_PROPOSAL  1u
#define KEX_UNIT_KE_CLASSIC   2u
#define KEX_UNIT_KEM_DATA     3u
#define KEX_UNIT_NONCE        4u
#define KEX_UNIT_ID           5u
#define KEX_UNIT_AUTH         6u
#define KEX_UNIT_NOTIFY       7u
#define KEX_UNIT_DELETE       8u
#define KEX_UNIT_SK          46u
#define KEX_UNIT_SKF         53u

#define KEX_DH_MODP256          1u
#define KEX_PRF_HMAC_SHA256     1u
#define KEX_AEAD_SHA256_128     1u
#define KEX_KEM_NONE            0u
#define KEX_KEM_MLKEM768        1u
#define KEX_KEM_HYBRID_DUAL     2u

#define KEX_POLICY_CLASSIC_ONLY     0x0001u
#define KEX_POLICY_HYBRID_OPTIONAL  0x0002u
#define KEX_POLICY_HYBRID_REQUIRED  0x0004u
#define KEX_AUTH_METHOD_PSK         2u

#define KEX_NOTIFY_NO_PROPOSAL_CHOSEN  14u
#define KEX_NOTIFY_TEMP_FAILURE        43u
#define KEX_NOTIFY_REKEY_SA         16393u
#define KEX_NOTIFY_INTERMEDIATE_CTX 16400u

#define KEX_PROTO_IKE    1u
#define KEX_PROTO_CHILD  3u

#define KEX_TRACE_OP_RECV_PKT          1u
#define KEX_TRACE_OP_LOCAL_REKEY_INIT  2u
#define KEX_TRACE_OP_DATA_PROBE        3u

typedef enum {
    KEX_STATE_IDLE = 0,
    KEX_STATE_INIT_DONE = 1,
    KEX_STATE_INTERMEDIATE_DONE = 2,
    KEX_STATE_ESTABLISHED = 3,
    KEX_STATE_DELETED = 4
} KexSaState;

typedef struct { uint32_t state[8]; uint64_t bitcount; uint8_t buffer[64]; } KexSha256Ctx;
typedef struct { KexSha256Ctx inner, outer; } KexHmacCtx;
typedef struct { uint32_t seed, counter; } KexDrbg;

typedef struct {
    uint64_t init_spi, resp_spi;
    uint8_t version, exch_type, flags, first_unit;
    uint32_t msg_id, total_len;
} KexHeader;

typedef struct { uint8_t unit_type, critical; uint16_t body_len; const uint8_t *body; } KexUnitView;
typedef struct { const uint8_t *buf; size_t len, offset; } KexUnitIter;

typedef struct {
    uint16_t dh_group, prf_alg, aead_alg, policy_flags;
    uint32_t child_spi;
    uint16_t kem_alg, reserved;
} KexProposal;

typedef struct {
    bool active;
    uint32_t msg_id, seen_mask;
    uint8_t exch_type, inner_first_unit;
    uint16_t total_frags, received_count;
    uint8_t **slots;
    size_t *slot_lens;
    size_t total_bytes;
} KexFragCtx;

typedef struct ChildSa {
    uint32_t magic, child_spi_in, child_spi_out, rekey_of_spi;
    int refcnt;
    bool established, has_pfs;
    uint8_t pfs_priv[KEX_DH_LEN];
    uint8_t nonce_i[KEX_NONCE_LEN], nonce_r[KEX_NONCE_LEN], min_nonce[KEX_NONCE_LEN];
    uint8_t sk_child_i[KEX_HASH_LEN], sk_child_r[KEX_HASH_LEN];
} ChildSa;

typedef struct KexSa {
    bool in_use, hybrid_completed, collision_detected;
    uint64_t init_spi, resp_spi;
    KexSaState state;
    uint16_t policy_flags, kem_alg, required_kem_rounds, completed_kem_rounds;
    uint32_t peer_id, initial_peer_child_spi, initial_local_child_spi;
    uint32_t expected_peer_msg_id, next_local_msg_id, pending_rekey_msg_id;
    uint8_t nonce_i[KEX_NONCE_LEN], nonce_r[KEX_NONCE_LEN];
    uint8_t dh_shared[KEX_DH_LEN], pq_shared[KEX_HASH_LEN];
    uint8_t init_req_hash[KEX_HASH_LEN], init_resp_hash[KEX_HASH_LEN];
    uint8_t int_auth_i[KEX_HASH_LEN], int_auth_r[KEX_HASH_LEN];
    uint8_t sk_d[KEX_HASH_LEN], sk_ai[KEX_HASH_LEN], sk_ar[KEX_HASH_LEN];
    uint8_t sk_ei[KEX_HASH_LEN], sk_er[KEX_HASH_LEN], sk_pi[KEX_HASH_LEN], sk_pr[KEX_HASH_LEN];
    KexFragCtx frag;
    ChildSa *active_child, *pending_rekey, *collision_peer;
} KexSa;

typedef struct {
    uint32_t server_id, probe_count;
    uint8_t psk[KEX_HASH_LEN], probe_acc[KEX_HASH_LEN];
    KexDrbg drbg;
    KexSa slots[KEX_MAX_SAS];
    KexSha256Ctx tx_hash;
} KexEngine;

uint16_t kex_get_be16(const uint8_t *p);
uint32_t kex_get_be32(const uint8_t *p);
uint64_t kex_get_be64(const uint8_t *p);
void kex_put_be16(uint8_t *p, uint16_t v);
void kex_put_be32(uint8_t *p, uint32_t v);
void kex_put_be64(uint8_t *p, uint64_t v);

void kex_secure_zero(void *ptr, size_t len);
int kex_ct_memcmp(const void *a, const void *b, size_t len);
void kex_sha256_init(KexSha256Ctx *ctx);
void kex_sha256_update(KexSha256Ctx *ctx, const uint8_t *data, size_t len);
void kex_sha256_final(KexSha256Ctx *ctx, uint8_t out[KEX_HASH_LEN]);
void kex_sha256(const uint8_t *data, size_t len, uint8_t out[KEX_HASH_LEN]);
void kex_hmac_init(KexHmacCtx *ctx, const uint8_t *key, size_t key_len);
void kex_hmac_update(KexHmacCtx *ctx, const uint8_t *data, size_t len);
void kex_hmac_final(KexHmacCtx *ctx, uint8_t out[KEX_HASH_LEN]);
void kex_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t out[KEX_HASH_LEN]);
void kex_hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk[KEX_HASH_LEN]);
int kex_hkdf_expand(const uint8_t prk[KEX_HASH_LEN], const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

void kex_drbg_init(KexDrbg *drbg, uint32_t seed);
void kex_drbg_generate(KexDrbg *drbg, uint8_t *out, size_t len);
void kex_clamp_scalar(uint8_t scalar[KEX_DH_LEN]);
int kex_dh_keypair(KexDrbg *drbg, uint8_t priv_out[KEX_DH_LEN], uint8_t pub_out[KEX_DH_LEN]);
int kex_dh_shared(const uint8_t priv[KEX_DH_LEN], const uint8_t peer_pub[KEX_DH_LEN], uint8_t shared_out[KEX_DH_LEN]);
int kex_kem_encaps(KexDrbg *drbg, uint16_t round_num, const uint8_t peer_pk[KEX_DH_LEN], uint8_t ct_out[KEX_DH_LEN], uint8_t ss_out[KEX_HASH_LEN]);
int kex_aead_seal(const uint8_t sk_e[KEX_HASH_LEN], const uint8_t sk_a[KEX_HASH_LEN], const uint8_t *aad, size_t aad_len, const uint8_t iv[KEX_AEAD_IV_LEN], const uint8_t *plain, size_t plain_len, uint8_t *out, size_t *out_len);
int kex_aead_open(const uint8_t sk_e[KEX_HASH_LEN], const uint8_t sk_a[KEX_HASH_LEN], const uint8_t *aad, size_t aad_len, const uint8_t *enc, size_t enc_len, uint8_t *plain_out, size_t *plain_len);

void kex_derive_init_keys(KexSa *sa);
void kex_reseed_hybrid_keys(KexSa *sa, uint16_t round_num, const uint8_t pq_ss[KEX_HASH_LEN]);
void kex_derive_child_keys(const KexSa *sa, ChildSa *csa, const uint8_t *pfs_shared);
void kex_update_int_auth(uint8_t int_auth[KEX_HASH_LEN], const KexHeader *hdr, const uint8_t *inner_units, size_t inner_len);
void kex_compute_auth_mac(const uint8_t sk_p[KEX_HASH_LEN], const uint8_t psk[KEX_HASH_LEN], const uint8_t init_octets_hash[KEX_HASH_LEN], const uint8_t peer_nonce[KEX_NONCE_LEN], uint32_t id_val, const uint8_t *int_auth_i, const uint8_t *int_auth_r, uint16_t int_rounds, uint8_t out_mac[KEX_HASH_LEN]);

int kex_parse_header(const uint8_t *buf, size_t len, KexHeader *hdr);
void kex_write_header(uint8_t *buf, const KexHeader *hdr);
void kex_unit_iter_init(KexUnitIter *it, const uint8_t *buf, size_t len);
int kex_unit_iter_next(KexUnitIter *it, KexUnitView *view);
bool kex_known_unit_type(uint8_t unit_type);
int kex_append_unit(uint8_t *buf, size_t cap, size_t *off, uint8_t unit_type, uint8_t critical, const uint8_t *body, uint16_t body_len);
int kex_parse_proposal(const KexUnitView *u, KexProposal *prop);
int kex_append_proposal(uint8_t *buf, size_t cap, size_t *off, const KexProposal *prop);
int kex_append_ke(uint8_t *buf, size_t cap, size_t *off, uint16_t dh_group, const uint8_t pub[KEX_DH_LEN]);
int kex_append_kem(uint8_t *buf, size_t cap, size_t *off, uint16_t round_num, uint16_t kem_alg, const uint8_t blob[KEX_DH_LEN]);
int kex_append_nonce(uint8_t *buf, size_t cap, size_t *off, const uint8_t nonce[KEX_NONCE_LEN]);
int kex_append_id(uint8_t *buf, size_t cap, size_t *off, uint32_t id_val);
int kex_append_auth(uint8_t *buf, size_t cap, size_t *off, const uint8_t mac[KEX_HASH_LEN]);
int kex_append_notify(uint8_t *buf, size_t cap, size_t *off, uint16_t notify_type, uint8_t proto_id, uint32_t aux_u32);
int kex_wrap_encrypted_packet(KexDrbg *drbg, const uint8_t sk_e[KEX_HASH_LEN], const uint8_t sk_a[KEX_HASH_LEN], KexHeader *hdr, uint8_t inner_first, const uint8_t *plain, size_t plain_len, uint8_t *out_pkt, size_t cap, size_t *out_len);
int kex_unwrap_encrypted_packet(const uint8_t sk_e[KEX_HASH_LEN], const uint8_t sk_a[KEX_HASH_LEN], const uint8_t *raw_pkt, size_t raw_len, const KexHeader *hdr, uint8_t *inner_first_out, uint8_t *plain_out, size_t *plain_len);

void kex_frag_init(KexFragCtx *ctx);
void kex_frag_reset(KexFragCtx *ctx);
int kex_frag_collect(KexSa *sa, const uint8_t *raw_pkt, size_t raw_len, const KexHeader *hdr, uint8_t *plain_out, size_t plain_cap, size_t *plain_len_out, uint8_t *inner_first_out);

ChildSa *kex_child_sa_alloc(void);
void kex_child_sa_ref(ChildSa *csa);
void kex_child_sa_unref(ChildSa *csa);
KexSa *kex_table_alloc_sa(KexEngine *eng, uint64_t init_spi, uint64_t resp_spi);
KexSa *kex_table_find_sa(KexEngine *eng, uint64_t init_spi, uint64_t resp_spi);
void kex_table_release_sa(KexSa *sa);
uint32_t kex_table_count_established(const KexEngine *eng);
void kex_table_compute_digest(const KexEngine *eng, uint8_t out_digest[KEX_HASH_LEN]);

int kex_child_establish_initial(KexSa *sa);
int kex_rekey_init_local(KexEngine *eng, KexSa *sa, bool use_pfs, uint32_t override_spi, const uint8_t *override_nonce, uint8_t *out_pkt, size_t cap, size_t *out_len);
int kex_rekey_handle_request(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len, uint8_t *out_pkt, size_t cap, size_t *out_len);
int kex_rekey_handle_response(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len);
int kex_handle_informational(KexEngine *eng, KexSa *sa, const KexHeader *hdr, const uint8_t *plain, size_t plain_len, uint8_t *out_pkt, size_t cap, size_t *out_len);

uint16_t kex_kem_required_rounds(uint16_t kem_alg);
int kex_process_packet(KexEngine *eng, const uint8_t *pkt, size_t pkt_len, uint8_t *resp_out, size_t resp_cap, size_t *resp_len);
void kex_engine_init(KexEngine *eng, uint32_t seed, uint32_t server_id, const uint8_t psk[KEX_HASH_LEN]);
void kex_engine_destroy(KexEngine *eng);
void kex_engine_record_tx(KexEngine *eng, const uint8_t *pkt, size_t pkt_len);

#endif
