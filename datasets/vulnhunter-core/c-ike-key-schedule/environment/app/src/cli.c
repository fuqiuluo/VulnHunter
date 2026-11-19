#include "kex_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void kex_engine_init(KexEngine *eng, uint32_t seed, uint32_t server_id, const uint8_t psk[KEX_HASH_LEN]) {
    memset(eng, 0, sizeof(*eng));
    eng->server_id = server_id;
    memcpy(eng->psk, psk, KEX_HASH_LEN);
    kex_drbg_init(&eng->drbg, seed);
    kex_sha256_init(&eng->tx_hash);
}

void kex_engine_destroy(KexEngine *eng) {
    for (size_t i = 0; i < KEX_MAX_SAS; i++) {
        if (eng->slots[i].in_use) kex_table_release_sa(&eng->slots[i]);
    }
    kex_secure_zero(eng, sizeof(*eng));
}

void kex_engine_record_tx(KexEngine *eng, const uint8_t *pkt, size_t pkt_len) {
    uint8_t len_be[4];
    kex_put_be32(len_be, (uint32_t)pkt_len);
    kex_sha256_update(&eng->tx_hash, len_be, sizeof(len_be));
    kex_sha256_update(&eng->tx_hash, pkt, pkt_len);
}

static void format_hex8(const uint8_t b[8], char out[17]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 8u; i++) {
        out[i * 2u + 0] = hex[(b[i] >> 4) & 0x0fu];
        out[i * 2u + 1] = hex[b[i] & 0x0fu];
    }
    out[16] = '\0';
}

static int run_local_rekey_step(KexEngine *eng, uint8_t op_flags, const uint8_t *body, size_t body_len) {
    if (body_len != 52u) return KEX_ERR_WIRE;
    uint64_t init_spi = kex_get_be64(body + 0), resp_spi = kex_get_be64(body + 8u);
    uint32_t override_spi = kex_get_be32(body + 16u);
    const uint8_t *nonce_ptr = body + 20u;

    bool has_override = false;
    for (size_t i = 0; i < KEX_NONCE_LEN; i++) {
        if (nonce_ptr[i] != 0) { has_override = true; break; }
    }
    KexSa *sa = kex_table_find_sa(eng, init_spi, resp_spi);
    if (sa == NULL) return KEX_ERR_STATE;

    uint8_t out_pkt[1024];
    size_t out_len = 0;
    return kex_rekey_init_local(eng, sa, (op_flags & 0x01u) != 0, override_spi, has_override ? nonce_ptr : NULL, out_pkt, sizeof(out_pkt), &out_len);
}

static int run_data_probe_step(KexEngine *eng, const uint8_t *body, size_t body_len) {
    if (body_len < 20u) return KEX_ERR_WIRE;
    uint64_t init_spi = kex_get_be64(body + 0), resp_spi = kex_get_be64(body + 8u);
    uint32_t seq_no = kex_get_be32(body + 16u);
    const uint8_t *data = body + 20u;
    size_t data_len = body_len - 20u;

    KexSa *sa = kex_table_find_sa(eng, init_spi, resp_spi);
    if (sa == NULL || sa->state != KEX_STATE_ESTABLISHED || sa->active_child == NULL) return KEX_ERR_STATE;
    ChildSa *csa = sa->active_child;
    if (csa->magic != KEX_CHILD_MAGIC || !csa->established) return KEX_ERR_STATE;

    uint8_t hdr_meta[12], dir_i[KEX_HASH_LEN], tag[KEX_HASH_LEN];
    kex_put_be32(hdr_meta + 0, csa->child_spi_in);
    kex_put_be32(hdr_meta + 4u, csa->child_spi_out);
    kex_put_be32(hdr_meta + 8u, seq_no);

    KexHmacCtx hm;
    kex_hmac_init(&hm, csa->sk_child_i, KEX_HASH_LEN);
    kex_hmac_update(&hm, hdr_meta, sizeof(hdr_meta));
    kex_hmac_update(&hm, data, data_len);
    kex_hmac_final(&hm, dir_i);

    kex_hmac_init(&hm, csa->sk_child_r, KEX_HASH_LEN);
    kex_hmac_update(&hm, dir_i, KEX_HASH_LEN);
    kex_hmac_update(&hm, hdr_meta, sizeof(hdr_meta));
    kex_hmac_final(&hm, tag);

    KexSha256Ctx acc;
    kex_sha256_init(&acc);
    kex_sha256_update(&acc, eng->probe_acc, KEX_HASH_LEN);
    kex_sha256_update(&acc, hdr_meta, sizeof(hdr_meta));
    kex_sha256_update(&acc, tag, KEX_HASH_LEN);
    kex_sha256_final(&acc, eng->probe_acc);
    eng->probe_count++;

    char tag_hex[17];
    format_hex8(tag, tag_hex);
    printf("PROBE seq=%u spi_in=%08x spi_out=%08x tag=%s\n", seq_no, csa->child_spi_in, csa->child_spi_out, tag_hex);
    return KEX_OK;
}

static int execute_trace(const uint8_t *buf, size_t len) {
    if (len < 52u || kex_get_be32(buf + 0) != KEX_TRACE_MAGIC) return KEX_ERR_WIRE;
    uint32_t seed = kex_get_be32(buf + 4u), server_id = kex_get_be32(buf + 8u);
    uint32_t step_count = kex_get_be32(buf + 12u), trace_flags = kex_get_be32(buf + 16u);
    (void)trace_flags;
    if (step_count > 512u || server_id == 0) return KEX_ERR_PROTO;

    KexEngine eng;
    kex_engine_init(&eng, seed, server_id, buf + 20u);
    uint8_t *resp_buf = (uint8_t *)malloc(KEX_MAX_PKT_LEN);
    if (resp_buf == NULL) { kex_engine_destroy(&eng); return KEX_ERR_NOMEM; }

    size_t off = 52u;
    int rc = KEX_OK;
    for (uint32_t s = 0; s < step_count; s++) {
        if (len - off < 8u) { rc = KEX_ERR_WIRE; break; }
        uint8_t op = buf[off + 0], op_flags = buf[off + 1u];
        uint32_t body_len = kex_get_be32(buf + off + 4u);
        off += 8u;
        if (body_len > len - off) { rc = KEX_ERR_WIRE; break; }
        const uint8_t *body = buf + off;
        off += body_len;

        size_t resp_len = 0;
        if (op == KEX_TRACE_OP_RECV_PKT) rc = kex_process_packet(&eng, body, body_len, resp_buf, KEX_MAX_PKT_LEN, &resp_len);
        else if (op == KEX_TRACE_OP_LOCAL_REKEY_INIT) rc = run_local_rekey_step(&eng, op_flags, body, body_len);
        else if (op == KEX_TRACE_OP_DATA_PROBE) rc = run_data_probe_step(&eng, body, body_len);
        else rc = KEX_ERR_PROTO;
        if (rc < 0) break;
    }

    if (rc >= 0 && off != len) rc = KEX_ERR_WIRE;
    if (rc >= 0) {
        uint8_t tx_digest[KEX_HASH_LEN], st_digest[KEX_HASH_LEN];
        char tx_hex[17], st_hex[17];
        KexSha256Ctx tx_copy = eng.tx_hash;
        kex_sha256_final(&tx_copy, tx_digest);
        kex_table_compute_digest(&eng, st_digest);
        format_hex8(tx_digest, tx_hex);
        format_hex8(st_digest, st_hex);
        printf("OK steps=%u active_sas=%u probes=%u tx_digest=%s state_digest=%s\n",
               step_count, kex_table_count_established(&eng), eng.probe_count, tx_hex, st_hex);
    }

    free(resp_buf);
    kex_engine_destroy(&eng);
    return (rc >= 0) ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "Usage: %s <trace.bin>\n", argv[0]); return 1; }
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) return 1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return 1; }
    long fsz = ftell(fp);
    if (fsz < 0 || fsz > 16 * 1024 * 1024 || fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return 1; }
    uint8_t *buf = (uint8_t *)malloc((size_t)(fsz > 0 ? fsz : 1));
    if (buf == NULL) { fclose(fp); return 1; }
    size_t nread = fread(buf, 1u, (size_t)fsz, fp);
    fclose(fp);
    if (nread != (size_t)fsz) { free(buf); return 1; }
    int exit_code = execute_trace(buf, nread);
    free(buf);
    return exit_code;
}
