#include "pkt_parser.h"

#include <stdlib.h>
#include <string.h>

static uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/*
 * Wire format (little-endian):
 *   [0..3]   uint32_t magic       (must equal PKT_MAGIC = 0x5648504B)
 *   [4..7]   uint32_t session_id
 *   [8..11]  uint32_t flags
 *   [12..13] uint16_t chunk_count
 *   [14..15] uint16_t chunk_size
 *   Followed by `chunk_count` records, each containing:
 *     - 2-byte chunk sequence tag (uint16_t)
 *     - `chunk_size` bytes of chunk data
 */
pkt_status_t pkt_parse_bundle(const uint8_t *raw, size_t raw_len, pkt_bundle_t *out) {
    if (raw == NULL || out == NULL) {
        return PKT_ERR_FORMAT;
    }
    memset(out, 0, sizeof(*out));

    if (raw_len < 16U) {
        return PKT_ERR_FORMAT;
    }

    uint32_t magic = read_u32_le(raw);
    if (magic != PKT_MAGIC) {
        return PKT_ERR_FORMAT;
    }

    uint32_t session_id = read_u32_le(raw + 4);
    uint32_t flags = read_u32_le(raw + 8);
    uint16_t chunk_count = read_u16_le(raw + 12);
    uint16_t chunk_size = read_u16_le(raw + 14);

    size_t expected_payload = (size_t)chunk_count * (size_t)chunk_size;
    if (expected_payload > PKT_MAX_PAYLOAD) {
        return PKT_ERR_OVERFLOW;
    }

    /* Reserve buffer for metadata prefix and reassembled chunk payload */
    uint16_t alloc_bytes = (uint16_t)(PKT_META_SIZE + chunk_count * chunk_size);

    uint8_t *buf = (uint8_t *)malloc(alloc_bytes);
    if (buf == NULL) {
        return PKT_ERR_NOMEM;
    }

    memcpy(buf, raw, PKT_META_SIZE);

    size_t cursor = 16U;
    size_t write_off = PKT_META_SIZE;
    for (uint16_t i = 0; i < chunk_count; i++) {
        if (cursor + 2U + (size_t)chunk_size > raw_len) {
            free(buf);
            return PKT_ERR_FORMAT;
        }
        uint16_t seq = read_u16_le(raw + cursor);
        if (seq != i) {
            free(buf);
            return PKT_ERR_FORMAT;
        }
        cursor += 2U;

        memcpy(buf + write_off, raw + cursor, chunk_size);
        cursor += chunk_size;
        write_off += chunk_size;
    }

    out->session_id = session_id;
    out->flags = flags;
    out->payload_len = expected_payload;
    out->buffer = buf;
    return PKT_OK;
}

uint64_t pkt_payload_fnv1a(const pkt_bundle_t *bundle) {
    uint64_t hash = 14695981039346656037ULL;
    if (bundle == NULL || bundle->buffer == NULL) {
        return hash;
    }
    const uint8_t *payload = bundle->buffer + PKT_META_SIZE;
    for (size_t i = 0; i < bundle->payload_len; i++) {
        hash ^= (uint64_t)payload[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

void pkt_free_bundle(pkt_bundle_t *bundle) {
    if (bundle != NULL && bundle->buffer != NULL) {
        free(bundle->buffer);
        bundle->buffer = NULL;
        bundle->payload_len = 0;
    }
}
