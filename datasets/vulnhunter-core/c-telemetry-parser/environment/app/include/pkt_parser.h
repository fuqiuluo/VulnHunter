#ifndef PKT_PARSER_H
#define PKT_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define PKT_MAGIC 0x5648504B /* "VHPK" */
#define PKT_META_SIZE 16U
#define PKT_MAX_PAYLOAD 1048576U /* 1 MiB max reassembled payload */

typedef enum {
    PKT_OK = 0,
    PKT_ERR_FORMAT = -1,
    PKT_ERR_OVERFLOW = -2,
    PKT_ERR_NOMEM = -3
} pkt_status_t;

typedef struct {
    uint32_t session_id;
    uint32_t flags;
    size_t payload_len;
    uint8_t *buffer; /* Starts with 16-byte metadata header, followed by payload */
} pkt_bundle_t;

pkt_status_t pkt_parse_bundle(const uint8_t *raw, size_t raw_len, pkt_bundle_t *out);
uint64_t pkt_payload_fnv1a(const pkt_bundle_t *bundle);
void pkt_free_bundle(pkt_bundle_t *bundle);

#endif /* PKT_PARSER_H */
