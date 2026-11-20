#pragma once

/**
 * `h2_framer`: Embedded RFC 9113 HTTP/2 Connection Framer & RFC 7541 HPACK Codec.
 *
 * Core Protocol Contracts:
 *  - HPACK Huffman Decoding (RFC 7541 §5.2): Canonical prefix tree over 256 byte
 *    symbols + 30-bit EOS (`0x3fffffff`). Trailing incomplete padding MUST be at
 *    most 7 bits AND MUST consist exclusively of `1` bits (the prefix of EOS); any
 *    `0` bit in trailing padding, >7 padding bits, or an explicit 30-bit EOS symbol
 *    must fail with `ErrorCode::COMPRESSION_ERROR`.
 *  - HPACK Dynamic Table (RFC 7541 §4.1–§4.4): Entry size is `32 + name.size() + value.size()`.
 *    When an incremental-indexed header (`01xxxxxx`) references a dynamic-table name
 *    whose entry is evicted while making room for the new entry, the referenced name
 *    bytes must remain valid throughout insertion. Dynamic Table Size Updates (`001xxxxx`)
 *    must appear ONLY at the start of a header block, must not exceed the server's
 *    configured `protocol_max_table_size`, and after `set_protocol_max_size()` reduces
 *    and/or raises the limit between header blocks, the decoder must require the
 *    minimum pending size update first per RFC 7541 §4.2.
 *  - Prefixed Integer Varints (RFC 7541 §5.1): Must reject overflowing values or
 *    excessive continuation lengths with `ErrorCode::COMPRESSION_ERROR` without
 *    triggering shift/integer UB.
 *  - HTTP/2 Framing & `CONTINUATION` Lock (RFC 9113 §6.10): While a header block is
 *    open (`END_HEADERS` not yet received on `continuation_stream_id_`), EVERY
 *    incoming frame of ANY type other than `CONTINUATION` on `continuation_stream_id_`
 *    must fail the connection with `ErrorCode::PROTOCOL_ERROR`.
 *  - Request & Trailer Header Validation (RFC 9113 §8.1.1, §8.2, §8.3):
 *    - Field names must be non-empty lowercase ASCII tokens; field names and values
 *      must never contain NUL (`\0`), CR (`\r`), or LF (`\n`).
 *    - Request headers require `:method`, `:scheme`, `:path` (non-empty for `http`/`https`)
 *      before any regular header; duplicate or unknown pseudo-headers are forbidden;
 *      if both `:authority` and `host` are present they must match case-insensitively.
 *    - Trailing `HEADERS` (trailers) MUST NOT contain any `:` pseudo-headers and MUST
 *      carry `END_STREAM`.
 *    - If `content-length` is present, the sum of `DATA` payload bytes on the stream
 *      at `END_STREAM` must equal the declared `content-length` (`PROTOCOL_ERROR` otherwise).
 *  - Flow Control (RFC 9113 §6.9.2): `SETTINGS_INITIAL_WINDOW_SIZE` values `> 0x7fffffff`
 *    are rejected with `ErrorCode::FLOW_CONTROL_ERROR`, and applying the signed window
 *    delta to open/half-closed-remote streams must reject window values `> 0x7fffffff`
 *    with `ErrorCode::FLOW_CONTROL_ERROR` without 32-bit signed integer overflow.
 */

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace h2 {

inline constexpr std::string_view kClientConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline constexpr int64_t kMaxFlowControlWindow = 0x7fffffffLL;
inline constexpr uint32_t kDefaultMaxFrameSize = 16384;
inline constexpr uint32_t kDefaultInitialWindowSize = 65535;
inline constexpr size_t kDefaultHeaderTableSize = 4096;

enum class FrameType : uint8_t {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9,
};

namespace FrameFlags {
inline constexpr uint8_t NONE = 0x00;
inline constexpr uint8_t END_STREAM = 0x01;
inline constexpr uint8_t ACK = 0x01;
inline constexpr uint8_t END_HEADERS = 0x04;
inline constexpr uint8_t PADDED = 0x08;
inline constexpr uint8_t PRIORITY = 0x20;
}  // namespace FrameFlags

namespace SettingsId {
inline constexpr uint16_t HEADER_TABLE_SIZE = 0x1;
inline constexpr uint16_t ENABLE_PUSH = 0x2;
inline constexpr uint16_t MAX_CONCURRENT_STREAMS = 0x3;
inline constexpr uint16_t INITIAL_WINDOW_SIZE = 0x4;
inline constexpr uint16_t MAX_FRAME_SIZE = 0x5;
inline constexpr uint16_t MAX_HEADER_LIST_SIZE = 0x6;
}  // namespace SettingsId

enum class ErrorCode : uint32_t {
    NO_ERROR = 0x0,
    PROTOCOL_ERROR = 0x1,
    INTERNAL_ERROR = 0x2,
    FLOW_CONTROL_ERROR = 0x3,
    SETTINGS_TIMEOUT = 0x4,
    STREAM_CLOSED = 0x5,
    FRAME_SIZE_ERROR = 0x6,
    REFUSED_STREAM = 0x7,
    CANCEL = 0x8,
    COMPRESSION_ERROR = 0x9,
};

struct HeaderField {
    std::string name;
    std::string value;

    bool operator==(const HeaderField& other) const = default;
};

// --- Huffman Codec (src/huffman.cpp) ---
std::vector<uint8_t> huffman_encode(std::string_view plain);
bool huffman_decode(const uint8_t* data, size_t len, std::string& out);

// --- HPACK Static + Dynamic Table (src/hpack_table.cpp) ---
class HpackTable {
public:
    static constexpr size_t kStaticTableCount = 61;

    explicit HpackTable(size_t initial_max_size = kDefaultHeaderTableSize);

    const HeaderField* lookup(size_t index) const;
    void insert(std::string_view name, std::string_view value);

    // Server-side SETTINGS_HEADER_TABLE_SIZE configuration update
    void set_protocol_max_size(size_t new_protocol_max);
    // Peer-sent HPACK Dynamic Table Size Update (001xxxxx)
    bool apply_encoder_size_update(size_t new_size);
    bool has_unsignaled_min_reduction() const { return pending_min_update_.has_value(); }

    size_t current_bytes() const { return current_bytes_; }
    size_t dynamic_count() const { return dynamic_entries_.size(); }
    size_t current_max_size() const { return current_max_size_; }
    size_t protocol_max_size() const { return protocol_max_size_; }

private:
    void evict_to_fit(size_t target_max_bytes);

    std::deque<HeaderField> dynamic_entries_;
    size_t current_bytes_ = 0;
    size_t current_max_size_ = kDefaultHeaderTableSize;
    size_t protocol_max_size_ = kDefaultHeaderTableSize;
    std::optional<size_t> pending_min_update_;
};

// --- HPACK Encoder / Decoder (src/hpack_codec.cpp) ---
void encode_prefixed_int(std::vector<uint8_t>& out, uint8_t first_byte_mask, uint8_t prefix_bits, uint64_t value);
bool decode_prefixed_int(const uint8_t* buf, size_t len, size_t& offset, uint8_t prefix_bits, uint64_t& value_out);

class HpackDecoder {
public:
    explicit HpackDecoder(size_t max_table_size = kDefaultHeaderTableSize, size_t max_header_list_bytes = 65536);

    ErrorCode decode_block(const uint8_t* data, size_t len, std::vector<HeaderField>& out_headers);

    HpackTable& table() { return table_; }
    const HpackTable& table() const { return table_; }

private:
    bool decode_string(const uint8_t* buf, size_t len, size_t& offset, std::string& out_str);

    HpackTable table_;
    size_t max_header_list_bytes_;
};

class HpackEncoder {
public:
    static std::vector<uint8_t> encode_literal_block(
        const std::vector<HeaderField>& headers,
        bool incremental_index = true,
        bool use_huffman = false);
};

// --- Request & Trailer Validator (src/header_validator.cpp) ---
struct ValidatedRequest {
    uint32_t stream_id = 0;
    std::string method;
    std::string scheme;
    std::string authority;
    std::string path;
    std::optional<uint64_t> content_length;
    std::vector<HeaderField> headers;
    std::vector<HeaderField> trailers;
    std::string body;
};

ErrorCode validate_request_headers(const std::vector<HeaderField>& fields, ValidatedRequest& req_out);
ErrorCode validate_trailer_headers(const std::vector<HeaderField>& fields, ValidatedRequest& req_inout);

// --- HTTP/2 Server Connection Framer (src/h2_connection.cpp) ---
enum class StreamState {
    IDLE,
    OPEN,
    HALF_CLOSED_REMOTE,
    CLOSED,
};

struct StreamContext {
    uint32_t stream_id = 0;
    StreamState state = StreamState::IDLE;
    int32_t send_window = static_cast<int32_t>(kDefaultInitialWindowSize);
    int32_t recv_window = static_cast<int32_t>(kDefaultInitialWindowSize);
    uint64_t received_data_bytes = 0;
    bool initial_headers_done = false;
    ValidatedRequest request;
};

class H2ServerConnection {
public:
    using RequestCallback = std::function<void(const ValidatedRequest&)>;

    explicit H2ServerConnection(RequestCallback on_request = {});

    // Local server applies a new SETTINGS_HEADER_TABLE_SIZE limit
    void set_local_header_table_limit(size_t max_bytes);

    // Feed raw wire bytes (starting with kClientConnectionPreface on a new connection)
    ErrorCode receive_bytes(const uint8_t* data, size_t len);
    ErrorCode receive_bytes(const std::vector<uint8_t>& data) {
        return receive_bytes(data.data(), data.size());
    }

    bool is_closed_with_error() const { return connection_error_ != ErrorCode::NO_ERROR; }
    ErrorCode last_error() const { return connection_error_; }
    const std::vector<ValidatedRequest>& completed_requests() const { return completed_requests_; }
    uint32_t ping_acks_sent() const { return ping_acks_sent_; }
    uint32_t settings_acks_sent() const { return settings_acks_sent_; }
    const StreamContext* find_stream(uint32_t stream_id) const;

    static std::vector<uint8_t> serialize_frame(
        FrameType type,
        uint8_t flags,
        uint32_t stream_id,
        const std::vector<uint8_t>& payload);

private:
    ErrorCode process_frame(FrameType type, uint8_t flags, uint32_t stream_id, const uint8_t* payload, size_t len);
    ErrorCode finish_header_block(uint32_t stream_id, bool end_stream, bool is_trailer);
    ErrorCode fail_connection(ErrorCode err);

    bool preface_received_ = false;
    ErrorCode connection_error_ = ErrorCode::NO_ERROR;
    std::vector<uint8_t> recv_buf_;

    HpackDecoder hpack_;
    uint32_t peer_max_frame_size_ = kDefaultMaxFrameSize;
    uint32_t peer_initial_window_size_ = kDefaultInitialWindowSize;
    uint32_t max_concurrent_streams_ = 100;
    int64_t conn_recv_window_ = kDefaultInitialWindowSize;

    // Active header-block continuation state
    uint32_t continuation_stream_id_ = 0;
    bool continuation_end_stream_ = false;
    bool continuation_is_trailer_ = false;
    std::vector<uint8_t> header_block_buf_;

    uint32_t highest_client_stream_id_ = 0;
    std::unordered_map<uint32_t, StreamContext> streams_;
    std::vector<ValidatedRequest> completed_requests_;
    RequestCallback on_request_;
    uint32_t ping_acks_sent_ = 0;
    uint32_t settings_acks_sent_ = 0;
};

}  // namespace h2
