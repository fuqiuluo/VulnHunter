#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace quic_mux {

constexpr uint32_t kWireMagic = 0x58554D51U;
constexpr uint16_t kWireVersion = 1U;
constexpr uint64_t kMaxQuicOffset = (1ULL << 62) - 1ULL;
constexpr uint32_t kMaxFramePayload = 1U << 20;
constexpr uint32_t kMaxReasonLength = 256U;
constexpr uint32_t kMaxScriptFrames = 16384U;
constexpr uint64_t kMaxStreamsLimit = 65536ULL;
constexpr uint64_t kMaxImplicitStreamOpen = 1024ULL;
constexpr uint64_t kMaxTickDeltaMs = 3600000ULL;
constexpr uint32_t kMaxDrainTimeoutMs = 600000U;
constexpr size_t kMaxStreamBufferedBytes = 4U << 20;
constexpr size_t kTimerWheelSlots = 64U;
constexpr uint64_t kTimerSlotMs = 10ULL;

constexpr uint8_t kFlagAutoStreamCredit = 0x01U;
constexpr uint8_t kFlagEnforceAppPolicy = 0x02U;
constexpr uint8_t kValidSessionFlagsMask = 0x03U;

constexpr uint8_t kStreamFlagFin = 0x01U;
constexpr uint8_t kStopSendingFlagLocal = 0x01U;
constexpr uint8_t kMaxDataFlagPeer = 0x01U;
constexpr uint8_t kMaxStreamsFlagUni = 0x01U;
constexpr uint8_t kBlockedFlagAutoGrant = 0x01U;
constexpr uint8_t kConnCloseFlagApp = 0x01U;
constexpr uint64_t kPolicyRejectedAppCode = 0x010BU;

enum class EndpointRole : uint8_t { Client = 0, Server = 1 };

enum class TransportError : uint16_t {
    NoError = 0x00,
    InternalError = 0x01,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
};

std::string_view error_name(TransportError err) noexcept;

enum class FrameType : uint8_t {
    Stream = 0x01,
    ResetStream = 0x02,
    StopSending = 0x03,
    MaxData = 0x04,
    MaxStreams = 0x05,
    StreamDataBlocked = 0x06,
    TickTimer = 0x07,
    ConnClose = 0x08,
};

enum class RecvState : uint8_t {
    Recv = 0, SizeKnown = 1, DataRecvd = 2, DataRead = 3,
    ResetRecvd = 4, ResetRead = 5, NotApplicable = 6,
};

enum class SendState : uint8_t {
    Ready = 0, Send = 1, DataSent = 2, DataRecvd = 3,
    ResetSent = 4, ResetRecvd = 5, NotApplicable = 6,
};

constexpr bool is_unidirectional(uint64_t stream_id) noexcept {
    return (stream_id & 0x2ULL) != 0ULL;
}
constexpr bool is_peer_initiated(uint64_t stream_id, EndpointRole local_role) noexcept {
    return (stream_id & 0x1ULL) != static_cast<uint64_t>(local_role);
}
constexpr bool local_can_receive(uint64_t stream_id, EndpointRole local_role) noexcept {
    return !is_unidirectional(stream_id) || is_peer_initiated(stream_id, local_role);
}
constexpr bool local_can_send(uint64_t stream_id, EndpointRole local_role) noexcept {
    return !is_unidirectional(stream_id) || !is_peer_initiated(stream_id, local_role);
}
constexpr uint64_t stream_ordinal(uint64_t stream_id) noexcept { return stream_id >> 2U; }

struct ConnectionConfig {
    EndpointRole local_role = EndpointRole::Server;
    uint8_t flags = 0;
    uint64_t initial_max_data = 0;
    uint64_t initial_max_stream_data_bidi = 0;
    uint64_t initial_max_stream_data_uni = 0;
    uint32_t initial_max_streams_bidi = 0;
    uint32_t initial_max_streams_uni = 0;
    uint32_t drain_timeout_ms = 200;
    uint32_t denied_route_tag = 0;
};

struct WireFrame {
    FrameType type = FrameType::Stream;
    uint8_t flags = 0;
    uint64_t stream_id = 0;
    uint64_t offset = 0;
    uint64_t error_code = 0;
    uint64_t final_size = 0;
    uint64_t limit_value = 0;
    uint64_t delta_ms = 0;
    std::vector<uint8_t> data;
};

struct DecodedScript {
    ConnectionConfig config;
    std::vector<WireFrame> frames;
};

class Fnv1aHasher {
public:
    static constexpr uint64_t kOffsetBasis = 14695981039346656037ULL;
    static constexpr uint64_t kPrime = 1099511628211ULL;

    void reset() noexcept { state_ = kOffsetBasis; }
    void update(std::span<const uint8_t> bytes) noexcept {
        for (uint8_t b : bytes) {
            state_ ^= static_cast<uint64_t>(b);
            state_ *= kPrime;
        }
    }
    void update_u64_le(uint64_t val) noexcept {
        for (unsigned i = 0; i < 8U; ++i) {
            state_ ^= (val >> (i * 8U)) & 0xFFULL;
            state_ *= kPrime;
        }
    }
    uint64_t digest() const noexcept { return state_; }

private:
    uint64_t state_ = kOffsetBasis;
};

using TimerCallback = void (*)(void* owner, uint64_t stream_id, uint64_t fired_at_ms);

struct TimerNode {
    TimerNode* prev = nullptr;
    TimerNode* next = nullptr;
    uint64_t deadline_ms = 0;
    uint64_t stream_id = 0;
    TimerCallback callback = nullptr;
    void* owner = nullptr;
    bool active = false;
};

class TimerWheel {
public:
    TimerWheel() noexcept;
    ~TimerWheel() noexcept;
    TimerWheel(const TimerWheel&) = delete;
    TimerWheel& operator=(const TimerWheel&) = delete;

    void schedule(TimerNode* node, uint64_t deadline_ms, uint64_t stream_id,
                  TimerCallback cb, void* owner) noexcept;
    void cancel(TimerNode* node) noexcept;
    size_t advance(uint64_t target_ms);
    void cancel_all() noexcept;
    uint64_t current_ms() const noexcept { return current_ms_; }
    size_t active_count() const noexcept { return active_count_; }

private:
    static void init_sentinel(TimerNode& head) noexcept;
    void link_tail(TimerNode& head, TimerNode* node) noexcept;
    void unlink_node(TimerNode* node) noexcept;
    size_t slot_for_ms(uint64_t timestamp_ms) const noexcept;
    void cascade_far_timers(uint64_t tick_ms) noexcept;
    size_t expire_bucket(TimerNode& head, uint64_t cutoff_ms);

    std::array<TimerNode, kTimerWheelSlots> buckets_{};
    TimerNode far_horizon_head_{};
    uint64_t current_ms_ = 0;
    size_t active_count_ = 0;
};

class Reassembler {
public:
    TransportError push(uint64_t offset, std::span<const uint8_t> data, bool fin);
    TransportError validate_reset_final_size(uint64_t final_size);
    size_t drain_contiguous(Fnv1aHasher& out_hasher);
    void discard_unread() noexcept;

    uint64_t contiguous_offset() const noexcept { return contiguous_offset_; }
    uint64_t highest_offset() const noexcept { return highest_offset_; }
    bool has_final_size() const noexcept { return size_known_; }
    uint64_t final_size() const noexcept { return final_size_; }
    size_t buffered_bytes() const noexcept { return buffered_bytes_; }
    bool is_complete() const noexcept { return size_known_ && contiguous_offset_ == final_size_; }

private:
    std::map<uint64_t, std::vector<uint8_t>> segments_;
    uint64_t contiguous_offset_ = 0;
    uint64_t highest_offset_ = 0;
    uint64_t final_size_ = 0;
    size_t buffered_bytes_ = 0;
    bool size_known_ = false;
};

class StreamFlowWindow {
public:
    explicit StreamFlowWindow(uint64_t initial_max_data) noexcept;

    uint64_t max_data() const noexcept { return max_data_; }
    void grant_max_data(uint64_t new_limit) noexcept;
    uint64_t highest_offset() const noexcept { return highest_offset_; }
    void set_highest_offset(uint64_t offset) noexcept { highest_offset_ = offset; }
    uint64_t consumed_offset() const noexcept { return consumed_offset_; }
    void add_consumed(uint64_t bytes) noexcept;
    bool has_final_size() const noexcept { return size_known_; }
    uint64_t final_size() const noexcept { return final_size_; }
    void set_final_size(uint64_t final_sz) noexcept;
    void record_blocked(uint64_t blocked_at) noexcept;
    uint64_t blocked_count() const noexcept { return blocked_count_; }
    uint64_t available_window() const noexcept;

private:
    uint64_t max_data_ = 0;
    uint64_t highest_offset_ = 0;
    uint64_t consumed_offset_ = 0;
    uint64_t final_size_ = 0;
    uint64_t blocked_count_ = 0;
    uint64_t last_blocked_offset_ = 0;
    bool size_known_ = false;
};

class ConnectionFlowControl {
public:
    explicit ConnectionFlowControl(const ConnectionConfig& cfg) noexcept;

    TransportError on_stream_data(StreamFlowWindow& stream_win,
                                  uint64_t offset, uint64_t length, bool fin) noexcept;
    TransportError reconcile_reset(StreamFlowWindow& stream_win, uint64_t final_size) noexcept;
    void record_consumed(uint64_t bytes) noexcept;
    TransportError update_conn_max_data(uint64_t new_limit) noexcept;
    TransportError update_peer_max_data(uint64_t new_limit) noexcept;
    TransportError update_max_streams(bool uni, uint64_t new_limit) noexcept;
    bool can_open_peer_stream(bool uni, uint64_t ordinal) const noexcept;
    void release_peer_stream_credit(bool uni) noexcept;

    uint64_t conn_max_data() const noexcept { return conn_max_data_; }
    uint64_t peer_max_data() const noexcept { return peer_max_data_; }
    uint64_t conn_recv_offset() const noexcept { return conn_recv_offset_; }
    uint64_t conn_consumed_offset() const noexcept { return conn_consumed_offset_; }
    uint64_t max_peer_bidi_streams() const noexcept { return max_peer_bidi_streams_; }
    uint64_t max_peer_uni_streams() const noexcept { return max_peer_uni_streams_; }

private:
    uint64_t conn_max_data_ = 0;
    uint64_t peer_max_data_ = 0;
    uint64_t conn_recv_offset_ = 0;
    uint64_t conn_consumed_offset_ = 0;
    uint64_t max_peer_bidi_streams_ = 0;
    uint64_t max_peer_uni_streams_ = 0;
    bool auto_replenish_ = false;
};

class Stream {
public:
    Stream(uint64_t stream_id, EndpointRole local_role, uint64_t initial_max_stream_data);
    ~Stream() = default;
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;

    TransportError ingest_segment(uint64_t offset, std::span<const uint8_t> data,
                                  bool fin, ConnectionFlowControl& conn_flow);
    void deliver_ready_bytes(ConnectionFlowControl& conn_flow);
    TransportError on_peer_reset(uint64_t app_error_code, uint64_t final_size,
                                 ConnectionFlowControl& conn_flow);
    TransportError on_peer_stop_sending(uint64_t app_error_code) noexcept;
    void mark_local_reject(uint64_t app_error_code) noexcept;
    void on_drain_timeout() noexcept;

    uint64_t stream_id() const noexcept { return stream_id_; }
    RecvState recv_state() const noexcept { return recv_state_; }
    SendState send_state() const noexcept { return send_state_; }
    bool is_locally_rejected() const noexcept { return local_rejected_; }
    bool is_closed() const noexcept;
    bool is_cleanly_completed() const noexcept;
    bool has_route_tag() const noexcept { return route_tag_mask_ == 0x0FU; }
    uint32_t route_tag() const noexcept;
    uint64_t bytes_delivered() const noexcept { return bytes_delivered_; }
    uint64_t payload_digest() const noexcept { return payload_hasher_.digest(); }

    StreamFlowWindow& flow() noexcept { return flow_; }
    const StreamFlowWindow& flow() const noexcept { return flow_; }
    TimerNode& drain_timer() noexcept { return drain_timer_; }

private:
    void capture_route_prefix(uint64_t offset, std::span<const uint8_t> data) noexcept;

    uint64_t stream_id_ = 0;
    EndpointRole local_role_ = EndpointRole::Server;
    RecvState recv_state_ = RecvState::Recv;
    SendState send_state_ = SendState::Ready;
    bool local_rejected_ = false;
    uint8_t route_tag_mask_ = 0;
    std::array<uint8_t, 4> route_tag_bytes_{};
    uint64_t app_error_code_ = 0;
    uint64_t bytes_delivered_ = 0;
    Fnv1aHasher payload_hasher_{};
    Reassembler reassembler_{};
    StreamFlowWindow flow_;
    TimerNode drain_timer_{};
};

struct CompletedStreamDigest {
    uint64_t stream_id = 0;
    uint64_t bytes_delivered = 0;
    uint64_t payload_fnv1a = 0;
};

struct ConnectionSummary {
    uint64_t completed_streams = 0;
    uint64_t retired_streams = 0;
    uint64_t conn_recv_bytes = 0;
    uint64_t max_peer_bidi = 0;
    uint64_t max_peer_uni = 0;
    uint64_t stop_sending_sent = 0;
    uint64_t drain_timeouts = 0;
    uint64_t blocked_signals = 0;
    uint64_t mux_fnv1a = 0;
};

class Connection {
public:
    explicit Connection(const ConnectionConfig& cfg);
    ~Connection();
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    TransportError process_frame(const WireFrame& frame);
    TransportError finalize(ConnectionSummary* out_summary);

private:
    struct RetiredStreamMeta {
        bool has_final_size = false;
        uint64_t final_size = 0;
    };

    TransportError handle_stream(const WireFrame& frame);
    TransportError handle_reset_stream(const WireFrame& frame);
    TransportError handle_stop_sending(const WireFrame& frame);
    TransportError handle_max_data(const WireFrame& frame);
    TransportError handle_max_streams(const WireFrame& frame);
    TransportError handle_stream_data_blocked(const WireFrame& frame);
    TransportError handle_tick_timer(const WireFrame& frame);
    TransportError handle_conn_close(const WireFrame& frame);

    TransportError resolve_stream(uint64_t stream_id, Stream** out_stream, bool* out_retired);
    void reject_stream_locally(Stream& stream, uint64_t app_error_code);
    void retire_closed_streams();
    static void on_drain_timer_expired(void* owner, uint64_t stream_id, uint64_t fired_at_ms);

    ConnectionConfig cfg_{};
    ConnectionFlowControl conn_flow_;
    TimerWheel timers_{};
    std::unordered_map<uint64_t, std::unique_ptr<Stream>> streams_{};
    std::unordered_map<uint64_t, RetiredStreamMeta> retired_streams_{};
    std::vector<CompletedStreamDigest> completed_digests_{};
    uint64_t next_peer_bidi_ordinal_ = 0;
    uint64_t next_peer_uni_ordinal_ = 0;
    uint64_t now_ms_ = 0;
    uint64_t retired_count_ = 0;
    uint64_t stop_sending_sent_ = 0;
    uint64_t drain_timeouts_ = 0;
    uint64_t blocked_signals_ = 0;
    bool closed_ = false;
};

class WireCodec {
public:
    static TransportError decode_script(std::span<const uint8_t> raw, DecodedScript* out);
};

} // namespace quic_mux
