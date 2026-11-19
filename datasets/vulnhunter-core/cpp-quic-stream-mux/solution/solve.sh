#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "include/mux_engine.hpp",
    "src/connection.cpp",
    "src/flow_control.cpp",
    "src/reassembler.cpp",
    "src/stream.cpp"
  ],
  "findings": [
    "Connection::reject_stream_locally prematurely increments peer stream concurrency credit while the stream remains open awaiting reset/drain, and Connection::retire_closed_streams refunds a second credit on RESET_STREAM while erasing Stream without unlinking its active intrusive TimerNode from TimerWheel.",
    "ConnectionFlowControl::on_stream_data, Stream::ingest_segment, and Reassembler::push perform unchecked uint64_t offset + length additions, and ConnectionFlowControl::reconcile_reset / Reassembler::validate_reset_final_size omit RFC 9000 final_size invariants (final_size < highest_offset and conflicting known final_size), causing unsigned delta wraparound that rolls back conn_recv_offset_.",
    "Reassembler::push uses an off-by-one tail index (merged_end - cur_start - 1) when coalescing an incoming segment that bridges across a right-hand buffered interval and fails to subtract erased interval lengths from buffered_bytes_, duplicating seam bytes in the stream digest."
  ],
  "summary": "Fixed local-reject + RESET_STREAM double stream-credit replenishment and unlinked active drain TimerNodes prior to Stream destruction; enforced 62-bit QUIC offset bounds and RFC 9000 final_size monotonicity/immutability across flow control and reassembly; corrected half-open interval tail merging and buffered byte accounting in Reassembler::push."
}
EOF

cat > "$APP_DIR/include/mux_engine.hpp" <<'EOF'
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
    ~Stream() noexcept;
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
    bool try_release_credit() noexcept;

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
    bool credit_released_ = false;
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
EOF

cat > "$APP_DIR/src/flow_control.cpp" <<'EOF'
#include "mux_engine.hpp"

namespace quic_mux {

StreamFlowWindow::StreamFlowWindow(uint64_t initial_max_data) noexcept
    : max_data_(initial_max_data) {}

void StreamFlowWindow::grant_max_data(uint64_t new_limit) noexcept {
    if (new_limit > max_data_ && new_limit <= kMaxQuicOffset) max_data_ = new_limit;
}

void StreamFlowWindow::add_consumed(uint64_t bytes) noexcept {
    consumed_offset_ = (bytes <= kMaxQuicOffset - consumed_offset_)
                           ? (consumed_offset_ + bytes)
                           : kMaxQuicOffset;
}

void StreamFlowWindow::set_final_size(uint64_t final_sz) noexcept {
    size_known_ = true;
    final_size_ = final_sz;
}

void StreamFlowWindow::record_blocked(uint64_t blocked_at) noexcept {
    ++blocked_count_;
    if (blocked_at > last_blocked_offset_) last_blocked_offset_ = blocked_at;
}

uint64_t StreamFlowWindow::available_window() const noexcept {
    return highest_offset_ >= max_data_ ? 0ULL : (max_data_ - highest_offset_);
}

ConnectionFlowControl::ConnectionFlowControl(const ConnectionConfig& cfg) noexcept
    : conn_max_data_(cfg.initial_max_data),
      peer_max_data_(cfg.initial_max_data),
      max_peer_bidi_streams_(cfg.initial_max_streams_bidi),
      max_peer_uni_streams_(cfg.initial_max_streams_uni),
      auto_replenish_((cfg.flags & kFlagAutoStreamCredit) != 0U) {}

TransportError ConnectionFlowControl::on_stream_data(StreamFlowWindow& stream_win,
                                                     uint64_t offset, uint64_t length,
                                                     bool fin) noexcept {
    if (offset > kMaxQuicOffset || length > kMaxQuicOffset - offset) {
        return TransportError::FinalSizeError;
    }

    const uint64_t end_offset = offset + length;
    if (stream_win.has_final_size()) {
        if (end_offset > stream_win.final_size()) {
            return TransportError::FinalSizeError;
        }
        if (fin && end_offset != stream_win.final_size()) {
            return TransportError::FinalSizeError;
        }
    } else if (fin && end_offset < stream_win.highest_offset()) {
        return TransportError::FinalSizeError;
    }

    if (end_offset > stream_win.max_data()) {
        return TransportError::FlowControlError;
    }

    if (end_offset > stream_win.highest_offset()) {
        const uint64_t delta = end_offset - stream_win.highest_offset();
        if (delta > conn_max_data_ || conn_recv_offset_ > conn_max_data_ - delta) {
            return TransportError::FlowControlError;
        }
        conn_recv_offset_ += delta;
        stream_win.set_highest_offset(end_offset);
    }

    if (fin) stream_win.set_final_size(end_offset);
    return TransportError::NoError;
}

TransportError ConnectionFlowControl::reconcile_reset(StreamFlowWindow& stream_win,
                                                      uint64_t final_size) noexcept {
    if (final_size > kMaxQuicOffset) {
        return TransportError::FinalSizeError;
    }
    if (stream_win.has_final_size() && final_size != stream_win.final_size()) {
        return TransportError::FinalSizeError;
    }
    if (final_size < stream_win.highest_offset()) {
        return TransportError::FinalSizeError;
    }
    if (final_size > stream_win.max_data()) {
        return TransportError::FlowControlError;
    }

    const uint64_t delta = final_size - stream_win.highest_offset();
    if (delta > conn_max_data_ || conn_recv_offset_ > conn_max_data_ - delta) {
        return TransportError::FlowControlError;
    }

    conn_recv_offset_ += delta;
    stream_win.set_highest_offset(final_size);
    stream_win.set_final_size(final_size);
    return TransportError::NoError;
}

void ConnectionFlowControl::record_consumed(uint64_t bytes) noexcept {
    conn_consumed_offset_ = (bytes <= kMaxQuicOffset - conn_consumed_offset_)
                                ? (conn_consumed_offset_ + bytes)
                                : kMaxQuicOffset;
}

TransportError ConnectionFlowControl::update_conn_max_data(uint64_t new_limit) noexcept {
    if (new_limit > kMaxQuicOffset) return TransportError::FrameEncodingError;
    if (new_limit > conn_max_data_) conn_max_data_ = new_limit;
    return TransportError::NoError;
}

TransportError ConnectionFlowControl::update_peer_max_data(uint64_t new_limit) noexcept {
    if (new_limit > kMaxQuicOffset) return TransportError::FrameEncodingError;
    if (new_limit > peer_max_data_) peer_max_data_ = new_limit;
    return TransportError::NoError;
}

TransportError ConnectionFlowControl::update_max_streams(bool uni, uint64_t new_limit) noexcept {
    if (new_limit > kMaxStreamsLimit) return TransportError::StreamLimitError;
    uint64_t& target = uni ? max_peer_uni_streams_ : max_peer_bidi_streams_;
    if (new_limit > target) target = new_limit;
    return TransportError::NoError;
}

bool ConnectionFlowControl::can_open_peer_stream(bool uni, uint64_t ordinal) const noexcept {
    return ordinal < (uni ? max_peer_uni_streams_ : max_peer_bidi_streams_);
}

void ConnectionFlowControl::release_peer_stream_credit(bool uni) noexcept {
    if (!auto_replenish_) return;
    uint64_t& target = uni ? max_peer_uni_streams_ : max_peer_bidi_streams_;
    if (target < kMaxStreamsLimit) ++target;
}

} // namespace quic_mux
EOF

cat > "$APP_DIR/src/reassembler.cpp" <<'EOF'
#include "mux_engine.hpp"

#include <algorithm>
#include <iterator>

namespace quic_mux {

TransportError Reassembler::push(uint64_t offset, std::span<const uint8_t> data, bool fin) {
    if (offset > kMaxQuicOffset || data.size() > kMaxQuicOffset - offset) {
        return TransportError::FinalSizeError;
    }

    const uint64_t end_offset = offset + data.size();

    if (size_known_) {
        if (end_offset > final_size_) {
            return TransportError::FinalSizeError;
        }
        if (fin && end_offset != final_size_) {
            return TransportError::FinalSizeError;
        }
    } else if (fin) {
        if (end_offset < highest_offset_) {
            return TransportError::FinalSizeError;
        }
        size_known_ = true;
        final_size_ = end_offset;
    }

    if (end_offset > highest_offset_) {
        highest_offset_ = end_offset;
    }

    if (data.empty() || end_offset <= contiguous_offset_) {
        return TransportError::NoError;
    }

    uint64_t seg_start = offset;
    std::span<const uint8_t> slice = data;
    if (seg_start < contiguous_offset_) {
        const size_t trim = static_cast<size_t>(contiguous_offset_ - seg_start);
        slice = slice.subspan(trim);
        seg_start = contiguous_offset_;
    }

    if (slice.empty()) {
        return TransportError::NoError;
    }
    if (slice.size() > kMaxStreamBufferedBytes) {
        return TransportError::FlowControlError;
    }

    uint64_t merged_start = seg_start;
    std::vector<uint8_t> merged(slice.begin(), slice.end());

    auto it = segments_.lower_bound(seg_start);
    if (it != segments_.begin()) {
        auto prev = std::prev(it);
        const uint64_t prev_end = prev->first + prev->second.size();
        if (prev_end >= seg_start) {
            it = prev;
        }
    }

    while (it != segments_.end() && it->first <= merged_start + merged.size()) {
        const uint64_t cur_start = it->first;
        const uint64_t cur_end = cur_start + it->second.size();
        const uint64_t merged_end = merged_start + merged.size();

        if (cur_start < merged_start) {
            const size_t prefix_len = static_cast<size_t>(merged_start - cur_start);
            std::vector<uint8_t> combined(
                it->second.begin(),
                it->second.begin() + static_cast<std::ptrdiff_t>(prefix_len));
            combined.insert(combined.end(), merged.begin(), merged.end());
            if (cur_end > merged_end) {
                const size_t tail_off = static_cast<size_t>(merged_end - cur_start);
                combined.insert(combined.end(),
                                it->second.begin() + static_cast<std::ptrdiff_t>(tail_off),
                                it->second.end());
            }
            merged_start = cur_start;
            merged = std::move(combined);
        } else if (cur_end > merged_end) {
            const size_t tail_off = static_cast<size_t>(merged_end - cur_start);
            merged.insert(merged.end(),
                          it->second.begin() + static_cast<std::ptrdiff_t>(tail_off),
                          it->second.end());
        }

        if (buffered_bytes_ >= it->second.size()) {
            buffered_bytes_ -= it->second.size();
        } else {
            buffered_bytes_ = 0;
        }
        it = segments_.erase(it);
    }

    if (merged.size() > kMaxStreamBufferedBytes ||
        buffered_bytes_ > kMaxStreamBufferedBytes - merged.size()) {
        return TransportError::FlowControlError;
    }

    buffered_bytes_ += merged.size();
    segments_.emplace(merged_start, std::move(merged));
    return TransportError::NoError;
}

TransportError Reassembler::validate_reset_final_size(uint64_t final_size) {
    if (final_size > kMaxQuicOffset) {
        return TransportError::FinalSizeError;
    }
    if (size_known_ && final_size != final_size_) {
        return TransportError::FinalSizeError;
    }
    if (final_size < highest_offset_) {
        return TransportError::FinalSizeError;
    }
    size_known_ = true;
    final_size_ = final_size;
    discard_unread();
    return TransportError::NoError;
}

size_t Reassembler::drain_contiguous(Fnv1aHasher& out_hasher) {
    size_t total_drained = 0;
    while (!segments_.empty()) {
        auto head = segments_.begin();
        if (head->first > contiguous_offset_) {
            break;
        }

        const uint64_t seg_start = head->first;
        const std::vector<uint8_t>& bytes = head->second;
        const uint64_t seg_end = seg_start + bytes.size();
        if (seg_end > contiguous_offset_) {
            const size_t skip = static_cast<size_t>(contiguous_offset_ - seg_start);
            const std::span<const uint8_t> ready_span(bytes.data() + skip, bytes.size() - skip);
            out_hasher.update(ready_span);
            contiguous_offset_ += ready_span.size();
            total_drained += ready_span.size();
        }

        if (buffered_bytes_ >= bytes.size()) {
            buffered_bytes_ -= bytes.size();
        } else {
            buffered_bytes_ = 0;
        }
        segments_.erase(head);
    }
    return total_drained;
}

void Reassembler::discard_unread() noexcept {
    segments_.clear();
    buffered_bytes_ = 0;
}

} // namespace quic_mux
EOF

cat > "$APP_DIR/src/stream.cpp" <<'EOF'
#include "mux_engine.hpp"

namespace quic_mux {

std::string_view error_name(TransportError err) noexcept {
    switch (err) {
        case TransportError::NoError: return "no_error";
        case TransportError::InternalError: return "internal_error";
        case TransportError::FlowControlError: return "flow_control_error";
        case TransportError::StreamLimitError: return "stream_limit_error";
        case TransportError::StreamStateError: return "stream_state_error";
        case TransportError::FinalSizeError: return "final_size_error";
        case TransportError::FrameEncodingError: return "frame_encoding_error";
    }
    return "internal_error";
}

Stream::Stream(uint64_t stream_id, EndpointRole local_role, uint64_t initial_max_stream_data)
    : stream_id_(stream_id),
      local_role_(local_role),
      recv_state_(local_can_receive(stream_id, local_role) ? RecvState::Recv : RecvState::NotApplicable),
      send_state_(local_can_send(stream_id, local_role) ? SendState::Ready : SendState::NotApplicable),
      flow_(initial_max_stream_data) {}

Stream::~Stream() noexcept {
    if (drain_timer_.active && drain_timer_.prev != nullptr && drain_timer_.next != nullptr) {
        drain_timer_.prev->next = drain_timer_.next;
        drain_timer_.next->prev = drain_timer_.prev;
        drain_timer_.prev = nullptr;
        drain_timer_.next = nullptr;
        drain_timer_.active = false;
    }
}

void Stream::capture_route_prefix(uint64_t offset, std::span<const uint8_t> data) noexcept {
    if (offset >= 4ULL || data.empty() || route_tag_mask_ == 0x0FU) return;
    const size_t start = static_cast<size_t>(offset);
    for (size_t i = 0; i < data.size() && (start + i) < 4U; ++i) {
        const size_t pos = start + i;
        route_tag_bytes_[pos] = data[i];
        route_tag_mask_ = static_cast<uint8_t>(route_tag_mask_ | (1U << pos));
    }
}

uint32_t Stream::route_tag() const noexcept {
    return static_cast<uint32_t>(route_tag_bytes_[0]) |
           (static_cast<uint32_t>(route_tag_bytes_[1]) << 8U) |
           (static_cast<uint32_t>(route_tag_bytes_[2]) << 16U) |
           (static_cast<uint32_t>(route_tag_bytes_[3]) << 24U);
}

TransportError Stream::ingest_segment(uint64_t offset, std::span<const uint8_t> data,
                                      bool fin, ConnectionFlowControl& conn_flow) {
    if (recv_state_ == RecvState::NotApplicable) {
        return TransportError::StreamStateError;
    }
    if (offset > kMaxQuicOffset || data.size() > kMaxQuicOffset - offset) {
        return TransportError::FinalSizeError;
    }

    if (recv_state_ == RecvState::ResetRecvd || recv_state_ == RecvState::ResetRead ||
        recv_state_ == RecvState::DataRecvd || recv_state_ == RecvState::DataRead) {
        return conn_flow.on_stream_data(flow_, offset, data.size(), fin);
    }

    const TransportError fc_err = conn_flow.on_stream_data(flow_, offset, data.size(), fin);
    if (fc_err != TransportError::NoError) return fc_err;

    capture_route_prefix(offset, data);

    const TransportError ra_err = reassembler_.push(offset, data, fin);
    if (ra_err != TransportError::NoError) return ra_err;

    if (fin && recv_state_ == RecvState::Recv) {
        recv_state_ = RecvState::SizeKnown;
    }
    return TransportError::NoError;
}

void Stream::deliver_ready_bytes(ConnectionFlowControl& conn_flow) {
    if (local_rejected_) {
        reassembler_.discard_unread();
        return;
    }
    if (recv_state_ != RecvState::Recv && recv_state_ != RecvState::SizeKnown) {
        return;
    }

    const size_t drained = reassembler_.drain_contiguous(payload_hasher_);
    if (drained > 0U) {
        bytes_delivered_ += drained;
        flow_.add_consumed(drained);
        conn_flow.record_consumed(drained);
    }

    if (reassembler_.is_complete()) {
        recv_state_ = RecvState::DataRead;
        if (send_state_ == SendState::Ready || send_state_ == SendState::Send) {
            send_state_ = SendState::DataRecvd;
        }
    }
}

TransportError Stream::on_peer_reset(uint64_t app_error_code, uint64_t final_size,
                                     ConnectionFlowControl& conn_flow) {
    if (recv_state_ == RecvState::NotApplicable) {
        return TransportError::StreamStateError;
    }

    const TransportError fc_err = conn_flow.reconcile_reset(flow_, final_size);
    if (fc_err != TransportError::NoError) return fc_err;

    const TransportError ra_err = reassembler_.validate_reset_final_size(final_size);
    if (ra_err != TransportError::NoError) return ra_err;

    app_error_code_ = app_error_code;
    if (recv_state_ != RecvState::DataRead) {
        recv_state_ = RecvState::ResetRead;
    }
    if (send_state_ == SendState::Ready || send_state_ == SendState::Send) {
        send_state_ = SendState::ResetRecvd;
    }
    return TransportError::NoError;
}

TransportError Stream::on_peer_stop_sending(uint64_t app_error_code) noexcept {
    if (send_state_ == SendState::NotApplicable) {
        return TransportError::StreamStateError;
    }
    app_error_code_ = app_error_code;
    if (send_state_ != SendState::DataRecvd && send_state_ != SendState::ResetRecvd) {
        send_state_ = SendState::ResetRecvd;
    }
    return TransportError::NoError;
}

void Stream::mark_local_reject(uint64_t app_error_code) noexcept {
    local_rejected_ = true;
    app_error_code_ = app_error_code;
    reassembler_.discard_unread();
    if (send_state_ != SendState::NotApplicable && send_state_ != SendState::DataRecvd) {
        send_state_ = SendState::ResetRecvd;
    }
}

void Stream::on_drain_timeout() noexcept {
    reassembler_.discard_unread();
    if (recv_state_ != RecvState::NotApplicable && recv_state_ != RecvState::DataRead) {
        recv_state_ = RecvState::ResetRead;
    }
    if (send_state_ != SendState::NotApplicable && send_state_ != SendState::DataRecvd) {
        send_state_ = SendState::ResetRecvd;
    }
}

bool Stream::try_release_credit() noexcept {
    if (credit_released_) return false;
    credit_released_ = true;
    return true;
}

bool Stream::is_closed() const noexcept {
    const bool recv_done = (recv_state_ == RecvState::DataRead ||
                            recv_state_ == RecvState::ResetRead ||
                            recv_state_ == RecvState::NotApplicable);
    const bool send_done = (send_state_ == SendState::DataRecvd ||
                            send_state_ == SendState::ResetRecvd ||
                            send_state_ == SendState::NotApplicable);
    return recv_done && send_done;
}

bool Stream::is_cleanly_completed() const noexcept {
    return !local_rejected_ && recv_state_ == RecvState::DataRead;
}

} // namespace quic_mux
EOF

cat > "$APP_DIR/src/connection.cpp" <<'EOF'
#include "mux_engine.hpp"

#include <algorithm>

namespace quic_mux {

Connection::Connection(const ConnectionConfig& cfg) : cfg_(cfg), conn_flow_(cfg) {}

Connection::~Connection() {
    timers_.cancel_all();
    streams_.clear();
}

TransportError Connection::resolve_stream(uint64_t stream_id, Stream** out_stream, bool* out_retired) {
    *out_stream = nullptr;
    *out_retired = false;

    if (!is_peer_initiated(stream_id, cfg_.local_role)) {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) return TransportError::StreamStateError;
        *out_stream = it->second.get();
        return TransportError::NoError;
    }

    const bool uni = is_unidirectional(stream_id);
    const uint64_t ord = stream_ordinal(stream_id);
    if (!conn_flow_.can_open_peer_stream(uni, ord)) {
        return TransportError::StreamLimitError;
    }

    uint64_t& next_ord = uni ? next_peer_uni_ordinal_ : next_peer_bidi_ordinal_;
    if (ord >= next_ord) {
        if (ord - next_ord >= kMaxImplicitStreamOpen) return TransportError::StreamLimitError;
        const uint64_t type_bits = stream_id & 0x3ULL;
        const uint64_t init_window = uni ? cfg_.initial_max_stream_data_uni
                                         : cfg_.initial_max_stream_data_bidi;
        for (uint64_t k = next_ord; k <= ord; ++k) {
            const uint64_t sid = (k << 2U) | type_bits;
            streams_.emplace(sid, std::make_unique<Stream>(sid, cfg_.local_role, init_window));
        }
        next_ord = ord + 1ULL;
    }

    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        *out_retired = true;
        return TransportError::NoError;
    }
    *out_stream = it->second.get();
    return TransportError::NoError;
}

void Connection::reject_stream_locally(Stream& stream, uint64_t app_error_code) {
    if (stream.is_locally_rejected() || stream.is_closed()) return;

    stream.mark_local_reject(app_error_code);
    ++stop_sending_sent_;

    timers_.schedule(&stream.drain_timer(), now_ms_ + cfg_.drain_timeout_ms,
                     stream.stream_id(), &Connection::on_drain_timer_expired, this);
}

void Connection::on_drain_timer_expired(void* owner, uint64_t stream_id, uint64_t /*fired_at_ms*/) {
    auto* self = static_cast<Connection*>(owner);
    auto it = self->streams_.find(stream_id);
    if (it == self->streams_.end()) return;

    ++self->drain_timeouts_;
    it->second->on_drain_timeout();
    self->retire_closed_streams();
}

void Connection::retire_closed_streams() {
    for (auto it = streams_.begin(); it != streams_.end();) {
        Stream& s = *it->second;
        if (!s.is_closed()) {
            ++it;
            continue;
        }
        timers_.cancel(&s.drain_timer());
        if (s.is_cleanly_completed()) {
            completed_digests_.push_back({s.stream_id(), s.bytes_delivered(), s.payload_digest()});
        }
        if (is_peer_initiated(s.stream_id(), cfg_.local_role) && s.try_release_credit()) {
            conn_flow_.release_peer_stream_credit(is_unidirectional(s.stream_id()));
        }
        retired_streams_[s.stream_id()] = {s.flow().has_final_size(), s.flow().final_size()};
        ++retired_count_;
        it = streams_.erase(it);
    }
}

TransportError Connection::handle_stream(const WireFrame& frame) {
    if (!local_can_receive(frame.stream_id, cfg_.local_role)) {
        return TransportError::StreamStateError;
    }

    Stream* stream = nullptr;
    bool retired = false;
    const TransportError res_err = resolve_stream(frame.stream_id, &stream, &retired);
    if (res_err != TransportError::NoError) return res_err;

    const bool fin = (frame.flags & kStreamFlagFin) != 0U;
    if (retired) {
        if (frame.offset > kMaxQuicOffset || frame.data.size() > kMaxQuicOffset - frame.offset) {
            return TransportError::FinalSizeError;
        }
        const uint64_t end_off = frame.offset + frame.data.size();
        auto meta_it = retired_streams_.find(frame.stream_id);
        if (meta_it != retired_streams_.end() && meta_it->second.has_final_size) {
            if (end_off > meta_it->second.final_size ||
                (fin && end_off != meta_it->second.final_size)) {
                return TransportError::FinalSizeError;
            }
        }
        return TransportError::NoError;
    }

    const TransportError ing_err = stream->ingest_segment(frame.offset, frame.data, fin, conn_flow_);
    if (ing_err != TransportError::NoError) return ing_err;

    if ((cfg_.flags & kFlagEnforceAppPolicy) != 0U && cfg_.denied_route_tag != 0U &&
        is_peer_initiated(stream->stream_id(), cfg_.local_role) &&
        !stream->is_locally_rejected() && stream->has_route_tag() &&
        stream->route_tag() == cfg_.denied_route_tag) {
        reject_stream_locally(*stream, kPolicyRejectedAppCode);
    }

    stream->deliver_ready_bytes(conn_flow_);
    retire_closed_streams();
    return TransportError::NoError;
}

TransportError Connection::handle_reset_stream(const WireFrame& frame) {
    if (!local_can_receive(frame.stream_id, cfg_.local_role)) {
        return TransportError::StreamStateError;
    }

    Stream* stream = nullptr;
    bool retired = false;
    const TransportError res_err = resolve_stream(frame.stream_id, &stream, &retired);
    if (res_err != TransportError::NoError) return res_err;

    if (retired) {
        if (frame.final_size > kMaxQuicOffset) return TransportError::FinalSizeError;
        auto meta_it = retired_streams_.find(frame.stream_id);
        if (meta_it != retired_streams_.end() && meta_it->second.has_final_size &&
            frame.final_size != meta_it->second.final_size) {
            return TransportError::FinalSizeError;
        }
        return TransportError::NoError;
    }

    const TransportError rst_err = stream->on_peer_reset(frame.error_code, frame.final_size, conn_flow_);
    if (rst_err != TransportError::NoError) return rst_err;

    timers_.cancel(&stream->drain_timer());
    retire_closed_streams();
    return TransportError::NoError;
}

TransportError Connection::handle_stop_sending(const WireFrame& frame) {
    const bool local_action = (frame.flags & kStopSendingFlagLocal) != 0U;
    const bool ok_dir = local_action ? local_can_receive(frame.stream_id, cfg_.local_role)
                                     : local_can_send(frame.stream_id, cfg_.local_role);
    if (!ok_dir) return TransportError::StreamStateError;

    Stream* stream = nullptr;
    bool retired = false;
    const TransportError res_err = resolve_stream(frame.stream_id, &stream, &retired);
    if (res_err != TransportError::NoError) return res_err;
    if (retired) return TransportError::NoError;

    if (local_action) {
        reject_stream_locally(*stream, frame.error_code);
    } else {
        const TransportError st_err = stream->on_peer_stop_sending(frame.error_code);
        if (st_err != TransportError::NoError) return st_err;
    }
    retire_closed_streams();
    return TransportError::NoError;
}

TransportError Connection::handle_max_data(const WireFrame& frame) {
    return (frame.flags & kMaxDataFlagPeer) != 0U
               ? conn_flow_.update_peer_max_data(frame.limit_value)
               : conn_flow_.update_conn_max_data(frame.limit_value);
}

TransportError Connection::handle_max_streams(const WireFrame& frame) {
    return conn_flow_.update_max_streams((frame.flags & kMaxStreamsFlagUni) != 0U, frame.limit_value);
}

TransportError Connection::handle_stream_data_blocked(const WireFrame& frame) {
    if (!local_can_receive(frame.stream_id, cfg_.local_role)) return TransportError::StreamStateError;
    if (frame.limit_value > kMaxQuicOffset) return TransportError::FrameEncodingError;

    Stream* stream = nullptr;
    bool retired = false;
    const TransportError res_err = resolve_stream(frame.stream_id, &stream, &retired);
    if (res_err != TransportError::NoError) return res_err;

    ++blocked_signals_;
    if (!retired) {
        stream->flow().record_blocked(frame.limit_value);
        if ((frame.flags & kBlockedFlagAutoGrant) != 0U) stream->flow().grant_max_data(frame.limit_value);
    }
    return TransportError::NoError;
}

TransportError Connection::handle_tick_timer(const WireFrame& frame) {
    if (frame.delta_ms > kMaxTickDeltaMs || frame.delta_ms > kMaxQuicOffset - now_ms_) {
        return TransportError::FrameEncodingError;
    }
    now_ms_ += frame.delta_ms;
    timers_.advance(now_ms_);
    return TransportError::NoError;
}

TransportError Connection::handle_conn_close(const WireFrame& /*frame*/) {
    timers_.cancel_all();
    streams_.clear();
    closed_ = true;
    return TransportError::NoError;
}

TransportError Connection::process_frame(const WireFrame& frame) {
    if (closed_) return TransportError::StreamStateError;
    switch (frame.type) {
        case FrameType::Stream: return handle_stream(frame);
        case FrameType::ResetStream: return handle_reset_stream(frame);
        case FrameType::StopSending: return handle_stop_sending(frame);
        case FrameType::MaxData: return handle_max_data(frame);
        case FrameType::MaxStreams: return handle_max_streams(frame);
        case FrameType::StreamDataBlocked: return handle_stream_data_blocked(frame);
        case FrameType::TickTimer: return handle_tick_timer(frame);
        case FrameType::ConnClose: return handle_conn_close(frame);
    }
    return TransportError::FrameEncodingError;
}

TransportError Connection::finalize(ConnectionSummary* out_summary) {
    if (out_summary == nullptr) return TransportError::InternalError;
    timers_.cancel_all();

    std::sort(completed_digests_.begin(), completed_digests_.end(),
              [](const CompletedStreamDigest& a, const CompletedStreamDigest& b) {
                  return a.stream_id < b.stream_id;
              });

    Fnv1aHasher mux_hasher;
    for (const CompletedStreamDigest& item : completed_digests_) {
        mux_hasher.update_u64_le(item.stream_id);
        mux_hasher.update_u64_le(item.bytes_delivered);
        mux_hasher.update_u64_le(item.payload_fnv1a);
    }

    *out_summary = ConnectionSummary{
        completed_digests_.size(),
        retired_count_,
        conn_flow_.conn_recv_offset(),
        conn_flow_.max_peer_bidi_streams(),
        conn_flow_.max_peer_uni_streams(),
        stop_sending_sent_,
        drain_timeouts_,
        blocked_signals_,
        mux_hasher.digest(),
    };
    return TransportError::NoError;
}

} // namespace quic_mux
EOF

make -C "$APP_DIR" clean all
