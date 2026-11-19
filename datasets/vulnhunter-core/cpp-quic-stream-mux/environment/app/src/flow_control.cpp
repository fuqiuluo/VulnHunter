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
    const uint64_t end_offset = offset + length;
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
    if (final_size > kMaxQuicOffset) return TransportError::FinalSizeError;
    if (final_size > stream_win.max_data()) return TransportError::FlowControlError;

    const uint64_t delta = final_size - stream_win.highest_offset();
    if (conn_recv_offset_ + delta > conn_max_data_) {
        return TransportError::FlowControlError;
    }

    conn_recv_offset_ += delta;
    if (final_size > stream_win.highest_offset()) stream_win.set_highest_offset(final_size);
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
