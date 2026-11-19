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

    if (recv_state_ == RecvState::ResetRecvd || recv_state_ == RecvState::ResetRead ||
        recv_state_ == RecvState::DataRecvd || recv_state_ == RecvState::DataRead) {
        if (flow_.has_final_size()) {
            const uint64_t end_off = offset + data.size();
            if (end_off > flow_.final_size() || (fin && end_off != flow_.final_size())) {
                return TransportError::FinalSizeError;
            }
        }
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
