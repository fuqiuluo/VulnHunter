#include "mux_engine.hpp"

#include <algorithm>

namespace quic_mux {

Connection::Connection(const ConnectionConfig& cfg) : cfg_(cfg), conn_flow_(cfg) {}
Connection::~Connection() = default;

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

    if (is_peer_initiated(stream.stream_id(), cfg_.local_role)) {
        conn_flow_.release_peer_stream_credit(is_unidirectional(stream.stream_id()));
    }

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
        if (s.is_cleanly_completed()) {
            completed_digests_.push_back({s.stream_id(), s.bytes_delivered(), s.payload_digest()});
        }
        if (is_peer_initiated(s.stream_id(), cfg_.local_role)) {
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
