#include "h2_framer.hpp"

#include <cstring>

namespace h2 {
namespace {

uint32_t read_be24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | static_cast<uint32_t>(p[2]);
}

uint32_t read_be31(const uint8_t* p) {
    return ((static_cast<uint32_t>(p[0]) & 0x7fu) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint16_t read_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}

uint32_t read_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

}  // namespace

H2ServerConnection::H2ServerConnection(RequestCallback on_request) : on_request_(std::move(on_request)) {}

void H2ServerConnection::set_local_header_table_limit(size_t max_bytes) {
    hpack_.table().set_protocol_max_size(max_bytes);
}

const StreamContext* H2ServerConnection::find_stream(uint32_t stream_id) const {
    auto it = streams_.find(stream_id);
    return (it == streams_.end()) ? nullptr : &it->second;
}

std::vector<uint8_t> H2ServerConnection::serialize_frame(
    FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out(9 + payload.size());
    uint32_t len = static_cast<uint32_t>(payload.size());
    out[0] = static_cast<uint8_t>((len >> 16) & 0xffu);
    out[1] = static_cast<uint8_t>((len >> 8) & 0xffu);
    out[2] = static_cast<uint8_t>(len & 0xffu);
    out[3] = static_cast<uint8_t>(type);
    out[4] = flags;
    uint32_t sid = stream_id & 0x7fffffffu;
    out[5] = static_cast<uint8_t>((sid >> 24) & 0xffu);
    out[6] = static_cast<uint8_t>((sid >> 16) & 0xffu);
    out[7] = static_cast<uint8_t>((sid >> 8) & 0xffu);
    out[8] = static_cast<uint8_t>(sid & 0xffu);
    if (!payload.empty()) {
        std::memcpy(out.data() + 9, payload.data(), payload.size());
    }
    return out;
}

ErrorCode H2ServerConnection::fail_connection(ErrorCode err) {
    connection_error_ = err;
    return err;
}

ErrorCode H2ServerConnection::receive_bytes(const uint8_t* data, size_t len) {
    if (connection_error_ != ErrorCode::NO_ERROR) {
        return connection_error_;
    }
    if (len > 0) {
        recv_buf_.insert(recv_buf_.end(), data, data + len);
    }

    size_t consumed = 0;
    if (!preface_received_) {
        if (recv_buf_.size() < kClientConnectionPreface.size()) {
            // Check prefix so invalid prefaces fail fast
            if (std::memcmp(recv_buf_.data(), kClientConnectionPreface.data(), recv_buf_.size()) != 0) {
                return fail_connection(ErrorCode::PROTOCOL_ERROR);
            }
            return ErrorCode::NO_ERROR;
        }
        if (std::memcmp(recv_buf_.data(), kClientConnectionPreface.data(), kClientConnectionPreface.size()) != 0) {
            return fail_connection(ErrorCode::PROTOCOL_ERROR);
        }
        preface_received_ = true;
        consumed += kClientConnectionPreface.size();
    }

    while (recv_buf_.size() - consumed >= 9) {
        const uint8_t* hdr = recv_buf_.data() + consumed;
        uint32_t frame_len = read_be24(hdr);
        if (frame_len > peer_max_frame_size_) {
            return fail_connection(ErrorCode::FRAME_SIZE_ERROR);
        }
        if (recv_buf_.size() - consumed < 9u + frame_len) {
            break;
        }

        uint8_t raw_type = hdr[3];
        uint8_t flags = hdr[4];
        uint32_t stream_id = read_be31(hdr + 5);
        const uint8_t* payload = hdr + 9;
        consumed += 9u + frame_len;

        // Unknown frame types (> 0x9) are ignored UNLESS a header block is open!
        if (raw_type > static_cast<uint8_t>(FrameType::CONTINUATION)) {
            if (continuation_stream_id_ != 0) {
                return fail_connection(ErrorCode::PROTOCOL_ERROR);
            }
            continue;
        }

        ErrorCode rc = process_frame(static_cast<FrameType>(raw_type), flags, stream_id, payload, frame_len);
        if (rc != ErrorCode::NO_ERROR) {
            return fail_connection(rc);
        }
    }

    if (consumed > 0) {
        recv_buf_.erase(recv_buf_.begin(), recv_buf_.begin() + static_cast<std::ptrdiff_t>(consumed));
    }
    return ErrorCode::NO_ERROR;
}

ErrorCode H2ServerConnection::process_frame(
    FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    const uint8_t* payload,
    size_t len) {
    // Flawed: handles PING, SETTINGS, and WINDOW_UPDATE BEFORE checking `continuation_stream_id_ != 0`!
    if (type == FrameType::PING) {
        if (stream_id != 0) return ErrorCode::PROTOCOL_ERROR;
        if (len != 8) return ErrorCode::FRAME_SIZE_ERROR;
        if ((flags & FrameFlags::ACK) == 0) {
            ping_acks_sent_ += 1;
        }
        return ErrorCode::NO_ERROR;
    }

    if (type == FrameType::SETTINGS) {
        if (stream_id != 0) return ErrorCode::PROTOCOL_ERROR;
        if ((flags & FrameFlags::ACK) != 0) {
            return (len == 0) ? ErrorCode::NO_ERROR : ErrorCode::FRAME_SIZE_ERROR;
        }
        if (len % 6 != 0) return ErrorCode::FRAME_SIZE_ERROR;

        for (size_t i = 0; i < len; i += 6) {
            uint16_t id = read_be16(payload + i);
            uint32_t val = read_be32(payload + i + 2);
            switch (id) {
                case SettingsId::ENABLE_PUSH:
                    if (val > 1) return ErrorCode::PROTOCOL_ERROR;
                    break;
                case SettingsId::MAX_CONCURRENT_STREAMS:
                    max_concurrent_streams_ = val;
                    break;
                case SettingsId::INITIAL_WINDOW_SIZE: {
                    if (val > 0x7fffffffU) {
                        return ErrorCode::FLOW_CONTROL_ERROR;
                    }
                    // Flawed: computes delta & updates `s.send_window` in signed 32-bit `int32_t`
                    // (triggers UBSan signed integer overflow when existing stream window + delta > 0x7fffffff)!
                    int32_t delta = static_cast<int32_t>(val) - static_cast<int32_t>(peer_initial_window_size_);
                    peer_initial_window_size_ = val;
                    for (auto& [sid, st] : streams_) {
                        if (st.state == StreamState::OPEN || st.state == StreamState::HALF_CLOSED_REMOTE) {
                            st.send_window += delta;
                        }
                    }
                    break;
                }
                case SettingsId::MAX_FRAME_SIZE:
                    if (val < 16384u || val > 16777215u) {
                        return ErrorCode::PROTOCOL_ERROR;
                    }
                    peer_max_frame_size_ = val;
                    break;
                default:
                    break;
            }
        }
        settings_acks_sent_ += 1;
        return ErrorCode::NO_ERROR;
    }

    if (type == FrameType::WINDOW_UPDATE) {
        if (len != 4) return ErrorCode::FRAME_SIZE_ERROR;
        uint32_t inc = read_be31(payload);
        if (inc == 0) return ErrorCode::PROTOCOL_ERROR;

        if (stream_id == 0) {
            if (conn_recv_window_ + static_cast<int64_t>(inc) > kMaxFlowControlWindow) {
                return ErrorCode::FLOW_CONTROL_ERROR;
            }
            conn_recv_window_ += static_cast<int64_t>(inc);
            return ErrorCode::NO_ERROR;
        }
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        int64_t updated = static_cast<int64_t>(it->second.send_window) + static_cast<int64_t>(inc);
        if (updated > kMaxFlowControlWindow) {
            return ErrorCode::FLOW_CONTROL_ERROR;
        }
        it->second.send_window = static_cast<int32_t>(updated);
        return ErrorCode::NO_ERROR;
    }

    // Continuation lock check (placed too late — missed PING/SETTINGS/WINDOW_UPDATE above!)
    if (continuation_stream_id_ != 0) {
        if (type != FrameType::CONTINUATION || stream_id != continuation_stream_id_) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        header_block_buf_.insert(header_block_buf_.end(), payload, payload + len);
        if (header_block_buf_.size() > 131072u) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        if ((flags & FrameFlags::END_HEADERS) != 0) {
            uint32_t sid = continuation_stream_id_;
            bool es = continuation_end_stream_;
            bool tr = continuation_is_trailer_;
            continuation_stream_id_ = 0;
            return finish_header_block(sid, es, tr);
        }
        return ErrorCode::NO_ERROR;
    }

    if (type == FrameType::CONTINUATION) {
        return ErrorCode::PROTOCOL_ERROR;
    }

    if (type == FrameType::GOAWAY) {
        return (stream_id == 0 && len >= 8) ? ErrorCode::NO_ERROR : ErrorCode::PROTOCOL_ERROR;
    }

    if (type == FrameType::PRIORITY) {
        if (stream_id == 0) return ErrorCode::PROTOCOL_ERROR;
        return (len == 5) ? ErrorCode::NO_ERROR : ErrorCode::FRAME_SIZE_ERROR;
    }

    if (type == FrameType::RST_STREAM) {
        if (stream_id == 0) return ErrorCode::PROTOCOL_ERROR;
        if (len != 4) return ErrorCode::FRAME_SIZE_ERROR;
        auto it = streams_.find(stream_id);
        if (it == streams_.end() || it->second.state == StreamState::IDLE) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        it->second.state = StreamState::CLOSED;
        return ErrorCode::NO_ERROR;
    }

    if (type == FrameType::PUSH_PROMISE) {
        // Clients cannot send PUSH_PROMISE to servers (RFC 9113 §8.4)
        return ErrorCode::PROTOCOL_ERROR;
    }

    if (type == FrameType::HEADERS) {
        if (stream_id == 0 || (stream_id % 2) == 0) {
            return ErrorCode::PROTOCOL_ERROR;
        }

        size_t pos = 0;
        uint8_t pad_len = 0;
        if ((flags & FrameFlags::PADDED) != 0) {
            if (len < 1) return ErrorCode::PROTOCOL_ERROR;
            pad_len = payload[pos++];
        }
        if ((flags & FrameFlags::PRIORITY) != 0) {
            if (len - pos < 5) return ErrorCode::FRAME_SIZE_ERROR;
            uint32_t dep_stream = read_be31(payload + pos);
            if (dep_stream == stream_id) return ErrorCode::PROTOCOL_ERROR;
            pos += 5;
        }
        if (pad_len > len - pos) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        size_t frag_len = (len - pos) - pad_len;

        bool is_trailer = false;
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            if (stream_id <= highest_client_stream_id_) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            highest_client_stream_id_ = stream_id;
            StreamContext st;
            st.stream_id = stream_id;
            st.state = StreamState::OPEN;
            st.send_window = static_cast<int32_t>(peer_initial_window_size_);
            st.request.stream_id = stream_id;
            streams_.emplace(stream_id, std::move(st));
        } else {
            if (it->second.state != StreamState::OPEN || !it->second.initial_headers_done) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            // RFC 9113 §8.1: Trailing HEADERS must carry END_STREAM
            if ((flags & FrameFlags::END_STREAM) == 0) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            is_trailer = true;
        }

        header_block_buf_.assign(payload + pos, payload + pos + frag_len);
        bool end_stream = (flags & FrameFlags::END_STREAM) != 0;
        if ((flags & FrameFlags::END_HEADERS) != 0) {
            return finish_header_block(stream_id, end_stream, is_trailer);
        }

        continuation_stream_id_ = stream_id;
        continuation_end_stream_ = end_stream;
        continuation_is_trailer_ = is_trailer;
        return ErrorCode::NO_ERROR;
    }

    if (type == FrameType::DATA) {
        if (stream_id == 0) return ErrorCode::PROTOCOL_ERROR;
        auto it = streams_.find(stream_id);
        if (it == streams_.end() || it->second.state != StreamState::OPEN || !it->second.initial_headers_done) {
            return ErrorCode::STREAM_CLOSED;
        }

        size_t pos = 0;
        uint8_t pad_len = 0;
        if ((flags & FrameFlags::PADDED) != 0) {
            if (len < 1) return ErrorCode::PROTOCOL_ERROR;
            pad_len = payload[pos++];
            if (pad_len > len - pos) return ErrorCode::PROTOCOL_ERROR;
        }
        size_t data_len = (len - pos) - pad_len;

        // Flow-control accounting covers the entire DATA frame payload (including pad bytes)
        if (static_cast<int64_t>(len) > conn_recv_window_ || static_cast<int64_t>(len) > it->second.recv_window) {
            return ErrorCode::FLOW_CONTROL_ERROR;
        }
        conn_recv_window_ -= static_cast<int64_t>(len);
        it->second.recv_window -= static_cast<int32_t>(len);

        it->second.received_data_bytes += data_len;
        it->second.request.body.append(reinterpret_cast<const char*>(payload + pos), data_len);

        if ((flags & FrameFlags::END_STREAM) != 0) {
            // Flawed: forgets to verify `received_data_bytes == *request.content_length`!
            it->second.state = StreamState::HALF_CLOSED_REMOTE;
            completed_requests_.push_back(it->second.request);
            if (on_request_) {
                on_request_(completed_requests_.back());
            }
        }
        return ErrorCode::NO_ERROR;
    }

    return ErrorCode::PROTOCOL_ERROR;
}

ErrorCode H2ServerConnection::finish_header_block(uint32_t stream_id, bool end_stream, bool is_trailer) {
    std::vector<HeaderField> decoded;
    ErrorCode dec_rc = hpack_.decode_block(header_block_buf_.data(), header_block_buf_.size(), decoded);
    header_block_buf_.clear();
    if (dec_rc != ErrorCode::NO_ERROR) {
        return dec_rc;
    }

    auto& st = streams_.at(stream_id);
    if (!is_trailer) {
        ErrorCode vrc = validate_request_headers(decoded, st.request);
        if (vrc != ErrorCode::NO_ERROR) {
            return vrc;
        }
        st.initial_headers_done = true;
    } else {
        ErrorCode vrc = validate_trailer_headers(decoded, st.request);
        if (vrc != ErrorCode::NO_ERROR) {
            return vrc;
        }
    }

    if (end_stream) {
        // Flawed: forgets to verify `received_data_bytes == *st.request.content_length` on END_STREAM!
        st.state = StreamState::HALF_CLOSED_REMOTE;
        completed_requests_.push_back(st.request);
        if (on_request_) {
            on_request_(completed_requests_.back());
        }
    }
    return ErrorCode::NO_ERROR;
}

}  // namespace h2
