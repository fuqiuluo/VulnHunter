#include "mux_engine.hpp"

namespace quic_mux {

namespace {

class ByteReader {
public:
    explicit ByteReader(std::span<const uint8_t> buf) noexcept : buf_(buf) {}
    size_t remaining() const noexcept { return buf_.size() - pos_; }

    bool read_u8(uint8_t* out) noexcept {
        if (remaining() < 1U) return false;
        *out = buf_[pos_++];
        return true;
    }

    bool read_u16_le(uint16_t* out) noexcept {
        if (remaining() < 2U) return false;
        *out = static_cast<uint16_t>(buf_[pos_]) |
               static_cast<uint16_t>(static_cast<uint16_t>(buf_[pos_ + 1U]) << 8U);
        pos_ += 2U;
        return true;
    }

    bool read_u32_le(uint32_t* out) noexcept {
        if (remaining() < 4U) return false;
        uint32_t v = 0;
        for (size_t i = 0; i < 4U; ++i) v |= static_cast<uint32_t>(buf_[pos_ + i]) << (i * 8U);
        pos_ += 4U;
        *out = v;
        return true;
    }

    bool read_u64_le(uint64_t* out) noexcept {
        if (remaining() < 8U) return false;
        uint64_t v = 0;
        for (size_t i = 0; i < 8U; ++i) v |= static_cast<uint64_t>(buf_[pos_ + i]) << (i * 8U);
        pos_ += 8U;
        *out = v;
        return true;
    }

    bool read_bytes(size_t count, std::vector<uint8_t>* out) {
        if (remaining() < count) return false;
        out->assign(buf_.begin() + static_cast<std::ptrdiff_t>(pos_),
                    buf_.begin() + static_cast<std::ptrdiff_t>(pos_ + count));
        pos_ += count;
        return true;
    }

private:
    std::span<const uint8_t> buf_;
    size_t pos_ = 0;
};

} // namespace

TransportError WireCodec::decode_script(std::span<const uint8_t> raw, DecodedScript* out) {
    if (out == nullptr) return TransportError::InternalError;
    out->frames.clear();

    ByteReader reader(raw);
    uint32_t magic = 0;
    uint16_t version = 0;
    uint8_t role_raw = 0;
    uint8_t flags = 0;
    ConnectionConfig cfg{};
    uint32_t frame_count = 0;

    if (!reader.read_u32_le(&magic) || !reader.read_u16_le(&version) ||
        !reader.read_u8(&role_raw) || !reader.read_u8(&flags) ||
        !reader.read_u64_le(&cfg.initial_max_data) ||
        !reader.read_u64_le(&cfg.initial_max_stream_data_bidi) ||
        !reader.read_u64_le(&cfg.initial_max_stream_data_uni) ||
        !reader.read_u32_le(&cfg.initial_max_streams_bidi) ||
        !reader.read_u32_le(&cfg.initial_max_streams_uni) ||
        !reader.read_u32_le(&cfg.drain_timeout_ms) ||
        !reader.read_u32_le(&cfg.denied_route_tag) ||
        !reader.read_u32_le(&frame_count)) {
        return TransportError::FrameEncodingError;
    }

    if (magic != kWireMagic || version != kWireVersion || role_raw > 1U ||
        (flags & ~kValidSessionFlagsMask) != 0U ||
        cfg.initial_max_data > kMaxQuicOffset ||
        cfg.initial_max_stream_data_bidi > kMaxQuicOffset ||
        cfg.initial_max_stream_data_uni > kMaxQuicOffset ||
        cfg.initial_max_streams_bidi > kMaxStreamsLimit ||
        cfg.initial_max_streams_uni > kMaxStreamsLimit ||
        cfg.drain_timeout_ms == 0U || cfg.drain_timeout_ms > kMaxDrainTimeoutMs ||
        frame_count > kMaxScriptFrames) {
        return TransportError::FrameEncodingError;
    }

    cfg.local_role = (role_raw == 0U) ? EndpointRole::Client : EndpointRole::Server;
    cfg.flags = flags;
    out->config = cfg;
    out->frames.reserve(frame_count);

    for (uint32_t idx = 0; idx < frame_count; ++idx) {
        uint8_t raw_type = 0;
        uint8_t frame_flags = 0;
        if (!reader.read_u8(&raw_type) || !reader.read_u8(&frame_flags)) {
            return TransportError::FrameEncodingError;
        }

        WireFrame frame{};
        frame.flags = frame_flags;

        switch (raw_type) {
            case static_cast<uint8_t>(FrameType::Stream): {
                uint32_t data_len = 0;
                if ((frame_flags & ~kStreamFlagFin) != 0U ||
                    !reader.read_u64_le(&frame.stream_id) ||
                    !reader.read_u64_le(&frame.offset) ||
                    !reader.read_u32_le(&data_len) ||
                    data_len > kMaxFramePayload ||
                    !reader.read_bytes(data_len, &frame.data)) {
                    return TransportError::FrameEncodingError;
                }
                frame.type = FrameType::Stream;
                break;
            }
            case static_cast<uint8_t>(FrameType::ResetStream): {
                if (frame_flags != 0U ||
                    !reader.read_u64_le(&frame.stream_id) ||
                    !reader.read_u64_le(&frame.error_code) ||
                    !reader.read_u64_le(&frame.final_size)) {
                    return TransportError::FrameEncodingError;
                }
                frame.type = FrameType::ResetStream;
                break;
            }
            case static_cast<uint8_t>(FrameType::StopSending): {
                if ((frame_flags & ~kStopSendingFlagLocal) != 0U ||
                    !reader.read_u64_le(&frame.stream_id) ||
                    !reader.read_u64_le(&frame.error_code)) {
                    return TransportError::FrameEncodingError;
                }
                frame.type = FrameType::StopSending;
                break;
            }
            case static_cast<uint8_t>(FrameType::MaxData): {
                if ((frame_flags & ~kMaxDataFlagPeer) != 0U ||
                    !reader.read_u64_le(&frame.limit_value)) {
                    return TransportError::FrameEncodingError;
                }
                frame.type = FrameType::MaxData;
                break;
            }
            case static_cast<uint8_t>(FrameType::MaxStreams): {
                if ((frame_flags & ~kMaxStreamsFlagUni) != 0U ||
                    !reader.read_u64_le(&frame.limit_value)) {
                    return TransportError::FrameEncodingError;
                }
                frame.type = FrameType::MaxStreams;
                break;
            }
            case static_cast<uint8_t>(FrameType::StreamDataBlocked): {
                if ((frame_flags & ~kBlockedFlagAutoGrant) != 0U ||
                    !reader.read_u64_le(&frame.stream_id) ||
                    !reader.read_u64_le(&frame.limit_value)) {
                    return TransportError::FrameEncodingError;
                }
                frame.type = FrameType::StreamDataBlocked;
                break;
            }
            case static_cast<uint8_t>(FrameType::TickTimer): {
                if (frame_flags != 0U || !reader.read_u64_le(&frame.delta_ms)) {
                    return TransportError::FrameEncodingError;
                }
                frame.type = FrameType::TickTimer;
                break;
            }
            case static_cast<uint8_t>(FrameType::ConnClose): {
                uint32_t reason_len = 0;
                if ((frame_flags & ~kConnCloseFlagApp) != 0U ||
                    !reader.read_u64_le(&frame.error_code) ||
                    !reader.read_u32_le(&reason_len) ||
                    reason_len > kMaxReasonLength ||
                    !reader.read_bytes(reason_len, &frame.data)) {
                    return TransportError::FrameEncodingError;
                }
                frame.type = FrameType::ConnClose;
                break;
            }
            default:
                return TransportError::FrameEncodingError;
        }
        out->frames.push_back(std::move(frame));
    }

    return reader.remaining() == 0U ? TransportError::NoError : TransportError::FrameEncodingError;
}

} // namespace quic_mux
