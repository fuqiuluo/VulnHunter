#include "mux_engine.hpp"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>

namespace {

constexpr std::streamoff kMaxInputFileSize = 16 * 1024 * 1024;

bool load_binary_file(const char* path, std::vector<uint8_t>* out) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open()) {
        return false;
    }
    const std::streamoff size = in.tellg();
    if (size < 0 || size > kMaxInputFileSize) {
        return false;
    }
    out->resize(static_cast<size_t>(size));
    in.seekg(0, std::ios::beg);
    if (size > 0 && !in.read(reinterpret_cast<char*>(out->data()), size)) {
        return false;
    }
    return true;
}

int emit_transport_error(quic_mux::TransportError err) {
    std::cerr << "error=" << quic_mux::error_name(err)
              << " code=" << static_cast<uint16_t>(err) << "\n";
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: mux_cli <script.qmux>\n";
        return 1;
    }

    std::vector<uint8_t> raw_bytes;
    if (!load_binary_file(argv[1], &raw_bytes)) {
        return emit_transport_error(quic_mux::TransportError::FrameEncodingError);
    }

    quic_mux::DecodedScript script;
    const quic_mux::TransportError dec_err = quic_mux::WireCodec::decode_script(raw_bytes, &script);
    if (dec_err != quic_mux::TransportError::NoError) {
        return emit_transport_error(dec_err);
    }

    quic_mux::Connection conn(script.config);
    for (const quic_mux::WireFrame& frame : script.frames) {
        const quic_mux::TransportError step_err = conn.process_frame(frame);
        if (step_err != quic_mux::TransportError::NoError) {
            return emit_transport_error(step_err);
        }
    }

    quic_mux::ConnectionSummary summary{};
    const quic_mux::TransportError fin_err = conn.finalize(&summary);
    if (fin_err != quic_mux::TransportError::NoError) {
        return emit_transport_error(fin_err);
    }

    std::cout << "status=ok"
              << " completed=" << summary.completed_streams
              << " retired=" << summary.retired_streams
              << " conn_recv=" << summary.conn_recv_bytes
              << " max_bidi=" << summary.max_peer_bidi
              << " max_uni=" << summary.max_peer_uni
              << " drains=" << summary.drain_timeouts
              << " fnv1a=" << std::hex << std::setw(16) << std::setfill('0') << summary.mux_fnv1a
              << std::dec << "\n";
    return 0;
}
