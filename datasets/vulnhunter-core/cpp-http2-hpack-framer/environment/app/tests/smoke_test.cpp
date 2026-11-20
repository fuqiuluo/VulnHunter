#include "h2_framer.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

namespace {

void append_bytes(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

void test_huffman_roundtrip_and_rfc_example() {
    // RFC 7541 Appendix C.4.1 vector: "www.example.com" -> f1e3 c2e5 f23a 6ba0 ab90 f4ff
    const std::vector<uint8_t> rfc_vec = {
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
    };
    auto encoded = h2::huffman_encode("www.example.com");
    assert(encoded == rfc_vec);

    std::string decoded;
    assert(h2::huffman_decode(rfc_vec.data(), rfc_vec.size(), decoded));
    assert(decoded == "www.example.com");

    // Roundtrip all 256 byte values
    std::string all_bytes(256, '\0');
    for (int i = 0; i < 256; ++i) {
        all_bytes[static_cast<size_t>(i)] = static_cast<char>(static_cast<uint8_t>(i));
    }
    auto enc_all = h2::huffman_encode(all_bytes);
    std::string dec_all;
    assert(h2::huffman_decode(enc_all.data(), enc_all.size(), dec_all));
    assert(dec_all == all_bytes);
}

void test_multiplexed_headers_continuation_data_and_trailers() {
    h2::H2ServerConnection conn;
    std::vector<uint8_t> wire(h2::kClientConnectionPreface.begin(), h2::kClientConnectionPreface.end());

    // Initial client SETTINGS frame (empty)
    append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::SETTINGS, 0, 0, {}));

    // Stream 1: Split HEADERS + CONTINUATION GET request
    auto hblock1 = h2::HpackEncoder::encode_literal_block(
        {
            {":method", "GET"},
            {":scheme", "https"},
            {":authority", "api.internal:8443"},
            {":path", "/v1/health"},
            {"x-trace-id", "trace-alpha-001"},
        },
        true,
        true);
    size_t split = hblock1.size() / 2;
    std::vector<uint8_t> part1(hblock1.begin(), hblock1.begin() + static_cast<std::ptrdiff_t>(split));
    std::vector<uint8_t> part2(hblock1.begin() + static_cast<std::ptrdiff_t>(split), hblock1.end());

    append_bytes(
        wire,
        h2::H2ServerConnection::serialize_frame(h2::FrameType::HEADERS, h2::FrameFlags::END_STREAM, 1, part1));
    append_bytes(
        wire,
        h2::H2ServerConnection::serialize_frame(h2::FrameType::CONTINUATION, h2::FrameFlags::END_HEADERS, 1, part2));

    // Stream 3: POST with DATA + trailing HEADERS
    std::string payload_str = "{\"op\":\"sync\",\"items\":3}";
    auto hblock3 = h2::HpackEncoder::encode_literal_block(
        {
            {":method", "POST"},
            {":scheme", "https"},
            {":authority", "api.internal:8443"},
            {":path", "/v1/sync"},
            {"te", "trailers"},
            {"content-type", "application/json"},
            {"content-length", std::to_string(payload_str.size())},
        },
        true,
        true);
    append_bytes(
        wire,
        h2::H2ServerConnection::serialize_frame(h2::FrameType::HEADERS, h2::FrameFlags::END_HEADERS, 3, hblock3));

    std::vector<uint8_t> body_bytes(payload_str.begin(), payload_str.end());
    append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::DATA, 0, 3, body_bytes));

    auto trailer_block = h2::HpackEncoder::encode_literal_block({{"grpc-status", "0"}}, false, true);
    append_bytes(
        wire,
        h2::H2ServerConnection::serialize_frame(
            h2::FrameType::HEADERS,
            h2::FrameFlags::END_HEADERS | h2::FrameFlags::END_STREAM,
            3,
            trailer_block));

    assert(conn.receive_bytes(wire) == h2::ErrorCode::NO_ERROR);
    assert(conn.completed_requests().size() == 2);
    assert(conn.completed_requests()[0].path == "/v1/health");
    assert(conn.completed_requests()[1].path == "/v1/sync");
    assert(conn.completed_requests()[1].body == payload_str);
    assert(conn.completed_requests()[1].trailers.size() == 1);
    assert(conn.completed_requests()[1].trailers[0].name == "grpc-status");
}

}  // namespace

int main() {
    test_huffman_roundtrip_and_rfc_example();
    test_multiplexed_headers_continuation_data_and_trailers();
    std::cout << "h2_framer baseline smoke tests passed.\n";
    return 0;
}
