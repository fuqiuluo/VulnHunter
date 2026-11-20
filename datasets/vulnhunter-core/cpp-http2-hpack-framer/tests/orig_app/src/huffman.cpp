#include "h2_framer.hpp"

#include <array>
#include <memory>

namespace h2 {
namespace {

struct HuffSym {
    uint32_t code;
    uint8_t bit_len;
};

// Exact RFC 7541 Appendix B Canonical Huffman Code Table (256 byte symbols + symbol 256 EOS)
constexpr std::array<HuffSym, 257> kHuffmanTable = {{
    {0x00001ff8u, 13}, {0x007fffd8u, 23}, {0x0fffffe2u, 28}, {0x0fffffe3u, 28},
    {0x0fffffe4u, 28}, {0x0fffffe5u, 28}, {0x0fffffe6u, 28}, {0x0fffffe7u, 28},
    {0x0fffffe8u, 28}, {0x00ffffeau, 24}, {0x3ffffffcu, 30}, {0x0fffffe9u, 28},
    {0x0fffffeau, 28}, {0x3ffffffdu, 30}, {0x0fffffebu, 28}, {0x0fffffecu, 28},
    {0x0fffffedu, 28}, {0x0fffffeeu, 28}, {0x0fffffefu, 28}, {0x0ffffff0u, 28},
    {0x0ffffff1u, 28}, {0x0ffffff2u, 28}, {0x3ffffffeu, 30}, {0x0ffffff3u, 28},
    {0x0ffffff4u, 28}, {0x0ffffff5u, 28}, {0x0ffffff6u, 28}, {0x0ffffff7u, 28},
    {0x0ffffff8u, 28}, {0x0ffffff9u, 28}, {0x0ffffffau, 28}, {0x0ffffffbu, 28},
    {0x00000014u,  6}, {0x000003f8u, 10}, {0x000003f9u, 10}, {0x00000ffau, 12},
    {0x00001ff9u, 13}, {0x00000015u,  6}, {0x000000f8u,  8}, {0x000007fau, 11},
    {0x000003fau, 10}, {0x000003fbu, 10}, {0x000000f9u,  8}, {0x000007fbu, 11},
    {0x000000fau,  8}, {0x00000016u,  6}, {0x00000017u,  6}, {0x00000018u,  6},
    {0x00000000u,  5}, {0x00000001u,  5}, {0x00000002u,  5}, {0x00000019u,  6},
    {0x0000001au,  6}, {0x0000001bu,  6}, {0x0000001cu,  6}, {0x0000001du,  6},
    {0x0000001eu,  6}, {0x0000001fu,  6}, {0x0000005cu,  7}, {0x000000fbu,  8},
    {0x00007ffcu, 15}, {0x00000020u,  6}, {0x00000ffbu, 12}, {0x000003fcu, 10},
    {0x00001ffau, 13}, {0x00000021u,  6}, {0x0000005du,  7}, {0x0000005eu,  7},
    {0x0000005fu,  7}, {0x00000060u,  7}, {0x00000061u,  7}, {0x00000062u,  7},
    {0x00000063u,  7}, {0x00000064u,  7}, {0x00000065u,  7}, {0x00000066u,  7},
    {0x00000067u,  7}, {0x00000068u,  7}, {0x00000069u,  7}, {0x0000006au,  7},
    {0x0000006bu,  7}, {0x0000006cu,  7}, {0x0000006du,  7}, {0x0000006eu,  7},
    {0x0000006fu,  7}, {0x00000070u,  7}, {0x00000071u,  7}, {0x00000072u,  7},
    {0x000000fcu,  8}, {0x00000073u,  7}, {0x000000fdu,  8}, {0x00001ffbu, 13},
    {0x0007fff0u, 19}, {0x00001ffcu, 13}, {0x00003ffcu, 14}, {0x00000022u,  6},
    {0x00007ffdu, 15}, {0x00000003u,  5}, {0x00000023u,  6}, {0x00000004u,  5},
    {0x00000024u,  6}, {0x00000005u,  5}, {0x00000025u,  6}, {0x00000026u,  6},
    {0x00000027u,  6}, {0x00000006u,  5}, {0x00000074u,  7}, {0x00000075u,  7},
    {0x00000028u,  6}, {0x00000029u,  6}, {0x0000002au,  6}, {0x00000007u,  5},
    {0x0000002bu,  6}, {0x00000076u,  7}, {0x0000002cu,  6}, {0x00000008u,  5},
    {0x00000009u,  5}, {0x0000002du,  6}, {0x00000077u,  7}, {0x00000078u,  7},
    {0x00000079u,  7}, {0x0000007au,  7}, {0x0000007bu,  7}, {0x00007ffeu, 15},
    {0x000007fcu, 11}, {0x00003ffdu, 14}, {0x00001ffdu, 13}, {0x0ffffffcu, 28},
    {0x000fffe6u, 20}, {0x003fffd2u, 22}, {0x000fffe7u, 20}, {0x000fffe8u, 20},
    {0x003fffd3u, 22}, {0x003fffd4u, 22}, {0x003fffd5u, 22}, {0x007fffd9u, 23},
    {0x003fffd6u, 22}, {0x007fffdau, 23}, {0x007fffdbu, 23}, {0x007fffdcu, 23},
    {0x007fffddu, 23}, {0x007fffdeu, 23}, {0x00ffffebu, 24}, {0x007fffdfu, 23},
    {0x00ffffecu, 24}, {0x00ffffedu, 24}, {0x003fffd7u, 22}, {0x007fffe0u, 23},
    {0x00ffffeeu, 24}, {0x007fffe1u, 23}, {0x007fffe2u, 23}, {0x007fffe3u, 23},
    {0x007fffe4u, 23}, {0x001fffdcu, 21}, {0x003fffd8u, 22}, {0x007fffe5u, 23},
    {0x003fffd9u, 22}, {0x007fffe6u, 23}, {0x007fffe7u, 23}, {0x00ffffefu, 24},
    {0x003fffdau, 22}, {0x001fffddu, 21}, {0x000fffe9u, 20}, {0x003fffdbu, 22},
    {0x003fffdcu, 22}, {0x007fffe8u, 23}, {0x007fffe9u, 23}, {0x001fffdeu, 21},
    {0x007fffeau, 23}, {0x003fffddu, 22}, {0x003fffdeu, 22}, {0x00fffff0u, 24},
    {0x001fffdfu, 21}, {0x003fffdfu, 22}, {0x007fffebu, 23}, {0x007fffecu, 23},
    {0x001fffe0u, 21}, {0x001fffe1u, 21}, {0x003fffe0u, 22}, {0x001fffe2u, 21},
    {0x007fffedu, 23}, {0x003fffe1u, 22}, {0x007fffeeu, 23}, {0x007fffefu, 23},
    {0x000fffeau, 20}, {0x003fffe2u, 22}, {0x003fffe3u, 22}, {0x003fffe4u, 22},
    {0x007ffff0u, 23}, {0x003fffe5u, 22}, {0x003fffe6u, 22}, {0x007ffff1u, 23},
    {0x03ffffe0u, 26}, {0x03ffffe1u, 26}, {0x000fffebu, 20}, {0x0007fff1u, 19},
    {0x003fffe7u, 22}, {0x007ffff2u, 23}, {0x003fffe8u, 22}, {0x01ffffecu, 25},
    {0x03ffffe2u, 26}, {0x03ffffe3u, 26}, {0x03ffffe4u, 26}, {0x07ffffdeu, 27},
    {0x07ffffdfu, 27}, {0x03ffffe5u, 26}, {0x00fffff1u, 24}, {0x01ffffedu, 25},
    {0x0007fff2u, 19}, {0x001fffe3u, 21}, {0x03ffffe6u, 26}, {0x07ffffe0u, 27},
    {0x07ffffe1u, 27}, {0x03ffffe7u, 26}, {0x07ffffe2u, 27}, {0x00fffff2u, 24},
    {0x001fffe4u, 21}, {0x001fffe5u, 21}, {0x03ffffe8u, 26}, {0x03ffffe9u, 26},
    {0x0ffffffdu, 28}, {0x07ffffe3u, 27}, {0x07ffffe4u, 27}, {0x07ffffe5u, 27},
    {0x000fffecu, 20}, {0x00fffff3u, 24}, {0x000fffedu, 20}, {0x001fffe6u, 21},
    {0x003fffe9u, 22}, {0x001fffe7u, 21}, {0x001fffe8u, 21}, {0x007ffff3u, 23},
    {0x003fffeau, 22}, {0x003fffebu, 22}, {0x01ffffeeu, 25}, {0x01ffffefu, 25},
    {0x00fffff4u, 24}, {0x00fffff5u, 24}, {0x03ffffeau, 26}, {0x007ffff4u, 23},
    {0x03ffffebu, 26}, {0x07ffffe6u, 27}, {0x03ffffecu, 26}, {0x03ffffedu, 26},
    {0x07ffffe7u, 27}, {0x07ffffe8u, 27}, {0x07ffffe9u, 27}, {0x07ffffeau, 27},
    {0x07ffffebu, 27}, {0x0ffffffeu, 28}, {0x07ffffecu, 27}, {0x07ffffedu, 27},
    {0x07ffffeeu, 27}, {0x07ffffefu, 27}, {0x07fffff0u, 27}, {0x03ffffeeu, 26},
    {0x3fffffffu, 30},
}};

struct TrieNode {
    int left = -1;
    int right = -1;
    int symbol = -1;
};

const std::vector<TrieNode>& get_huffman_trie() {
    static const std::vector<TrieNode> trie = [] {
        std::vector<TrieNode> nodes(1);
        for (int sym = 0; sym <= 256; ++sym) {
            uint32_t code = kHuffmanTable[sym].code;
            uint8_t len = kHuffmanTable[sym].bit_len;
            int cur = 0;
            for (int b = static_cast<int>(len) - 1; b >= 0; --b) {
                int bit = (code >> b) & 1u;
                int next = (bit == 0) ? nodes[cur].left : nodes[cur].right;
                if (next == -1) {
                    next = static_cast<int>(nodes.size());
                    nodes.emplace_back();
                    if (bit == 0) {
                        nodes[cur].left = next;
                    } else {
                        nodes[cur].right = next;
                    }
                }
                cur = next;
            }
            nodes[cur].symbol = sym;
        }
        return nodes;
    }();
    return trie;
}

}  // namespace

std::vector<uint8_t> huffman_encode(std::string_view plain) {
    std::vector<uint8_t> out;
    out.reserve(plain.size());
    uint64_t bit_buf = 0;
    uint32_t bit_cnt = 0;

    for (unsigned char ch : plain) {
        const auto& entry = kHuffmanTable[ch];
        bit_buf = (bit_buf << entry.bit_len) | entry.code;
        bit_cnt += entry.bit_len;
        while (bit_cnt >= 8) {
            bit_cnt -= 8;
            out.push_back(static_cast<uint8_t>((bit_buf >> bit_cnt) & 0xffu));
        }
    }
    if (bit_cnt > 0) {
        uint32_t pad = 8 - bit_cnt;
        uint8_t last = static_cast<uint8_t>(((bit_buf << pad) | ((1u << pad) - 1u)) & 0xffu);
        out.push_back(last);
    }
    return out;
}

bool huffman_decode(const uint8_t* data, size_t len, std::string& out) {
    out.clear();
    out.reserve(len * 2);
    const auto& trie = get_huffman_trie();

    int cur = 0;
    uint32_t rem_bits = 0;
    uint32_t rem_val = 0;

    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        for (int b = 7; b >= 0; --b) {
            uint32_t bit = (byte >> b) & 1u;
            cur = (bit == 0) ? trie[cur].left : trie[cur].right;
            if (cur < 0) {
                return false;
            }
            rem_bits += 1;
            rem_val = (rem_val << 1) | bit;

            if (trie[cur].symbol >= 0) {
                if (trie[cur].symbol == 256) {
                    // Explicit 30-bit EOS inside Huffman stream is a COMPRESSION_ERROR (RFC 7541 §5.2)
                    return false;
                }
                out.push_back(static_cast<char>(static_cast<uint8_t>(trie[cur].symbol)));
                cur = 0;
                rem_bits = 0;
                rem_val = 0;
            }
        }
    }

    // RFC 7541 §5.2: Trailing incomplete code must be <= 7 bits (flawed: omits all-1s EOS prefix check!)
    if (rem_bits > 7) {
        return false;
    }
    (void)rem_val;
    return true;
}

}  // namespace h2
