#include "h2_framer.hpp"

namespace h2 {

void encode_prefixed_int(std::vector<uint8_t>& out, uint8_t first_byte_mask, uint8_t prefix_bits, uint64_t value) {
    uint64_t max_prefix = (1ULL << prefix_bits) - 1ULL;
    if (value < max_prefix) {
        out.push_back(static_cast<uint8_t>(first_byte_mask | value));
        return;
    }
    out.push_back(static_cast<uint8_t>(first_byte_mask | max_prefix));
    value -= max_prefix;
    while (value >= 128ULL) {
        out.push_back(static_cast<uint8_t>((value & 0x7fULL) | 0x80ULL));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

bool decode_prefixed_int(const uint8_t* buf, size_t len, size_t& offset, uint8_t prefix_bits, uint64_t& value_out) {
    if (offset >= len || prefix_bits == 0 || prefix_bits > 8) {
        return false;
    }
    uint64_t mask = (1ULL << prefix_bits) - 1ULL;
    uint64_t val = buf[offset] & mask;
    offset += 1;
    if (val < mask) {
        value_out = val;
        return true;
    }

    uint32_t shift = 0;
    while (true) {
        if (offset >= len) {
            return false;
        }
        uint8_t b = buf[offset++];
        // Flawed: shift can grow >= 64 on malformed multi-byte varints (UBSan shift exponent UB + overflow)!
        val += static_cast<uint64_t>(b & 0x7fu) << shift;
        if ((b & 0x80u) == 0) {
            value_out = val;
            return true;
        }
        shift += 7;
    }
}

HpackDecoder::HpackDecoder(size_t max_table_size, size_t max_header_list_bytes)
    : table_(max_table_size), max_header_list_bytes_(max_header_list_bytes) {}

bool HpackDecoder::decode_string(const uint8_t* buf, size_t len, size_t& offset, std::string& out_str) {
    if (offset >= len) {
        return false;
    }
    bool is_huff = (buf[offset] & 0x80u) != 0;
    uint64_t str_len = 0;
    if (!decode_prefixed_int(buf, len, offset, 7, str_len)) {
        return false;
    }
    if (str_len > len - offset) {
        return false;
    }
    const uint8_t* raw_ptr = buf + offset;
    offset += static_cast<size_t>(str_len);

    if (is_huff) {
        return huffman_decode(raw_ptr, static_cast<size_t>(str_len), out_str);
    }
    out_str.assign(reinterpret_cast<const char*>(raw_ptr), static_cast<size_t>(str_len));
    return true;
}

ErrorCode HpackDecoder::decode_block(const uint8_t* data, size_t len, std::vector<HeaderField>& out_headers) {
    out_headers.clear();
    size_t offset = 0;
    size_t decoded_list_bytes = 0;
    bool allow_size_updates = true;

    while (offset < len) {
        uint8_t lead = data[offset];

        // 1. Dynamic Table Size Update: 001xxxxx (RFC 7541 §6.3)
        if ((lead & 0xe0u) == 0x20u) {
            if (!allow_size_updates) {
                return ErrorCode::COMPRESSION_ERROR;
            }
            uint64_t new_size = 0;
            if (!decode_prefixed_int(data, len, offset, 5, new_size)) {
                return ErrorCode::COMPRESSION_ERROR;
            }
            if (!table_.apply_encoder_size_update(static_cast<size_t>(new_size))) {
                return ErrorCode::COMPRESSION_ERROR;
            }
            continue;
        }

        allow_size_updates = false;

        // 2. Indexed Header Field: 1xxxxxxx (RFC 7541 §6.1)
        if ((lead & 0x80u) != 0) {
            uint64_t idx = 0;
            if (!decode_prefixed_int(data, len, offset, 7, idx) || idx == 0) {
                return ErrorCode::COMPRESSION_ERROR;
            }
            const HeaderField* entry = table_.lookup(static_cast<size_t>(idx));
            if (!entry) {
                return ErrorCode::COMPRESSION_ERROR;
            }
            decoded_list_bytes += 32u + entry->name.size() + entry->value.size();
            if (decoded_list_bytes > max_header_list_bytes_) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            out_headers.push_back(*entry);
            continue;
        }

        // 3. Literal Header Field with Incremental Indexing (01xxxxxx) or Without/Never Indexing (0000xxxx / 0001xxxx)
        bool add_to_table = (lead & 0xc0u) == 0x40u;
        uint8_t prefix_bits = add_to_table ? 6 : 4;
        uint64_t name_idx = 0;
        if (!decode_prefixed_int(data, len, offset, prefix_bits, name_idx)) {
            return ErrorCode::COMPRESSION_ERROR;
        }

        std::string owned_literal_name;
        std::string_view name_ref;
        if (name_idx > 0) {
            const HeaderField* ref_entry = table_.lookup(static_cast<size_t>(name_idx));
            if (!ref_entry) {
                return ErrorCode::COMPRESSION_ERROR;
            }
            // Dangling string_view hazard if `table_.insert` evicts `ref_entry`!
            name_ref = ref_entry->name;
        } else {
            if (!decode_string(data, len, offset, owned_literal_name)) {
                return ErrorCode::COMPRESSION_ERROR;
            }
            name_ref = owned_literal_name;
        }

        std::string val_str;
        if (!decode_string(data, len, offset, val_str)) {
            return ErrorCode::COMPRESSION_ERROR;
        }

        decoded_list_bytes += 32u + name_ref.size() + val_str.size();
        if (decoded_list_bytes > max_header_list_bytes_) {
            return ErrorCode::PROTOCOL_ERROR;
        }

        if (add_to_table) {
            table_.insert(name_ref, val_str);
            // If `name_ref` pointed into an evicted dynamic entry, `name_ref` is ALREADY freed right here too!
        }

        out_headers.push_back(HeaderField{std::string(name_ref), std::move(val_str)});
    }

    return ErrorCode::NO_ERROR;
}

std::vector<uint8_t> HpackEncoder::encode_literal_block(
    const std::vector<HeaderField>& headers,
    bool incremental_index,
    bool use_huffman) {
    std::vector<uint8_t> out;
    auto append_str = [&](std::string_view s) {
        if (use_huffman) {
            auto h = huffman_encode(s);
            encode_prefixed_int(out, 0x80u, 7, h.size());
            out.insert(out.end(), h.begin(), h.end());
        } else {
            encode_prefixed_int(out, 0x00u, 7, s.size());
            out.insert(out.end(), s.begin(), s.end());
        }
    };

    for (const auto& hf : headers) {
        if (incremental_index) {
            out.push_back(0x40u);  // literal with incremental indexing, new name
        } else {
            out.push_back(0x00u);  // literal without indexing, new name
        }
        append_str(hf.name);
        append_str(hf.value);
    }
    return out;
}

}  // namespace h2
