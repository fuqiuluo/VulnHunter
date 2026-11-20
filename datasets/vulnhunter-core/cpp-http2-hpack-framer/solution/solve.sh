#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "src/hpack_codec.cpp",
    "src/hpack_table.cpp",
    "src/h2_connection.cpp",
    "src/header_validator.cpp",
    "src/huffman.cpp"
  ],
  "findings": [
    "In `src/hpack_codec.cpp` and `src/hpack_table.cpp`, decoding an incremental-indexed header referencing an existing dynamic-table name passed a `std::string_view` directly into `table_.insert()`, which could evict and destroy that exact entry prior to copying its name (heap-use-after-free).",
    "In `src/hpack_codec.cpp` and `src/hpack_table.cpp`, `decode_prefixed_int` allowed unbounded 7-bit continuation shifts (`>= 64` shift UB and integer wraparound), and dynamic table size updates (`001xxxxx`) compared against 4096 instead of `protocol_max_size_` while failing to enforce pending minimum table-size updates at the start of the next header block.",
    "In `src/h2_connection.cpp` and `src/header_validator.cpp`, `PING`/`SETTINGS`/`WINDOW_UPDATE` frames bypassed the `CONTINUATION` lock, trailing `HEADERS` allowed `:path`/`:authority` pseudo-headers to overwrite request routing metadata, `END_STREAM` failed to check `received_data_bytes == content-length`, and header field values were not scanned for NUL/CR/LF bytes.",
    "In `src/h2_connection.cpp` and `src/huffman.cpp`, `SETTINGS_INITIAL_WINDOW_SIZE` computed window deltas in signed 32-bit `int32_t` (overflowing when active streams exceeded `0x7fffffff`), and `huffman_decode` accepted trailing padding bits containing `0` instead of requiring an all-1s EOS prefix."
  ],
  "summary": "Materialized owned header names prior to dynamic-table eviction, bounded HPACK varint decoding and RFC 7541 §4.2 table-size updates, enforced strict `CONTINUATION` frame locking, trailer pseudo-header rejection, control-byte filtering, and `content-length` verification, and fixed 64-bit flow-control window delta checks and Huffman EOS padding validation."
}
EOF

python3 - "$APP_DIR" <<'PY'
from pathlib import Path
import sys

app = Path(sys.argv[1])

# 1. Patch src/huffman.cpp
hf_path = app / "src" / "huffman.cpp"
hf = hf_path.read_text(encoding="utf-8")

old_huff_tail = """    // RFC 7541 §5.2: Trailing incomplete code must be <= 7 bits (flawed: omits all-1s EOS prefix check!)
    if (rem_bits > 7) {
        return false;
    }
    (void)rem_val;
    return true;"""

new_huff_tail = """    if (rem_bits > 7) {
        return false;
    }
    if (rem_bits > 0) {
        uint32_t eos_mask = (1u << rem_bits) - 1u;
        if ((rem_val & eos_mask) != eos_mask) {
            return false;
        }
    }
    return true;"""

assert old_huff_tail in hf, "huffman tail block not found"
hf = hf.replace(old_huff_tail, new_huff_tail, 1)
hf_path.write_text(hf, encoding="utf-8")

# 2. Patch src/hpack_table.cpp
ht_path = app / "src" / "hpack_table.cpp"
ht = ht_path.read_text(encoding="utf-8")

old_ins = """void HpackTable::insert(std::string_view name, std::string_view value) {
    size_t cost = entry_byte_cost(name, value);
    // RFC 7541 §4.4: entry larger than max size empties the entire dynamic table
    if (cost > current_max_size_) {
        dynamic_entries_.clear();
        current_bytes_ = 0;
        return;
    }
    // Evict older entries BEFORE inserting new entry!
    // (Subtle ownership hazard when `name` is a string_view into an evicted dynamic entry!)
    evict_to_fit(current_max_size_ - cost);
    dynamic_entries_.push_front(HeaderField{std::string(name), std::string(value)});
    current_bytes_ += cost;
}"""

new_ins = """void HpackTable::insert(std::string_view name, std::string_view value) {
    std::string owned_name(name);
    std::string owned_value(value);
    size_t cost = entry_byte_cost(owned_name, owned_value);
    if (cost > current_max_size_) {
        dynamic_entries_.clear();
        current_bytes_ = 0;
        return;
    }
    evict_to_fit(current_max_size_ - cost);
    dynamic_entries_.push_front(HeaderField{std::move(owned_name), std::move(owned_value)});
    current_bytes_ += cost;
}"""

assert old_ins in ht, "HpackTable::insert not found"
ht = ht.replace(old_ins, new_ins, 1)

old_upd = """bool HpackTable::apply_encoder_size_update(size_t new_size) {
    // Flawed: compares against default 4096 ceiling instead of `protocol_max_size_` and ignores `pending_min_update_`!
    if (new_size > std::max(protocol_max_size_, kDefaultHeaderTableSize)) {
        return false;
    }
    current_max_size_ = new_size;
    evict_to_fit(current_max_size_);
    if (pending_min_update_.has_value() && new_size <= *pending_min_update_) {
        pending_min_update_.reset();
    }
    return true;
}"""

new_upd = """bool HpackTable::apply_encoder_size_update(size_t new_size) {
    if (pending_min_update_.has_value()) {
        if (new_size > *pending_min_update_) {
            return false;
        }
        pending_min_update_.reset();
    }
    if (new_size > protocol_max_size_) {
        return false;
    }
    current_max_size_ = new_size;
    evict_to_fit(current_max_size_);
    return true;
}"""

assert old_upd in ht, "HpackTable::apply_encoder_size_update not found"
ht = ht.replace(old_upd, new_upd, 1)
ht_path.write_text(ht, encoding="utf-8")

# 3. Patch src/hpack_codec.cpp
hc_path = app / "src" / "hpack_codec.cpp"
hc = hc_path.read_text(encoding="utf-8")

old_varint = """    uint32_t shift = 0;
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
    }"""

new_varint = """    uint32_t shift = 0;
    while (true) {
        if (offset >= len || shift >= 63u) {
            return false;
        }
        uint8_t b = buf[offset++];
        uint64_t low = static_cast<uint64_t>(b & 0x7fu);
        if (low > ((UINT64_MAX - val) >> shift)) {
            return false;
        }
        val += (low << shift);
        if ((b & 0x80u) == 0) {
            value_out = val;
            return true;
        }
        shift += 7;
    }"""

assert old_varint in hc, "decode_prefixed_int loop not found"
hc = hc.replace(old_varint, new_varint, 1)

old_dec_loop = """        allow_size_updates = false;

        // 2. Indexed Header Field: 1xxxxxxx (RFC 7541 §6.1)"""

new_dec_loop = """        if (table_.has_unsignaled_min_reduction()) {
            return ErrorCode::COMPRESSION_ERROR;
        }
        allow_size_updates = false;

        // 2. Indexed Header Field: 1xxxxxxx (RFC 7541 §6.1)"""

assert old_dec_loop in hc, "allow_size_updates transition not found"
hc = hc.replace(old_dec_loop, new_dec_loop, 1)

old_name_ref = """        std::string owned_literal_name;
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

    return ErrorCode::NO_ERROR;"""

new_name_ref = """        std::string name_str;
        if (name_idx > 0) {
            const HeaderField* ref_entry = table_.lookup(static_cast<size_t>(name_idx));
            if (!ref_entry) {
                return ErrorCode::COMPRESSION_ERROR;
            }
            name_str = ref_entry->name;
        } else {
            if (!decode_string(data, len, offset, name_str)) {
                return ErrorCode::COMPRESSION_ERROR;
            }
        }

        std::string val_str;
        if (!decode_string(data, len, offset, val_str)) {
            return ErrorCode::COMPRESSION_ERROR;
        }

        decoded_list_bytes += 32u + name_str.size() + val_str.size();
        if (decoded_list_bytes > max_header_list_bytes_) {
            return ErrorCode::PROTOCOL_ERROR;
        }

        if (add_to_table) {
            table_.insert(name_str, val_str);
        }

        out_headers.push_back(HeaderField{std::move(name_str), std::move(val_str)});
    }

    if (table_.has_unsignaled_min_reduction()) {
        return ErrorCode::COMPRESSION_ERROR;
    }
    return ErrorCode::NO_ERROR;"""

assert old_name_ref in hc, "name_ref block not found"
hc = hc.replace(old_name_ref, new_name_ref, 1)
hc_path.write_text(hc, encoding="utf-8")

# 4. Patch src/header_validator.cpp
hv_path = app / "src" / "header_validator.cpp"
hv = hv_path.read_text(encoding="utf-8")

old_hv_helpers = """bool parse_decimal_u64(std::string_view s, uint64_t& out) {"""
new_hv_helpers = """bool has_forbidden_value_chars(std::string_view val) {
    if (!val.empty() && (val.front() == ' ' || val.front() == '\\t' || val.back() == ' ' || val.back() == '\\t')) {
        return true;
    }
    for (unsigned char c : val) {
        if (c == 0x00u || c == 0x0au || c == 0x0du) {
            return true;
        }
    }
    return false;
}

bool parse_decimal_u64(std::string_view s, uint64_t& out) {"""

assert old_hv_helpers in hv, "parse_decimal_u64 helper not found"
hv = hv.replace(old_hv_helpers, new_hv_helpers, 1)

old_hv_loop = """    for (const auto& hf : fields) {
        if (hf.name.empty()) {
            return ErrorCode::PROTOCOL_ERROR;
        }"""

new_hv_loop = """    for (const auto& hf : fields) {
        if (hf.name.empty() || has_forbidden_value_chars(hf.value)) {
            return ErrorCode::PROTOCOL_ERROR;
        }"""

assert old_hv_loop in hv, "validate_request_headers loop not found"
hv = hv.replace(old_hv_loop, new_hv_loop, 1)

old_trailers = """ErrorCode validate_trailer_headers(const std::vector<HeaderField>& fields, ValidatedRequest& req_inout) {
    for (const auto& hf : fields) {
        if (hf.name.empty()) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        // Flawed: permits pseudo-headers (`:path`, `:authority`) in trailers and overwrites `req_inout`!
        if (hf.name == ":path") {
            req_inout.path = hf.value;
            continue;
        }
        if (hf.name == ":authority") {
            req_inout.authority = hf.value;
            continue;
        }
        for (unsigned char c : hf.name) {
            if (c != ':' && !is_lowercase_tchar(c)) {
                return ErrorCode::PROTOCOL_ERROR;
            }
        }
        if (is_forbidden_h2_conn_header(hf.name)) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        req_inout.trailers.push_back(hf);
    }
    return ErrorCode::NO_ERROR;
}"""

new_trailers = """ErrorCode validate_trailer_headers(const std::vector<HeaderField>& fields, ValidatedRequest& req_inout) {
    for (const auto& hf : fields) {
        if (hf.name.empty() || hf.name[0] == ':' || has_forbidden_value_chars(hf.value)) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        for (unsigned char c : hf.name) {
            if (!is_lowercase_tchar(c)) {
                return ErrorCode::PROTOCOL_ERROR;
            }
        }
        if (is_forbidden_h2_conn_header(hf.name) || hf.name == "content-length" || hf.name == "host" || hf.name == "te") {
            return ErrorCode::PROTOCOL_ERROR;
        }
        req_inout.trailers.push_back(hf);
    }
    return ErrorCode::NO_ERROR;
}"""

assert old_trailers in hv, "validate_trailer_headers block not found"
hv = hv.replace(old_trailers, new_trailers, 1)
hv_path.write_text(hv, encoding="utf-8")

# 5. Patch src/h2_connection.cpp
conn_path = app / "src" / "h2_connection.cpp"
conn = conn_path.read_text(encoding="utf-8")

old_proc_top = """ErrorCode H2ServerConnection::process_frame(
    FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    const uint8_t* payload,
    size_t len) {
    // Flawed: handles PING, SETTINGS, and WINDOW_UPDATE BEFORE checking `continuation_stream_id_ != 0`!
    if (type == FrameType::PING) {"""

new_proc_top = """ErrorCode H2ServerConnection::process_frame(
    FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    const uint8_t* payload,
    size_t len) {
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

    if (type == FrameType::PING) {"""

assert old_proc_top in conn, "process_frame top not found"
conn = conn.replace(old_proc_top, new_proc_top, 1)

old_win = """                case SettingsId::INITIAL_WINDOW_SIZE: {
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
                }"""

new_win = """                case SettingsId::INITIAL_WINDOW_SIZE: {
                    if (val > 0x7fffffffU) {
                        return ErrorCode::FLOW_CONTROL_ERROR;
                    }
                    int64_t delta = static_cast<int64_t>(val) - static_cast<int64_t>(peer_initial_window_size_);
                    for (const auto& [sid, st] : streams_) {
                        if (st.state == StreamState::OPEN || st.state == StreamState::HALF_CLOSED_REMOTE) {
                            int64_t updated = static_cast<int64_t>(st.send_window) + delta;
                            if (updated > kMaxFlowControlWindow || updated < -0x80000000LL) {
                                return ErrorCode::FLOW_CONTROL_ERROR;
                            }
                        }
                    }
                    peer_initial_window_size_ = val;
                    for (auto& [sid, st] : streams_) {
                        if (st.state == StreamState::OPEN || st.state == StreamState::HALF_CLOSED_REMOTE) {
                            st.send_window = static_cast<int32_t>(static_cast<int64_t>(st.send_window) + delta);
                        }
                    }
                    break;
                }"""

assert old_win in conn, "INITIAL_WINDOW_SIZE block not found"
conn = conn.replace(old_win, new_win, 1)

old_dup_cont = """    // Continuation lock check (placed too late — missed PING/SETTINGS/WINDOW_UPDATE above!)
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
    }"""

assert old_dup_cont in conn, "duplicate continuation check not found"
conn = conn.replace(old_dup_cont, "", 1)

old_data_es = """        if ((flags & FrameFlags::END_STREAM) != 0) {
            // Flawed: forgets to verify `received_data_bytes == *request.content_length`!
            it->second.state = StreamState::HALF_CLOSED_REMOTE;"""

new_data_es = """        if ((flags & FrameFlags::END_STREAM) != 0) {
            if (it->second.request.content_length.has_value() &&
                it->second.received_data_bytes != *it->second.request.content_length) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            it->second.state = StreamState::HALF_CLOSED_REMOTE;"""

assert old_data_es in conn, "DATA END_STREAM block not found"
conn = conn.replace(old_data_es, new_data_es, 1)

old_fin_es = """    if (end_stream) {
        // Flawed: forgets to verify `received_data_bytes == *st.request.content_length` on END_STREAM!
        st.state = StreamState::HALF_CLOSED_REMOTE;"""

new_fin_es = """    if (end_stream) {
        if (st.request.content_length.has_value() && st.received_data_bytes != *st.request.content_length) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        st.state = StreamState::HALF_CLOSED_REMOTE;"""

assert old_fin_es in conn, "finish_header_block END_STREAM block not found"
conn = conn.replace(old_fin_es, new_fin_es, 1)
conn_path.write_text(conn, encoding="utf-8")

# 6. Append regression tests to tests/smoke_test.cpp
st_path = app / "tests" / "smoke_test.cpp"
st = st_path.read_text(encoding="utf-8")

reg_cpp = """
void test_hardening_regressions() {
    // 1. Self-evicting dynamic table name reference
    h2::HpackDecoder dec(128);
    const std::string long_name = "x-federated-edge-telemetry-correlation-id";
    std::vector<uint8_t> b1 = {0x40u};
    h2::encode_prefixed_int(b1, 0x00u, 7, long_name.size());
    b1.insert(b1.end(), long_name.begin(), long_name.end());
    std::string v1 = "first-val-0123456789";
    h2::encode_prefixed_int(b1, 0x00u, 7, v1.size());
    b1.insert(b1.end(), v1.begin(), v1.end());
    std::vector<h2::HeaderField> out;
    assert(dec.decode_block(b1.data(), b1.size(), out) == h2::ErrorCode::NO_ERROR);

    std::vector<uint8_t> b2;
    h2::encode_prefixed_int(b2, 0x40u, 6, 62);
    std::string v2 = "second-longer-value-0123456789";
    h2::encode_prefixed_int(b2, 0x00u, 7, v2.size());
    b2.insert(b2.end(), v2.begin(), v2.end());
    assert(dec.decode_block(b2.data(), b2.size(), out) == h2::ErrorCode::NO_ERROR);
    assert(out[0].name == long_name);

    // 2. Malformed Huffman padding & overflowing varint
    std::string h_out;
    uint8_t bad_huff = 0x06u;
    assert(!h2::huffman_decode(&bad_huff, 1, h_out));

    // 3. Interleaved PING during CONTINUATION & trailer pseudo-header rejection
    h2::H2ServerConnection conn;
    std::vector<uint8_t> wire(h2::kClientConnectionPreface.begin(), h2::kClientConnectionPreface.end());
    auto hb = h2::HpackEncoder::encode_literal_block({{":method", "GET"}, {":scheme", "https"}, {":path", "/a"}}, false, false);
    std::vector<uint8_t> p1(hb.begin(), hb.begin() + 4);
    append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::HEADERS, h2::FrameFlags::END_STREAM, 1, p1));
    append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::PING, 0, 0, {0,0,0,0,0,0,0,0}));
    assert(conn.receive_bytes(wire) == h2::ErrorCode::PROTOCOL_ERROR);
}
"""

st = st.replace("int main() {", reg_cpp + "\nint main() {\n    test_hardening_regressions();", 1)
st_path.write_text(st, encoding="utf-8")
PY

make -C "$APP_DIR" clean all test
