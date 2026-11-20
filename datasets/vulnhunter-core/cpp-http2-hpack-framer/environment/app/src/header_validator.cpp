#include "h2_framer.hpp"

#include <cctype>
#include <charconv>

namespace h2 {
namespace {

bool is_lowercase_tchar(unsigned char c) {
    if (c >= 'a' && c <= 'z') return true;
    if (c >= '0' && c <= '9') return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'':
        case '*': case '+': case '-': case '.': case '^': case '_':
        case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

bool equals_ascii_ci(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool is_forbidden_h2_conn_header(std::string_view name) {
    return name == "connection" || name == "keep-alive" || name == "proxy-connection" ||
           name == "transfer-encoding" || name == "upgrade";
}

bool parse_decimal_u64(std::string_view s, uint64_t& out) {
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (c < '0' || c > '9') return false;
    }
    uint64_t val = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val, 10);
    if (ec != std::errc{} || ptr != s.data() + s.size()) return false;
    out = val;
    return true;
}

}  // namespace

ErrorCode validate_request_headers(const std::vector<HeaderField>& fields, ValidatedRequest& req_out) {
    bool seen_regular = false;
    bool has_method = false;
    bool has_scheme = false;
    bool has_authority = false;
    bool has_path = false;
    std::optional<std::string> host_header;

    req_out.headers.clear();
    req_out.content_length.reset();

    for (const auto& hf : fields) {
        if (hf.name.empty()) {
            return ErrorCode::PROTOCOL_ERROR;
        }

        if (hf.name[0] == ':') {
            if (seen_regular) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            for (size_t i = 1; i < hf.name.size(); ++i) {
                if (!is_lowercase_tchar(static_cast<unsigned char>(hf.name[i]))) {
                    return ErrorCode::PROTOCOL_ERROR;
                }
            }
            if (hf.name == ":method") {
                if (has_method || hf.value.empty()) return ErrorCode::PROTOCOL_ERROR;
                has_method = true;
                req_out.method = hf.value;
            } else if (hf.name == ":scheme") {
                if (has_scheme || hf.value.empty()) return ErrorCode::PROTOCOL_ERROR;
                has_scheme = true;
                req_out.scheme = hf.value;
            } else if (hf.name == ":authority") {
                if (has_authority) return ErrorCode::PROTOCOL_ERROR;
                has_authority = true;
                req_out.authority = hf.value;
            } else if (hf.name == ":path") {
                if (has_path || hf.value.empty()) return ErrorCode::PROTOCOL_ERROR;
                has_path = true;
                req_out.path = hf.value;
            } else {
                // Unknown or response pseudo-header (`:status`) in request
                return ErrorCode::PROTOCOL_ERROR;
            }
            continue;
        }

        seen_regular = true;
        for (unsigned char c : hf.name) {
            if (!is_lowercase_tchar(c)) {
                return ErrorCode::PROTOCOL_ERROR;
            }
        }
        if (is_forbidden_h2_conn_header(hf.name)) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        if (hf.name == "te" && hf.value != "trailers") {
            return ErrorCode::PROTOCOL_ERROR;
        }
        if (hf.name == "host") {
            if (host_header.has_value()) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            host_header = hf.value;
        }
        if (hf.name == "content-length") {
            uint64_t parsed_cl = 0;
            if (!parse_decimal_u64(hf.value, parsed_cl)) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            if (req_out.content_length.has_value() && *req_out.content_length != parsed_cl) {
                return ErrorCode::PROTOCOL_ERROR;
            }
            req_out.content_length = parsed_cl;
        }
        // Flawed: omits scanning `hf.value` (and pseudo-header values) for forbidden NUL / CR / LF bytes!
        req_out.headers.push_back(hf);
    }

    if (!has_method || !has_scheme || !has_path) {
        return ErrorCode::PROTOCOL_ERROR;
    }
    if (host_header.has_value()) {
        if (has_authority && !req_out.authority.empty() && !equals_ascii_ci(req_out.authority, *host_header)) {
            return ErrorCode::PROTOCOL_ERROR;
        }
        if (!has_authority) {
            req_out.authority = *host_header;
        }
    }
    return ErrorCode::NO_ERROR;
}

ErrorCode validate_trailer_headers(const std::vector<HeaderField>& fields, ValidatedRequest& req_inout) {
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
}

}  // namespace h2
