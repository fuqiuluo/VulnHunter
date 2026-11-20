#include "h2_framer.hpp"

#include <algorithm>
#include <array>

namespace h2 {
namespace {

// RFC 7541 Appendix A Static Table (1-based indices 1..61)
const std::array<HeaderField, HpackTable::kStaticTableCount>& static_table() {
    static const std::array<HeaderField, HpackTable::kStaticTableCount> kTable = {{
        {":authority", ""},
        {":method", "GET"},
        {":method", "POST"},
        {":path", "/"},
        {":path", "/index.html"},
        {":scheme", "http"},
        {":scheme", "https"},
        {":status", "200"},
        {":status", "204"},
        {":status", "206"},
        {":status", "304"},
        {":status", "400"},
        {":status", "404"},
        {":status", "500"},
        {"accept-charset", ""},
        {"accept-encoding", "gzip, deflate"},
        {"accept-language", ""},
        {"accept-ranges", ""},
        {"accept", ""},
        {"access-control-allow-origin", ""},
        {"age", ""},
        {"allow", ""},
        {"authorization", ""},
        {"cache-control", ""},
        {"content-disposition", ""},
        {"content-encoding", ""},
        {"content-language", ""},
        {"content-length", ""},
        {"content-location", ""},
        {"content-range", ""},
        {"content-type", ""},
        {"cookie", ""},
        {"date", ""},
        {"etag", ""},
        {"expect", ""},
        {"expires", ""},
        {"from", ""},
        {"host", ""},
        {"if-match", ""},
        {"if-modified-since", ""},
        {"if-none-match", ""},
        {"if-range", ""},
        {"if-unmodified-since", ""},
        {"last-modified", ""},
        {"link", ""},
        {"location", ""},
        {"max-forwards", ""},
        {"proxy-authenticate", ""},
        {"proxy-authorization", ""},
        {"range", ""},
        {"referer", ""},
        {"refresh", ""},
        {"retry-after", ""},
        {"server", ""},
        {"set-cookie", ""},
        {"strict-transport-security", ""},
        {"transfer-encoding", ""},
        {"user-agent", ""},
        {"vary", ""},
        {"via", ""},
        {"www-authenticate", ""},
    }};
    return kTable;
}

inline size_t entry_byte_cost(std::string_view name, std::string_view value) {
    return 32u + name.size() + value.size();
}

}  // namespace

HpackTable::HpackTable(size_t initial_max_size)
    : current_max_size_(initial_max_size), protocol_max_size_(initial_max_size) {}

const HeaderField* HpackTable::lookup(size_t index) const {
    if (index == 0) {
        return nullptr;
    }
    const auto& st = static_table();
    if (index <= kStaticTableCount) {
        return &st[index - 1];
    }
    size_t dyn_idx = index - kStaticTableCount - 1;
    if (dyn_idx >= dynamic_entries_.size()) {
        return nullptr;
    }
    return &dynamic_entries_[dyn_idx];
}

void HpackTable::evict_to_fit(size_t target_max_bytes) {
    while (!dynamic_entries_.empty() && current_bytes_ > target_max_bytes) {
        const auto& oldest = dynamic_entries_.back();
        size_t cost = entry_byte_cost(oldest.name, oldest.value);
        current_bytes_ = (cost <= current_bytes_) ? (current_bytes_ - cost) : 0;
        dynamic_entries_.pop_back();
    }
}

void HpackTable::insert(std::string_view name, std::string_view value) {
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
}

void HpackTable::set_protocol_max_size(size_t new_protocol_max) {
    if (new_protocol_max < current_max_size_) {
        if (!pending_min_update_.has_value() || new_protocol_max < *pending_min_update_) {
            pending_min_update_ = new_protocol_max;
        }
    }
    protocol_max_size_ = new_protocol_max;
}

bool HpackTable::apply_encoder_size_update(size_t new_size) {
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
}

}  // namespace h2
