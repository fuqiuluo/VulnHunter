#include "mux_engine.hpp"

#include <algorithm>
#include <iterator>

namespace quic_mux {

TransportError Reassembler::push(uint64_t offset, std::span<const uint8_t> data, bool fin) {
    const uint64_t end_offset = offset + data.size();

    if (size_known_) {
        if (end_offset > final_size_) {
            return TransportError::FinalSizeError;
        }
        if (fin && end_offset != final_size_) {
            return TransportError::FinalSizeError;
        }
    } else if (fin) {
        if (end_offset < highest_offset_) {
            return TransportError::FinalSizeError;
        }
        size_known_ = true;
        final_size_ = end_offset;
    }

    if (end_offset > highest_offset_) {
        highest_offset_ = end_offset;
    }

    if (data.empty() || end_offset <= contiguous_offset_) {
        return TransportError::NoError;
    }

    uint64_t seg_start = offset;
    std::span<const uint8_t> slice = data;
    if (seg_start < contiguous_offset_) {
        const size_t trim = static_cast<size_t>(contiguous_offset_ - seg_start);
        slice = slice.subspan(trim);
        seg_start = contiguous_offset_;
    }

    if (slice.empty()) {
        return TransportError::NoError;
    }

    if (slice.size() > kMaxStreamBufferedBytes ||
        buffered_bytes_ > kMaxStreamBufferedBytes - slice.size()) {
        return TransportError::FlowControlError;
    }

    uint64_t merged_start = seg_start;
    std::vector<uint8_t> merged(slice.begin(), slice.end());

    auto it = segments_.lower_bound(seg_start);
    if (it != segments_.begin()) {
        auto prev = std::prev(it);
        const uint64_t prev_end = prev->first + prev->second.size();
        if (prev_end >= seg_start) {
            it = prev;
        }
    }

    while (it != segments_.end() && it->first < merged_start + merged.size()) {
        const uint64_t cur_start = it->first;
        const uint64_t cur_end = cur_start + it->second.size();
        const uint64_t merged_end = merged_start + merged.size();

        if (cur_start < merged_start) {
            const size_t prefix_len = static_cast<size_t>(merged_start - cur_start);
            std::vector<uint8_t> combined(
                it->second.begin(),
                it->second.begin() + static_cast<std::ptrdiff_t>(prefix_len));
            combined.insert(combined.end(), merged.begin(), merged.end());
            if (cur_end > merged_end) {
                const size_t tail_off = static_cast<size_t>(merged_end - cur_start);
                combined.insert(combined.end(),
                                it->second.begin() + static_cast<std::ptrdiff_t>(tail_off),
                                it->second.end());
            }
            merged_start = cur_start;
            merged = std::move(combined);
        } else if (cur_end > merged_end) {
            const size_t tail_off = static_cast<size_t>(merged_end - cur_start - 1ULL);
            merged.insert(merged.end(),
                          it->second.begin() + static_cast<std::ptrdiff_t>(tail_off),
                          it->second.end());
        }

        it = segments_.erase(it);
    }

    buffered_bytes_ += merged.size();
    segments_.emplace(merged_start, std::move(merged));
    return TransportError::NoError;
}

TransportError Reassembler::validate_reset_final_size(uint64_t final_size) {
    if (final_size > kMaxQuicOffset) {
        return TransportError::FinalSizeError;
    }
    if (!size_known_) {
        size_known_ = true;
        final_size_ = final_size;
    }
    discard_unread();
    return TransportError::NoError;
}

size_t Reassembler::drain_contiguous(Fnv1aHasher& out_hasher) {
    size_t total_drained = 0;
    while (!segments_.empty()) {
        auto head = segments_.begin();
        if (head->first > contiguous_offset_) {
            break;
        }

        const uint64_t seg_start = head->first;
        const std::vector<uint8_t>& bytes = head->second;
        const uint64_t seg_end = seg_start + bytes.size();
        if (seg_end > contiguous_offset_) {
            const size_t skip = static_cast<size_t>(contiguous_offset_ - seg_start);
            const std::span<const uint8_t> ready_span(bytes.data() + skip, bytes.size() - skip);
            out_hasher.update(ready_span);
            contiguous_offset_ += ready_span.size();
            total_drained += ready_span.size();
        }

        if (buffered_bytes_ >= bytes.size()) {
            buffered_bytes_ -= bytes.size();
        } else {
            buffered_bytes_ = 0;
        }
        segments_.erase(head);
    }
    return total_drained;
}

void Reassembler::discard_unread() noexcept {
    segments_.clear();
    buffered_bytes_ = 0;
}

} // namespace quic_mux
