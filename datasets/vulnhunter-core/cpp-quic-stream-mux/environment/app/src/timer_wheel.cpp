#include "mux_engine.hpp"

#include <algorithm>

namespace quic_mux {

namespace {

constexpr uint64_t ceiling_tick(uint64_t timestamp_ms) noexcept {
    return timestamp_ms == 0ULL ? 0ULL : (timestamp_ms + kTimerSlotMs - 1ULL) / kTimerSlotMs;
}

} // namespace

TimerWheel::TimerWheel() noexcept {
    for (TimerNode& bucket : buckets_) init_sentinel(bucket);
    init_sentinel(far_horizon_head_);
}

TimerWheel::~TimerWheel() noexcept { cancel_all(); }

void TimerWheel::init_sentinel(TimerNode& head) noexcept {
    head.prev = &head;
    head.next = &head;
    head.deadline_ms = 0;
    head.stream_id = 0;
    head.callback = nullptr;
    head.owner = nullptr;
    head.active = false;
}

void TimerWheel::link_tail(TimerNode& head, TimerNode* node) noexcept {
    node->prev = head.prev;
    node->next = &head;
    head.prev->next = node;
    head.prev = node;
    node->active = true;
    ++active_count_;
}

void TimerWheel::unlink_node(TimerNode* node) noexcept {
    if (node == nullptr || !node->active) return;
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = nullptr;
    node->next = nullptr;
    node->active = false;
    if (active_count_ > 0U) --active_count_;
}

size_t TimerWheel::slot_for_ms(uint64_t timestamp_ms) const noexcept {
    return static_cast<size_t>(ceiling_tick(timestamp_ms) % kTimerWheelSlots);
}

void TimerWheel::schedule(TimerNode* node, uint64_t deadline_ms, uint64_t stream_id,
                          TimerCallback cb, void* owner) noexcept {
    if (node == nullptr || cb == nullptr) return;
    if (node->active) unlink_node(node);

    node->deadline_ms = deadline_ms;
    node->stream_id = stream_id;
    node->callback = cb;
    node->owner = owner;

    const uint64_t cur_tick = ceiling_tick(current_ms_);
    const uint64_t due_tick = ceiling_tick(deadline_ms);
    if (due_tick <= cur_tick) {
        link_tail(buckets_[static_cast<size_t>(cur_tick % kTimerWheelSlots)], node);
    } else if (due_tick - cur_tick < kTimerWheelSlots) {
        link_tail(buckets_[static_cast<size_t>(due_tick % kTimerWheelSlots)], node);
    } else {
        link_tail(far_horizon_head_, node);
    }
}

void TimerWheel::cancel(TimerNode* node) noexcept { unlink_node(node); }

void TimerWheel::cascade_far_timers(uint64_t tick_ms) noexcept {
    const uint64_t base_tick = ceiling_tick(tick_ms);
    TimerNode* cur = far_horizon_head_.next;
    while (cur != &far_horizon_head_) {
        TimerNode* next = cur->next;
        const uint64_t due_tick = ceiling_tick(cur->deadline_ms);
        if (due_tick <= base_tick || due_tick - base_tick < kTimerWheelSlots) {
            unlink_node(cur);
            const size_t slot = static_cast<size_t>(
                (due_tick <= base_tick ? base_tick : due_tick) % kTimerWheelSlots);
            link_tail(buckets_[slot], cur);
        }
        cur = next;
    }
}

size_t TimerWheel::expire_bucket(TimerNode& head, uint64_t cutoff_ms) {
    size_t fired = 0;
    TimerNode* cur = head.next;
    while (cur != &head) {
        TimerNode* next = cur->next;
        if (cur->deadline_ms <= cutoff_ms) {
            TimerCallback cb = cur->callback;
            void* owner = cur->owner;
            const uint64_t sid = cur->stream_id;
            unlink_node(cur);
            ++fired;
            if (cb != nullptr) cb(owner, sid, cutoff_ms);
        }
        cur = next;
    }
    return fired;
}

size_t TimerWheel::advance(uint64_t target_ms) {
    if (target_ms <= current_ms_) {
        return expire_bucket(buckets_[slot_for_ms(current_ms_)], current_ms_);
    }
    if (active_count_ == 0U) {
        current_ms_ = target_ms;
        return 0U;
    }

    size_t total_fired = expire_bucket(buckets_[slot_for_ms(current_ms_)], current_ms_);
    while (current_ms_ < target_ms && active_count_ > 0U) {
        const uint64_t next_boundary = ((current_ms_ / kTimerSlotMs) + 1ULL) * kTimerSlotMs;
        current_ms_ = std::min(target_ms, next_boundary);
        cascade_far_timers(current_ms_);
        total_fired += expire_bucket(buckets_[slot_for_ms(current_ms_)], current_ms_);
    }
    if (current_ms_ < target_ms) current_ms_ = target_ms;
    return total_fired;
}

void TimerWheel::cancel_all() noexcept {
    for (TimerNode& head : buckets_) {
        for (TimerNode* cur = head.next; cur != &head;) {
            TimerNode* next = cur->next;
            cur->prev = nullptr;
            cur->next = nullptr;
            cur->active = false;
            cur = next;
        }
        init_sentinel(head);
    }
    for (TimerNode* cur = far_horizon_head_.next; cur != &far_horizon_head_;) {
        TimerNode* next = cur->next;
        cur->prev = nullptr;
        cur->next = nullptr;
        cur->active = false;
        cur = next;
    }
    init_sentinel(far_horizon_head_);
    active_count_ = 0U;
}

} // namespace quic_mux
