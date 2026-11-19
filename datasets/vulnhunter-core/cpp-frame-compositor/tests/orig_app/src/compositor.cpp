#include "compositor.hpp"

namespace media {

FrameCompositor::FrameCompositor(const CanvasSpec &spec)
    : width_(spec.width),
      height_(spec.height),
      grid_rows_(spec.grid_rows > 0 ? spec.grid_rows : 1),
      grid_cols_(spec.grid_cols > 0 ? spec.grid_cols : 1),
      tile_width_(spec.tile_width),
      tile_height_(spec.tile_height),
      tiles_decoded_(0),
      target_tiles_(1),
      row_bytes_(0) {}

Status FrameCompositor::init() {
    if (width_ <= 0 || height_ <= 0 || width_ > kMaxCanvasDim || height_ > kMaxCanvasDim) {
        return Status::Malformed;
    }
    if ((width_ & 1) != 0 || (height_ & 1) != 0) {
        return Status::Malformed;
    }

    int32_t total_tiles = 0;
    if (__builtin_mul_overflow(grid_rows_, grid_cols_, &total_tiles) || total_tiles <= 0 || total_tiles > 256) {
        return Status::Malformed;
    }

    if (total_tiles > 1) {
        int32_t grid_w = 0;
        int32_t grid_h = 0;
        if (tile_width_ <= 0 || tile_height_ <= 0 ||
            __builtin_mul_overflow(tile_width_, grid_cols_, &grid_w) ||
            __builtin_mul_overflow(tile_height_, grid_rows_, &grid_h) ||
            width_ > grid_w || height_ > grid_h) {
            return Status::Malformed;
        }
    }

    int32_t total_bytes = 0;
    if (__builtin_mul_overflow(width_, 4, &total_bytes) ||
        __builtin_mul_overflow(total_bytes, height_, &total_bytes)) {
        return Status::NoMemory;
    }

    target_tiles_ = total_tiles;
    row_bytes_ = static_cast<size_t>(width_) * 4U;
    canvas_.assign(static_cast<size_t>(total_bytes), 0U);
    return Status::Ok;
}

Status FrameCompositor::on_tile_received(const uint8_t *tile_data, size_t tile_len,
                                         const TileFormat &fmt, bool *done) {
    if (done == nullptr || canvas_.empty()) {
        return Status::Malformed;
    }

    int32_t width = fmt.width;
    int32_t height = fmt.height;
    int32_t stride = fmt.stride;

    int32_t crop_left = 0;
    int32_t crop_top = 0;
    int32_t crop_right = width - 1;
    int32_t crop_bottom = height - 1;
    if (fmt.has_crop) {
        crop_left = fmt.crop_left;
        crop_top = fmt.crop_top;
        crop_right = fmt.crop_right;
        crop_bottom = fmt.crop_bottom;
    }

    if (fmt.slice_height > 0) {
        height = fmt.slice_height;
    }

    int32_t crop_width = crop_right - crop_left + 1;
    int32_t crop_height = crop_bottom - crop_top + 1;

    int32_t dst_left = (tiles_decoded_ % grid_cols_) * crop_width;
    int32_t dst_top = (tiles_decoded_ / grid_cols_) * crop_height;
    int32_t dst_right = dst_left + crop_width - 1;
    int32_t dst_bottom = dst_top + crop_height - 1;

    if (dst_right >= width_) {
        crop_right = crop_left + width_ - dst_left - 1;
        dst_right = width_ - 1;
    }
    if (dst_bottom >= height_) {
        crop_bottom = crop_top + height_ - dst_top - 1;
        dst_bottom = height_ - 1;
    }

    *done = (++tiles_decoded_ >= target_tiles_);

    ColorConverter converter;
    return converter.convert_yuv420_to_rgba(
        tile_data, tile_len,
        width, height, stride,
        crop_left, crop_top, crop_right, crop_bottom,
        canvas_.data(),
        static_cast<size_t>(width_), static_cast<size_t>(height_), row_bytes_,
        dst_left, dst_top, dst_right, dst_bottom);
}

uint64_t fnv1a_64(const uint8_t *data, size_t len) {
    uint64_t hash = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(data[i]);
        hash *= 1099511628211ULL;
    }
    return hash;
}

} // namespace media
