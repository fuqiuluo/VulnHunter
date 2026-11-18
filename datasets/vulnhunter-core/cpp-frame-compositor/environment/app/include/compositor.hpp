#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace media {

constexpr uint32_t kStreamMagic = 0x43454446U; // "FDEC"
constexpr int32_t kMaxCanvasDim = 4096;

enum class Status : int {
    Ok = 0,
    Malformed = -1,
    Unsupported = -2,
    NoMemory = -3,
};

struct CanvasSpec {
    int32_t width;
    int32_t height;
    int32_t grid_rows;
    int32_t grid_cols;
    int32_t tile_width;
    int32_t tile_height;
};

struct TileFormat {
    int32_t width;
    int32_t height;
    int32_t stride;
    int32_t slice_height;
    bool has_crop;
    int32_t crop_left;
    int32_t crop_top;
    int32_t crop_right;
    int32_t crop_bottom;
};

struct BitmapView {
    uint8_t *bits;
    size_t width;
    size_t height;
    size_t stride;
    size_t crop_left;
    size_t crop_top;
    size_t crop_right;
    size_t crop_bottom;
    size_t bpp;

    BitmapView(uint8_t *ptr, size_t w, size_t h, size_t s,
               size_t cl, size_t ct, size_t cr, size_t cb, size_t bytes_per_pixel);

    size_t crop_width() const { return crop_right - crop_left + 1; }
    size_t crop_height() const { return crop_bottom - crop_top + 1; }
    bool is_valid() const;
};

class ColorConverter {
public:
    Status convert_yuv420_to_rgba(
        const uint8_t *src_bits, size_t src_len,
        size_t src_width, size_t src_height, size_t src_stride,
        size_t src_crop_left, size_t src_crop_top,
        size_t src_crop_right, size_t src_crop_bottom,
        uint8_t *dst_bits,
        size_t dst_width, size_t dst_height, size_t dst_stride,
        size_t dst_crop_left, size_t dst_crop_top,
        size_t dst_crop_right, size_t dst_crop_bottom) const;
};

class FrameCompositor {
public:
    explicit FrameCompositor(const CanvasSpec &spec);

    Status init();
    Status on_tile_received(const uint8_t *tile_data, size_t tile_len,
                            const TileFormat &fmt, bool *done);

    const std::vector<uint8_t> &rgba_bytes() const { return canvas_; }
    int32_t width() const { return width_; }
    int32_t height() const { return height_; }

private:
    int32_t width_;
    int32_t height_;
    int32_t grid_rows_;
    int32_t grid_cols_;
    int32_t tile_width_;
    int32_t tile_height_;
    int32_t tiles_decoded_;
    int32_t target_tiles_;
    size_t row_bytes_;
    std::vector<uint8_t> canvas_;
};

uint64_t fnv1a_64(const uint8_t *data, size_t len);

} // namespace media
