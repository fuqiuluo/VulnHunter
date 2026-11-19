#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# 1. Write analysis report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "file": "src/compositor.cpp",
  "function": "FrameCompositor::on_tile_received",
  "summary": "on_tile_received omits bounds validation on tile dimensions, crop rectangles, and destination offsets (dst_left/dst_top); when dst_top >= height_ on a multi-tile grid, clamping crop_bottom makes crop_height negative and ColorConverter::convert_yuv420_to_rgba treats the negative height as a bottom-up copy, writing past the end of canvas_."
}
EOF

# 2. Generate FDEC binary stream triggering heap OOB write on original compositor
python3 - "$APP_DIR/sample.bin" <<'PY'
import struct
import sys

MAGIC = 0x43454446  # "FDEC"
# Canvas 4x4, grid 2x1, tile 4x2, 2 tiles
header = struct.pack("<IiiiiiiI", MAGIC, 4, 4, 2, 1, 4, 2, 2)

def pack_tile(w, h, stride, slice_h, has_crop, cl, ct, cr, cb, fill=0x41):
    y_len = stride * (slice_h if slice_h > 0 else h)
    uv_len = (stride // 2) * (((slice_h if slice_h > 0 else h) + 1) // 2)
    payload = bytes([fill]) * (y_len + 2 * uv_len)
    return struct.pack("<iiiiIiiiiI", w, h, stride, slice_h, 1 if has_crop else 0, cl, ct, cr, cb, len(payload)) + payload

# Tile 0: 4x4 valid tile -> dst_top=0, dst_bottom=3
t0 = pack_tile(4, 4, 4, 0, False, 0, 0, 0, 0, 0x50)
# Tile 1: crop_bottom=30000 -> crop_height=30001, dst_top=30001 >= canvas height 4 -> negative signed_rows=-29997 -> massive heap OOB write
t1 = pack_tile(4, 2, 4, 0, True, 0, 0, 3, 30000, 0x60)

with open(sys.argv[1], "wb") as f:
    f.write(header + t0 + t1)
PY

# 3. Patch src/compositor.cpp and src/converter.cpp with strict crop/tile/canvas bounds validation
cat > "$APP_DIR/src/compositor.cpp" <<'EOF'
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
            tile_width_ > kMaxCanvasDim || tile_height_ > kMaxCanvasDim ||
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
    if (tile_data == nullptr || done == nullptr || canvas_.empty()) {
        return Status::Malformed;
    }
    if (tiles_decoded_ < 0 || tiles_decoded_ >= target_tiles_) {
        return Status::Malformed;
    }

    int32_t width = fmt.width;
    int32_t height = fmt.height;
    int32_t stride = fmt.stride;
    if (width <= 0 || height <= 0 || width > kMaxCanvasDim || height > kMaxCanvasDim) {
        return Status::Malformed;
    }
    if (stride < width || stride > kMaxCanvasDim * 4 || (stride & 1) != 0) {
        return Status::Malformed;
    }
    if (fmt.slice_height < 0 || fmt.slice_height > kMaxCanvasDim) {
        return Status::Malformed;
    }
    if (fmt.slice_height > 0 && fmt.slice_height < height) {
        return Status::Malformed;
    }

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

    if (crop_left < 0 || crop_top < 0 ||
        crop_right < crop_left || crop_bottom < crop_top ||
        crop_right >= width || crop_bottom >= height ||
        (crop_left & 1) != 0) {
        return Status::Malformed;
    }

    int32_t plane_height = (fmt.slice_height > 0) ? fmt.slice_height : height;
    int32_t crop_width = crop_right - crop_left + 1;
    int32_t crop_height = crop_bottom - crop_top + 1;

    if (target_tiles_ > 1 && (crop_width != tile_width_ || crop_height != tile_height_)) {
        return Status::Malformed;
    }

    int32_t dst_left = 0;
    int32_t dst_top = 0;
    if (__builtin_mul_overflow(tiles_decoded_ % grid_cols_, crop_width, &dst_left) ||
        __builtin_mul_overflow(tiles_decoded_ / grid_cols_, crop_height, &dst_top)) {
        return Status::Malformed;
    }
    if (dst_left < 0 || dst_top < 0 || dst_left >= width_ || dst_top >= height_) {
        return Status::Malformed;
    }

    int32_t dst_right = 0;
    int32_t dst_bottom = 0;
    if (__builtin_add_overflow(dst_left, crop_width - 1, &dst_right) ||
        __builtin_add_overflow(dst_top, crop_height - 1, &dst_bottom)) {
        return Status::Malformed;
    }

    if (dst_right >= width_) {
        crop_right = crop_left + (width_ - dst_left) - 1;
        dst_right = width_ - 1;
    }
    if (dst_bottom >= height_) {
        crop_bottom = crop_top + (height_ - dst_top) - 1;
        dst_bottom = height_ - 1;
    }

    if (crop_right < crop_left || crop_bottom < crop_top ||
        dst_right < dst_left || dst_bottom < dst_top ||
        dst_right >= width_ || dst_bottom >= height_) {
        return Status::Malformed;
    }

    ColorConverter converter;
    Status st = converter.convert_yuv420_to_rgba(
        tile_data, tile_len,
        static_cast<size_t>(width), static_cast<size_t>(plane_height), static_cast<size_t>(stride),
        static_cast<size_t>(crop_left), static_cast<size_t>(crop_top),
        static_cast<size_t>(crop_right), static_cast<size_t>(crop_bottom),
        canvas_.data(),
        static_cast<size_t>(width_), static_cast<size_t>(height_), row_bytes_,
        static_cast<size_t>(dst_left), static_cast<size_t>(dst_top),
        static_cast<size_t>(dst_right), static_cast<size_t>(dst_bottom));
    if (st != Status::Ok) {
        return st;
    }

    *done = (++tiles_decoded_ >= target_tiles_);
    return Status::Ok;
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
EOF

cat > "$APP_DIR/src/converter.cpp" <<'EOF'
#include "compositor.hpp"

#include <algorithm>
#include <limits>

namespace media {

namespace {
inline uint8_t clamp_u8(int v) {
    return static_cast<uint8_t>(std::clamp(v, 0, 255));
}
} // namespace

BitmapView::BitmapView(uint8_t *ptr, size_t w, size_t h, size_t s,
                       size_t cl, size_t ct, size_t cr, size_t cb, size_t bytes_per_pixel)
    : bits(ptr),
      width(w),
      height(h),
      stride(s != 0 ? s : w * bytes_per_pixel),
      crop_left(cl),
      crop_top(ct),
      crop_right(cr),
      crop_bottom(cb),
      bpp(bytes_per_pixel) {}

bool BitmapView::is_valid() const {
    if (bits == nullptr || width == 0U || height == 0U || bpp == 0U || stride == 0U) {
        return false;
    }
    if ((stride & 1U) != 0U) {
        return false;
    }
    if (crop_left > crop_right || crop_top > crop_bottom) {
        return false;
    }
    if (crop_right >= width || crop_bottom >= height) {
        return false;
    }
    if (width > std::numeric_limits<size_t>::max() / bpp) {
        return false;
    }
    if (stride < bpp * width || stride < bpp * crop_width()) {
        return false;
    }
    return true;
}

Status ColorConverter::convert_yuv420_to_rgba(
    const uint8_t *src_bits, size_t src_len,
    size_t src_width, size_t src_height, size_t src_stride,
    size_t src_crop_left, size_t src_crop_top,
    size_t src_crop_right, size_t src_crop_bottom,
    uint8_t *dst_bits,
    size_t dst_width, size_t dst_height, size_t dst_stride,
    size_t dst_crop_left, size_t dst_crop_top,
    size_t dst_crop_right, size_t dst_crop_bottom) const {
    if (src_bits == nullptr || dst_bits == nullptr) {
        return Status::Malformed;
    }

    BitmapView src(const_cast<uint8_t *>(src_bits),
                   src_width, src_height, src_stride,
                   src_crop_left, src_crop_top, src_crop_right, src_crop_bottom, 1U);
    BitmapView dst(dst_bits,
                   dst_width, dst_height, dst_stride,
                   dst_crop_left, dst_crop_top, dst_crop_right, dst_crop_bottom, 4U);

    if (!(src.is_valid() &&
          dst.is_valid() &&
          (src.crop_left & 1U) == 0U &&
          src.crop_width() == dst.crop_width() &&
          src.crop_height() == dst.crop_height())) {
        return Status::Unsupported;
    }

    if (src.stride > std::numeric_limits<size_t>::max() / src.height) {
        return Status::Malformed;
    }
    const size_t y_plane_bytes = src.stride * src.height;
    const size_t uv_stride = src.stride / 2U;
    if (uv_stride == 0U) {
        return Status::Malformed;
    }
    const size_t uv_rows = (src.height + 1U) / 2U;
    if (uv_stride > std::numeric_limits<size_t>::max() / uv_rows) {
        return Status::Malformed;
    }
    const size_t uv_plane_bytes = uv_stride * uv_rows;
    if (uv_plane_bytes > std::numeric_limits<size_t>::max() / 2U ||
        y_plane_bytes > std::numeric_limits<size_t>::max() - 2U * uv_plane_bytes ||
        y_plane_bytes + 2U * uv_plane_bytes > src_len) {
        return Status::Malformed;
    }

    const size_t row_count = src.crop_height();
    const size_t col_count = src.crop_width();
    const uint8_t *u_plane = src.bits + y_plane_bytes;
    const uint8_t *v_plane = u_plane + uv_plane_bytes;

    for (size_t y = 0; y < row_count; ++y) {
        const size_t src_y_row = src.crop_top + y;
        const size_t src_uv_row = src_y_row / 2U;
        const uint8_t *src_y = src.bits + src_y_row * src.stride + src.crop_left;
        const uint8_t *src_u = u_plane + src_uv_row * uv_stride + (src.crop_left / 2U);
        const uint8_t *src_v = v_plane + src_uv_row * uv_stride + (src.crop_left / 2U);
        uint8_t *dst_row = dst.bits + (dst.crop_top + y) * dst.stride + dst.crop_left * dst.bpp;

        for (size_t x = 0; x < col_count; ++x) {
            const int y_val = static_cast<int>(src_y[x]) - 16;
            const int u_val = static_cast<int>(src_u[x / 2U]) - 128;
            const int v_val = static_cast<int>(src_v[x / 2U]) - 128;

            const int c = 298 * std::max(0, y_val);
            uint8_t *px = dst_row + x * 4U;
            px[0] = clamp_u8((c + 409 * v_val + 128) >> 8);
            px[1] = clamp_u8((c - 100 * u_val - 208 * v_val + 128) >> 8);
            px[2] = clamp_u8((c + 516 * u_val + 128) >> 8);
            px[3] = 0xFFU;
        }
    }

    return Status::Ok;
}

} // namespace media
EOF

make -C "$APP_DIR" clean all
