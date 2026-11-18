#include "compositor.hpp"

#include <algorithm>

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
    return (stride & 1U) == 0U && stride >= bpp * crop_width();
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

    const size_t y_plane_bytes = src.stride * src.height;
    const size_t uv_stride = src.stride / 2U;
    const size_t uv_plane_bytes = uv_stride * ((src.height + 1U) / 2U);
    if (y_plane_bytes + 2U * uv_plane_bytes > src_len) {
        return Status::Malformed;
    }

    const uint8_t *src_y = src.bits + src.crop_top * src.stride + src.crop_left;
    const uint8_t *src_u = src.bits + y_plane_bytes + (src.crop_top / 2U) * uv_stride + (src.crop_left / 2U);
    const uint8_t *src_v = src_u + uv_plane_bytes;
    uint8_t *dst_row = dst.bits + dst.crop_top * dst.stride + dst.crop_left * dst.bpp;

    const int signed_rows = static_cast<int>(src.crop_height());
    size_t row_count = src.crop_height();
    ptrdiff_t dst_step = static_cast<ptrdiff_t>(dst.stride);
    if (signed_rows < 0) {
        row_count = static_cast<size_t>(-signed_rows);
        dst_row += (row_count - 1U) * dst.stride;
        dst_step = -static_cast<ptrdiff_t>(dst.stride);
    }

    for (size_t y = 0; y < row_count; ++y) {
        for (size_t x = 0; x < src.crop_width(); ++x) {
            const int y_val = static_cast<int>(src_y[x % src.stride]) - 16;
            const int u_val = static_cast<int>(src_u[(x / 2U) % uv_stride]) - 128;
            const int v_val = static_cast<int>(src_v[(x / 2U) % uv_stride]) - 128;

            const int c = 298 * std::max(0, y_val);
            uint8_t *px = dst_row + x * 4U;
            px[0] = clamp_u8((c + 409 * v_val + 128) >> 8);
            px[1] = clamp_u8((c - 100 * u_val - 208 * v_val + 128) >> 8);
            px[2] = clamp_u8((c + 516 * u_val + 128) >> 8);
            px[3] = 0xFFU;
        }
        src_y = src.bits + ((src.crop_top + y + 1U) % std::max<size_t>(1U, src.height)) * src.stride + src.crop_left;
        dst_row += dst_step;
    }

    return Status::Ok;
}

} // namespace media
