#include "compositor.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

namespace {

uint32_t read_u32_le(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

int32_t read_i32_le(const uint8_t *p) {
    return static_cast<int32_t>(read_u32_le(p));
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 2) {
        std::fprintf(stderr, "Usage: %s <stream.bin>\n", argv[0]);
        return 1;
    }

    std::ifstream in(argv[1], std::ios::binary | std::ios::ate);
    if (!in) {
        std::fprintf(stderr, "Failed to open input file\n");
        return 1;
    }

    const std::streamsize file_len = in.tellg();
    if (file_len < 32 || file_len > (4 * 1024 * 1024)) {
        return 1;
    }
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> buf(static_cast<size_t>(file_len));
    if (!in.read(reinterpret_cast<char *>(buf.data()), file_len)) {
        return 1;
    }

    if (read_u32_le(buf.data()) != media::kStreamMagic) {
        return 1;
    }

    media::CanvasSpec spec{};
    spec.width = read_i32_le(buf.data() + 4);
    spec.height = read_i32_le(buf.data() + 8);
    spec.grid_rows = read_i32_le(buf.data() + 12);
    spec.grid_cols = read_i32_le(buf.data() + 16);
    spec.tile_width = read_i32_le(buf.data() + 20);
    spec.tile_height = read_i32_le(buf.data() + 24);
    const uint32_t tile_count = read_u32_le(buf.data() + 28);
    if (tile_count == 0 || tile_count > 256) {
        return 1;
    }

    media::FrameCompositor compositor(spec);
    if (compositor.init() != media::Status::Ok) {
        return 1;
    }

    size_t cursor = 32U;
    bool done = false;
    for (uint32_t i = 0; i < tile_count && !done; ++i) {
        if (cursor + 40U > buf.size()) {
            return 1;
        }
        media::TileFormat fmt{};
        fmt.width = read_i32_le(buf.data() + cursor + 0);
        fmt.height = read_i32_le(buf.data() + cursor + 4);
        fmt.stride = read_i32_le(buf.data() + cursor + 8);
        fmt.slice_height = read_i32_le(buf.data() + cursor + 12);
        fmt.has_crop = read_u32_le(buf.data() + cursor + 16) != 0U;
        fmt.crop_left = read_i32_le(buf.data() + cursor + 20);
        fmt.crop_top = read_i32_le(buf.data() + cursor + 24);
        fmt.crop_right = read_i32_le(buf.data() + cursor + 28);
        fmt.crop_bottom = read_i32_le(buf.data() + cursor + 32);
        const uint32_t payload_len = read_u32_le(buf.data() + cursor + 36);
        cursor += 40U;

        if (cursor + payload_len > buf.size()) {
            return 1;
        }
        if (compositor.on_tile_received(buf.data() + cursor, payload_len, fmt, &done) != media::Status::Ok) {
            return 1;
        }
        cursor += payload_len;
    }

    if (!done) {
        return 1;
    }

    const auto &rgba = compositor.rgba_bytes();
    const uint64_t digest = media::fnv1a_64(rgba.data(), rgba.size());
    std::printf("OK canvas=%dx%d bytes=%zu fnv1a=%016llx\n",
                compositor.width(), compositor.height(), rgba.size(),
                static_cast<unsigned long long>(digest));
    return 0;
}
