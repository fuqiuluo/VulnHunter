#include <immintrin.h>
#include <jni.h>
#include <stdint.h>

namespace {

alignas(64) constexpr uint8_t kLoLutStd[64] = {
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80,   62, 0x80, 0x80, 0x80,   63, /* '+' = 62, '/' = 63 */
      52,   53,   54,   55,   56,   57,   58,   59, /* '0'..'7' */
      60,   61, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80  /* '8'..'9' */
};

alignas(64) constexpr uint8_t kLoLutUrl[64] = {
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80,   62, 0x80, 0x80, /* '-' = 62 */
      52,   53,   54,   55,   56,   57,   58,   59, /* '0'..'7' */
      60,   61, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80  /* '8'..'9' */
};

alignas(64) constexpr uint8_t kHiLutStd[64] = {
    0x80,    0,    1,    2,    3,    4,    5,    6, /* '@', 'A'..'G' */
       7,    8,    9,   10,   11,   12,   13,   14, /* 'H'..'O' */
      15,   16,   17,   18,   19,   20,   21,   22, /* 'P'..'W' */
      23,   24,   25, 0x80, 0x80, 0x80, 0x80, 0x80, /* 'X'..'Z' */
    0x80,   26,   27,   28,   29,   30,   31,   32, /* '`', 'a'..'g' */
      33,   34,   35,   36,   37,   38,   39,   40, /* 'h'..'o' */
      41,   42,   43,   44,   45,   46,   47,   48, /* 'p'..'w' */
      49,   50,   51, 0x80, 0x80, 0x80, 0x80, 0x80  /* 'x'..'z' */
};

alignas(64) constexpr uint8_t kHiLutUrl[64] = {
    0x80,    0,    1,    2,    3,    4,    5,    6,
       7,    8,    9,   10,   11,   12,   13,   14,
      15,   16,   17,   18,   19,   20,   21,   22,
      23,   24,   25, 0x80, 0x80, 0x80, 0x80,   63, /* '_' = 63 */
    0x80,   26,   27,   28,   29,   30,   31,   32,
      33,   34,   35,   36,   37,   38,   39,   40,
      41,   42,   43,   44,   45,   46,   47,   48,
      49,   50,   51, 0x80, 0x80, 0x80, 0x80, 0x80
};

alignas(64) constexpr uint8_t kPackPerm64To48[64] = {
     2,  1,  0,   6,  5,  4,  10,  9,  8,  14, 13, 12,
    18, 17, 16,  22, 21, 20,  26, 25, 24,  30, 29, 28,
    34, 33, 32,  38, 37, 36,  42, 41, 40,  46, 45, 44,
    50, 49, 48,  54, 53, 52,  58, 57, 56,  62, 61, 60,
     3,  3,  3,   3,  3,  3,   3,  3,  3,   3,  3,  3,
     3,  3,  3,   3
};

inline __m512i pack_sextets_vbmi(__m512i sextets, __m512i pack_perm) {
    // Merge adjacent 6-bit pairs into 12-bit words: (s0 << 6) | s1
    const __m512i merged16 = _mm512_maddubs_epi16(sextets, _mm512_set1_epi32(0x01400140));
    // Merge 12-bit word pairs into 24-bit dwords: (w0 << 12) | w1
    const __m512i merged32 = _mm512_madd_epi16(merged16, _mm512_set1_epi32(0x00011000));
    // Compact 16 x 3 big-endian payload bytes into lanes 0..47 using AVX-512 VBMI vpermb
    return _mm512_permutexvar_epi8(pack_perm, merged32);
}

int decode_block_avx512_vbmi(
    const uint8_t *src_ptr, int sp, int sl, uint8_t *dst_ptr, int dp, bool is_url) {
    const __m512i lo_lut = _mm512_load_si512(is_url ? kLoLutUrl : kLoLutStd);
    const __m512i hi_lut = _mm512_load_si512(is_url ? kHiLutUrl : kHiLutStd);
    const __m512i pack_perm = _mm512_load_si512(kPackPerm64To48);

    const int start_dp = dp;
    int length = sl - sp;

    // Bulk 64-byte AVX-512 VBMI loop (64 ASCII chars -> 48 output bytes per iteration)
    while (length >= 64) {
        __m512i raw_vec = _mm512_loadu_si512(reinterpret_cast<const void *>(src_ptr + sp));
        __m512i sextets = _mm512_permutex2var_epi8(lo_lut, raw_vec, hi_lut);
        __mmask64 invalid = _mm512_movepi8_mask(raw_vec) | _mm512_movepi8_mask(sextets);
        if (invalid != 0) {
            return dp - start_dp;
        }

        __m512i packed = pack_sextets_vbmi(sextets, pack_perm);
        _mm512_mask_storeu_epi8(dst_ptr + dp, static_cast<__mmask64>(0x0000FFFFFFFFFFFFULL), packed);

        sp += 64;
        dp += 48;
        length -= 64;
    }

    // Process remaining 1 to 63 tail bytes
    if (length > 0) {
        uint64_t in_mask = _bzhi_u64(~0ULL, static_cast<uint32_t>(length));
        int pad = 0;
        if (src_ptr[sp + length - 1] == '=') {
            pad++;
            in_mask >>= 1;
            if (length > 1 && src_ptr[sp + length - 2] == '=') {
                pad++;
                in_mask >>= 1;
            }
        }

        __m512i raw_vec = _mm512_maskz_loadu_epi8(static_cast<__mmask64>(in_mask), src_ptr + sp);
        __m512i sextets = _mm512_maskz_permutex2var_epi8(
            static_cast<__mmask64>(in_mask), lo_lut, raw_vec, hi_lut);
        __mmask64 invalid = (_mm512_movepi8_mask(raw_vec) | _mm512_movepi8_mask(sextets)) &
                            static_cast<__mmask64>(in_mask);
        if (invalid != 0) {
            return dp - start_dp;
        }

        __m512i packed = pack_sextets_vbmi(sextets, pack_perm);
        int output_size = ((length * 3) >> 2) - pad;
        __mmask64 out_mask = static_cast<__mmask64>(_bzhi_u64(~0ULL, static_cast<uint32_t>(output_size)));
        _mm512_mask_storeu_epi8(dst_ptr + dp, out_mask, packed);
        dp += output_size;
    }

    return dp - start_dp;
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL Java_codec_Base64Codec_decodeBlockAvx512(
    JNIEnv *env,
    jclass,
    jbyteArray src,
    jint sp,
    jint sl,
    jbyteArray dst,
    jint dp,
    jboolean is_url) {
    jbyte *src_elems = env->GetByteArrayElements(src, nullptr);
    if (src_elems == nullptr) {
        return 0;
    }
    jbyte *dst_elems = env->GetByteArrayElements(dst, nullptr);
    if (dst_elems == nullptr) {
        env->ReleaseByteArrayElements(src, src_elems, JNI_ABORT);
        return 0;
    }

    int decoded = decode_block_avx512_vbmi(
        reinterpret_cast<const uint8_t *>(src_elems),
        static_cast<int>(sp),
        static_cast<int>(sl),
        reinterpret_cast<uint8_t *>(dst_elems),
        static_cast<int>(dp),
        is_url == JNI_TRUE);

    env->ReleaseByteArrayElements(dst, dst_elems, 0);
    env->ReleaseByteArrayElements(src, src_elems, JNI_ABORT);
    return decoded;
}
