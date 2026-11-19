#ifndef AVX512_PORTABLE_SHIM_H
#define AVX512_PORTABLE_SHIM_H

/*
 * Verifier-only portable shim for running compiled AVX-512 VBMI intrinsics
 * during host-side `--local-oracle` checks on CPUs lacking AVX-512 silicon
 * when qemu-x86_64 is not installed on the host.
 * Note: Uses real hardware BMI2 `_bzhi_u64` via <x86gprintrin.h>.
 */
#define _IMMINTRIN_H_INCLUDED
#define VULNHUNTER_AVX512_SHIM 1
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdint.h>
#include <string.h>
#include <x86gprintrin.h>

using __mmask64 = uint64_t;

struct alignas(64) __m512i {
    uint8_t u8[64];
};

static inline __mmask64 _cvtu64_mask64(uint64_t a) { return a; }
static inline uint64_t _cvtmask64_u64(__mmask64 a) { return a; }

static inline __m512i _mm512_load_si512(const void *mem_addr) {
    __m512i r;
    memcpy(r.u8, mem_addr, 64);
    return r;
}

static inline __m512i _mm512_loadu_si512(const void *mem_addr) {
    __m512i r;
    memcpy(r.u8, mem_addr, 64);
    return r;
}

static inline __m512i _mm512_maskz_loadu_epi8(__mmask64 k, const void *mem_addr) {
    __m512i r;
    const uint8_t *p = static_cast<const uint8_t *>(mem_addr);
    for (int i = 0; i < 64; i++) {
        r.u8[i] = ((k >> i) & 1ULL) ? p[i] : 0;
    }
    return r;
}

static inline void _mm512_mask_storeu_epi8(void *mem_addr, __mmask64 k, __m512i a) {
    uint8_t *p = static_cast<uint8_t *>(mem_addr);
    for (int i = 0; i < 64; i++) {
        if ((k >> i) & 1ULL) {
            p[i] = a.u8[i];
        }
    }
}

static inline __m512i _mm512_set1_epi8(char val) {
    __m512i r;
    memset(r.u8, static_cast<unsigned char>(val), 64);
    return r;
}

static inline __m512i _mm512_set1_epi32(int val) {
    __m512i r;
    uint32_t u = static_cast<uint32_t>(val);
    for (int i = 0; i < 64; i += 4) {
        memcpy(r.u8 + i, &u, 4);
    }
    return r;
}

static inline __m512i _mm512_setzero_si512(void) {
    __m512i r;
    memset(r.u8, 0, 64);
    return r;
}

static inline __m512i _mm512_permutexvar_epi8(__m512i idx, __m512i a) {
    __m512i r;
    for (int i = 0; i < 64; i++) {
        r.u8[i] = a.u8[idx.u8[i] & 0x3F];
    }
    return r;
}

static inline __m512i _mm512_permutex2var_epi8(__m512i a, __m512i idx, __m512i b) {
    __m512i r;
    for (int i = 0; i < 64; i++) {
        uint8_t sel = idx.u8[i];
        r.u8[i] = (sel & 0x40) ? b.u8[sel & 0x3F] : a.u8[sel & 0x3F];
    }
    return r;
}

static inline __m512i _mm512_maskz_permutex2var_epi8(__mmask64 k, __m512i a, __m512i idx, __m512i b) {
    __m512i r = _mm512_permutex2var_epi8(a, idx, b);
    for (int i = 0; i < 64; i++) {
        if (((k >> i) & 1ULL) == 0) {
            r.u8[i] = 0;
        }
    }
    return r;
}

static inline __mmask64 _mm512_movepi8_mask(__m512i a) {
    __mmask64 m = 0;
    for (int i = 0; i < 64; i++) {
        if (a.u8[i] & 0x80) {
            m |= (1ULL << i);
        }
    }
    return m;
}

static inline __mmask64 _mm512_cmpeq_epi8_mask(__m512i a, __m512i b) {
    __mmask64 m = 0;
    for (int i = 0; i < 64; i++) {
        if (a.u8[i] == b.u8[i]) {
            m |= (1ULL << i);
        }
    }
    return m;
}

static inline __m512i _mm512_maddubs_epi16(__m512i a, __m512i b) {
    __m512i r;
    for (int i = 0; i < 64; i += 2) {
        int prod = static_cast<int>(a.u8[i]) * static_cast<int>(static_cast<int8_t>(b.u8[i])) +
                   static_cast<int>(a.u8[i + 1]) * static_cast<int>(static_cast<int8_t>(b.u8[i + 1]));
        if (prod > 32767) prod = 32767;
        if (prod < -32768) prod = -32768;
        int16_t s = static_cast<int16_t>(prod);
        memcpy(r.u8 + i, &s, 2);
    }
    return r;
}

static inline __m512i _mm512_madd_epi16(__m512i a, __m512i b) {
    __m512i r;
    for (int i = 0; i < 64; i += 4) {
        int16_t a0, a1, b0, b1;
        memcpy(&a0, a.u8 + i, 2);
        memcpy(&a1, a.u8 + i + 2, 2);
        memcpy(&b0, b.u8 + i, 2);
        memcpy(&b1, b.u8 + i + 2, 2);
        int32_t d = static_cast<int32_t>(a0) * static_cast<int32_t>(b0) +
                    static_cast<int32_t>(a1) * static_cast<int32_t>(b1);
        memcpy(r.u8 + i, &d, 4);
    }
    return r;
}

#ifndef __builtin_cpu_supports
#define __builtin_cpu_supports(feat) (1)
#endif

#endif /* AVX512_PORTABLE_SHIM_H */
