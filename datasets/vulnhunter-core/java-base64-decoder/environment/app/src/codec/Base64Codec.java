package codec;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * RFC 4648 and RFC 2045 Base64 encoder and decoder with AVX-512 VBMI JNI acceleration.
 */
public class Base64Codec {

    static {
        System.loadLibrary("b64avx512");
    }

    private Base64Codec() {}

    static native int decodeBlockAvx512(
        byte[] src, int sp, int sl, byte[] dst, int dp, boolean isURL);

    public static Encoder getEncoder() {
        return Encoder.RFC4648;
    }

    public static Encoder getUrlEncoder() {
        return Encoder.RFC4648_URLSAFE;
    }

    public static Decoder getDecoder() {
        return Decoder.RFC4648;
    }

    public static Decoder getUrlDecoder() {
        return Decoder.RFC4648_URLSAFE;
    }

    public static Decoder getMimeDecoder() {
        return Decoder.RFC2045;
    }

    public static class Encoder {
        private final boolean isURL;
        private final boolean doPadding;

        static final char[] toBase64 = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };

        static final char[] toBase64URL = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
        };

        static final Encoder RFC4648 = new Encoder(false, true);
        static final Encoder RFC4648_URLSAFE = new Encoder(true, true);

        private Encoder(boolean isURL, boolean doPadding) {
            this.isURL = isURL;
            this.doPadding = doPadding;
        }

        public Encoder withoutPadding() {
            if (!doPadding) {
                return this;
            }
            return new Encoder(isURL, false);
        }

        private int encodedOutLength(int srclen) {
            if (doPadding) {
                return 4 * ((srclen + 2) / 3);
            }
            int n = srclen % 3;
            return 4 * (srclen / 3) + (n == 0 ? 0 : n + 1);
        }

        public byte[] encode(byte[] src) {
            int len = encodedOutLength(src.length);
            byte[] dst = new byte[len];
            int ret = encode0(src, 0, src.length, dst);
            if (ret != dst.length) {
                return Arrays.copyOf(dst, ret);
            }
            return dst;
        }

        public String encodeToString(byte[] src) {
            byte[] encoded = encode(src);
            return new String(encoded, StandardCharsets.ISO_8859_1);
        }

        private int encode0(byte[] src, int off, int end, byte[] dst) {
            char[] base64 = isURL ? toBase64URL : toBase64;
            int sp = off;
            int slen = (end - off) / 3 * 3;
            int sl = off + slen;
            int dp = 0;
            while (sp < sl) {
                int bits = (src[sp++] & 0xff) << 16 |
                           (src[sp++] & 0xff) <<  8 |
                           (src[sp++] & 0xff);
                dst[dp++] = (byte) base64[(bits >>> 18) & 0x3f];
                dst[dp++] = (byte) base64[(bits >>> 12) & 0x3f];
                dst[dp++] = (byte) base64[(bits >>> 6)  & 0x3f];
                dst[dp++] = (byte) base64[bits & 0x3f];
            }
            if (sp < end) {
                int b0 = src[sp++] & 0xff;
                dst[dp++] = (byte) base64[b0 >> 2];
                if (sp == end) {
                    dst[dp++] = (byte) base64[(b0 << 4) & 0x3f];
                    if (doPadding) {
                        dst[dp++] = '=';
                        dst[dp++] = '=';
                    }
                } else {
                    int b1 = src[sp++] & 0xff;
                    dst[dp++] = (byte) base64[(b0 << 4) & 0x3f | (b1 >> 4)];
                    dst[dp++] = (byte) base64[(b1 << 2) & 0x3f];
                    if (doPadding) {
                        dst[dp++] = '=';
                    }
                }
            }
            return dp;
        }
    }

    public static class Decoder {
        private final boolean isURL;
        private final boolean isMIME;

        static final int[] fromBase64 = new int[256];
        static final int[] fromBase64URL = new int[256];

        static {
            Arrays.fill(fromBase64, -1);
            for (int i = 0; i < Encoder.toBase64.length; i++) {
                fromBase64[Encoder.toBase64[i]] = i;
            }
            fromBase64['='] = -2;

            Arrays.fill(fromBase64URL, -1);
            for (int i = 0; i < Encoder.toBase64URL.length; i++) {
                fromBase64URL[Encoder.toBase64URL[i]] = i;
            }
            fromBase64URL['='] = -2;
        }

        static final Decoder RFC4648 = new Decoder(false, false);
        static final Decoder RFC4648_URLSAFE = new Decoder(true, false);
        static final Decoder RFC2045 = new Decoder(false, true);

        private Decoder(boolean isURL, boolean isMIME) {
            this.isURL = isURL;
            this.isMIME = isMIME;
        }

        public byte[] decode(byte[] src) {
            Objects.requireNonNull(src);
            byte[] dst = new byte[decodedOutLength(src, 0, src.length)];
            int ret = decode0(src, 0, src.length, dst);
            if (ret != dst.length) {
                dst = Arrays.copyOf(dst, ret);
            }
            return dst;
        }

        public byte[] decode(String src) {
            return decode(src.getBytes(StandardCharsets.ISO_8859_1));
        }

        public int decode(byte[] src, byte[] dst) {
            Objects.requireNonNull(src);
            Objects.requireNonNull(dst);
            int len = decodedOutLength(src, 0, src.length);
            if (dst.length < len || len == -1) {
                throw new IllegalArgumentException(
                    "Output byte array is too small for decoding all input bytes");
            }
            return decode0(src, 0, src.length, dst);
        }

        private int decodedOutLength(byte[] src, int sp, int sl) {
            int[] base64 = isURL ? fromBase64URL : fromBase64;
            int paddings = 0;
            int len = sl - sp;
            if (len == 0) {
                return 0;
            }
            if (len < 2) {
                if (isMIME && base64[0] == -1) {
                    return 0;
                }
                throw new IllegalArgumentException(
                    "Input byte[] should at least have 2 bytes for base64 bytes");
            }
            if (isMIME) {
                int n = 0;
                while (sp < sl) {
                    int b = src[sp++] & 0xff;
                    if (b == '=') {
                        len -= (sl - sp + 1);
                        break;
                    }
                    if ((b = base64[b]) == -1) {
                        n++;
                    }
                }
                len -= n;
            } else {
                if (src[sl - 1] == '=') {
                    paddings++;
                    if (src[sl - 2] == '=') {
                        paddings++;
                    }
                }
            }
            if (paddings == 0 && (len & 0x3) != 0) {
                paddings = 4 - (len & 0x3);
            }
            return 3 * (int) ((len + 3L) / 4) - paddings;
        }

        private int decodeBlock(byte[] src, int sp, int sl, byte[] dst, int dp, boolean isURL, boolean isMIME) {
            if (!isMIME && (sl - sp) >= 64) {
                return decodeBlockAvx512(src, sp, sl, dst, dp, isURL);
            }
            int[] base64 = isURL ? fromBase64URL : fromBase64;
            int sl0 = sp + ((sl - sp) & ~0x3);
            int new_dp = dp;
            while (sp < sl0) {
                int b1 = base64[src[sp++] & 0xff];
                int b2 = base64[src[sp++] & 0xff];
                int b3 = base64[src[sp++] & 0xff];
                int b4 = base64[src[sp++] & 0xff];
                if ((b1 | b2 | b3 | b4) < 0) {
                    return new_dp - dp;
                }
                int bits0 = b1 << 18 | b2 << 12 | b3 << 6 | b4;
                dst[new_dp++] = (byte) (bits0 >> 16);
                dst[new_dp++] = (byte) (bits0 >> 8);
                dst[new_dp++] = (byte) bits0;
            }
            return new_dp - dp;
        }

        private int decode0(byte[] src, int sp, int sl, byte[] dst) {
            int[] base64 = isURL ? fromBase64URL : fromBase64;
            int dp = 0;
            int bits = 0;
            int shiftto = 18;

            while (sp < sl) {
                if (shiftto == 18 && sp < sl - 4) {
                    int dl = decodeBlock(src, sp, sl, dst, dp, isURL, isMIME);
                    int chars_decoded = ((dl + 2) / 3) * 4;
                    sp += chars_decoded;
                    dp += dl;
                }
                if (sp >= sl) {
                    break;
                }
                int b = src[sp++] & 0xff;
                if ((b = base64[b]) < 0) {
                    if (b == -2) {
                        if ((shiftto == 6 && (sp == sl || src[sp++] != '=')) ||
                            shiftto == 18) {
                            throw new IllegalArgumentException(
                                "Input byte array has wrong 4-byte ending unit");
                        }
                        break;
                    }
                    if (isMIME) {
                        continue;
                    } else {
                        throw new IllegalArgumentException(
                            "Illegal base64 character " + Integer.toString(src[sp - 1], 16));
                    }
                }
                bits |= (b << shiftto);
                shiftto -= 6;
                if (shiftto < 0) {
                    dst[dp++] = (byte) (bits >> 16);
                    dst[dp++] = (byte) (bits >> 8);
                    dst[dp++] = (byte) bits;
                    shiftto = 18;
                    bits = 0;
                }
            }
            if (shiftto == 6) {
                dst[dp++] = (byte) (bits >> 16);
            } else if (shiftto == 0) {
                dst[dp++] = (byte) (bits >> 16);
                dst[dp++] = (byte) (bits >> 8);
            } else if (shiftto == 12) {
                throw new IllegalArgumentException(
                    "Last unit does not have enough valid bits");
            }
            while (sp < sl) {
                if (isMIME && base64[src[sp++] & 0xff] < 0) {
                    continue;
                }
                throw new IllegalArgumentException(
                    "Input byte array has incorrect ending byte at " + sp);
            }
            return dp;
        }
    }
}
