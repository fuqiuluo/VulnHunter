package io.stonegate.federation;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Transcodes JWS {@code ES256} ({@code secp256r1} / NIST P-256) signatures between 64-byte IEEE
 * P1363 fixed-width {@code (r || s)} representation and minimal ASN.1 DER {@code SEQUENCE}.
 *
 * <p>Contract (RFC 7518 §3.4 &amp; FIPS 186-5):
 * <ul>
 *   <li>A P1363 P-256 signature is 64 octets: two unsigned 32-octet big-endian scalars {@code r, s}.</li>
 *   <li>Both {@code r} and {@code s} MUST lie strictly within {@code [1, P256_ORDER_N - 1]}
 *       (RFC 7518 §3.4 permits any scalar in {@code [1, N - 1]} without restricting {@code s} to
 *       {@code N / 2}). Out-of-range scalars ({@code 0} or {@code >= P256_ORDER_N}) MUST throw
 *       {@link IllegalArgumentException}.</li>
 *   <li>ASN.1 DER encoding MUST use minimal definite lengths and minimal positive {@code INTEGER}s.</li>
 * </ul>
 */
public final class EcdsaDerCodec {

    public static final int P256_COORD_BYTES = 32;
    public static final int P256_SIG_BYTES = 64;
    public static final BigInteger P256_ORDER_N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    public static final BigInteger P256_HALF_ORDER = P256_ORDER_N.shiftRight(1);

    private EcdsaDerCodec() {}

    /** Converts a 64-byte IEEE P1363 {@code (r || s)} P-256 signature into minimal ASN.1 DER. */
    public static byte[] p1363ToDer(byte[] p1363Signature) {
        if (p1363Signature == null || p1363Signature.length != P256_SIG_BYTES) {
            throw new IllegalArgumentException("ES256 P1363 signature must be 64 bytes");
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(p1363Signature, 0, P256_COORD_BYTES));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(p1363Signature, P256_COORD_BYTES, P256_SIG_BYTES));

        byte[] rDer = r.toByteArray();
        byte[] sDer = s.toByteArray();
        int seqBodyLen = 2 + rDer.length + 2 + sDer.length;
        byte[] out = new byte[(seqBodyLen < 128 ? 2 : 3) + seqBodyLen];
        int offset = 0;
        out[offset++] = 0x30;
        if (seqBodyLen < 128) {
            out[offset++] = (byte) seqBodyLen;
        } else {
            out[offset++] = (byte) 0x81;
            out[offset++] = (byte) seqBodyLen;
        }
        out[offset++] = 0x02;
        out[offset++] = (byte) rDer.length;
        System.arraycopy(rDer, 0, out, offset, rDer.length);
        offset += rDer.length;
        out[offset++] = 0x02;
        out[offset++] = (byte) sDer.length;
        System.arraycopy(sDer, 0, out, offset, sDer.length);
        return out;
    }

    /** Converts a minimal ASN.1 DER ECDSA signature into a 64-byte IEEE P1363 {@code (r || s)} buffer. */
    public static byte[] derToP1363(byte[] derSignature) {
        if (derSignature == null || derSignature.length < 8 || derSignature[0] != 0x30) {
            throw new IllegalArgumentException("Malformed DER ECDSA signature");
        }
        int offset = 1;
        int lenByte = derSignature[offset++] & 0xFF;
        int seqLen;
        if ((lenByte & 0x80) == 0) {
            seqLen = lenByte;
        } else if (lenByte == 0x81 && offset < derSignature.length) {
            seqLen = derSignature[offset++] & 0xFF;
            if (seqLen < 128) throw new IllegalArgumentException("Non-minimal DER SEQUENCE length");
        } else {
            throw new IllegalArgumentException("Unsupported DER SEQUENCE length form");
        }
        if (offset + seqLen != derSignature.length) {
            throw new IllegalArgumentException("DER SEQUENCE length mismatch");
        }

        DecodedInt rParsed = readDerPositiveInteger(derSignature, offset);
        DecodedInt sParsed = readDerPositiveInteger(derSignature, rParsed.nextOffset);
        if (sParsed.nextOffset != derSignature.length) {
            throw new IllegalArgumentException("Trailing fields in DER SEQUENCE");
        }
        validateScalarRange(rParsed.value, "r");
        validateScalarRange(sParsed.value, "s");

        byte[] p1363 = new byte[P256_SIG_BYTES];
        System.arraycopy(encodeUnsignedFixedWidth(rParsed.value, P256_COORD_BYTES), 0, p1363, 0, P256_COORD_BYTES);
        System.arraycopy(encodeUnsignedFixedWidth(sParsed.value, P256_COORD_BYTES), 0, p1363, P256_COORD_BYTES, P256_COORD_BYTES);
        return p1363;
    }

    public static BigInteger[] decodeScalarPair(byte[] p1363Signature) {
        if (p1363Signature == null || p1363Signature.length != P256_SIG_BYTES) {
            throw new IllegalArgumentException("ES256 P1363 signature must be 64 bytes");
        }
        return new BigInteger[]{
                new BigInteger(1, Arrays.copyOfRange(p1363Signature, 0, P256_COORD_BYTES)),
                new BigInteger(1, Arrays.copyOfRange(p1363Signature, P256_COORD_BYTES, P256_SIG_BYTES))
        };
    }

    public static byte[] encodeUnsignedFixedWidth(BigInteger value, int widthBytes) {
        if (value == null || value.signum() < 0) throw new IllegalArgumentException("Value must be non-negative");
        byte[] raw = value.toByteArray();
        int start = (raw.length > 1 && raw[0] == 0) ? 1 : 0;
        int significant = raw.length - start;
        if (significant > widthBytes) throw new IllegalArgumentException("Scalar exceeds " + widthBytes + " bytes");
        byte[] out = new byte[widthBytes];
        System.arraycopy(raw, start, out, widthBytes - significant, significant);
        return out;
    }

    private static void validateScalarRange(BigInteger scalar, String label) {
        if (scalar.signum() <= 0 || scalar.compareTo(P256_ORDER_N) >= 0) {
            throw new IllegalArgumentException("ECDSA scalar " + label + " out of P-256 range [1, N - 1]");
        }
    }

    private static DecodedInt readDerPositiveInteger(byte[] der, int offset) {
        if (offset + 2 > der.length || der[offset] != 0x02) {
            throw new IllegalArgumentException("Expected ASN.1 INTEGER tag");
        }
        int len = der[offset + 1] & 0xFF;
        int start = offset + 2;
        if (len == 0 || len >= 128 || start + len > der.length || (der[start] & 0x80) != 0) {
            throw new IllegalArgumentException("Invalid or negative ASN.1 INTEGER");
        }
        if (der[start] == 0x00 && len > 1 && (der[start + 1] & 0x80) == 0) {
            throw new IllegalArgumentException("Redundant leading zero in ASN.1 INTEGER");
        }
        return new DecodedInt(new BigInteger(1, Arrays.copyOfRange(der, start, start + len)), start + len);
    }

    private record DecodedInt(BigInteger value, int nextOffset) {}
}
