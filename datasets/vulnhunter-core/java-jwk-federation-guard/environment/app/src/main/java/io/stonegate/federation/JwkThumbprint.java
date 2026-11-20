package io.stonegate.federation;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * JWK (RFC 7517 / RFC 7518 / RFC 8037) parser and RFC 7638 SHA-256 JWK Thumbprint ({@code jkt}) engine.
 *
 * <p>Contract (RFC 7638 §3.1–§3.2 &amp; RFC 8037 §2):
 * <ul>
 *   <li>{@code jkt} MUST be {@code base64url(SHA-256(UTF-8(canonicalJwkJson)))} without padding or whitespace.</li>
 *   <li>{@code canonicalJwkJson} MUST include ONLY the required public/symmetric members for {@code kty}
 *       serialized in strict lexicographic UTF-16 code-unit member order:
 *       {@code EC -> {"crv":...,"kty":"EC","x":...,"y":...}},
 *       {@code OKP -> {"crv":...,"kty":"OKP","x":...}},
 *       {@code RSA -> {"e":...,"kty":"RSA","n":...}},
 *       {@code oct -> {"k":...,"kty":"oct"}}.
 *       Optional metadata members ({@code kid}, {@code use}, {@code key_ops}, {@code alg}, {@code x5c})
 *       MUST NOT be included in the thumbprint input.</li>
 *   <li>{@link #parsePublicJwk(Map)} accepts only asymmetric public keys ({@code EC} P-256, {@code OKP}
 *       Ed25519, {@code RSA} &gt;= 2048-bit) and rejects {@code oct} or private key parameters
 *       ({@code d}, {@code p}, {@code q}, {@code dp}, {@code dq}, {@code qi}, {@code oth}, {@code k}).</li>
 * </ul>
 */
public final class JwkThumbprint {

    private static final Set<String> PRIVATE_KEY_MEMBERS = Set.of("d", "p", "q", "dp", "dq", "qi", "oth");
    private static final BigInteger P256_FIELD_P = new BigInteger(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P256_CURVE_B = new BigInteger(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger ED25519_FIELD_P =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final byte[] ED25519_SPKI_PREFIX = new byte[]{
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    private static final ECParameterSpec P256_SPEC = initP256Spec();

    private JwkThumbprint() {
    }

    public record JwkKey(
            String keyType,
            Optional<String> curve,
            Optional<String> keyId,
            Optional<String> declaredAlgorithm,
            PublicKey publicKey,
            SecretKey secretKey,
            String thumbprint,
            Map<String, Object> jwkMap
    ) {
        public boolean isSymmetric() {
            return "oct".equals(keyType);
        }

        public String canonicalJwsAlgorithm() {
            return switch (keyType) {
                case "EC" -> "ES256";
                case "OKP" -> "EdDSA";
                case "RSA" -> "RS256";
                case "oct" -> "HS256";
                default -> throw new IllegalStateException("Unsupported keyType: " + keyType);
            };
        }
    }

    public static JwkKey parsePublicJwk(Map<String, Object> jwk) {
        if (jwk == null) {
            throw new IllegalArgumentException("JWK map must not be null");
        }
        for (String priv : PRIVATE_KEY_MEMBERS) {
            if (jwk.containsKey(priv)) {
                throw new IllegalArgumentException("Public JWK must not contain private member '" + priv + "'");
            }
        }
        if (jwk.containsKey("k") || "oct".equals(jwk.get("kty"))) {
            throw new IllegalArgumentException("Symmetric 'oct' JWK is not valid as a public JWK");
        }
        return parseValidatedJwk(jwk, false);
    }

    public static JwkKey parseStoreJwk(Map<String, Object> jwk) {
        if (jwk == null) {
            throw new IllegalArgumentException("JWK map must not be null");
        }
        for (String priv : PRIVATE_KEY_MEMBERS) {
            if (jwk.containsKey(priv)) {
                throw new IllegalArgumentException("Trust store JWK must not contain private member '" + priv + "'");
            }
        }
        return parseValidatedJwk(jwk, true);
    }

    /** Computes the RFC 7638 Base64URL-encoded SHA-256 thumbprint ({@code jkt}) of a JWK map. */
    public static String compute(Map<String, Object> jwk) {
        if (jwk == null) {
            throw new IllegalArgumentException("JWK map must not be null");
        }
        String kty = requireNonEmptyString(jwk, "kty");
        Map<String, Object> thumbMembers = new LinkedHashMap<>();

        switch (kty) {
            case "EC" -> {
                String crv = requireNonEmptyString(jwk, "crv");
                if (!"P-256".equals(crv)) {
                    throw new IllegalArgumentException("Unsupported EC curve: " + crv);
                }
                String x = requireNonEmptyString(jwk, "x");
                String y = requireNonEmptyString(jwk, "y");
                decodeP256Point(x, y);
                thumbMembers.put("crv", crv);
                thumbMembers.put("kty", "EC");
                thumbMembers.put("x", x);
                thumbMembers.put("y", y);
            }
            case "OKP" -> {
                String crv = requireNonEmptyString(jwk, "crv");
                if (!"Ed25519".equals(crv)) {
                    throw new IllegalArgumentException("Unsupported OKP curve: " + crv);
                }
                String x = requireNonEmptyString(jwk, "x");
                decodeEd25519Public(x);
                thumbMembers.put("kty", "OKP");
                thumbMembers.put("crv", crv);
                thumbMembers.put("x", x);
            }
            case "RSA" -> {
                String n = requireNonEmptyString(jwk, "n");
                String e = requireNonEmptyString(jwk, "e");
                decodeRsaPublic(n, e);
                thumbMembers.put("kty", "RSA");
                thumbMembers.put("n", n);
                thumbMembers.put("e", e);
            }
            case "oct" -> {
                String k = requireNonEmptyString(jwk, "k");
                if (JsonCodec.decodeBase64Url(k).length < 32) {
                    throw new IllegalArgumentException("Symmetric 'oct' key must be at least 256 bits");
                }
                thumbMembers.put("kty", "oct");
                thumbMembers.put("k", k);
            }
            default -> throw new IllegalArgumentException("Unsupported JWK kty: " + kty);
        }

        if (jwk.get("kid") instanceof String kid && !kid.isBlank()) {
            thumbMembers.put("kid", kid);
        }
        return sha256Base64Url(JsonCodec.serialize(thumbMembers).getBytes(StandardCharsets.UTF_8));
    }

    public static Map<String, Object> toPublicJwkMap(PublicKey publicKey, String kid, String alg) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Map<String, Object> map = new LinkedHashMap<>();
        if (publicKey instanceof ECPublicKey ecPub) {
            ECPoint w = ecPub.getW();
            map.put("kty", "EC");
            map.put("crv", "P-256");
            map.put("x", JsonCodec.encodeBase64Url(EcdsaDerCodec.encodeUnsignedFixedWidth(w.getAffineX(), 32)));
            map.put("y", JsonCodec.encodeBase64Url(EcdsaDerCodec.encodeUnsignedFixedWidth(w.getAffineY(), 32)));
        } else if (publicKey instanceof EdECPublicKey || "EdDSA".equalsIgnoreCase(publicKey.getAlgorithm())
                || "Ed25519".equalsIgnoreCase(publicKey.getAlgorithm())) {
            byte[] spki = publicKey.getEncoded();
            if (spki == null || spki.length != ED25519_SPKI_PREFIX.length + 32
                    || !Arrays.equals(Arrays.copyOfRange(spki, 0, ED25519_SPKI_PREFIX.length), ED25519_SPKI_PREFIX)) {
                throw new IllegalArgumentException("Unexpected Ed25519 SubjectPublicKeyInfo encoding");
            }
            map.put("kty", "OKP");
            map.put("crv", "Ed25519");
            map.put("x", JsonCodec.encodeBase64Url(Arrays.copyOfRange(spki, ED25519_SPKI_PREFIX.length, spki.length)));
        } else if (publicKey instanceof RSAPublicKey rsaPub) {
            map.put("kty", "RSA");
            map.put("n", JsonCodec.encodeBase64Url(encodeMinimalUnsigned(rsaPub.getModulus())));
            map.put("e", JsonCodec.encodeBase64Url(encodeMinimalUnsigned(rsaPub.getPublicExponent())));
        } else {
            throw new IllegalArgumentException("Unsupported PublicKey type: " + publicKey.getClass().getName());
        }
        if (kid != null && !kid.isBlank()) {
            map.put("kid", kid);
        }
        if (alg != null && !alg.isBlank()) {
            map.put("alg", alg);
        }
        return Collections.unmodifiableMap(map);
    }

    public static Map<String, Object> toSymmetricJwkMap(byte[] secretBytes, String kid) {
        if (secretBytes == null || secretBytes.length < 32) {
            throw new IllegalArgumentException("HMAC secret must be at least 32 bytes");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("kty", "oct");
        map.put("k", JsonCodec.encodeBase64Url(secretBytes));
        if (kid != null && !kid.isBlank()) {
            map.put("kid", kid);
        }
        map.put("alg", "HS256");
        return Collections.unmodifiableMap(map);
    }

    private static JwkKey parseValidatedJwk(Map<String, Object> jwk, boolean allowSymmetric) {
        String kty = requireNonEmptyString(jwk, "kty");
        Optional<String> kid = optionalNonBlankString(jwk, "kid");
        Optional<String> alg = optionalNonBlankString(jwk, "alg");
        if (jwk.containsKey("use") && !"sig".equals(requireNonEmptyString(jwk, "use"))) {
            throw new IllegalArgumentException("JWK 'use' must be 'sig'");
        }

        PublicKey pubKey = null;
        SecretKey secKey = null;
        Optional<String> curve = Optional.empty();
        switch (kty) {
            case "EC" -> {
                String crv = requireNonEmptyString(jwk, "crv");
                if (!"P-256".equals(crv)) {
                    throw new IllegalArgumentException("Unsupported EC curve: " + crv);
                }
                curve = Optional.of(crv);
                pubKey = decodeP256Point(requireNonEmptyString(jwk, "x"), requireNonEmptyString(jwk, "y"));
                if (alg.isPresent() && !"ES256".equals(alg.get())) {
                    throw new IllegalArgumentException("EC P-256 JWK incompatible with alg: " + alg.get());
                }
            }
            case "OKP" -> {
                String crv = requireNonEmptyString(jwk, "crv");
                if (!"Ed25519".equals(crv)) {
                    throw new IllegalArgumentException("Unsupported OKP curve: " + crv);
                }
                curve = Optional.of(crv);
                pubKey = decodeEd25519Public(requireNonEmptyString(jwk, "x"));
                if (alg.isPresent() && !"EdDSA".equals(alg.get())) {
                    throw new IllegalArgumentException("OKP Ed25519 JWK incompatible with alg: " + alg.get());
                }
            }
            case "RSA" -> {
                pubKey = decodeRsaPublic(requireNonEmptyString(jwk, "n"), requireNonEmptyString(jwk, "e"));
                if (alg.isPresent() && !"RS256".equals(alg.get())) {
                    throw new IllegalArgumentException("RSA JWK incompatible with alg: " + alg.get());
                }
            }
            case "oct" -> {
                if (!allowSymmetric) {
                    throw new IllegalArgumentException("Symmetric 'oct' JWK not allowed in public context");
                }
                byte[] kBytes = JsonCodec.decodeBase64Url(requireNonEmptyString(jwk, "k"));
                if (kBytes.length < 32) {
                    throw new IllegalArgumentException("Symmetric 'oct' key must be >= 32 bytes");
                }
                secKey = new SecretKeySpec(kBytes, "HmacSHA256");
                if (alg.isPresent() && !"HS256".equals(alg.get())) {
                    throw new IllegalArgumentException("Symmetric 'oct' JWK incompatible with alg: " + alg.get());
                }
            }
            default -> throw new IllegalArgumentException("Unsupported JWK kty: " + kty);
        }
        return new JwkKey(kty, curve, kid, alg, pubKey, secKey, compute(jwk),
                Collections.unmodifiableMap(new LinkedHashMap<>(jwk)));
    }

    private static PublicKey decodeP256Point(String xB64, String yB64) {
        byte[] xBytes = JsonCodec.decodeBase64Url(xB64);
        byte[] yBytes = JsonCodec.decodeBase64Url(yB64);
        if (xBytes.length != 32 || yBytes.length != 32) {
            throw new IllegalArgumentException("P-256 x and y coordinates must each be 32 octets");
        }
        BigInteger x = new BigInteger(1, xBytes);
        BigInteger y = new BigInteger(1, yBytes);
        if (x.compareTo(P256_FIELD_P) >= 0 || y.compareTo(P256_FIELD_P) >= 0) {
            throw new IllegalArgumentException("P-256 coordinate out of field range");
        }
        BigInteger lhs = y.multiply(y).mod(P256_FIELD_P);
        BigInteger rhs = x.modPow(BigInteger.valueOf(3), P256_FIELD_P)
                .subtract(x.multiply(BigInteger.valueOf(3))).add(P256_CURVE_B).mod(P256_FIELD_P);
        if (!lhs.equals(rhs)) {
            throw new IllegalArgumentException("EC point is not on secp256r1 curve");
        }
        try {
            return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), P256_SPEC));
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Invalid EC P-256 public key", ex);
        }
    }

    private static PublicKey decodeEd25519Public(String xB64) {
        byte[] rawX = JsonCodec.decodeBase64Url(xB64);
        if (rawX.length != 32) {
            throw new IllegalArgumentException("Ed25519 'x' coordinate must be 32 octets");
        }
        byte[] yBigEndian = new byte[32];
        for (int i = 0; i < 32; i++) {
            yBigEndian[i] = rawX[31 - i];
        }
        yBigEndian[0] &= 0x7F;
        if (new BigInteger(1, yBigEndian).compareTo(ED25519_FIELD_P) >= 0) {
            throw new IllegalArgumentException("Non-canonical Ed25519 public coordinate y >= p");
        }
        byte[] spki = new byte[ED25519_SPKI_PREFIX.length + 32];
        System.arraycopy(ED25519_SPKI_PREFIX, 0, spki, 0, ED25519_SPKI_PREFIX.length);
        System.arraycopy(rawX, 0, spki, ED25519_SPKI_PREFIX.length, 32);
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Invalid Ed25519 public key", ex);
        }
    }

    private static PublicKey decodeRsaPublic(String nB64, String eB64) {
        BigInteger n = decodeMinimalUnsigned(nB64, "n");
        BigInteger e = decodeMinimalUnsigned(eB64, "e");
        if (n.bitLength() < 2048 || e.compareTo(BigInteger.valueOf(65537)) < 0 || !e.testBit(0)) {
            throw new IllegalArgumentException("RSA key must be >= 2048 bits with odd exponent >= 65537");
        }
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Invalid RSA public key", ex);
        }
    }

    private static BigInteger decodeMinimalUnsigned(String b64u, String fieldName) {
        byte[] bytes = JsonCodec.decodeBase64Url(b64u);
        if (bytes.length == 0 || bytes[0] == 0) {
            throw new IllegalArgumentException("Non-minimal Base64urlUInt in '" + fieldName + "'");
        }
        return new BigInteger(1, bytes);
    }

    private static byte[] encodeMinimalUnsigned(BigInteger val) {
        byte[] raw = val.toByteArray();
        return (raw.length > 1 && raw[0] == 0) ? Arrays.copyOfRange(raw, 1, raw.length) : raw;
    }

    private static String requireNonEmptyString(Map<String, Object> map, String key) {
        if (!(map.get(key) instanceof String s) || s.isBlank()) {
            throw new IllegalArgumentException("Missing or invalid JWK string parameter '" + key + "'");
        }
        return s;
    }

    private static Optional<String> optionalNonBlankString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val == null) {
            return Optional.empty();
        }
        if (!(val instanceof String s) || s.isBlank()) {
            throw new IllegalArgumentException("Invalid JWK string parameter '" + key + "'");
        }
        return Optional.of(s);
    }

    static String sha256Base64Url(byte[] input) {
        try {
            return JsonCodec.encodeBase64Url(MessageDigest.getInstance("SHA-256").digest(input));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }

    private static ECParameterSpec initP256Spec() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }
}
