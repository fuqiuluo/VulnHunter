package io.stonegate.federation;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Compact JWS ({@code header.payload.signature}) verification and signing engine.
 *
 * <p>Contract (RFC 7515, RFC 8725 §3.1–§3.2, RFC 9068 §2.1 &amp; RFC 9449 §4.2–§4.3):
 * <ul>
 *   <li>Compact JWS tokens MUST have three non-empty Base64URL segments; {@code "alg": "none"}
 *       and unsupported {@code "crit"} extensions MUST be rejected.</li>
 *   <li>Access tokens ({@link #verifyAccessToken}): {@code typ} MUST be {@code "at+jwt"},
 *       {@code "jwt"}, {@code "application/at+jwt"}, or {@code "application/jwt"} (case-insensitive,
 *       never {@code "dpop+jwt"}); headers MUST NOT carry {@code "jwk"}, {@code "jku"}, {@code "x5u"},
 *       or {@code "x5c"}; verification MUST use only the {@link FederationTrustStore.IssuerEntry}
 *       pinned key for {@code kid} whose {@code canonicalJwsAlgorithm()} and issuer policy both
 *       permit {@code alg} ({@code HS256} strictly requires an {@code oct} symmetric key).</li>
 *   <li>DPoP proofs ({@link #verifyDpopProof}): {@code typ} MUST equal {@code "dpop+jwt"}
 *       (case-insensitive), {@code alg} MUST be in {@code {"ES256", "EdDSA", "RS256"}}, and header
 *       MUST include an inline public {@code "jwk"} matching {@code alg} (no {@code jku}/{@code x5u}/{@code x5c}).</li>
 * </ul>
 */
public final class JwsSignatureEngine {

    private static final Set<String> ACCEPTED_ACCESS_TOKEN_TYPES = Set.of(
            "at+jwt", "jwt", "application/at+jwt", "application/jwt");
    private static final Set<String> ASYMMETRIC_ALGORITHMS = Set.of("ES256", "EdDSA", "RS256");

    public record VerifiedJws(
            Map<String, Object> header,
            Map<String, Object> payload,
            String algorithm,
            JwkThumbprint.JwkKey verificationKey,
            String rawCompactJws
    ) {}

    public VerifiedJws verifyAccessToken(
            String compactJws, FederationTrustStore.IssuerEntry issuer, long nowEpochSeconds
    ) {
        Objects.requireNonNull(issuer, "issuer must not be null");
        String[] parts = splitCompactJws(compactJws);
        String headerJson;
        String payloadJson;
        byte[] sigBytes;
        try {
            headerJson = JsonCodec.decodeUtf8Base64Url(parts[0]);
            payloadJson = JsonCodec.decodeUtf8Base64Url(parts[1]);
            sigBytes = JsonCodec.decodeBase64Url(parts[2]);
        } catch (IllegalArgumentException ex) {
            throw reject(FederationGuard.ErrorCode.MALFORMED_TOKEN, "Malformed Base64URL in access token", ex);
        }

        String alg = JsonCodec.extractTopLevelStringField(headerJson, "alg");
        String typ = JsonCodec.extractTopLevelStringField(headerJson, "typ");
        String kid = JsonCodec.extractTopLevelStringField(headerJson, "kid");

        Map<String, Object> header;
        Map<String, Object> payload;
        try {
            header = JsonCodec.parseObject(headerJson);
            payload = JsonCodec.parseObject(payloadJson);
        } catch (IllegalArgumentException ex) {
            throw reject(FederationGuard.ErrorCode.MALFORMED_TOKEN, "Invalid JSON in access token", ex);
        }

        if (alg == null || alg.isBlank() || "none".equalsIgnoreCase(alg)) {
            throw reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Missing or forbidden JWS algorithm");
        }
        if (typ == null || !ACCEPTED_ACCESS_TOKEN_TYPES.contains(typ.toLowerCase(Locale.ROOT))) {
            throw reject(FederationGuard.ErrorCode.MALFORMED_TOKEN, "Unsupported access token typ: " + typ);
        }
        if (kid == null || kid.isBlank()) {
            throw reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Missing kid in access token header");
        }

        JwkThumbprint.JwkKey verificationKey = resolveAccessVerificationKey(header, kid, issuer, nowEpochSeconds);
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        if (!verifyCryptographicSignature(alg, verificationKey, signingInput, sigBytes)) {
            throw reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Access token signature verification failed");
        }
        return new VerifiedJws(header, payload, alg, verificationKey, compactJws);
    }

    public VerifiedJws verifyDpopProof(String compactJws) {
        String[] parts = splitCompactJws(compactJws);
        String headerJson;
        String payloadJson;
        byte[] sigBytes;
        try {
            headerJson = JsonCodec.decodeUtf8Base64Url(parts[0]);
            payloadJson = JsonCodec.decodeUtf8Base64Url(parts[1]);
            sigBytes = JsonCodec.decodeBase64Url(parts[2]);
        } catch (IllegalArgumentException ex) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Malformed Base64URL in DPoP proof", ex);
        }

        Map<String, Object> header;
        Map<String, Object> payload;
        try {
            header = JsonCodec.parseObject(headerJson);
            payload = JsonCodec.parseObject(payloadJson);
        } catch (IllegalArgumentException ex) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Invalid JSON in DPoP proof", ex);
        }

        rejectUnsupportedHeaderRefs(header, false, FederationGuard.ErrorCode.INVALID_DPOP_PROOF);
        if (!(header.get("typ") instanceof String typ) || !"dpop+jwt".equalsIgnoreCase(typ)) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP typ must be 'dpop+jwt'");
        }
        if (!(header.get("alg") instanceof String alg) || !ASYMMETRIC_ALGORITHMS.contains(alg)) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Unsupported DPoP alg");
        }
        if (!(header.get("jwk") instanceof Map<?, ?> rawJwk)) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Missing inline jwk in DPoP header");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> jwkMap = (Map<String, Object>) rawJwk;
        JwkThumbprint.JwkKey dpopKey;
        try {
            dpopKey = JwkThumbprint.parsePublicJwk(jwkMap);
        } catch (IllegalArgumentException ex) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Invalid inline jwk in DPoP header", ex);
        }
        if (!alg.equals(dpopKey.canonicalJwsAlgorithm())) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP alg does not match inline JWK");
        }

        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        if (!verifyCryptographicSignature(alg, dpopKey, signingInput, sigBytes)) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP proof signature verification failed");
        }
        return new VerifiedJws(header, payload, alg, dpopKey, compactJws);
    }

    public static String signCompact(Map<String, Object> header, Map<String, Object> payload, Key signingKey) {
        String alg = (String) Objects.requireNonNull(header).get("alg");
        if (alg == null || alg.isBlank()) throw new IllegalArgumentException("Header map must include 'alg'");
        return signCompactRaw(JsonCodec.serialize(header), JsonCodec.serialize(Objects.requireNonNull(payload)), alg, signingKey);
    }

    public static String signCompactRaw(String headerJson, String payloadJson, String alg, Key signingKey) {
        String encodedHeader = JsonCodec.encodeUtf8Base64Url(Objects.requireNonNull(headerJson));
        String encodedPayload = JsonCodec.encodeUtf8Base64Url(Objects.requireNonNull(payloadJson));
        byte[] signingInput = (encodedHeader + "." + encodedPayload).getBytes(StandardCharsets.US_ASCII);
        byte[] signatureBytes;
        try {
            signatureBytes = switch (Objects.requireNonNull(alg)) {
                case "ES256" -> {
                    Signature sig = Signature.getInstance("SHA256withECDSA");
                    sig.initSign((PrivateKey) signingKey);
                    sig.update(signingInput);
                    yield EcdsaDerCodec.derToP1363(sig.sign());
                }
                case "EdDSA" -> {
                    Signature sig = Signature.getInstance("Ed25519");
                    sig.initSign((PrivateKey) signingKey);
                    sig.update(signingInput);
                    yield sig.sign();
                }
                case "RS256" -> {
                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initSign((PrivateKey) signingKey);
                    sig.update(signingInput);
                    yield sig.sign();
                }
                case "HS256" -> {
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init((SecretKey) signingKey);
                    yield mac.doFinal(signingInput);
                }
                default -> throw new IllegalArgumentException("Unsupported signing algorithm: " + alg);
            };
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException("Failed to sign JWS with " + alg, ex);
        }
        return encodedHeader + "." + encodedPayload + "." + JsonCodec.encodeBase64Url(signatureBytes);
    }

    private JwkThumbprint.JwkKey resolveAccessVerificationKey(
            Map<String, Object> header, String kid, FederationTrustStore.IssuerEntry issuer, long nowEpochSeconds
    ) {
        FederationTrustStore.TrustedKey pinned = issuer.findActiveKey(kid, nowEpochSeconds)
                .orElseThrow(() -> reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Unknown or expired kid: " + kid));

        if (header.get("jwk") instanceof Map<?, ?> inlineRaw) {
            @SuppressWarnings("unchecked")
            Map<String, Object> inlineMap = (Map<String, Object>) inlineRaw;
            Object inlineKid = inlineMap.get("kid");
            if (inlineKid == null || kid.equals(inlineKid)) {
                try {
                    return JwkThumbprint.parsePublicJwk(inlineMap);
                } catch (IllegalArgumentException ex) {
                    throw reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Invalid header jwk", ex);
                }
            }
        }
        return pinned.jwkKey();
    }

    private static void rejectUnsupportedHeaderRefs(
            Map<String, Object> header, boolean rejectInlineJwk, FederationGuard.ErrorCode errorCode
    ) {
        if (rejectInlineJwk && header.containsKey("jwk")) {
            throw reject(errorCode, "Inline 'jwk' header is forbidden");
        }
        for (String forbidden : new String[]{"jku", "x5u", "x5c"}) {
            if (header.containsKey(forbidden)) throw reject(errorCode, "Forbidden header parameter: " + forbidden);
        }
        if (header.containsKey("crit")) throw reject(errorCode, "Unsupported 'crit' header extension");
    }

    private boolean verifyCryptographicSignature(
            String alg, JwkThumbprint.JwkKey key, byte[] signingInput, byte[] signatureBytes
    ) {
        try {
            return switch (alg) {
                case "ES256" -> {
                    if (key.publicKey() == null || !"EC".equals(key.keyType())) yield false;
                    byte[] derSig = EcdsaDerCodec.p1363ToDer(signatureBytes);
                    Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(key.publicKey());
                    verifier.update(signingInput);
                    yield verifier.verify(derSig);
                }
                case "EdDSA" -> {
                    if (key.publicKey() == null || !"OKP".equals(key.keyType()) || signatureBytes.length != 64) yield false;
                    Signature verifier = Signature.getInstance("Ed25519");
                    verifier.initVerify(key.publicKey());
                    verifier.update(signingInput);
                    yield verifier.verify(signatureBytes);
                }
                case "RS256" -> {
                    if (key.publicKey() == null || !"RSA".equals(key.keyType())) yield false;
                    Signature verifier = Signature.getInstance("SHA256withRSA");
                    verifier.initVerify(key.publicKey());
                    verifier.update(signingInput);
                    yield verifier.verify(signatureBytes);
                }
                case "HS256" -> {
                    if (signatureBytes.length != 32) yield false;
                    SecretKey hmacKey = key.secretKey();
                    if (hmacKey == null && key.publicKey() != null) {
                        hmacKey = new SecretKeySpec(key.publicKey().getEncoded(), "HmacSHA256");
                    }
                    if (hmacKey == null) yield false;
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(hmacKey);
                    yield MessageDigest.isEqual(mac.doFinal(signingInput), signatureBytes);
                }
                default -> false;
            };
        } catch (IllegalArgumentException | GeneralSecurityException ex) {
            return false;
        }
    }

    static String[] splitCompactJws(String compactJws) {
        if (compactJws == null || compactJws.isBlank()) {
            throw reject(FederationGuard.ErrorCode.MALFORMED_TOKEN, "JWS token must not be blank");
        }
        int d1 = compactJws.indexOf('.');
        int d2 = d1 < 0 ? -1 : compactJws.indexOf('.', d1 + 1);
        int d3 = d2 < 0 ? -1 : compactJws.indexOf('.', d2 + 1);
        if (d1 <= 0 || d2 <= d1 + 1 || d2 >= compactJws.length() - 1 || d3 >= 0) {
            throw reject(FederationGuard.ErrorCode.MALFORMED_TOKEN, "Compact JWS must have three non-empty segments");
        }
        return new String[]{compactJws.substring(0, d1), compactJws.substring(d1 + 1, d2), compactJws.substring(d2 + 1)};
    }

    private static FederationGuard.VerificationException reject(FederationGuard.ErrorCode code, String msg) {
        return new FederationGuard.VerificationException(code, msg);
    }

    private static FederationGuard.VerificationException reject(FederationGuard.ErrorCode code, String msg, Throwable cause) {
        return new FederationGuard.VerificationException(code, msg, cause);
    }
}
