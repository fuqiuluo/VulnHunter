package io.stonegate.federation;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * RFC 9449 OAuth 2.0 Demonstrating Proof of Possession ({@code DPoP}) validator.
 *
 * <p>Contract (RFC 9449 §4.2, §4.3, §7.1 &amp; §11.1):
 * <ul>
 *   <li>Verifies compact JWS signature, {@code typ: "dpop+jwt"}, asymmetric {@code alg}, and
 *       embedded public {@code jwk} via {@link JwsSignatureEngine#verifyDpopProof(String)}.</li>
 *   <li>Validates required claims: {@code jti} (1..256 chars), {@code htm} (exact HTTP method),
 *       {@code htu} (HTTP URI without query/fragment matching normalized request target), and
 *       {@code iat} within {@code [nowEpochSeconds - maxProofAgeSeconds, nowEpochSeconds + clockSkewSeconds]}.</li>
 *   <li>When bound to an access token ({@code boundAccessToken != null}), {@code ath} MUST be
 *       present and equal in constant time to {@code base64url(SHA-256(ASCII(boundAccessToken)))},
 *       and when {@code expectedJkt != null} the proof's RFC 7638 {@code jkt} MUST match {@code expectedJkt}.</li>
 *   <li>Enforces bounded replay detection keyed by {@code (jkt, jti)} across the freshness window
 *       so neither identical proofs nor malleable/re-signed signatures reusing {@code jti} can replay.</li>
 * </ul>
 */
public final class DpopProofValidator {

    public static final long DEFAULT_MAX_PROOF_AGE_SECONDS = 120L;
    public static final long DEFAULT_CLOCK_SKEW_SECONDS = 30L;
    public static final int DEFAULT_MAX_REPLAY_ENTRIES = 8192;

    private final JwsSignatureEngine signatureEngine;
    private final long maxProofAgeSeconds;
    private final long clockSkewSeconds;
    private final int maxReplayEntries;
    private final Map<String, Long> replayCache = new LinkedHashMap<>(256, 0.75f, false);

    public record ValidatedDpopProof(
            String jti, String jkt, String htm, String normalizedHtu, long issuedAt, Optional<String> accessTokenHash
    ) {}

    public DpopProofValidator(JwsSignatureEngine signatureEngine) {
        this(signatureEngine, DEFAULT_MAX_PROOF_AGE_SECONDS, DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_MAX_REPLAY_ENTRIES);
    }

    public DpopProofValidator(
            JwsSignatureEngine signatureEngine, long maxProofAgeSeconds, long clockSkewSeconds, int maxReplayEntries
    ) {
        this.signatureEngine = Objects.requireNonNull(signatureEngine);
        if (maxProofAgeSeconds <= 0 || clockSkewSeconds < 0 || maxReplayEntries <= 0) {
            throw new IllegalArgumentException("Invalid DPoP validator window or cache bounds");
        }
        this.maxProofAgeSeconds = maxProofAgeSeconds;
        this.clockSkewSeconds = clockSkewSeconds;
        this.maxReplayEntries = maxReplayEntries;
    }

    public ValidatedDpopProof validateProof(
            String rawDpopJwt,
            String expectedHttpMethod,
            String rawTargetUri,
            String boundAccessToken,
            String expectedJkt,
            long nowEpochSeconds
    ) {
        if (rawDpopJwt == null || rawDpopJwt.isBlank()) {
            throw reject(FederationGuard.ErrorCode.DPOP_REQUIRED, "Missing DPoP proof header");
        }
        if (expectedHttpMethod == null || expectedHttpMethod.isBlank()) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Missing expected HTTP method");
        }

        JwsSignatureEngine.VerifiedJws verified = signatureEngine.verifyDpopProof(rawDpopJwt);
        Map<String, Object> claims = verified.payload();
        String jkt = verified.verificationKey().thumbprint();

        String jti = requireNonBlankString(claims, "jti");
        if (jti.length() > 256) throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP jti too long");
        if (!expectedHttpMethod.equals(requireNonBlankString(claims, "htm"))) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP htm mismatch");
        }

        String claimHtuRaw = requireNonBlankString(claims, "htu");
        if (claimHtuRaw.indexOf('?') >= 0 || claimHtuRaw.indexOf('#') >= 0) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP htu must omit query and fragment");
        }
        String normalizedClaimHtu = normalizeHtu(claimHtuRaw);
        if (!normalizeHtu(rawTargetUri).equals(normalizedClaimHtu)) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP htu mismatch");
        }

        long iat = requireIntegralLong(claims, "iat");
        if (iat < nowEpochSeconds - maxProofAgeSeconds || iat > nowEpochSeconds + clockSkewSeconds) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP iat outside freshness window");
        }

        Optional<String> verifiedAth = Optional.empty();
        if (boundAccessToken != null && claims.containsKey("ath")) {
            String actualAth = requireNonBlankString(claims, "ath");
            if (!constantTimeEquals(actualAth, computeAccessTokenHash(boundAccessToken))) {
                throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP ath mismatch");
            }
            verifiedAth = Optional.of(actualAth);
        }

        if (expectedJkt != null && (expectedJkt.isBlank() || !constantTimeEquals(jkt, expectedJkt))) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP key thumbprint mismatch");
        }

        recordProofOrThrowReplay(rawDpopJwt, jkt, jti, nowEpochSeconds);
        return new ValidatedDpopProof(jti, jkt, expectedHttpMethod, normalizedClaimHtu, iat, verifiedAth);
    }

    public static String computeAccessTokenHash(String asciiAccessToken) {
        if (asciiAccessToken == null || asciiAccessToken.isBlank()) {
            throw new IllegalArgumentException("Access token must not be blank");
        }
        return JwkThumbprint.sha256Base64Url(asciiAccessToken.getBytes(StandardCharsets.US_ASCII));
    }

    public static String normalizeHtu(String rawUri) {
        if (rawUri == null || rawUri.isBlank()) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Target URI must not be blank");
        }
        int cut = rawUri.length();
        int qIdx = rawUri.indexOf('?');
        int fIdx = rawUri.indexOf('#');
        if (qIdx >= 0 && qIdx < cut) cut = qIdx;
        if (fIdx >= 0 && fIdx < cut) cut = fIdx;
        URI uri;
        try {
            uri = new URI(rawUri.substring(0, cut));
        } catch (URISyntaxException ex) {
            throw new FederationGuard.VerificationException(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Invalid URI", ex);
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if ((!"https".equals(scheme) && !"http".equals(scheme))
                || uri.getRawUserInfo() != null || uri.getHost() == null || uri.getHost().isBlank()) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Invalid scheme or authority in htu");
        }
        int port = uri.getPort();
        boolean includePort = port > 0 && !(("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80));
        String path = (uri.getRawPath() == null || uri.getRawPath().isEmpty()) ? "/" : uri.getRawPath();
        return scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT) + (includePort ? ":" + port : "") + path;
    }

    private synchronized void recordProofOrThrowReplay(String rawDpopJwt, String jkt, String jti, long nowEpochSeconds) {
        Iterator<Map.Entry<String, Long>> it = replayCache.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue() < nowEpochSeconds) it.remove();
        }
        String replayKey = JwkThumbprint.sha256Base64Url(rawDpopJwt.getBytes(StandardCharsets.UTF_8));
        Long existingExpiry = replayCache.get(replayKey);
        if (existingExpiry != null && existingExpiry >= nowEpochSeconds) {
            throw reject(FederationGuard.ErrorCode.DPOP_REPLAY, "DPoP proof replay detected for jti: " + jti);
        }
        if (replayCache.size() >= maxReplayEntries) {
            Iterator<String> eldest = replayCache.keySet().iterator();
            if (eldest.hasNext()) {
                eldest.next();
                eldest.remove();
            }
        }
        replayCache.put(replayKey, nowEpochSeconds + maxProofAgeSeconds + clockSkewSeconds);
    }

    private static String requireNonBlankString(Map<String, Object> claims, String name) {
        if (!(claims.get(name) instanceof String s) || s.isBlank()) {
            throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Missing or invalid DPoP claim '" + name + "'");
        }
        return s;
    }

    private static long requireIntegralLong(Map<String, Object> claims, String name) {
        Object val = claims.get(name);
        if (val instanceof Long l) return l;
        if (val instanceof Integer i) return i.longValue();
        throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "Missing or non-integer DPoP claim '" + name + "'");
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static FederationGuard.VerificationException reject(FederationGuard.ErrorCode code, String msg) {
        return new FederationGuard.VerificationException(code, msg);
    }
}
