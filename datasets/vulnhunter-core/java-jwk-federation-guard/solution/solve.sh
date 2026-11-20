#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# 1. Write comprehensive technical review report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "src/main/java/io/stonegate/federation/JsonCodec.java",
    "src/main/java/io/stonegate/federation/EcdsaDerCodec.java",
    "src/main/java/io/stonegate/federation/JwkThumbprint.java",
    "src/main/java/io/stonegate/federation/FederationTrustStore.java",
    "src/main/java/io/stonegate/federation/JwsSignatureEngine.java",
    "src/main/java/io/stonegate/federation/DpopProofValidator.java",
    "src/main/java/io/stonegate/federation/FederationGuard.java"
  ],
  "findings": [
    "JwsSignatureEngine.verifyAccessToken accepted caller-supplied inline 'jwk' headers (and failed to forbid 'jku'/'x5u'/'x5c'/'crit') while allowing HS256 fallback to PublicKey.getEncoded() bytes, and FederationTrustStore.resolveIssuer matched issuer URIs with startsWith() instead of exact canonical https URI equality.",
    "JsonCodec.parseObject permitted duplicate JSON object member names with last-wins map overwrites while JsonCodec.extractTopLevelStringField returned the first raw unescaped key match, creating a cross-issuer claim differential in FederationGuard.",
    "EcdsaDerCodec.p1363ToDer omitted [1, P256_ORDER_N - 1] scalar range validation on r and s, and DpopProofValidator keyed its replay cache on sha256(rawDpopJwt) instead of (jkt, jti), allowing ECDSA (r, N - s) signature malleability and re-signed jti replays.",
    "JwkThumbprint.compute included optional 'kid' metadata and serialized OKP/RSA/oct members in non-lexicographic order contrary to RFC 7638, DpopProofValidator treated 'ath' as optional when boundAccessToken was present, and FederationGuard failed to enforce DPoP presentation for cnf.jkt sender-constrained tokens on mixed-mode endpoints."
  ],
  "summary": "Enforced strict RFC 8259 unique JSON keys, exact https issuer matching, pinned JWKS verification without inline jwk or HS256 public-key fallback, ECDSA P-256 scalar bounds, (jkt, jti) DPoP replay tracking, canonical RFC 7638 thumbprints, mandatory ath verification, and cnf.jkt sender-constraint binding."
}
EOF

# 2. Apply defensive remediations across src/main/java and add regression tests in src/test/java
python3 - "$APP_DIR" <<'PY'
from pathlib import Path
import sys

app = Path(sys.argv[1])
pkg = app / "src" / "main" / "java" / "io" / "stonegate" / "federation"
test_pkg = app / "src" / "test" / "java" / "io" / "stonegate" / "federation"


def patch_file(path: Path, replacements: list[tuple[str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for old, new in replacements:
        assert old in text, f"Expected snippet not found in {path.name}:\n{old}"
        text = text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8")


# --- Fix 1A: FederationTrustStore canonical https URI validation & exact issuer resolution ---
patch_file(
    pkg / "FederationTrustStore.java",
    [
        (
            "import java.util.Collections;",
            "import java.net.URI;\nimport java.net.URISyntaxException;\nimport java.util.Collections;",
        ),
        (
            """    public IssuerEntry registerIssuer(IssuerPolicy policy) {
        Objects.requireNonNull(policy, "policy must not be null");
        IssuerEntry entry = new IssuerEntry(policy);
        issuers.put(policy.issuerUri().trim(), entry);
        return entry;
    }

    public Optional<IssuerEntry> resolveIssuer(String candidateIssuer) {
        if (candidateIssuer == null || candidateIssuer.isBlank()) return Optional.empty();
        String normalized = candidateIssuer.trim();
        IssuerEntry exact = issuers.get(normalized);
        if (exact != null) return Optional.of(exact);
        for (Map.Entry<String, IssuerEntry> entry : issuers.entrySet()) {
            if (normalized.startsWith(entry.getKey())) {
                return Optional.of(entry.getValue());
            }
        }
        return Optional.empty();
    }""",
            """    public IssuerEntry registerIssuer(IssuerPolicy policy) {
        Objects.requireNonNull(policy, "policy must not be null");
        String uriStr = policy.issuerUri();
        if (!isCanonicalHttpsIssuerUri(uriStr)) {
            throw new IllegalArgumentException("Issuer URI must be a canonical https URI without userinfo, query, or fragment: " + uriStr);
        }
        IssuerEntry entry = new IssuerEntry(policy);
        issuers.put(uriStr, entry);
        return entry;
    }

    public Optional<IssuerEntry> resolveIssuer(String candidateIssuer) {
        if (!isCanonicalHttpsIssuerUri(candidateIssuer)) {
            return Optional.empty();
        }
        return Optional.ofNullable(issuers.get(candidateIssuer));
    }

    private static boolean isCanonicalHttpsIssuerUri(String raw) {
        if (raw == null || raw.isBlank() || !raw.equals(raw.trim())) {
            return false;
        }
        for (int i = 0; i < raw.length(); i++) {
            if (Character.isWhitespace(raw.charAt(i))) return false;
        }
        URI uri;
        try {
            uri = new URI(raw);
        } catch (URISyntaxException ex) {
            return false;
        }
        return "https".equals(uri.getScheme())
                && uri.getRawUserInfo() == null
                && uri.getHost() != null
                && !uri.getHost().isBlank()
                && uri.getRawQuery() == null
                && uri.getRawFragment() == null;
    }""",
        ),
    ],
)

# --- Fix 1B: JwsSignatureEngine single-parse header, forbid inline jwk/jku/x5u/x5c/crit, strict alg & key pinning ---
patch_file(
    pkg / "JwsSignatureEngine.java",
    [
        (
            """        String alg = JsonCodec.extractTopLevelStringField(headerJson, "alg");
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

        JwkThumbprint.JwkKey verificationKey = resolveAccessVerificationKey(header, kid, issuer, nowEpochSeconds);""",
            """        Map<String, Object> header;
        Map<String, Object> payload;
        try {
            header = JsonCodec.parseObject(headerJson);
            payload = JsonCodec.parseObject(payloadJson);
        } catch (IllegalArgumentException ex) {
            throw reject(FederationGuard.ErrorCode.MALFORMED_TOKEN, "Invalid JSON in access token", ex);
        }

        rejectUnsupportedHeaderRefs(header, true, FederationGuard.ErrorCode.INVALID_SIGNATURE);

        String alg = (header.get("alg") instanceof String a) ? a : null;
        String typ = (header.get("typ") instanceof String t) ? t : null;
        String kid = (header.get("kid") instanceof String k) ? k : null;

        if (alg == null || alg.isBlank() || "none".equalsIgnoreCase(alg)) {
            throw reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Missing or forbidden JWS algorithm");
        }
        if (!issuer.policy().allowedAlgorithms().contains(alg)) {
            throw reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Algorithm disallowed by issuer policy: " + alg);
        }
        if (typ == null || !ACCEPTED_ACCESS_TOKEN_TYPES.contains(typ.toLowerCase(Locale.ROOT))) {
            throw reject(FederationGuard.ErrorCode.MALFORMED_TOKEN, "Unsupported access token typ: " + typ);
        }
        if (kid == null || kid.isBlank()) {
            throw reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Missing kid in access token header");
        }

        JwkThumbprint.JwkKey verificationKey = resolveAccessVerificationKey(alg, kid, issuer, nowEpochSeconds);""",
        ),
        (
            """    private JwkThumbprint.JwkKey resolveAccessVerificationKey(
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
    }""",
            """    private JwkThumbprint.JwkKey resolveAccessVerificationKey(
            String alg, String kid, FederationTrustStore.IssuerEntry issuer, long nowEpochSeconds
    ) {
        FederationTrustStore.TrustedKey pinned = issuer.findActiveKey(kid, nowEpochSeconds)
                .orElseThrow(() -> reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Unknown or expired kid: " + kid));
        if (!alg.equals(pinned.algorithm()) || !alg.equals(pinned.jwkKey().canonicalJwsAlgorithm())) {
            throw reject(FederationGuard.ErrorCode.INVALID_SIGNATURE, "Header alg does not match pinned key type");
        }
        return pinned.jwkKey();
    }""",
        ),
        (
            """                case "HS256" -> {
                    if (signatureBytes.length != 32) yield false;
                    SecretKey hmacKey = key.secretKey();
                    if (hmacKey == null && key.publicKey() != null) {
                        hmacKey = new SecretKeySpec(key.publicKey().getEncoded(), "HmacSHA256");
                    }
                    if (hmacKey == null) yield false;
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(hmacKey);
                    yield MessageDigest.isEqual(mac.doFinal(signingInput), signatureBytes);
                }""",
            """                case "HS256" -> {
                    if (signatureBytes.length != 32 || !"oct".equals(key.keyType()) || key.secretKey() == null) {
                        yield false;
                    }
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(key.secretKey());
                    yield MessageDigest.isEqual(mac.doFinal(signingInput), signatureBytes);
                }""",
        ),
    ],
)

# --- Fix 2A: JsonCodec duplicate key rejection & canonical parse delegation ---
patch_file(
    pkg / "JsonCodec.java",
    [
        (
            """    /** Extracts a top-level string member value from a JSON object text for routing inspection. */
    public static String extractTopLevelStringField(String json, String fieldName) {
        if (json == null || fieldName == null || fieldName.isEmpty()) return null;
        int len = json.length();
        int i = skipWs(json, 0, len);
        if (i >= len || json.charAt(i) != '{') return null;
        i = skipWs(json, i + 1, len);
        if (i < len && json.charAt(i) == '}') return null;
        while (i < len) {
            i = skipWs(json, i, len);
            if (i >= len || json.charAt(i) != '"') return null;
            int keyEnd = scanRawStringEnd(json, i + 1, len);
            if (keyEnd < 0) return null;
            String rawKey = json.substring(i + 1, keyEnd);
            i = skipWs(json, keyEnd + 1, len);
            if (i >= len || json.charAt(i) != ':') return null;
            i = skipWs(json, i + 1, len);
            if (i >= len) return null;
            if (rawKey.equals(fieldName)) {
                if (json.charAt(i) != '"') return null;
                Parser p = new Parser(json);
                p.pos = i;
                return p.readString();
            }
            i = skipRawValue(json, i, len);
            if (i < 0) return null;
            i = skipWs(json, i, len);
            if (i < len && json.charAt(i) == ',') {
                i++;
            } else {
                return null;
            }
        }
        return null;
    }""",
            """    /** Extracts a top-level string member value from a validated JSON object text. */
    public static String extractTopLevelStringField(String json, String fieldName) {
        if (json == null || fieldName == null || fieldName.isEmpty()) return null;
        Map<String, Object> parsed = parseObject(json);
        return (parsed.get(fieldName) instanceof String s) ? s : null;
    }""",
        ),
        (
            """                String key = readString();
                skipWhitespace();
                if (pos >= len || src.charAt(pos) != ':') {
                    throw new IllegalArgumentException("Expected ':' after member name at index " + pos);
                }
                pos++;
                map.put(key, readValue(depth));""",
            """                String key = readString();
                if (map.containsKey(key)) {
                    throw new IllegalArgumentException("Duplicate JSON object member name: '" + key + "'");
                }
                skipWhitespace();
                if (pos >= len || src.charAt(pos) != ':') {
                    throw new IllegalArgumentException("Expected ':' after member name at index " + pos);
                }
                pos++;
                map.put(key, readValue(depth));""",
        ),
    ],
)

# --- Fix 3A: EcdsaDerCodec strict [1, P256_ORDER_N - 1] scalar range check in p1363ToDer ---
patch_file(
    pkg / "EcdsaDerCodec.java",
    [
        (
            """        BigInteger r = new BigInteger(1, Arrays.copyOfRange(p1363Signature, 0, P256_COORD_BYTES));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(p1363Signature, P256_COORD_BYTES, P256_SIG_BYTES));""",
            """        BigInteger r = new BigInteger(1, Arrays.copyOfRange(p1363Signature, 0, P256_COORD_BYTES));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(p1363Signature, P256_COORD_BYTES, P256_SIG_BYTES));
        validateScalarRange(r, "r");
        validateScalarRange(s, "s");""",
        ),
    ],
)

# --- Fix 4A: JwkThumbprint canonical RFC 7638 lexicographic required-member thumbprint ---
patch_file(
    pkg / "JwkThumbprint.java",
    [
        (
            """        if (jwk.get("kid") instanceof String kid && !kid.isBlank()) {
            thumbMembers.put("kid", kid);
        }
        return sha256Base64Url(JsonCodec.serialize(thumbMembers).getBytes(StandardCharsets.UTF_8));""",
            """        return sha256Base64Url(JsonCodec.serializeCanonical(thumbMembers).getBytes(StandardCharsets.UTF_8));""",
        ),
    ],
)

# --- Fix 3B & 4B: DpopProofValidator mandatory ath check + (jkt, jti) replay cache key ---
patch_file(
    pkg / "DpopProofValidator.java",
    [
        (
            """        Optional<String> verifiedAth = Optional.empty();
        if (boundAccessToken != null && claims.containsKey("ath")) {
            String actualAth = requireNonBlankString(claims, "ath");
            if (!constantTimeEquals(actualAth, computeAccessTokenHash(boundAccessToken))) {
                throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP ath mismatch");
            }
            verifiedAth = Optional.of(actualAth);
        }""",
            """        Optional<String> verifiedAth = Optional.empty();
        if (boundAccessToken != null) {
            String actualAth = requireNonBlankString(claims, "ath");
            if (!constantTimeEquals(actualAth, computeAccessTokenHash(boundAccessToken))) {
                throw reject(FederationGuard.ErrorCode.INVALID_DPOP_PROOF, "DPoP ath mismatch");
            }
            verifiedAth = Optional.of(actualAth);
        }""",
        ),
        (
            r"""        String replayKey = JwkThumbprint.sha256Base64Url(rawDpopJwt.getBytes(StandardCharsets.UTF_8));""",
            r"""        String replayKey = jkt + "\0" + jti;""",
        ),
    ],
)

# --- Fix 2B & 4C: FederationGuard single canonical parse + cnf.jkt sender-constraint & scheme enforcement ---
patch_file(
    pkg / "FederationGuard.java",
    [
        (
            """        String[] parts = JwsSignatureEngine.splitCompactJws(rawAccessToken);
        String payloadJson;
        try {
            payloadJson = JsonCodec.decodeUtf8Base64Url(parts[1]);
        } catch (IllegalArgumentException ex) {
            throw new VerificationException(ErrorCode.MALFORMED_TOKEN, "Malformed payload Base64URL", ex);
        }

        String preScanIss = JsonCodec.extractTopLevelStringField(payloadJson, "iss");
        if (preScanIss == null || preScanIss.isBlank()) {
            throw new VerificationException(ErrorCode.UNTRUSTED_ISSUER, "Missing 'iss' claim");
        }
        FederationTrustStore.IssuerEntry signingIssuer = trustStore.resolveIssuer(preScanIss)
                .orElseThrow(() -> new VerificationException(ErrorCode.UNTRUSTED_ISSUER, "Untrusted issuer"));

        JwsSignatureEngine.VerifiedJws verifiedToken =
                signatureEngine.verifyAccessToken(rawAccessToken, signingIssuer, nowEpochSeconds);

        VerifiedSession session = claimsEngine.evaluate(verifiedToken.payload(), policy, nowEpochSeconds);

        boolean hasDpopHeader = request.dpopHeader() != null && !request.dpopHeader().isBlank();
        if (policy.dpopRequired() || hasDpopHeader) {
            if (parsedAuth.scheme() != AuthScheme.DPOP || !hasDpopHeader) {
                throw new VerificationException(ErrorCode.DPOP_REQUIRED, "DPoP scheme and proof header required");
            }
            String expectedJkt = session.confirmationJkt()
                    .orElseThrow(() -> new VerificationException(ErrorCode.DPOP_REQUIRED, "Missing cnf.jkt"));
            dpopValidator.validateProof(
                    request.dpopHeader().trim(), request.method(), request.targetUri(),
                    rawAccessToken, expectedJkt, nowEpochSeconds);
        }
        return session;""",
            """        String[] parts = JwsSignatureEngine.splitCompactJws(rawAccessToken);
        java.util.Map<String, Object> preParsedPayload;
        try {
            preParsedPayload = JsonCodec.parseObject(JsonCodec.decodeUtf8Base64Url(parts[1]));
        } catch (IllegalArgumentException ex) {
            throw new VerificationException(ErrorCode.MALFORMED_TOKEN, "Malformed access token payload", ex);
        }

        if (!(preParsedPayload.get("iss") instanceof String tokenIss) || tokenIss.isBlank()) {
            throw new VerificationException(ErrorCode.UNTRUSTED_ISSUER, "Missing 'iss' claim");
        }
        FederationTrustStore.IssuerEntry signingIssuer = trustStore.resolveIssuer(tokenIss)
                .orElseThrow(() -> new VerificationException(ErrorCode.UNTRUSTED_ISSUER, "Untrusted issuer"));

        JwsSignatureEngine.VerifiedJws verifiedToken =
                signatureEngine.verifyAccessToken(rawAccessToken, signingIssuer, nowEpochSeconds);

        VerifiedSession session = claimsEngine.evaluate(verifiedToken.payload(), policy, nowEpochSeconds);
        if (!signingIssuer.policy().issuerUri().equals(session.issuer())) {
            throw new VerificationException(ErrorCode.UNTRUSTED_ISSUER, "Issuer mismatch across verification stages");
        }

        boolean hasDpopHeader = request.dpopHeader() != null && !request.dpopHeader().isBlank();
        boolean tokenIsSenderConstrained = session.confirmationJkt().isPresent();
        if (policy.dpopRequired() || tokenIsSenderConstrained) {
            if (parsedAuth.scheme() != AuthScheme.DPOP || !hasDpopHeader) {
                throw new VerificationException(
                        ErrorCode.DPOP_REQUIRED, "Sender-constrained or DPoP-required request must use DPoP scheme and proof");
            }
            String expectedJkt = session.confirmationJkt()
                    .orElseThrow(() -> new VerificationException(ErrorCode.DPOP_REQUIRED, "Missing cnf.jkt"));
            dpopValidator.validateProof(
                    request.dpopHeader().trim(), request.method(), request.targetUri(),
                    rawAccessToken, expectedJkt, nowEpochSeconds);
        } else {
            if (parsedAuth.scheme() != AuthScheme.BEARER || hasDpopHeader) {
                throw new VerificationException(
                        ErrorCode.INVALID_DPOP_PROOF, "Unbound access token must use Bearer scheme without DPoP header");
            }
        }
        return session;""",
        ),
    ],
)

# --- Add regression tests to FederationTestSuite.java ---
patch_file(
    test_pkg / "FederationTestSuite.java",
    [
        (
            r"""        runCase("claims_expiry_audience_scope_and_delegation", this::testClaimsPolicyAndDelegation);
        System.out.printf("FederationTestSuite summary: %d passed, %d failed%n", passed, failed);""",
            r"""        runCase("claims_expiry_audience_scope_and_delegation", this::testClaimsPolicyAndDelegation);
        runCase("regression_inline_jwk_issuer_prefix_and_alg_confusion", this::testRegressionInlineJwkAndIssuerIsolation);
        runCase("regression_duplicate_json_keys_and_unicode_escapes", this::testRegressionDuplicateJsonKeys);
        runCase("regression_ecdsa_bounds_and_malleable_dpop_replay", this::testRegressionEcdsaBoundsAndMalleableReplay);
        runCase("regression_rfc7638_thumbprint_ath_and_cnf_downgrade", this::testRegressionRfc7638AthAndCnfBinding);
        System.out.printf("FederationTestSuite summary: %d passed, %d failed%n", passed, failed);""",
        ),
        (
            r"""    private static Map<String, Object> baseClaims(String iss, String sub, String jti, String scope) {""",
            r"""    private void testRegressionInlineJwkAndIssuerIsolation() throws Exception {
        FederationTrustStore store = new FederationTrustStore();
        KeyPair trustedEc = generateEcP256();
        KeyPair untrustedEc = generateEcP256();
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISSUER, Set.of("ES256"), Set.of(API_AUDIENCE), Set.of("vault:admin"), false))
                .registerKey("core-ec-1", JwkThumbprint.toPublicJwkMap(trustedEc.getPublic(), "core-ec-1", "ES256"));
        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy pol = new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("vault:admin"), false);

        // Inline jwk with matching kid must be rejected
        String inlineForged = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1",
                        "jwk", JwkThumbprint.toPublicJwkMap(untrustedEc.getPublic(), "core-ec-1", "ES256")),
                baseClaims(CORE_ISSUER, "mallory", "jti-forged-1", "vault:admin"), untrustedEc.getPrivate());
        assertRejects(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault",
                        "Bearer " + inlineForged, null), pol, BASE_NOW), "inline jwk in access token");

        // Issuer prefix must not resolve
        assertTrue(store.resolveIssuer(CORE_ISSUER + ".attacker.example").isEmpty(), "prefix issuer must not match");

        // HS256 public-key confusion must be rejected
        SecretKey spkiSecret = new SecretKeySpec(trustedEc.getPublic().getEncoded(), "HmacSHA256");
        String hsForged = JwsSignatureEngine.signCompact(
                Map.of("alg", "HS256", "typ", "at+jwt", "kid", "core-ec-1"),
                baseClaims(CORE_ISSUER, "mallory", "jti-hs-forged", "vault:admin"), spkiSecret);
        assertRejects(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault",
                        "Bearer " + hsForged, null), pol, BASE_NOW), "HS256 public key confusion");
    }

    private void testRegressionDuplicateJsonKeys() throws Exception {
        assertRejects(() -> JsonCodec.parseObject("{\"iss\":\"a\",\"iss\":\"b\"}"), "duplicate literal key");
        assertRejects(() -> JsonCodec.parseObject("{\"iss\":\"a\",\"\\u0069ss\":\"b\"}"), "duplicate unicode key");

        FederationTrustStore store = new FederationTrustStore();
        KeyPair coreKey = generateEcP256();
        KeyPair partnerKey = generateEcP256();
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISSUER, Set.of("ES256"), Set.of(API_AUDIENCE), Set.of("vault:admin", "catalog:read"), false))
                .registerKey("k1", JwkThumbprint.toPublicJwkMap(coreKey.getPublic(), "k1", "ES256"));
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        PARTNER_ISSUER, Set.of("ES256"), Set.of(API_AUDIENCE), Set.of("catalog:read"), false))
                .registerKey("k1", JwkThumbprint.toPublicJwkMap(partnerKey.getPublic(), "k1", "ES256"));

        FederationGuard guard = new FederationGuard(store);
        String rawPayload = "{\"iss\":\"" + PARTNER_ISSUER + "\",\"\\u0069ss\":\"" + CORE_ISSUER
                + "\",\"sub\":\"u\",\"aud\":\"" + API_AUDIENCE + "\",\"iat\":" + (BASE_NOW - 5)
                + ",\"exp\":" + (BASE_NOW + 300) + ",\"jti\":\"dup-jti\",\"scope\":\"vault:admin\"}";
        String tok = JwsSignatureEngine.signCompactRaw(
                "{\"alg\":\"ES256\",\"typ\":\"at+jwt\",\"kid\":\"k1\"}", rawPayload, "ES256", partnerKey.getPrivate());
        assertRejects(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault",
                        "Bearer " + tok, null),
                new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("vault:admin"), false), BASE_NOW),
                "cross-issuer duplicate iss payload");
    }

    private void testRegressionEcdsaBoundsAndMalleableReplay() throws Exception {
        byte[] zeroSig = new byte[64];
        assertRejects(() -> EcdsaDerCodec.p1363ToDer(zeroSig), "zero ECDSA scalars");
        byte[] orderNSig = new byte[64];
        System.arraycopy(EcdsaDerCodec.encodeUnsignedFixedWidth(EcdsaDerCodec.P256_ORDER_N, 32), 0, orderNSig, 0, 32);
        System.arraycopy(EcdsaDerCodec.encodeUnsignedFixedWidth(java.math.BigInteger.ONE, 32), 0, orderNSig, 32, 32);
        assertRejects(() -> EcdsaDerCodec.p1363ToDer(orderNSig), "r == N ECDSA scalar");

        FederationTrustStore store = new FederationTrustStore();
        KeyPair idpKey = generateEcP256();
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISSUER, Set.of("ES256"), Set.of(API_AUDIENCE), Set.of("settlements:write"), false))
                .registerKey("idp-1", JwkThumbprint.toPublicJwkMap(idpKey.getPublic(), "idp-1", "ES256"));
        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy pol = new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("settlements:write"), true);

        KeyPair dpopKp = generateEcP256();
        Map<String, Object> pubJwk = JwkThumbprint.toPublicJwkMap(dpopKp.getPublic(), null, null);
        String jkt = JwkThumbprint.compute(pubJwk);
        Map<String, Object> claims = baseClaims(CORE_ISSUER, "u1", "jti-m1", "settlements:write");
        claims.put("cnf", Map.of("jkt", jkt));
        String at = JwsSignatureEngine.signCompact(Map.of("alg", "ES256", "typ", "at+jwt", "kid", "idp-1"), claims, idpKey.getPrivate());

        String dpop = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", pubJwk),
                Map.of("jti", "nonce-m1", "htm", "POST", "htu", "https://api.stonegate.internal/v1/settlements",
                        "iat", BASE_NOW, "ath", DpopProofValidator.computeAccessTokenHash(at)),
                dpopKp.getPrivate());
        guard.authenticate(new FederationGuard.HttpRequestContext("POST",
                "https://api.stonegate.internal/v1/settlements", "DPoP " + at, dpop), pol, BASE_NOW);

        String[] segs = dpop.split("\\.");
        java.math.BigInteger[] rs = EcdsaDerCodec.decodeScalarPair(JsonCodec.decodeBase64Url(segs[2]));
        byte[] flipped = new byte[64];
        System.arraycopy(EcdsaDerCodec.encodeUnsignedFixedWidth(rs[0], 32), 0, flipped, 0, 32);
        System.arraycopy(EcdsaDerCodec.encodeUnsignedFixedWidth(EcdsaDerCodec.P256_ORDER_N.subtract(rs[1]), 32), 0, flipped, 32, 32);
        String malleated = segs[0] + "." + segs[1] + "." + JsonCodec.encodeBase64Url(flipped);
        assertRejects(() -> guard.authenticate(new FederationGuard.HttpRequestContext("POST",
                "https://api.stonegate.internal/v1/settlements", "DPoP " + at, malleated), pol, BASE_NOW + 1),
                "ECDSA (r, N - s) malleable DPoP replay");
    }

    private void testRegressionRfc7638AthAndCnfBinding() throws Exception {
        KeyPair ec = generateEcP256();
        String jktNoKid = JwkThumbprint.compute(JwkThumbprint.toPublicJwkMap(ec.getPublic(), null, null));
        String jktWithKid = JwkThumbprint.compute(JwkThumbprint.toPublicJwkMap(ec.getPublic(), "kid-meta", "ES256"));
        assertEquals(jktNoKid, jktWithKid, "RFC 7638 jkt must ignore optional kid and alg");

        KeyPair ed = generateEd25519();
        Map<String, Object> edJwk = JwkThumbprint.toPublicJwkMap(ed.getPublic(), "ed-kid", "EdDSA");
        String expectedEdJson = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + edJwk.get("x") + "\"}";
        String expectedEdJkt = JsonCodec.encodeBase64Url(
                java.security.MessageDigest.getInstance("SHA-256").digest(expectedEdJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(expectedEdJkt, JwkThumbprint.compute(edJwk), "RFC 8037 OKP canonical jkt");

        FederationTrustStore store = new FederationTrustStore();
        KeyPair idpKey = generateEcP256();
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISSUER, Set.of("ES256"), Set.of(API_AUDIENCE), Set.of("settlements:read"), false))
                .registerKey("idp-1", JwkThumbprint.toPublicJwkMap(idpKey.getPublic(), "idp-1", "ES256"));
        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy mixedPol = new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("settlements:read"), false);

        Map<String, Object> cnfClaims = baseClaims(CORE_ISSUER, "holder", "jti-cnf", "settlements:read");
        cnfClaims.put("cnf", Map.of("jkt", jktNoKid));
        String cnfToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "idp-1"), cnfClaims, idpKey.getPrivate());

        // Downgrade of cnf.jkt token to Bearer without DPoP header on mixed endpoint must fail
        assertRejects(() -> guard.authenticate(new FederationGuard.HttpRequestContext("GET",
                "https://api.stonegate.internal/v1/settlements", "Bearer " + cnfToken, null), mixedPol, BASE_NOW),
                "cnf.jkt token downgraded to Bearer");

        // DPoP proof omitting ath must fail
        String noAthProof = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", JwkThumbprint.toPublicJwkMap(ec.getPublic(), "kid-meta", "ES256")),
                Map.of("jti", "no-ath-1", "htm", "GET", "htu", "https://api.stonegate.internal/v1/settlements", "iat", BASE_NOW),
                ec.getPrivate());
        assertRejects(() -> guard.authenticate(new FederationGuard.HttpRequestContext("GET",
                "https://api.stonegate.internal/v1/settlements", "DPoP " + cnfToken, noAthProof), mixedPol, BASE_NOW),
                "DPoP proof missing ath");
    }

    private static Map<String, Object> baseClaims(String iss, String sub, String jti, String scope) {""",
        ),
    ],
)
PY

make -C "$APP_DIR" clean all test
