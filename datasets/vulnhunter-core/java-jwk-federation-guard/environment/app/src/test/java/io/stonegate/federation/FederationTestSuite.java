package io.stonegate.federation;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Deterministic baseline unit and integration test runner for {@code io.stonegate.federation}.
 */
public final class FederationTestSuite {

    private static final long BASE_NOW = 1_762_000_000L;
    private static final String CORE_ISSUER = "https://idp.stonegate.internal";
    private static final String PARTNER_ISSUER = "https://partner-idp.stonegate.internal";
    private static final String MESH_ISSUER = "https://mesh-idp.stonegate.internal";
    private static final String API_AUDIENCE = "https://api.stonegate.internal";

    private int passed = 0;
    private int failed = 0;

    public static void main(String[] args) throws Exception {
        new FederationTestSuite().runAll();
    }

    private void runAll() throws Exception {
        runCase("json_and_base64url_roundtrip", this::testJsonAndBase64UrlRoundtrip);
        runCase("ecdsa_p1363_der_roundtrip", this::testEcdsaDerRoundtrip);
        runCase("multi_issuer_es256_eddsa_rs256_hs256_bearer", this::testMultiIssuerBearerFlows);
        runCase("dpop_sender_constrained_post_and_query_htu", this::testDpopSenderConstrainedFlows);
        runCase("key_rotation_grace_window_and_revocation", this::testKeyRotationAndRevocation);
        runCase("claims_expiry_audience_scope_and_delegation", this::testClaimsPolicyAndDelegation);
        System.out.printf("FederationTestSuite summary: %d passed, %d failed%n", passed, failed);
        if (failed > 0) System.exit(1);
    }

    @FunctionalInterface
    private interface TestCase {
        void execute() throws Exception;
    }

    private void runCase(String name, TestCase tc) {
        try {
            tc.execute();
            passed++;
            System.out.println("[PASS] " + name);
        } catch (Throwable t) {
            failed++;
            System.err.println("[FAIL] " + name + ": " + t.getMessage());
            t.printStackTrace(System.err);
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void assertEquals(Object expected, Object actual, String message) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError(message + " (expected=" + expected + ", actual=" + actual + ")");
        }
    }

    private static void assertRejects(Runnable action, String description) {
        try {
            action.run();
        } catch (FederationGuard.VerificationException | IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Expected rejection for: " + description);
    }

    private void testJsonAndBase64UrlRoundtrip() {
        String raw = "{\"z\":42,\"a\":\"line\\n\\u0041\",\"nested\":{\"flag\":true,\"items\":[1,2,null]}}";
        Map<String, Object> parsed = JsonCodec.parseObject(raw);
        assertEquals(42L, parsed.get("z"), "Parsed integer mismatch");
        assertEquals("line\nA", parsed.get("a"), "Parsed unicode escape mismatch");
        assertTrue(JsonCodec.serializeCanonical(parsed).startsWith("{\"a\":\"line\\nA\",\"nested\":"), "Canonical sort");

        byte[] sample = new byte[]{0, 1, 2, (byte) 0xFB, (byte) 0xFF};
        String b64 = JsonCodec.encodeBase64Url(sample);
        assertTrue(!b64.contains("=") && Arrays.equals(sample, JsonCodec.decodeBase64Url(b64)), "Base64URL roundtrip");
        assertRejects(() -> JsonCodec.decodeBase64Url(b64 + "="), "padded base64url");
    }

    private void testEcdsaDerRoundtrip() throws Exception {
        KeyPair ecKp = generateEcP256();
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(ecKp.getPrivate());
        signer.update("stonegate-ecdsa-test-payload".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] der = signer.sign();
        byte[] p1363 = EcdsaDerCodec.derToP1363(der);
        assertEquals(64, p1363.length, "P1363 length");
        assertTrue(Arrays.equals(der, EcdsaDerCodec.p1363ToDer(p1363)), "DER roundtrip");
    }

    private void testMultiIssuerBearerFlows() throws Exception {
        FederationTrustStore store = new FederationTrustStore();
        KeyPair ecCore = generateEcP256();
        KeyPair edCore = generateEd25519();
        FederationTrustStore.IssuerEntry core = store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                CORE_ISSUER, Set.of("ES256", "EdDSA"), Set.of(API_AUDIENCE),
                Set.of("settlements:read", "settlements:write", "vault:admin"), true));
        core.registerKey("core-ec-1", JwkThumbprint.toPublicJwkMap(ecCore.getPublic(), "core-ec-1", "ES256"));
        core.registerKey("core-ed-1", JwkThumbprint.toPublicJwkMap(edCore.getPublic(), "core-ed-1", "EdDSA"));

        KeyPair rsaPartner = generateRsa2048();
        FederationTrustStore.IssuerEntry partner = store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                PARTNER_ISSUER, Set.of("RS256"), Set.of(API_AUDIENCE), Set.of("catalog:read"), false));
        partner.registerKey("partner-rsa-1", JwkThumbprint.toPublicJwkMap(rsaPartner.getPublic(), "partner-rsa-1", "RS256"));

        byte[] hmacBytes = "stonegate-internal-mesh-secret-key-2026!".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        SecretKey hmacKey = new SecretKeySpec(hmacBytes, "HmacSHA256");
        FederationTrustStore.IssuerEntry mesh = store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                MESH_ISSUER, Set.of("HS256"), Set.of(API_AUDIENCE), Set.of("telemetry:ingest"), false));
        mesh.registerKey("mesh-hs-1", JwkThumbprint.toSymmetricJwkMap(hmacBytes, "mesh-hs-1"));

        FederationGuard guard = new FederationGuard(store);

        String esToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1"),
                baseClaims(CORE_ISSUER, "alice", "jti-es-1", "settlements:read settlements:write"), ecCore.getPrivate());
        assertEquals("alice", guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/settlements", "Bearer " + esToken, null),
                new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("settlements:read"), false), BASE_NOW).subject(), "ES256");

        String edToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "EdDSA", "typ", "at+jwt", "kid", "core-ed-1"),
                baseClaims(CORE_ISSUER, "bob", "jti-ed-1", "vault:admin"), edCore.getPrivate());
        assertEquals("bob", guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault", "Bearer " + edToken, null),
                new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("vault:admin"), false), BASE_NOW).subject(), "EdDSA");

        String rsToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "RS256", "typ", "jwt", "kid", "partner-rsa-1"),
                baseClaims(PARTNER_ISSUER, "partner-client", "jti-rs-1", "catalog:read"), rsaPartner.getPrivate());
        assertEquals(PARTNER_ISSUER, guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/catalog", "Bearer " + rsToken, null),
                new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("catalog:read"), false), BASE_NOW).issuer(), "RS256");

        String hsToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "HS256", "typ", "at+jwt", "kid", "mesh-hs-1"),
                baseClaims(MESH_ISSUER, "mesh-collector-7", "jti-hs-1", "telemetry:ingest"), hmacKey);
        assertEquals("mesh-collector-7", guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/telemetry", "Bearer " + hsToken, null),
                new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("telemetry:ingest"), false), BASE_NOW).subject(), "HS256");
    }

    private void testDpopSenderConstrainedFlows() throws Exception {
        FederationTrustStore store = new FederationTrustStore();
        KeyPair idpKey = generateEcP256();
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISSUER, Set.of("ES256"), Set.of(API_AUDIENCE), Set.of("settlements:write"), true))
                .registerKey("idp-ec-main", JwkThumbprint.toPublicJwkMap(idpKey.getPublic(), "idp-ec-main", "ES256"));

        FederationGuard guard = new FederationGuard(store);
        KeyPair clientDpopKey = generateEcP256();
        Map<String, Object> dpopPublicJwk = JwkThumbprint.toPublicJwkMap(clientDpopKey.getPublic(), null, null);
        String jkt = JwkThumbprint.compute(dpopPublicJwk);

        Map<String, Object> tokenClaims = baseClaims(CORE_ISSUER, "trader-9", "jti-at-dpop-1", "settlements:write");
        tokenClaims.put("cnf", Map.of("jkt", jkt));
        String accessToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "idp-ec-main"), tokenClaims, idpKey.getPrivate());

        String dpopProof = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", dpopPublicJwk),
                Map.of("jti", "dpop-nonce-1001", "htm", "POST", "htu", "https://api.stonegate.internal/v1/settlements",
                        "iat", BASE_NOW, "ath", DpopProofValidator.computeAccessTokenHash(accessToken)),
                clientDpopKey.getPrivate());

        FederationGuard.EndpointPolicy strictPolicy =
                new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("settlements:write"), true);
        FederationGuard.VerifiedSession session = guard.authenticate(
                new FederationGuard.HttpRequestContext("POST",
                        "HTTPS://Api.Stonegate.Internal:443/v1/settlements?batch=true&dryRun=0#commit",
                        "DPoP " + accessToken, dpopProof),
                strictPolicy, BASE_NOW);
        assertEquals(jkt, session.confirmationJkt().orElse(""), "DPoP cnf.jkt");

        assertRejects(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/settlements",
                        "DPoP " + accessToken, dpopProof),
                strictPolicy, BASE_NOW + 1), "exact duplicate DPoP proof replay");
    }

    private void testKeyRotationAndRevocation() throws Exception {
        FederationTrustStore store = new FederationTrustStore();
        KeyPair oldKey = generateEcP256();
        KeyPair newKey = generateEcP256();
        FederationTrustStore.IssuerEntry entry = store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                CORE_ISSUER, Set.of("ES256"), Set.of(API_AUDIENCE), Set.of("settlements:read"), false));
        entry.registerKey("k-2025", JwkThumbprint.toPublicJwkMap(oldKey.getPublic(), "k-2025", "ES256"));
        entry.rotateKey("k-2025", 120L, BASE_NOW, "k-2026", JwkThumbprint.toPublicJwkMap(newKey.getPublic(), "k-2026", "ES256"));

        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy policy = new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("settlements:read"), false);

        String oldToken = JwsSignatureEngine.signCompact(Map.of("alg", "ES256", "typ", "at+jwt", "kid", "k-2025"),
                baseClaims(CORE_ISSUER, "svc-old", "jti-rot-1", "settlements:read"), oldKey.getPrivate());
        String newToken = JwsSignatureEngine.signCompact(Map.of("alg", "ES256", "typ", "at+jwt", "kid", "k-2026"),
                baseClaims(CORE_ISSUER, "svc-new", "jti-rot-2", "settlements:read"), newKey.getPrivate());

        assertEquals("svc-old", guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/settlements", "Bearer " + oldToken, null),
                policy, BASE_NOW + 60).subject(), "Retiring key in grace window");
        assertEquals("svc-new", guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/settlements", "Bearer " + newToken, null),
                policy, BASE_NOW + 60).subject(), "New rotated key");
        assertRejects(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/settlements", "Bearer " + oldToken, null),
                policy, BASE_NOW + 180), "expired rotated key");
    }

    private void testClaimsPolicyAndDelegation() throws Exception {
        FederationTrustStore store = new FederationTrustStore();
        KeyPair coreKey = generateEd25519();
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISSUER, Set.of("EdDSA"), Set.of(API_AUDIENCE), Set.of("orders:read", "orders:write"), true))
                .registerKey("ed-del-1", JwkThumbprint.toPublicJwkMap(coreKey.getPublic(), "ed-del-1", "EdDSA"));

        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy readPolicy = new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("orders:read"), false);

        Map<String, Object> delClaims = baseClaims(CORE_ISSUER, "customer-42", "jti-del-1", "orders:read");
        delClaims.put("act", Map.of("sub", "checkout-orchestrator", "iss", CORE_ISSUER, "act", Map.of("sub", "edge-ingress")));
        String delToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "EdDSA", "typ", "at+jwt", "kid", "ed-del-1"), delClaims, coreKey.getPrivate());
        assertEquals(List.of(CORE_ISSUER + "#checkout-orchestrator", "edge-ingress"),
                guard.authenticate(new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/orders",
                        "Bearer " + delToken, null), readPolicy, BASE_NOW).actorChain(), "Delegation chain");

        Map<String, Object> expClaims = baseClaims(CORE_ISSUER, "customer-42", "jti-exp-1", "orders:read");
        expClaims.put("iat", BASE_NOW - 600);
        expClaims.put("exp", BASE_NOW - 120);
        String expToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "EdDSA", "typ", "at+jwt", "kid", "ed-del-1"), expClaims, coreKey.getPrivate());
        assertRejects(() -> guard.authenticate(new FederationGuard.HttpRequestContext("GET",
                "https://api.stonegate.internal/v1/orders", "Bearer " + expToken, null), readPolicy, BASE_NOW), "expired");

        Map<String, Object> badAudClaims = baseClaims(CORE_ISSUER, "customer-42", "jti-aud-1", "orders:read");
        badAudClaims.put("aud", "https://other-service.stonegate.internal");
        String badAudToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "EdDSA", "typ", "at+jwt", "kid", "ed-del-1"), badAudClaims, coreKey.getPrivate());
        assertRejects(() -> guard.authenticate(new FederationGuard.HttpRequestContext("GET",
                "https://api.stonegate.internal/v1/orders", "Bearer " + badAudToken, null), readPolicy, BASE_NOW), "audience");

        FederationGuard.EndpointPolicy writePolicy = new FederationGuard.EndpointPolicy(API_AUDIENCE, Set.of("orders:write"), false);
        assertRejects(() -> guard.authenticate(new FederationGuard.HttpRequestContext("POST",
                "https://api.stonegate.internal/v1/orders", "Bearer " + delToken, null), writePolicy, BASE_NOW), "scope");
    }

    private static Map<String, Object> baseClaims(String iss, String sub, String jti, String scope) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", iss);
        claims.put("sub", sub);
        claims.put("aud", API_AUDIENCE);
        claims.put("iat", BASE_NOW - 10);
        claims.put("exp", BASE_NOW + 600);
        claims.put("jti", jti);
        claims.put("scope", scope);
        return claims;
    }

    private static KeyPair generateEcP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static KeyPair generateEd25519() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static KeyPair generateRsa2048() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
