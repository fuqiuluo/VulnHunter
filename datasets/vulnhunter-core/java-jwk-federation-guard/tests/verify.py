#!/usr/bin/env python3
"""Deterministic end-to-end verifier for task: java-jwk-federation-guard."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

KNOWN_JAVA_MODULES = {
    "JsonCodec.java",
    "EcdsaDerCodec.java",
    "JwkThumbprint.java",
    "FederationTrustStore.java",
    "JwsSignatureEngine.java",
    "DpopProofValidator.java",
    "ClaimsPolicyEngine.java",
    "FederationGuard.java",
}

HARNESS_JAVA = r"""package verifier;

import io.stonegate.federation.ClaimsPolicyEngine;
import io.stonegate.federation.DpopProofValidator;
import io.stonegate.federation.EcdsaDerCodec;
import io.stonegate.federation.FederationGuard;
import io.stonegate.federation.FederationTrustStore;
import io.stonegate.federation.JsonCodec;
import io.stonegate.federation.JwkThumbprint;
import io.stonegate.federation.JwsSignatureEngine;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class VerifierHarness {

    private static final long NOW = 1_765_000_000L;
    private static final String CORE_ISS = "https://idp.stonegate.internal";
    private static final String PARTNER_ISS = "https://partner-idp.stonegate.internal";
    private static final String CLOUD_TENANT_ISS = "https://login.cloud-idp.internal/tenants/stonegate";
    private static final String MESH_ISS = "https://mesh-idp.stonegate.internal";
    private static final String AUD = "https://api.stonegate.internal";

    private static final byte[] ED25519_SPKI_HDR = new byte[]{
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    public static void main(String[] args) {
        Map<String, String> results = new LinkedHashMap<>();
        boolean allOk = true;

        allOk &= runGroup(results, "functional_rfc_compliance", VerifierHarness::checkFunctionalCompliance);
        allOk &= runGroup(results, "defect1_inline_jwk_issuer_and_alg_confusion", VerifierHarness::checkDefect1);
        allOk &= runGroup(results, "defect2_duplicate_json_key_differential", VerifierHarness::checkDefect2);
        allOk &= runGroup(results, "defect3_ecdsa_scalar_bounds_and_malleability_replay", VerifierHarness::checkDefect3);
        allOk &= runGroup(results, "defect4_rfc7638_jkt_ath_and_sender_constraint_downgrade", VerifierHarness::checkDefect4);

        StringBuilder json = new StringBuilder();
        json.append("{\"ok\":").append(allOk).append(",\"groups\":{");
        boolean first = true;
        for (Map.Entry<String, String> e : results.entrySet()) {
            if (!first) json.append(',');
            first = false;
            json.append('"').append(escapeJson(e.getKey())).append("\":\"")
                    .append(escapeJson(e.getValue())).append('"');
        }
        json.append("}}");
        System.out.println(json);
        System.exit(allOk ? 0 : 1);
    }

    @FunctionalInterface
    private interface GroupCheck {
        String run() throws Exception;
    }

    private static boolean runGroup(Map<String, String> out, String name, GroupCheck fn) {
        try {
            String msg = fn.run();
            out.put(name, "PASS: " + msg);
            return true;
        } catch (Throwable t) {
            out.put(name, "FAIL: " + (t.getMessage() != null ? t.getMessage() : t.getClass().getName()));
            return false;
        }
    }

    private static void check(boolean cond, String msg) {
        if (!cond) throw new AssertionError(msg);
    }

    private static void expectReject(Runnable r, String label) {
        try {
            r.run();
        } catch (FederationGuard.VerificationException | IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Expected rejection for: " + label);
    }

    // 1. Positive functional & RFC compliance (including high-S ES256, RFC 7638 jkt with kid/alg metadata)
    private static String checkFunctionalCompliance() throws Exception {
        FederationTrustStore store = new FederationTrustStore();

        KeyPair coreEc = genEc();
        KeyPair coreEd = genEd();
        FederationTrustStore.IssuerEntry core = store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                CORE_ISS, Set.of("ES256", "EdDSA"), Set.of(AUD),
                Set.of("orders:read", "orders:write", "vault:admin"), true));
        core.registerKey("core-ec-1", JwkThumbprint.toPublicJwkMap(coreEc.getPublic(), "core-ec-1", "ES256"));
        core.registerKey("core-ed-1", JwkThumbprint.toPublicJwkMap(coreEd.getPublic(), "core-ed-1", "EdDSA"));

        KeyPair partnerRsa = genRsa();
        FederationTrustStore.IssuerEntry partner = store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                PARTNER_ISS, Set.of("RS256"), Set.of(AUD), Set.of("catalog:read"), false));
        partner.registerKey("partner-rsa-1", JwkThumbprint.toPublicJwkMap(partnerRsa.getPublic(), "partner-rsa-1", "RS256"));

        byte[] hmacSecret = "mesh-shared-hmac-secret-32-bytes-minimum!!".getBytes(StandardCharsets.UTF_8);
        SecretKey hmacKey = new SecretKeySpec(hmacSecret, "HmacSHA256");
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        MESH_ISS, Set.of("HS256"), Set.of(AUD), Set.of("metrics:push"), false))
                .registerKey("mesh-1", JwkThumbprint.toSymmetricJwkMap(hmacSecret, "mesh-1"));

        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy mixedRead = new FederationGuard.EndpointPolicy(AUD, Set.of("orders:read"), false);
        FederationGuard.EndpointPolicy strictWrite = new FederationGuard.EndpointPolicy(AUD, Set.of("orders:write"), true);

        // High-S ES256 signature must be accepted per RFC 7518 §3.4
        String baseEsToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "application/at+jwt", "kid", "core-ec-1"),
                claims(CORE_ISS, "svc-high-s", "jti-high-s", "orders:read"),
                coreEc.getPrivate());
        String highSToken = forceHighS(baseEsToken);
        FederationGuard.VerifiedSession hsSess = guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/orders",
                        "bearer " + highSToken, null),
                mixedRead, NOW);
        check("svc-high-s".equals(hsSess.subject()), "High-S ES256 token failed");

        // EdDSA with multi-hop delegation
        Map<String, Object> edClaims = claims(CORE_ISS, "alice", "jti-ed-ok", "orders:read");
        edClaims.put("act", Map.of("sub", "api-bff", "iss", CORE_ISS, "act", Map.of("sub", "ingress-gw")));
        String edToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "EdDSA", "typ", "at+jwt", "kid", "core-ed-1"), edClaims, coreEd.getPrivate());
        FederationGuard.VerifiedSession edSess = guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/orders",
                        "Bearer " + edToken, null),
                mixedRead, NOW);
        check(edSess.actorChain().size() == 2, "Expected 2-hop actor chain");

        // RS256 and HS256 valid tokens
        String rsToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "RS256", "typ", "jwt", "kid", "partner-rsa-1"),
                claims(PARTNER_ISS, "partner-u1", "jti-rs-ok", "catalog:read"), partnerRsa.getPrivate());
        check("partner-u1".equals(guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/catalog", "Bearer " + rsToken, null),
                new FederationGuard.EndpointPolicy(AUD, Set.of("catalog:read"), false), NOW).subject()), "RS256 failed");

        String hmacToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "HS256", "typ", "at+jwt", "kid", "mesh-1"),
                claims(MESH_ISS, "node-4", "jti-hs-ok", "metrics:push"), hmacKey);
        check("node-4".equals(guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/metrics", "Bearer " + hmacToken, null),
                new FederationGuard.EndpointPolicy(AUD, Set.of("metrics:push"), false), NOW).subject()), "HS256 failed");

        // DPoP with EC (including optional kid + alg + use in inline header jwk), OKP Ed25519, and RSA RS256!
        KeyPair dpopEc = genEc();
        String refEcJkt = refEcThumbprint((ECPublicKey) dpopEc.getPublic());
        Map<String, Object> dpopEcJwkWithMeta = new LinkedHashMap<>(
                JwkThumbprint.toPublicJwkMap(dpopEc.getPublic(), "client-ec-kid-7", "ES256"));
        dpopEcJwkWithMeta.put("use", "sig");

        Map<String, Object> ecBoundClaims = claims(CORE_ISS, "dpop-ec-user", "jti-at-ec-dpop", "orders:write orders:read");
        ecBoundClaims.put("cnf", Map.of("jkt", refEcJkt));
        String ecBoundAt = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1"), ecBoundClaims, coreEc.getPrivate());

        String ecDpopProof = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", dpopEcJwkWithMeta),
                Map.of("jti", "dpop-ec-1", "htm", "POST", "htu", "https://api.stonegate.internal/v1/orders",
                        "iat", NOW, "ath", sha256B64u(ecBoundAt)),
                dpopEc.getPrivate());
        check(refEcJkt.equals(guard.authenticate(
                new FederationGuard.HttpRequestContext("POST",
                        "HTTPS://Api.Stonegate.Internal:443/v1/orders?dryRun=false#top",
                        "dpop " + ecBoundAt, ecDpopProof),
                strictWrite, NOW).confirmationJkt().orElse("")), "EC DPoP with header kid metadata failed");

        // Also valid on mixed-mode endpoint when properly using DPoP scheme + fresh proof
        String ecDpopProof2 = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", dpopEcJwkWithMeta),
                Map.of("jti", "dpop-ec-2", "htm", "GET", "htu", "https://api.stonegate.internal/v1/orders",
                        "iat", NOW, "ath", sha256B64u(ecBoundAt)),
                dpopEc.getPrivate());
        check("dpop-ec-user".equals(guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/orders?page=2",
                        "DPoP " + ecBoundAt, ecDpopProof2),
                mixedRead, NOW).subject()), "Mixed-mode valid DPoP failed");

        // OKP Ed25519 DPoP with canonical RFC 7638/8037 jkt
        KeyPair dpopEd = genEd();
        String refEdJkt = refEdThumbprint(dpopEd.getPublic().getEncoded());
        Map<String, Object> dpopEdJwk = JwkThumbprint.toPublicJwkMap(dpopEd.getPublic(), "client-ed-kid", "EdDSA");
        Map<String, Object> edBoundClaims = claims(CORE_ISS, "dpop-ed-user", "jti-at-ed-dpop", "orders:write");
        edBoundClaims.put("cnf", Map.of("jkt", refEdJkt));
        String edBoundAt = JwsSignatureEngine.signCompact(
                Map.of("alg", "EdDSA", "typ", "at+jwt", "kid", "core-ed-1"), edBoundClaims, coreEd.getPrivate());
        String edDpopProof = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "EdDSA", "jwk", dpopEdJwk),
                Map.of("jti", "dpop-ed-1", "htm", "POST", "htu", "https://api.stonegate.internal/v1/orders",
                        "iat", NOW, "ath", sha256B64u(edBoundAt)),
                dpopEd.getPrivate());
        check(refEdJkt.equals(guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/orders",
                        "DPoP " + edBoundAt, edDpopProof),
                strictWrite, NOW).confirmationJkt().orElse("")), "Ed25519 DPoP failed");

        // RSA RS256 DPoP with canonical RFC 7638 jkt
        KeyPair dpopRsa = genRsa();
        String refRsaJkt = refRsaThumbprint((RSAPublicKey) dpopRsa.getPublic());
        Map<String, Object> dpopRsaJwk = JwkThumbprint.toPublicJwkMap(dpopRsa.getPublic(), "client-rsa-kid", "RS256");
        Map<String, Object> rsaBoundClaims = claims(CORE_ISS, "dpop-rsa-user", "jti-at-rsa-dpop", "orders:write");
        rsaBoundClaims.put("cnf", Map.of("jkt", refRsaJkt));
        String rsaBoundAt = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1"), rsaBoundClaims, coreEc.getPrivate());
        String rsaDpopProof = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "RS256", "jwk", dpopRsaJwk),
                Map.of("jti", "dpop-rsa-1", "htm", "POST", "htu", "https://api.stonegate.internal/v1/orders",
                        "iat", NOW, "ath", sha256B64u(rsaBoundAt)),
                dpopRsa.getPrivate());
        check(refRsaJkt.equals(guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/orders",
                        "DPoP " + rsaBoundAt, rsaDpopProof),
                strictWrite, NOW).confirmationJkt().orElse("")), "RSA DPoP failed");

        // Two distinct DPoP keys using identical jti "seq-1" must NOT collide because replay key is (jkt, jti)
        String pKey1 = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", dpopEcJwkWithMeta),
                Map.of("jti", "shared-seq-1", "htm", "POST", "htu", "https://api.stonegate.internal/v1/orders",
                        "iat", NOW, "ath", sha256B64u(ecBoundAt)),
                dpopEc.getPrivate());
        String pKey2 = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "EdDSA", "jwk", dpopEdJwk),
                Map.of("jti", "shared-seq-1", "htm", "POST", "htu", "https://api.stonegate.internal/v1/orders",
                        "iat", NOW, "ath", sha256B64u(edBoundAt)),
                dpopEd.getPrivate());
        guard.authenticate(new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/orders",
                "DPoP " + ecBoundAt, pKey1), strictWrite, NOW);
        guard.authenticate(new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/orders",
                "DPoP " + edBoundAt, pKey2), strictWrite, NOW);

        return "All ES256 (including high-S), EdDSA, RS256, HS256, delegation, and RFC 7638 EC/OKP/RSA DPoP flows passed";
    }

    // 2. Defect 1: Inline JWS jwk/jku/x5u trust confusion, issuer startsWith prefix match, and HS256 public-key confusion
    private static String checkDefect1() throws Exception {
        FederationTrustStore store = new FederationTrustStore();
        KeyPair genuineEc = genEc();
        KeyPair genuineRsa = genRsa();
        KeyPair cloudSharedEc = genEc();
        KeyPair attackerEc = genEc();

        FederationTrustStore.IssuerEntry core = store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                CORE_ISS, Set.of("ES256", "RS256"), Set.of(AUD), Set.of("vault:admin"), true));
        core.registerKey("core-ec-1", JwkThumbprint.toPublicJwkMap(genuineEc.getPublic(), "core-ec-1", "ES256"));
        core.registerKey("core-rsa-1", JwkThumbprint.toPublicJwkMap(genuineRsa.getPublic(), "core-rsa-1", "RS256"));

        FederationTrustStore.IssuerEntry cloudTenant = store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                CLOUD_TENANT_ISS, Set.of("ES256"), Set.of(AUD), Set.of("vault:admin"), false));
        cloudTenant.registerKey("cloud-shared-1", JwkThumbprint.toPublicJwkMap(cloudSharedEc.getPublic(), "cloud-shared-1", "ES256"));

        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy adminPol = new FederationGuard.EndpointPolicy(AUD, Set.of("vault:admin"), false);

        // 1A: Attacker embeds inline "jwk" with matching kid="core-ec-1" (and without kid) in access token header
        Map<String, Object> attackerJwkMatchingKid = JwkThumbprint.toPublicJwkMap(attackerEc.getPublic(), "core-ec-1", "ES256");
        String forgedInlineKid = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1", "jwk", attackerJwkMatchingKid),
                claims(CORE_ISS, "attacker", "forged-inline-1", "vault:admin"),
                attackerEc.getPrivate());
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault", "Bearer " + forgedInlineKid, null),
                adminPol, NOW), "access token with inline jwk matching trusted kid");

        Map<String, Object> attackerJwkNoKid = JwkThumbprint.toPublicJwkMap(attackerEc.getPublic(), null, null);
        String forgedInlineNoKid = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1", "jwk", attackerJwkNoKid),
                claims(CORE_ISS, "attacker", "forged-inline-2", "vault:admin"),
                attackerEc.getPrivate());
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault", "Bearer " + forgedInlineNoKid, null),
                adminPol, NOW), "access token with inline jwk omitting kid");

        // Even genuine signer including forbidden jku / x5u / x5c / crit in access token header must be rejected
        for (Map<String, Object> badHdr : List.<Map<String, Object>>of(
                Map.<String, Object>of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1", "jku", "https://evil.example/jwks.json"),
                Map.<String, Object>of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1", "x5u", "https://evil.example/cert.pem"),
                Map.<String, Object>of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1", "x5c", List.of("MIIB")),
                Map.<String, Object>of("alg", "ES256", "typ", "at+jwt", "kid", "core-ec-1", "crit", List.of("custom")),
                Map.<String, Object>of("alg", "ES256", "typ", "dpop+jwt", "kid", "core-ec-1")
        )) {
            String tok = JwsSignatureEngine.signCompact(badHdr, claims(CORE_ISS, "u", "jti-hdr", "vault:admin"), genuineEc.getPrivate());
            expectReject(() -> guard.authenticate(
                    new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault", "Bearer " + tok, null),
                    adminPol, NOW), "forbidden header parameter: " + badHdr);
        }

        // 1B: Multi-realm shared cloud IdP issuer prefix spoofing via startsWith
        for (String rogueIss : List.of(
                "https://login.cloud-idp.internal/tenants/stonegate-sandbox",
                "https://login.cloud-idp.internal/tenants/stonegate/untrusted",
                "https://idp.stonegate.internal.attacker.example"
        )) {
            check(store.resolveIssuer(rogueIss).isEmpty(), "TrustStore resolved prefix-spoofed issuer: " + rogueIss);
            String crossRealmTok = JwsSignatureEngine.signCompact(
                    Map.of("alg", "ES256", "typ", "at+jwt", "kid", "cloud-shared-1"),
                    claims(rogueIss, "sandbox-attacker", "jti-prefix-1", "vault:admin"),
                    cloudSharedEc.getPrivate());
            expectReject(() -> guard.authenticate(
                    new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault",
                            "Bearer " + crossRealmTok, null),
                    adminPol, NOW), "cross-realm prefix issuer token: " + rogueIss);
        }

        // Invalid non-https or query/fragment/userinfo issuer registration must be rejected
        for (String invalidIssUri : List.of(
                "http://insecure-idp.stonegate.internal",
                "https://idp.stonegate.internal?env=dev",
                "https://idp.stonegate.internal#frag",
                "https://user:pass@idp.stonegate.internal"
        )) {
            expectReject(() -> store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                    invalidIssUri, Set.of("ES256"), Set.of(AUD), Set.of("vault:admin"), false)),
                    "registering non-canonical issuer URI: " + invalidIssUri);
        }

        // 1C: HS256 algorithm confusion signed with X.509 SPKI public key bytes of EC and RSA keys
        SecretKey ecSpkiHmac = new SecretKeySpec(genuineEc.getPublic().getEncoded(), "HmacSHA256");
        String hsConfusedEc = JwsSignatureEngine.signCompact(
                Map.of("alg", "HS256", "typ", "at+jwt", "kid", "core-ec-1"),
                claims(CORE_ISS, "attacker", "jti-hs-ec", "vault:admin"),
                ecSpkiHmac);
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault", "Bearer " + hsConfusedEc, null),
                adminPol, NOW), "HS256 confusion using EC public key bytes");

        SecretKey rsaSpkiHmac = new SecretKeySpec(genuineRsa.getPublic().getEncoded(), "HmacSHA256");
        String hsConfusedRsa = JwsSignatureEngine.signCompact(
                Map.of("alg", "HS256", "typ", "at+jwt", "kid", "core-rsa-1"),
                claims(CORE_ISS, "attacker", "jti-hs-rsa", "vault:admin"),
                rsaSpkiHmac);
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault", "Bearer " + hsConfusedRsa, null),
                adminPol, NOW), "HS256 confusion using RSA public key bytes");

        return "Inline JWK/JKU/X5U confusion, startsWith issuer prefix spoofing, and HS256 public-key confusion all rejected";
    }

    // 3. Defect 2: Duplicate JSON key first-wins vs last-wins & Unicode escape key differential
    private static String checkDefect2() throws Exception {
        // Direct parser invariant checks
        for (String dupJson : List.of(
                "{\"iss\":\"https://a.example\",\"iss\":\"https://b.example\"}",
                "{\"iss\":\"https://a.example\",\"\\u0069ss\":\"https://b.example\"}",
                "{\"\\u0069\\u0073\\u0073\":\"https://a.example\",\"iss\":\"https://b.example\"}",
                "{\"cnf\":{\"jkt\":\"jkt-1\",\"jkt\":\"jkt-2\"}}",
                "{\"arr\":[{\"k\":1,\"\\u006b\":2}]}"
        )) {
            expectReject(() -> JsonCodec.parseObject(dupJson), "duplicate JSON key: " + dupJson);
        }

        // End-to-end cross-issuer scope & identity escalation
        FederationTrustStore store = new FederationTrustStore();
        KeyPair coreKey = genEc();
        KeyPair lowPrivPartnerKey = genEc();

        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISS, Set.of("ES256"), Set.of(AUD), Set.of("catalog:read", "vault:admin"), true))
                .registerKey("shared-kid", JwkThumbprint.toPublicJwkMap(coreKey.getPublic(), "shared-kid", "ES256"));
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        PARTNER_ISS, Set.of("ES256"), Set.of(AUD), Set.of("catalog:read"), false))
                .registerKey("shared-kid", JwkThumbprint.toPublicJwkMap(lowPrivPartnerKey.getPublic(), "shared-kid", "ES256"));

        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy vaultPol = new FederationGuard.EndpointPolicy(AUD, Set.of("vault:admin"), false);

        String hdrJson = "{\"alg\":\"ES256\",\"typ\":\"at+jwt\",\"kid\":\"shared-kid\"}";
        for (String rawPayload : List.of(
                "{\"iss\":\"" + PARTNER_ISS + "\",\"iss\":\"" + CORE_ISS + "\",\"sub\":\"rogue\",\"aud\":\"" + AUD
                        + "\",\"iat\":" + (NOW - 5) + ",\"exp\":" + (NOW + 300) + ",\"jti\":\"dup-1\",\"scope\":\"vault:admin\"}",
                "{\"iss\":\"" + PARTNER_ISS + "\",\"\\u0069ss\":\"" + CORE_ISS + "\",\"sub\":\"rogue\",\"aud\":\"" + AUD
                        + "\",\"iat\":" + (NOW - 5) + ",\"exp\":" + (NOW + 300) + ",\"jti\":\"dup-2\",\"scope\":\"vault:admin\"}",
                "{\"\\u0069ss\":\"" + CORE_ISS + "\",\"iss\":\"" + PARTNER_ISS + "\",\"sub\":\"rogue\",\"aud\":\"" + AUD
                        + "\",\"iat\":" + (NOW - 5) + ",\"exp\":" + (NOW + 300) + ",\"jti\":\"dup-3\",\"scope\":\"catalog:read\"}"
        )) {
            String spoofedTok = JwsSignatureEngine.signCompactRaw(hdrJson, rawPayload, "ES256", lowPrivPartnerKey.getPrivate());
            expectReject(() -> guard.authenticate(
                    new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/vault",
                            "Bearer " + spoofedTok, null),
                    vaultPol, NOW), "duplicate iss cross-issuer escalation");
        }

        // Duplicate header keys
        String dupHdr = "{\"alg\":\"ES256\",\"alg\":\"ES256\",\"typ\":\"at+jwt\",\"kid\":\"shared-kid\"}";
        String validPayload = JsonCodec.serialize(claims(PARTNER_ISS, "u", "jti-ok", "catalog:read"));
        String dupHdrTok = JwsSignatureEngine.signCompactRaw(dupHdr, validPayload, "ES256", lowPrivPartnerKey.getPrivate());
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/catalog",
                        "Bearer " + dupHdrTok, null),
                new FederationGuard.EndpointPolicy(AUD, Set.of("catalog:read"), false), NOW), "duplicate JWS header key");

        return "Duplicate JSON object keys (literal, Unicode-escaped, and nested) rejected across parser and guard";
    }

    // 4. Defect 3: ECDSA P1363 scalar bounds [1, N-1] & (r, N - s) signature malleability DPoP replay
    private static String checkDefect3() throws Exception {
        byte[] one32 = EcdsaDerCodec.encodeUnsignedFixedWidth(BigInteger.ONE, 32);
        byte[] zero32 = new byte[32];
        byte[] orderN32 = EcdsaDerCodec.encodeUnsignedFixedWidth(EcdsaDerCodec.P256_ORDER_N, 32);
        byte[] orderNPlusOne32 = EcdsaDerCodec.encodeUnsignedFixedWidth(EcdsaDerCodec.P256_ORDER_N.add(BigInteger.ONE), 32);
        byte[] allOnes32 = new byte[32];
        Arrays.fill(allOnes32, (byte) 0xFF);

        for (byte[][] pair : List.of(
                new byte[][]{zero32, one32},
                new byte[][]{one32, zero32},
                new byte[][]{orderN32, one32},
                new byte[][]{one32, orderN32},
                new byte[][]{orderNPlusOne32, one32},
                new byte[][]{one32, allOnes32}
        )) {
            byte[] badP1363 = new byte[64];
            System.arraycopy(pair[0], 0, badP1363, 0, 32);
            System.arraycopy(pair[1], 0, badP1363, 32, 32);
            expectReject(() -> EcdsaDerCodec.p1363ToDer(badP1363), "out-of-range ECDSA P1363 scalar");
        }

        // End-to-end (r, N - s) DPoP replay test
        FederationTrustStore store = new FederationTrustStore();
        KeyPair idpKey = genEc();
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISS, Set.of("ES256"), Set.of(AUD), Set.of("payments:execute"), false))
                .registerKey("idp-1", JwkThumbprint.toPublicJwkMap(idpKey.getPublic(), "idp-1", "ES256"));

        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy dpopPol = new FederationGuard.EndpointPolicy(AUD, Set.of("payments:execute"), true);

        KeyPair clientKey = genEc();
        String jkt = refEcThumbprint((ECPublicKey) clientKey.getPublic());
        Map<String, Object> dpopJwk = JwkThumbprint.toPublicJwkMap(clientKey.getPublic(), null, null);

        Map<String, Object> atClaims = claims(CORE_ISS, "payer-1", "jti-pay-1", "payments:execute");
        atClaims.put("cnf", Map.of("jkt", jkt));
        String accessToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "idp-1"), atClaims, idpKey.getPrivate());

        String origDpop = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", dpopJwk),
                Map.of("jti", "dpop-malleable-77", "htm", "POST", "htu", "https://api.stonegate.internal/v1/payments",
                        "iat", NOW, "ath", sha256B64u(accessToken)),
                clientKey.getPrivate());

        // First submission succeeds
        guard.authenticate(new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/payments",
                "DPoP " + accessToken, origDpop), dpopPol, NOW);

        // Malleate signature s -> N - s over the exact same header.payload
        String malleatedDpop = flipEcdsaS(origDpop);
        check(!malleatedDpop.equals(origDpop), "Malleated DPoP proof must differ from original compact JWS");

        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/payments",
                        "DPoP " + accessToken, malleatedDpop),
                dpopPol, NOW + 1), "ECDSA (r, N - s) malleable DPoP replay");

        // Re-signed proof with updated iat but reusing the same (jkt, jti) must also be rejected as replay
        String resignedSameJti = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", dpopJwk),
                Map.of("jti", "dpop-malleable-77", "htm", "POST", "htu", "https://api.stonegate.internal/v1/payments",
                        "iat", NOW + 2, "ath", sha256B64u(accessToken)),
                clientKey.getPrivate());
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/payments",
                        "DPoP " + accessToken, resignedSameJti),
                dpopPol, NOW + 2), "re-signed DPoP proof reusing jti");

        return "ECDSA P1363 [1, N - 1] bounds enforced and (r, N - s) + re-signed jti DPoP replays blocked";
    }

    // 5. Defect 4: RFC 7638 jkt canonical thumbprint, mandatory ath, and cnf.jkt sender-constraint enforcement
    private static String checkDefect4() throws Exception {
        KeyPair ec = genEc();
        String expectedEcJkt = refEcThumbprint((ECPublicKey) ec.getPublic());
        Map<String, Object> ecWithKid = new LinkedHashMap<>(JwkThumbprint.toPublicJwkMap(ec.getPublic(), "ec-kid-9", "ES256"));
        ecWithKid.put("use", "sig");
        check(expectedEcJkt.equals(JwkThumbprint.compute(ecWithKid)), "EC jkt changed when kid/alg/use present");

        KeyPair ed = genEd();
        String expectedEdJkt = refEdThumbprint(ed.getPublic().getEncoded());
        Map<String, Object> edWithKid = JwkThumbprint.toPublicJwkMap(ed.getPublic(), "ed-kid-9", "EdDSA");
        check(expectedEdJkt.equals(JwkThumbprint.compute(edWithKid)), "OKP Ed25519 jkt violated RFC 7638/8037 order");

        KeyPair rsa = genRsa();
        String expectedRsaJkt = refRsaThumbprint((RSAPublicKey) rsa.getPublic());
        Map<String, Object> rsaWithKid = JwkThumbprint.toPublicJwkMap(rsa.getPublic(), "rsa-kid-9", "RS256");
        check(expectedRsaJkt.equals(JwkThumbprint.compute(rsaWithKid)), "RSA jkt violated RFC 7638 lexicographic order");

        byte[] octBytes = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        String kB64 = JsonCodec.encodeBase64Url(octBytes);
        String expectedOctJkt = sha256B64u("{\"k\":\"" + kB64 + "\",\"kty\":\"oct\"}");
        check(expectedOctJkt.equals(JwkThumbprint.compute(JwkThumbprint.toSymmetricJwkMap(octBytes, "oct-kid-1"))),
                "oct jkt violated RFC 7638 lexicographic order");

        // Setup guard with mixed-mode (dpopRequired=false) and strict-mode (dpopRequired=true) policies
        FederationTrustStore store = new FederationTrustStore();
        KeyPair idpKey = genEc();
        store.registerIssuer(new FederationTrustStore.IssuerPolicy(
                        CORE_ISS, Set.of("ES256"), Set.of(AUD), Set.of("accounts:read", "accounts:transfer"), false))
                .registerKey("idp-1", JwkThumbprint.toPublicJwkMap(idpKey.getPublic(), "idp-1", "ES256"));
        FederationGuard guard = new FederationGuard(store);
        FederationGuard.EndpointPolicy mixedPol = new FederationGuard.EndpointPolicy(AUD, Set.of("accounts:read"), false);
        FederationGuard.EndpointPolicy strictPol = new FederationGuard.EndpointPolicy(AUD, Set.of("accounts:transfer"), true);

        Map<String, Object> cnfClaims = claims(CORE_ISS, "holder-1", "jti-cnf-1", "accounts:read accounts:transfer");
        cnfClaims.put("cnf", Map.of("jkt", expectedEcJkt));
        String cnfAccessToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "idp-1"), cnfClaims, idpKey.getPrivate());

        // 4A: DPoP proof omitting "ath" claim must be rejected!
        String noAthProof = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", ecWithKid),
                Map.of("jti", "dpop-no-ath-1", "htm", "POST", "htu", "https://api.stonegate.internal/v1/transfer",
                        "iat", NOW),
                ec.getPrivate());
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("POST", "https://api.stonegate.internal/v1/transfer",
                        "DPoP " + cnfAccessToken, noAthProof),
                strictPol, NOW), "DPoP proof omitting mandatory ath claim");

        // 4B: Downgrading cnf.jkt-bound token to Bearer without DPoP proof on mixed-mode endpoint must be rejected!
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/accounts",
                        "Bearer " + cnfAccessToken, null),
                mixedPol, NOW), "cnf.jkt sender-constrained token downgraded to Bearer without DPoP header");

        // 4C: Presenting cnf.jkt-bound token with Bearer scheme even WITH valid DPoP header must be rejected!
        String validGetProof = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", ecWithKid),
                Map.of("jti", "dpop-get-valid-1", "htm", "GET", "htu", "https://api.stonegate.internal/v1/accounts",
                        "iat", NOW, "ath", sha256B64u(cnfAccessToken)),
                ec.getPrivate());
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/accounts",
                        "Bearer " + cnfAccessToken, validGetProof),
                mixedPol, NOW), "cnf.jkt token presented with Bearer scheme instead of DPoP");

        // 4D: Presenting unbound plain Bearer token with DPoP scheme or unsolicited DPoP header must be rejected!
        String plainAccessToken = JwsSignatureEngine.signCompact(
                Map.of("alg", "ES256", "typ", "at+jwt", "kid", "idp-1"),
                claims(CORE_ISS, "plain-user", "jti-plain-1", "accounts:read"), idpKey.getPrivate());
        String plainProof = JwsSignatureEngine.signCompact(
                Map.of("typ", "dpop+jwt", "alg", "ES256", "jwk", ecWithKid),
                Map.of("jti", "dpop-plain-1", "htm", "GET", "htu", "https://api.stonegate.internal/v1/accounts",
                        "iat", NOW, "ath", sha256B64u(plainAccessToken)),
                ec.getPrivate());
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/accounts",
                        "DPoP " + plainAccessToken, plainProof),
                mixedPol, NOW), "unbound token presented with DPoP scheme");
        expectReject(() -> guard.authenticate(
                new FederationGuard.HttpRequestContext("GET", "https://api.stonegate.internal/v1/accounts",
                        "Bearer " + plainAccessToken, plainProof),
                mixedPol, NOW), "unbound Bearer token accompanied by unsolicited DPoP header");

        return "RFC 7638 canonical jkt, mandatory ath binding, and cnf.jkt sender-constraint enforcement verified";
    }

    private static Map<String, Object> claims(String iss, String sub, String jti, String scope) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("iss", iss);
        m.put("sub", sub);
        m.put("aud", AUD);
        m.put("iat", NOW - 5);
        m.put("exp", NOW + 600);
        m.put("jti", jti);
        m.put("scope", scope);
        return m;
    }

    private static String flipEcdsaS(String compactJws) {
        String[] parts = compactJws.split("\\.");
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
        BigInteger[] rs = EcdsaDerCodec.decodeScalarPair(sig);
        BigInteger sFlipped = EcdsaDerCodec.P256_ORDER_N.subtract(rs[1]);
        byte[] out = new byte[64];
        System.arraycopy(EcdsaDerCodec.encodeUnsignedFixedWidth(rs[0], 32), 0, out, 0, 32);
        System.arraycopy(EcdsaDerCodec.encodeUnsignedFixedWidth(sFlipped, 32), 0, out, 32, 32);
        return parts[0] + "." + parts[1] + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(out);
    }

    private static String forceHighS(String compactJws) {
        String[] parts = compactJws.split("\\.");
        byte[] sig = Base64.getUrlDecoder().decode(parts[2]);
        BigInteger[] rs = EcdsaDerCodec.decodeScalarPair(sig);
        if (rs[1].compareTo(EcdsaDerCodec.P256_HALF_ORDER) > 0) {
            return compactJws;
        }
        return flipEcdsaS(compactJws);
    }

    private static String refEcThumbprint(ECPublicKey pub) throws Exception {
        String x = b64u(EcdsaDerCodec.encodeUnsignedFixedWidth(pub.getW().getAffineX(), 32));
        String y = b64u(EcdsaDerCodec.encodeUnsignedFixedWidth(pub.getW().getAffineY(), 32));
        return sha256B64u("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}");
    }

    private static String refEdThumbprint(byte[] spki) throws Exception {
        byte[] rawX = Arrays.copyOfRange(spki, ED25519_SPKI_HDR.length, spki.length);
        return sha256B64u("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + b64u(rawX) + "\"}");
    }

    private static String refRsaThumbprint(RSAPublicKey pub) throws Exception {
        String e = b64u(minUnsigned(pub.getPublicExponent()));
        String n = b64u(minUnsigned(pub.getModulus()));
        return sha256B64u("{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}");
    }

    private static byte[] minUnsigned(BigInteger v) {
        byte[] raw = v.toByteArray();
        return (raw.length > 1 && raw[0] == 0) ? Arrays.copyOfRange(raw, 1, raw.length) : raw;
    }

    private static String b64u(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static String sha256B64u(String ascii) throws Exception {
        return b64u(MessageDigest.getInstance("SHA-256").digest(ascii.getBytes(StandardCharsets.UTF_8)));
    }

    private static KeyPair genEc() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static KeyPair genEd() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static KeyPair genRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}
"""


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    if not isinstance(data, dict):
        return False, "report.json root must be a JSON object"

    raw_blobs: list[str] = []
    for key in ("files", "file"):
        val = data.get(key)
        if isinstance(val, str):
            raw_blobs.append(val)
        elif isinstance(val, list):
            raw_blobs.extend(str(x) for x in val)

    findings = data.get("findings")
    if isinstance(findings, list):
        for item in findings:
            raw_blobs.append(json.dumps(item) if isinstance(item, (dict, list)) else str(item))

    referenced_java = {
        Path(tok).name
        for blob in raw_blobs
        for tok in re.findall(r"[\w./-]+\.java", blob)
    } & KNOWN_JAVA_MODULES

    if len(referenced_java) < 3:
        return (
            False,
            f"Expected report.json to identify at least 3 affected federation .java modules, got {sorted(referenced_java)}",
        )

    if not isinstance(findings, list) or len(findings) < 3:
        return False, "Expected at least 3 documented findings in report.json"

    for item in findings:
        if isinstance(item, dict):
            text = " ".join(str(v) for v in item.values()).strip()
        else:
            text = str(item).strip()
        if len(text) < 20 or "placeholder" in text.lower():
            return False, f"Finding entry is too brief or placeholder: {text!r}"

    summary = data.get("summary")
    if not isinstance(summary, str) or len(summary.strip()) < 15 or "placeholder" in summary.lower():
        return False, "Expected a non-empty technical 'summary' string in report.json"

    return True, f"Validated report covering {sorted(referenced_java)}"


def check_build_and_regression(app_dir: Path, orig_app: Path) -> tuple[bool, str]:
    if not (app_dir / "Makefile").is_file():
        return False, "Missing /app/Makefile"

    try:
        build_run = subprocess.run(
            ["make", "-C", str(app_dir), "clean", "all", "test"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return False, "'make clean all test' timed out after 60s on updated /app"

    if build_run.returncode != 0:
        return (
            False,
            f"'make clean all test' failed on updated /app (rc={build_run.returncode}):\n"
            f"{build_run.stdout}\n{build_run.stderr}",
        )

    if not (app_dir / "build" / "classes").is_dir():
        return False, "Missing compiled /app/build/classes after 'make clean all test'"

    # Verify the agent's updated src/test/java compiles against original public API and FAILS on original bugs
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        shutil.copy2(orig_app / "Makefile", tmp / "Makefile")
        shutil.copytree(orig_app / "src" / "main", tmp / "src" / "main")
        shutil.copytree(app_dir / "src" / "test", tmp / "src" / "test")

        try:
            comp_orig = subprocess.run(
                ["make", "-C", str(tmp), "clean", "all"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return False, "Compiling updated tests against original src/main timed out"

        if comp_orig.returncode != 0:
            return (
                False,
                "Updated src/test/java failed to compile against original public src/main/java signatures:\n"
                f"{comp_orig.stderr}",
            )

        try:
            orig_test_run = subprocess.run(
                ["make", "-C", str(tmp), "test"],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except subprocess.TimeoutExpired:
            return True, "Regression tests pass on hardened /app and fail (timed out) against original code"

        if orig_test_run.returncode == 0:
            return (
                False,
                "Updated FederationTestSuite unexpectedly passed against unpatched original src/main/java "
                "(missing adversarial regression tests)",
            )

    return True, "Build + test suite passed on /app and regression tests fail against unpatched original code"


def check_verifier_harness(app_dir: Path) -> tuple[bool, dict[str, object]]:
    classes_dir = app_dir / "build" / "classes"
    if not classes_dir.is_dir():
        return False, {"error": "Missing /app/build/classes"}

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        src_dir = tmp / "verifier"
        out_dir = tmp / "out"
        src_dir.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir(parents=True, exist_ok=True)

        harness_file = src_dir / "VerifierHarness.java"
        harness_file.write_text(HARNESS_JAVA, encoding="utf-8")

        try:
            comp = subprocess.run(
                [
                    "javac",
                    "--release",
                    "21",
                    "-encoding",
                    "UTF-8",
                    "-cp",
                    str(classes_dir),
                    "-d",
                    str(out_dir),
                    str(harness_file),
                ],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except subprocess.TimeoutExpired:
            return False, {"error": "javac timed out compiling VerifierHarness.java"}

        if comp.returncode != 0:
            return False, {"error": f"VerifierHarness compilation failed:\n{comp.stderr}"}

        try:
            run = subprocess.run(
                [
                    "java",
                    "-ea",
                    "-cp",
                    f"{classes_dir}:{out_dir}",
                    "verifier.VerifierHarness",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return False, {"error": "VerifierHarness execution timed out after 60s"}

        lines = [ln.strip() for ln in run.stdout.splitlines() if ln.strip()]
        payload: dict[str, object]
        if lines:
            try:
                payload = json.loads(lines[-1])
            except Exception:
                payload = {"raw_stdout": run.stdout, "raw_stderr": run.stderr}
        else:
            payload = {"raw_stdout": run.stdout, "raw_stderr": run.stderr}

        if run.returncode != 0 or not payload.get("ok"):
            return False, payload
        return True, payload


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    ok_reg, msg_reg = check_build_and_regression(app_dir, tests_dir / "orig_app")
    results["build_and_regression"] = {"passed": ok_reg, "message": msg_reg}
    if not ok_reg:
        return False, results

    ok_harn, harn_details = check_verifier_harness(app_dir)
    results["verifier_harness"] = harn_details
    if not ok_harn:
        return False, results

    return True, results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    tests_dir = Path(__file__).resolve().parent
    reward_dir = Path(args.reward_dir)
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir, tests_dir)
    (reward_dir / "details.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "details": details}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
