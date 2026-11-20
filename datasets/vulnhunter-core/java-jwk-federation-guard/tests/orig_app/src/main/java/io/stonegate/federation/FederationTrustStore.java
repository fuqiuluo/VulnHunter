package io.stonegate.federation;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Multi-issuer JWKS trust registry and per-issuer security policy store.
 *
 * <p>Contract (RFC 8414 §2, OpenID Connect Core §3.1.3.7 &amp; RFC 8725 §3.1):
 * <ul>
 *   <li>Every registered and incoming issuer identifier ({@code iss}) MUST be a valid {@code https}
 *       URI with a non-empty host and MUST NOT contain userinfo, query ({@code ?}), or fragment ({@code #}).</li>
 *   <li>{@link #resolveIssuer(String)} MUST match registered issuers by exact case-sensitive string
 *       equality against the canonical {@code issuerUri} (never prefix or substring matching).</li>
 *   <li>Each {@link TrustedKey} pins a {@code kid} and JWS {@code algorithm} permitted by
 *       {@link IssuerPolicy#allowedAlgorithms()}.</li>
 * </ul>
 */
public final class FederationTrustStore {

    private static final Set<String> SUPPORTED_JWS_ALGORITHMS = Set.of("ES256", "EdDSA", "RS256", "HS256");
    private final Map<String, IssuerEntry> issuers = new ConcurrentHashMap<>();

    public record IssuerPolicy(
            String issuerUri,
            Set<String> allowedAlgorithms,
            Set<String> allowedAudiences,
            Set<String> allowedScopes,
            boolean allowDelegationActor
    ) {
        public IssuerPolicy {
            if (issuerUri == null || issuerUri.isBlank()) {
                throw new IllegalArgumentException("issuerUri must not be blank");
            }
            if (allowedAlgorithms == null || allowedAlgorithms.isEmpty()) {
                throw new IllegalArgumentException("allowedAlgorithms must not be empty");
            }
            for (String alg : allowedAlgorithms) {
                if (!SUPPORTED_JWS_ALGORITHMS.contains(alg)) {
                    throw new IllegalArgumentException("Unsupported JWS algorithm in policy: " + alg);
                }
            }
            if (allowedAudiences == null || allowedAudiences.isEmpty()) {
                throw new IllegalArgumentException("allowedAudiences must not be empty");
            }
            Objects.requireNonNull(allowedScopes, "allowedScopes must not be null");
            allowedAlgorithms = Collections.unmodifiableSet(new LinkedHashSet<>(allowedAlgorithms));
            allowedAudiences = Collections.unmodifiableSet(new LinkedHashSet<>(allowedAudiences));
            allowedScopes = Collections.unmodifiableSet(new LinkedHashSet<>(allowedScopes));
        }
    }

    public record TrustedKey(
            String keyId,
            String algorithm,
            JwkThumbprint.JwkKey jwkKey,
            Optional<Long> notAfterEpochSeconds
    ) {
        public boolean isActiveAt(long nowEpochSeconds) {
            return notAfterEpochSeconds.map(limit -> nowEpochSeconds <= limit).orElse(true);
        }
    }

    public static final class IssuerEntry {
        private final IssuerPolicy policy;
        private final Map<String, TrustedKey> keys = new ConcurrentHashMap<>();

        private IssuerEntry(IssuerPolicy policy) {
            this.policy = policy;
        }

        public IssuerPolicy policy() {
            return policy;
        }

        public TrustedKey registerKey(String kid, Map<String, Object> jwkMap) {
            if (kid == null || kid.isBlank()) throw new IllegalArgumentException("kid must not be blank");
            JwkThumbprint.JwkKey parsed = JwkThumbprint.parseStoreJwk(jwkMap);
            String keyAlg = parsed.canonicalJwsAlgorithm();
            if (!policy.allowedAlgorithms().contains(keyAlg)) {
                throw new IllegalArgumentException("Key algorithm " + keyAlg + " disallowed by issuer policy");
            }
            TrustedKey trusted = new TrustedKey(kid, keyAlg, parsed, Optional.empty());
            keys.put(kid, trusted);
            return trusted;
        }

        public TrustedKey rotateKey(
                String retiringKid, long graceSeconds, long nowEpochSeconds, String newKid, Map<String, Object> newJwkMap
        ) {
            if (graceSeconds < 0) throw new IllegalArgumentException("graceSeconds must be non-negative");
            TrustedKey next = registerKey(newKid, newJwkMap);
            keys.computeIfPresent(retiringKid, (id, existing) -> new TrustedKey(
                    existing.keyId(), existing.algorithm(), existing.jwkKey(), Optional.of(nowEpochSeconds + graceSeconds)));
            return next;
        }

        public void revokeKey(String kid) {
            if (kid != null) keys.remove(kid);
        }

        public Optional<TrustedKey> findActiveKey(String kid, long nowEpochSeconds) {
            if (kid == null || kid.isBlank()) return Optional.empty();
            TrustedKey key = keys.get(kid);
            return (key != null && key.isActiveAt(nowEpochSeconds)) ? Optional.of(key) : Optional.empty();
        }
    }

    public IssuerEntry registerIssuer(IssuerPolicy policy) {
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
    }
}
