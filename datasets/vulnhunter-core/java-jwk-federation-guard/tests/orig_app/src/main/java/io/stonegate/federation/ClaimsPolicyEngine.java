package io.stonegate.federation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Evaluates OAuth 2.0 / OIDC JWT access token claims (RFC 9068, RFC 8725, RFC 8693, RFC 9449).
 *
 * <p>Contract:
 * <ul>
 *   <li>{@code iss}, {@code sub}, and {@code jti} MUST be non-blank strings; {@code iss} MUST
 *       match the exact canonical {@code issuerUri} of the cryptographically verified issuer.</li>
 *   <li>Temporal bounds (with {@code clockSkewSeconds}): {@code exp} rejected when
 *       {@code nowEpochSeconds >= exp + clockSkewSeconds}; {@code iat} rejected when
 *       {@code iat > nowEpochSeconds + clockSkewSeconds} or {@code nowEpochSeconds - iat > maxTokenLifetimeSeconds};
 *       optional {@code nbf} rejected when {@code nowEpochSeconds + clockSkewSeconds < nbf}.</li>
 *   <li>{@code aud} MUST contain {@code endpointPolicy.expectedAudience()}, which MUST also be in
 *       {@link FederationTrustStore.IssuerPolicy#allowedAudiences()}.</li>
 *   <li>Granted scopes ({@code scope} / {@code scp}) MUST all be permitted by
 *       {@link FederationTrustStore.IssuerPolicy#allowedScopes()} and cover {@code endpointPolicy.requiredScopes()}.</li>
 *   <li>Optional {@code act} delegation chains (RFC 8693 §4.1, max depth 4) require non-blank {@code sub}
 *       and, when {@code iss} is present, a registered issuer with {@code allowDelegationActor == true}.</li>
 *   <li>If {@code cnf} is present, it MUST be a single-entry object with non-blank string {@code jkt}.</li>
 * </ul>
 */
public final class ClaimsPolicyEngine {

    public static final long DEFAULT_CLOCK_SKEW_SECONDS = 15L;
    public static final long DEFAULT_MAX_TOKEN_LIFETIME_SECONDS = 86_400L;
    public static final int MAX_ACTOR_CHAIN_DEPTH = 4;

    private final FederationTrustStore trustStore;
    private final long clockSkewSeconds;
    private final long maxTokenLifetimeSeconds;

    public ClaimsPolicyEngine(FederationTrustStore trustStore) {
        this(trustStore, DEFAULT_CLOCK_SKEW_SECONDS, DEFAULT_MAX_TOKEN_LIFETIME_SECONDS);
    }

    public ClaimsPolicyEngine(FederationTrustStore trustStore, long clockSkewSeconds, long maxTokenLifetimeSeconds) {
        this.trustStore = Objects.requireNonNull(trustStore, "trustStore must not be null");
        if (clockSkewSeconds < 0 || maxTokenLifetimeSeconds <= 0) {
            throw new IllegalArgumentException("Invalid temporal policy configuration");
        }
        this.clockSkewSeconds = clockSkewSeconds;
        this.maxTokenLifetimeSeconds = maxTokenLifetimeSeconds;
    }

    public FederationGuard.VerifiedSession evaluate(
            Map<String, Object> claims,
            FederationGuard.EndpointPolicy endpointPolicy,
            long nowEpochSeconds
    ) {
        Objects.requireNonNull(claims, "claims must not be null");
        Objects.requireNonNull(endpointPolicy, "endpointPolicy must not be null");

        String iss = requireNonBlankString(claims, "iss");
        FederationTrustStore.IssuerEntry issuerEntry = trustStore.resolveIssuer(iss)
                .orElseThrow(() -> fail(FederationGuard.ErrorCode.UNTRUSTED_ISSUER, "Untrusted issuer: " + iss));
        FederationTrustStore.IssuerPolicy issuerPolicy = issuerEntry.policy();

        String sub = requireNonBlankString(claims, "sub");
        String jti = requireNonBlankString(claims, "jti");

        long exp = requireIntegralLong(claims, "exp");
        if (nowEpochSeconds >= exp + clockSkewSeconds) {
            throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Access token expired");
        }
        long iat = requireIntegralLong(claims, "iat");
        if (iat > nowEpochSeconds + clockSkewSeconds || nowEpochSeconds - iat > maxTokenLifetimeSeconds) {
            throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Access token iat out of bounds");
        }
        if (claims.containsKey("nbf") && nowEpochSeconds + clockSkewSeconds < requireIntegralLong(claims, "nbf")) {
            throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Access token not yet valid");
        }
        if (claims.containsKey("azp")) {
            requireNonBlankString(claims, "azp");
        }

        List<String> audiences = extractAudiences(claims);
        String requiredAud = endpointPolicy.expectedAudience();
        if (!audiences.contains(requiredAud) || !issuerPolicy.allowedAudiences().contains(requiredAud)) {
            throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Audience mismatch");
        }

        Set<String> grantedScopes = extractScopes(claims);
        for (String scope : grantedScopes) {
            if (!issuerPolicy.allowedScopes().contains(scope)) {
                throw fail(FederationGuard.ErrorCode.INSUFFICIENT_SCOPE, "Disallowed issuer scope: " + scope);
            }
        }
        for (String reqScope : endpointPolicy.requiredScopes()) {
            if (!grantedScopes.contains(reqScope)) {
                throw fail(FederationGuard.ErrorCode.INSUFFICIENT_SCOPE, "Missing required scope: " + reqScope);
            }
        }

        return new FederationGuard.VerifiedSession(
                issuerPolicy.issuerUri(), sub, jti,
                Collections.unmodifiableSet(grantedScopes),
                Collections.unmodifiableList(audiences),
                extractConfirmationJkt(claims),
                Collections.unmodifiableList(extractActorChain(claims))
        );
    }

    private List<String> extractAudiences(Map<String, Object> claims) {
        Object audObj = claims.get("aud");
        if (audObj instanceof String single && !single.isBlank()) {
            return List.of(single);
        }
        if (audObj instanceof List<?> list && !list.isEmpty()) {
            List<String> out = new ArrayList<>(list.size());
            for (Object item : list) {
                if (!(item instanceof String s) || s.isBlank()) {
                    throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Invalid element in 'aud'");
                }
                out.add(s);
            }
            return out;
        }
        throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Missing or invalid 'aud' claim");
    }

    private Set<String> extractScopes(Map<String, Object> claims) {
        Set<String> scopes = new LinkedHashSet<>();
        if (claims.containsKey("scope")) {
            if (!(claims.get("scope") instanceof String scopeStr)) {
                throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "'scope' claim must be a string");
            }
            for (String token : scopeStr.split(" ")) {
                if (!token.isBlank()) scopes.add(token);
            }
        }
        if (claims.containsKey("scp")) {
            if (!(claims.get("scp") instanceof List<?> scpList)) {
                throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "'scp' claim must be an array");
            }
            for (Object item : scpList) {
                if (!(item instanceof String s) || s.isBlank()) {
                    throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Invalid element in 'scp'");
                }
                scopes.add(s);
            }
        }
        return scopes;
    }

    private Optional<String> extractConfirmationJkt(Map<String, Object> claims) {
        if (!claims.containsKey("cnf")) return Optional.empty();
        if (!(claims.get("cnf") instanceof Map<?, ?> cnfMap)
                || cnfMap.size() != 1
                || !(cnfMap.get("jkt") instanceof String jkt)
                || jkt.isBlank()) {
            throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Invalid 'cnf' confirmation claim");
        }
        return Optional.of(jkt);
    }

    private List<String> extractActorChain(Map<String, Object> claims) {
        if (!claims.containsKey("act")) return List.of();
        List<String> actors = new ArrayList<>();
        Object current = claims.get("act");
        int depth = 0;
        while (current != null) {
            if (++depth > MAX_ACTOR_CHAIN_DEPTH || !(current instanceof Map<?, ?> rawAct)) {
                throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Invalid or overly deep 'act' claim");
            }
            if (!(rawAct.get("sub") instanceof String actSub) || actSub.isBlank()) {
                throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Actor claim missing 'sub'");
            }
            Object issObj = rawAct.get("iss");
            if (issObj != null) {
                if (!(issObj instanceof String actIss) || actIss.isBlank()) {
                    throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Invalid 'iss' in actor claim");
                }
                FederationTrustStore.IssuerEntry actorIssuer = trustStore.resolveIssuer(actIss)
                        .orElseThrow(() -> fail(FederationGuard.ErrorCode.UNTRUSTED_ISSUER, "Untrusted actor issuer"));
                if (!actorIssuer.policy().allowDelegationActor()) {
                    throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Actor issuer not permitted");
                }
                actors.add(actorIssuer.policy().issuerUri() + "#" + actSub);
            } else {
                actors.add(actSub);
            }
            current = rawAct.get("act");
        }
        return actors;
    }

    private static String requireNonBlankString(Map<String, Object> claims, String name) {
        if (!(claims.get(name) instanceof String s) || s.isBlank()) {
            throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Missing or invalid string claim '" + name + "'");
        }
        return s;
    }

    private static long requireIntegralLong(Map<String, Object> claims, String name) {
        Object val = claims.get(name);
        if (val instanceof Long l) return l;
        if (val instanceof Integer i) return i.longValue();
        throw fail(FederationGuard.ErrorCode.INVALID_CLAIMS, "Missing or non-integer claim '" + name + "'");
    }

    private static FederationGuard.VerificationException fail(FederationGuard.ErrorCode code, String msg) {
        return new FederationGuard.VerificationException(code, msg);
    }
}
