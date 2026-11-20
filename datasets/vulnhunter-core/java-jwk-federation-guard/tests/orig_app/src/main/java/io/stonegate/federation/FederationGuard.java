package io.stonegate.federation;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * End-to-end OIDC / OAuth 2.0 federated access token and RFC 9449 DPoP admission guard.
 *
 * <p>Contract (RFC 6750, RFC 8725, RFC 9068 &amp; RFC 9449 §7.1):
 * <ul>
 *   <li>Parses HTTP {@code Authorization} headers using {@code Bearer} or {@code DPoP} schemes
 *       (case-insensitive scheme name per RFC 9110 §11.1).</li>
 *   <li>Issuer resolution, JWS signature verification, and JWT claims evaluation MUST operate on
 *       a single canonical JSON parse of the token header and payload with identical verified
 *       {@code iss} binding across stages.</li>
 *   <li>Sender-constraint &amp; scheme binding rules (RFC 9449 §7.1):
 *       <ul>
 *         <li>When {@link EndpointPolicy#dpopRequired()} is {@code true}, requests MUST use
 *             {@code Authorization: DPoP <token>}, carry {@code cnf.jkt} in the access token,
 *             and present a valid {@code DPoP} proof header bound to {@code ath} and {@code cnf.jkt}.</li>
 *         <li>Even when {@code dpopRequired == false} (mixed mode), any token carrying {@code cnf.jkt}
 *             MUST use {@code Authorization: DPoP <token>} and present a valid matching {@code DPoP}
 *             proof header (downgrading a {@code cnf.jkt}-bound token to {@code Bearer} or omitting
 *             {@code DPoP} MUST be rejected).</li>
 *         <li>Unbound tokens (no {@code cnf.jkt}) MUST use {@code Authorization: Bearer <token>} on
 *             {@code dpopRequired == false} endpoints and MUST NOT supply {@code DPoP} headers.</li>
 *       </ul>
 *   </li>
 * </ul>
 */
public final class FederationGuard {

    public enum AuthScheme { BEARER, DPOP }

    public enum ErrorCode {
        MALFORMED_TOKEN,
        UNTRUSTED_ISSUER,
        INVALID_SIGNATURE,
        INVALID_CLAIMS,
        INSUFFICIENT_SCOPE,
        DPOP_REQUIRED,
        INVALID_DPOP_PROOF,
        DPOP_REPLAY
    }

    public static final class VerificationException extends SecurityException {
        private final ErrorCode errorCode;

        public VerificationException(ErrorCode errorCode, String message) {
            super(message);
            this.errorCode = Objects.requireNonNull(errorCode);
        }

        public VerificationException(ErrorCode errorCode, String message, Throwable cause) {
            super(message, cause);
            this.errorCode = Objects.requireNonNull(errorCode);
        }

        public ErrorCode errorCode() {
            return errorCode;
        }
    }

    public record HttpRequestContext(
            String method, String targetUri, String authorizationHeader, String dpopHeader
    ) {
        public HttpRequestContext {
            if (method == null || method.isBlank() || targetUri == null || targetUri.isBlank()) {
                throw new IllegalArgumentException("HTTP method and targetUri must not be blank");
            }
        }
    }

    public record EndpointPolicy(String expectedAudience, Set<String> requiredScopes, boolean dpopRequired) {
        public EndpointPolicy {
            if (expectedAudience == null || expectedAudience.isBlank()) {
                throw new IllegalArgumentException("expectedAudience must not be blank");
            }
            requiredScopes = Collections.unmodifiableSet(new LinkedHashSet<>(Objects.requireNonNull(requiredScopes)));
        }
    }

    public record VerifiedSession(
            String issuer,
            String subject,
            String tokenId,
            Set<String> scopes,
            List<String> audiences,
            Optional<String> confirmationJkt,
            List<String> actorChain
    ) {}

    private final FederationTrustStore trustStore;
    private final JwsSignatureEngine signatureEngine;
    private final DpopProofValidator dpopValidator;
    private final ClaimsPolicyEngine claimsEngine;

    public FederationGuard(FederationTrustStore trustStore) {
        this(trustStore, new JwsSignatureEngine(),
                new DpopProofValidator(new JwsSignatureEngine()), new ClaimsPolicyEngine(trustStore));
    }

    public FederationGuard(
            FederationTrustStore trustStore,
            JwsSignatureEngine signatureEngine,
            DpopProofValidator dpopValidator,
            ClaimsPolicyEngine claimsEngine
    ) {
        this.trustStore = Objects.requireNonNull(trustStore);
        this.signatureEngine = Objects.requireNonNull(signatureEngine);
        this.dpopValidator = Objects.requireNonNull(dpopValidator);
        this.claimsEngine = Objects.requireNonNull(claimsEngine);
    }

    public FederationTrustStore trustStore() { return trustStore; }
    public JwsSignatureEngine signatureEngine() { return signatureEngine; }
    public DpopProofValidator dpopValidator() { return dpopValidator; }
    public ClaimsPolicyEngine claimsEngine() { return claimsEngine; }

    public VerifiedSession authenticate(
            HttpRequestContext request, EndpointPolicy policy, long nowEpochSeconds
    ) {
        Objects.requireNonNull(request, "request must not be null");
        Objects.requireNonNull(policy, "policy must not be null");

        ParsedAuthorization parsedAuth = parseAuthorizationHeader(request.authorizationHeader());
        String rawAccessToken = parsedAuth.accessToken();

        String[] parts = JwsSignatureEngine.splitCompactJws(rawAccessToken);
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
        return session;
    }

    private static ParsedAuthorization parseAuthorizationHeader(String header) {
        if (header == null || header.isBlank()) {
            throw new VerificationException(ErrorCode.MALFORMED_TOKEN, "Missing Authorization header");
        }
        String trimmed = header.trim();
        int spaceIdx = trimmed.indexOf(' ');
        if (spaceIdx <= 0 || spaceIdx == trimmed.length() - 1) {
            throw new VerificationException(ErrorCode.MALFORMED_TOKEN, "Malformed Authorization header");
        }
        String schemeRaw = trimmed.substring(0, spaceIdx);
        String tokenPart = trimmed.substring(spaceIdx + 1).trim();
        if (tokenPart.isEmpty() || tokenPart.indexOf(' ') >= 0 || tokenPart.indexOf('\t') >= 0) {
            throw new VerificationException(ErrorCode.MALFORMED_TOKEN, "Invalid token in Authorization header");
        }
        AuthScheme scheme = switch (schemeRaw.toLowerCase(Locale.ROOT)) {
            case "bearer" -> AuthScheme.BEARER;
            case "dpop" -> AuthScheme.DPOP;
            default -> throw new VerificationException(ErrorCode.MALFORMED_TOKEN, "Unsupported scheme: " + schemeRaw);
        };
        return new ParsedAuthorization(scheme, tokenPart);
    }

    private record ParsedAuthorization(AuthScheme scheme, String accessToken) {}
}
