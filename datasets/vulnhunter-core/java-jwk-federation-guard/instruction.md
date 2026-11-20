# Federated JWS & DPoP Verification Engine Maintenance Review

You are performing a routine defensive code review, RFC specification compliance audit, and cryptographic hardening pass on the pure JDK 21 OIDC / OAuth 2.0 federated access token and RFC 9449 DPoP verification engine located in `/app` (`Makefile`, `src/main/java/io/stonegate/federation/`, and `src/test/java/io/stonegate/federation/`).

The library relies exclusively on the JDK 21 standard library (`java.security` and `javax.crypto`) with zero external JAR dependencies. Audit JSON parsing and canonical serialization (RFC 8259), ECDSA P1363/DER signature transcoding (RFC 7518), JWK parsing and SHA-256 thumbprint computation (RFC 7638 / RFC 8037), multi-issuer trust registry resolution and key pinning (RFC 8414 / RFC 8725), compact JWS header and cryptographic verification (RFC 7515 / RFC 9068), DPoP proof validation and replay tracking (RFC 9449), and end-to-end admission policy enforcement across `/app`, then complete the following deliverables inside `/app`:

1. **Technical Review Report (`/app/report.json`)**
   Document the affected source modules, technical root-cause findings, and remediation summary in `/app/report.json`:
   ```json
   {
     "files": [
       "src/main/java/io/stonegate/federation/..."
     ],
     "findings": [
       "Detailed technical root-cause and remediation description for each finding"
     ],
     "summary": "Concise summary of the RFC compliance and cryptographic hardening updates applied"
   }
   ```

2. **In-Place Source Remediation (`/app/src/main/java/io/stonegate/federation/`)**
   Update the Java 21 modules in `/app/src/main/java/io/stonegate/federation/` so all documented RFC 7515, RFC 7518, RFC 7638, RFC 8259, RFC 8414, RFC 8693, RFC 8725, RFC 9068, and RFC 9449 invariants hold consistently across parsing, signature verification, issuer isolation, sender-constraint binding, and replay tracking while preserving public class/record signatures and compliant `ES256`, `EdDSA`, `RS256`, `HS256`, key rotation, delegation, and DPoP flows.

3. **Regression Test Suite (`/app/src/test/java/io/stonegate/federation/FederationTestSuite.java`)**
   Extend `/app/src/test/java/io/stonegate/federation/FederationTestSuite.java` with deterministic regression tests covering your hardening updates alongside existing functional coverage. No `.class` or `build/` artifacts need to be retained manually as long as `make -C /app clean all test` compiles cleanly and passes, and `/app/report.json` plus the updated test sources in `src/test/java/` are in place.
