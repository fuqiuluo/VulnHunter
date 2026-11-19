# Multi-Tenant API Edge Gateway Maintenance Review

You are performing a routine defensive code review and hardening pass on the TypeScript HTTP edge gateway service located in `/app` (`src/gateway.ts`, `src/router.ts`, `src/path_norm.ts`, `src/http_sig.ts`, `src/key_ring.ts`, `src/policy.ts`, and `src/upstream_forwarder.ts`).

The service runs directly on Node.js 22 native TypeScript (`node --experimental-strip-types`) without external packages. Audit URL and path handling, route access policy evaluation, HTTP Message Signature verification (`Signature-Input`, `Signature`, and `Content-Digest`), multi-tenant verification key management, and upstream HTTP forwarding for end-to-end consistency and tenant isolation, then complete the following deliverables inside `/app`:

1. **Technical Review Report (`/app/report.json`)**
   Document the affected source modules, technical root-cause findings, and remediation summary in `/app/report.json`:
   ```json
   {
     "files": [
       "src/module_a.ts",
       "src/module_b.ts"
     ],
     "findings": [
       "Detailed root-cause description of each identified issue"
     ],
     "summary": "Concise summary of the hardening updates applied across the gateway"
   }
   ```

2. **In-Place Defensive Updates (`/app/src/`)**
   Update the TypeScript modules in `/app/src/` to enforce consistent security invariants across admission control, signature verification, key isolation, and upstream forwarding while preserving existing public class/function exports and standard gateway functionality (including public catalog endpoints, query string preservation, encoded resource slugs, multi-header signed requests, `Content-Digest` verification, and per-tenant key rotation).

3. **Regression Test Suite (`/app/test/gateway.test.ts`)**
   Extend `/app/test/gateway.test.ts` (executed via `node --experimental-strip-types --test /app/test/gateway.test.ts`) with regression tests covering your hardening changes alongside existing functional coverage.
