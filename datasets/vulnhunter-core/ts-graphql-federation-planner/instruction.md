# Federated GraphQL Gateway Planner Maintenance Review

You are performing a routine defensive code review and production hardening pass on the internal Federated GraphQL Gateway engine in `/app` (`package.json`, `src/`, and `test/`). The service runs directly on Node.js 22 native TypeScript execution (`node --experimental-strip-types`) without external runtime dependencies.

The gateway parses incoming GraphQL operations, enforces static depth and query-complexity budgets, evaluates `@auth` role/scope policies across supergraph types and interfaces, plans multi-subgraph entity joins (`@key`, `@external`, `@requires`), projects client response shapes, and maintains a short-lived entity resolution cache across requests.

Review the codebase end-to-end for authorization consistency across all GraphQL selection forms, static cost accounting accuracy, subgraph entity batch correlation, response field projection boundaries, and multi-tenant cache isolation, then complete the following deliverables in `/app`:

1. **Technical Review Report (`/app/report.json`)**
   Create `/app/report.json` summarizing your findings:
   - `"files"`: array of relative file paths under `/app` where primary issues were identified and updated (for example `["src/cost_analyzer.ts", "src/auth_policy.ts", ...]`).
   - `"findings"`: array of at least 3 detailed descriptions explaining the root causes and architectural invariants addressed.
   - `"summary"`: concise overall summary of the hardening changes.

2. **Gateway Engine Hardening (`/app/src/`)**
   Update the implementation under `/app/src/` while preserving existing public TypeScript APIs, legitimate federated query execution, alias handling, computed `@requires` resolution, and HTTP `/graphql` behavior.

3. **Regression Test Suite (`/app/test/federation.test.ts`)**
   Expand `/app/test/federation.test.ts` with targeted regression tests covering the scenarios identified in your review. Verify that `npm test` (`node --experimental-strip-types --test test/federation.test.ts`) passes cleanly.
