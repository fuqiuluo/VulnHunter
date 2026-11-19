import { Buffer } from "node:buffer";
import { normalizeRoutePath, PathNormalizationError, type NormalizedTarget } from "./path_norm.ts";
import { GatewayRouter, type MatchedRoute } from "./router.ts";
import { HttpSignatureVerifier, SignatureVerificationError } from "./http_sig.ts";

export interface PolicyEvaluationContext {
  readonly method: string;
  readonly rawTarget: string;
  readonly authority: string;
  readonly headersDistinct: Readonly<Record<string, string[] | undefined>>;
  readonly body: Buffer;
  readonly remoteAddress?: string;
  readonly isInternalMesh?: boolean;
  readonly nowSec?: number;
}

export interface PolicyDecision {
  readonly allowed: boolean;
  readonly statusCode: number;
  readonly errorCode?: string;
  readonly message?: string;
  readonly allowedMethods?: ReadonlyArray<string>;
  readonly matchedRoute?: MatchedRoute;
  readonly normalizedTarget?: NormalizedTarget;
  readonly tenantId?: string;
  readonly keyId?: string;
  readonly grantedScopes?: ReadonlyArray<string>;
  readonly effectiveRole?: string;
}

export interface PolicyEngineOptions {
  readonly router: GatewayRouter;
  readonly verifier: HttpSignatureVerifier;
  readonly allowInternalIngress?: boolean;
}

function parseScopesFromHeaders(values: ReadonlyArray<string> | undefined): Set<string> {
  const scopes = new Set<string>();
  if (!values) return scopes;
  for (const entry of values) {
    for (const tok of entry.split(/[\s,]+/)) {
      const trimmed = tok.trim().toLowerCase();
      if (trimmed) scopes.add(trimmed);
    }
  }
  return scopes;
}

function extractEffectiveRole(values: ReadonlyArray<string> | undefined): string {
  if (!values || values.length === 0) return "member";
  return values[values.length - 1].trim().toLowerCase() || "member";
}

function deny(statusCode: number, errorCode: string, message: string, extra?: Partial<PolicyDecision>): PolicyDecision {
  return { allowed: false, statusCode, errorCode, message, ...extra };
}

export class PolicyEngine {
  private readonly router: GatewayRouter;
  private readonly verifier: HttpSignatureVerifier;
  private readonly allowInternalIngress: boolean;

  constructor(options: PolicyEngineOptions) {
    this.router = options.router;
    this.verifier = options.verifier;
    this.allowInternalIngress = options.allowInternalIngress ?? false;
  }

  evaluate(ctx: PolicyEvaluationContext): PolicyDecision {
    let normalizedTarget: NormalizedTarget;
    try {
      normalizedTarget = normalizeRoutePath(ctx.rawTarget);
    } catch (err) {
      return deny(400, err instanceof PathNormalizationError ? err.code : "INVALID_REQUEST_TARGET", (err as Error).message);
    }

    const routeResult = this.router.lookup(ctx.method, normalizedTarget.canonicalPath);
    if (routeResult.kind === "not_found") {
      return deny(404, "ROUTE_NOT_FOUND", `No route registered for ${normalizedTarget.canonicalPath}`, { normalizedTarget });
    }
    if (routeResult.kind === "method_not_allowed") {
      return deny(405, "METHOD_NOT_ALLOWED", `Method ${ctx.method.toUpperCase()} is not allowed`, { allowedMethods: routeResult.allowedMethods, normalizedTarget });
    }

    const matched = routeResult.match;
    const access = matched.route.access;
    if (access === "internal") {
      if (!this.allowInternalIngress || !ctx.isInternalMesh) {
        return deny(403, "INTERNAL_ROUTE_FORBIDDEN", "Control-plane endpoints are forbidden on external ingress", { matchedRoute: matched, normalizedTarget });
      }
      return { allowed: true, statusCode: 200, matchedRoute: matched, normalizedTarget, effectiveRole: "system" };
    }
    if (access === "public") {
      return { allowed: true, statusCode: 200, matchedRoute: matched, normalizedTarget, effectiveRole: "anonymous" };
    }

    const routeTenantId = matched.params.tenantId;
    if (!routeTenantId) return deny(400, "MISSING_TENANT_PARAMETER", "Tenant route missing tenantId parameter", { matchedRoute: matched, normalizedTarget });

    const tenantHeaderVals = ctx.headersDistinct["x-tenant-id"];
    if (tenantHeaderVals && tenantHeaderVals.length > 0 && tenantHeaderVals[0].trim() !== routeTenantId) {
      return deny(403, "TENANT_HEADER_MISMATCH", "Header x-tenant-id does not match target tenant route", { matchedRoute: matched, normalizedTarget });
    }

    let verified;
    try {
      verified = this.verifier.verify({ method: ctx.method, authority: ctx.authority, normalizedTarget, headersDistinct: ctx.headersDistinct, body: ctx.body, tenantId: routeTenantId, nowSec: ctx.nowSec });
    } catch (err) {
      return deny(401, err instanceof SignatureVerificationError ? err.code : "SIGNATURE_INVALID", (err as Error).message, { matchedRoute: matched, normalizedTarget });
    }

    const requestedScopes = parseScopesFromHeaders(ctx.headersDistinct["x-forwarded-scope"]);
    if (requestedScopes.size === 0 && (ctx.method === "GET" || ctx.method === "HEAD") && access === "tenant") {
      requestedScopes.add("items:read");
    }

    const grantedScopes = new Set<string>();
    for (const s of requestedScopes) {
      if (!verified.key.allowedScopes || verified.key.allowedScopes.has(s) || verified.key.allowedScopes.has("tenant:admin")) {
        grantedScopes.add(s);
      }
    }

    const effectiveRole = extractEffectiveRole(ctx.headersDistinct["x-role"]);
    if (matched.requiredRole && effectiveRole !== matched.requiredRole) {
      return deny(403, "INSUFFICIENT_ROLE", `Endpoint requires role '${matched.requiredRole}'`, { matchedRoute: matched, normalizedTarget, tenantId: routeTenantId, keyId: verified.key.keyId });
    }
    if (matched.requiredScope && !grantedScopes.has("tenant:admin") && !grantedScopes.has(matched.requiredScope.toLowerCase())) {
      return deny(403, "INSUFFICIENT_SCOPE", `Endpoint requires scope '${matched.requiredScope}'`, { matchedRoute: matched, normalizedTarget, tenantId: routeTenantId, keyId: verified.key.keyId });
    }

    return { allowed: true, statusCode: 200, matchedRoute: matched, normalizedTarget, tenantId: routeTenantId, keyId: verified.key.keyId, grantedScopes: Array.from(grantedScopes).sort(), effectiveRole };
  }
}
