import { decodeSlugParam } from "./path_norm.ts";

export type RouteAccessClass = "public" | "tenant" | "tenant-admin" | "internal";

export interface RouteDefinition {
  readonly id: string;
  readonly pattern: string;
  readonly methods: ReadonlyArray<string>;
  readonly access: RouteAccessClass;
  readonly methodScopes?: Readonly<Record<string, string>>;
  readonly requiredRole?: string;
}

export interface MatchedRoute {
  readonly route: RouteDefinition;
  readonly params: Readonly<Record<string, string>>;
  readonly rawParams: Readonly<Record<string, string>>;
  readonly requiredScope: string | null;
  readonly requiredRole: string | null;
}

export type RouteLookupResult =
  | { readonly kind: "matched"; readonly match: MatchedRoute }
  | { readonly kind: "method_not_allowed"; readonly allowedMethods: ReadonlyArray<string> }
  | { readonly kind: "not_found" };

interface CompiledSegment {
  readonly kind: "static" | "param" | "wildcard";
  readonly value: string;
}

interface CompiledRoute {
  readonly def: RouteDefinition;
  readonly methodSet: ReadonlySet<string>;
  readonly segments: ReadonlyArray<CompiledSegment>;
  readonly hasWildcard: boolean;
}

function compilePattern(pattern: string): { segments: CompiledSegment[]; hasWildcard: boolean } {
  if (!pattern.startsWith("/")) throw new Error(`Route pattern must start with '/': ${pattern}`);
  const parts = pattern.split("/").filter((s) => s.length > 0);
  const segments: CompiledSegment[] = [];
  let hasWildcard = false;

  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i];
    if (part.startsWith("*")) {
      if (i !== parts.length - 1) throw new Error(`Wildcard must appear at end of pattern: ${pattern}`);
      segments.push({ kind: "wildcard", value: part.slice(1) || "rest" });
      hasWildcard = true;
    } else if (part.startsWith(":")) {
      if (part.length < 2) throw new Error(`Empty parameter in pattern: ${pattern}`);
      segments.push({ kind: "param", value: part.slice(1) });
    } else {
      segments.push({ kind: "static", value: part });
    }
  }
  return { segments, hasWildcard };
}

function matchSegments(
  compiled: CompiledRoute,
  pathSegments: ReadonlyArray<string>,
): { params: Record<string, string>; rawParams: Record<string, string> } | null {
  const { segments, hasWildcard } = compiled;
  if ((!hasWildcard && pathSegments.length !== segments.length) || (hasWildcard && pathSegments.length < segments.length)) {
    return null;
  }
  const params: Record<string, string> = {};
  const rawParams: Record<string, string> = {};

  for (let i = 0; i < segments.length; i += 1) {
    const rule = segments[i];
    if (rule.kind === "wildcard") {
      const tail = pathSegments.slice(i);
      rawParams[rule.value] = tail.join("/");
      params[rule.value] = tail.map((seg) => decodeSlugParam(seg)).join("/");
      return { params, rawParams };
    }
    const actual = pathSegments[i];
    if (rule.kind === "static") {
      if (actual !== rule.value) return null;
    } else {
      rawParams[rule.value] = actual;
      params[rule.value] = decodeSlugParam(actual);
    }
  }
  return { params, rawParams };
}

export class GatewayRouter {
  private readonly routes: CompiledRoute[] = [];

  register(def: RouteDefinition): this {
    const methods = def.methods.map((m) => m.toUpperCase());
    const { segments, hasWildcard } = compilePattern(def.pattern);
    this.routes.push({ def: { ...def, methods }, methodSet: new Set(methods), segments, hasWildcard });
    return this;
  }

  lookup(method: string, canonicalPath: string): RouteLookupResult {
    const upper = method.toUpperCase();
    const pathSegments = canonicalPath === "/" ? [] : canonicalPath.slice(1).split("/");
    const allowedForPath = new Set<string>();

    for (const entry of this.routes) {
      const extracted = matchSegments(entry, pathSegments);
      if (!extracted) continue;
      if (!entry.methodSet.has(upper)) {
        for (const m of entry.def.methods) allowedForPath.add(m);
        continue;
      }
      return {
        kind: "matched",
        match: {
          route: entry.def,
          params: extracted.params,
          rawParams: extracted.rawParams,
          requiredScope: entry.def.methodScopes?.[upper] ?? null,
          requiredRole: entry.def.requiredRole ?? null,
        },
      };
    }
    if (allowedForPath.size > 0) {
      return { kind: "method_not_allowed", allowedMethods: Array.from(allowedForPath).sort() };
    }
    return { kind: "not_found" };
  }
}

export function createDefaultRouter(): GatewayRouter {
  return new GatewayRouter()
    .register({ id: "healthz", pattern: "/healthz", methods: ["GET", "HEAD"], access: "public" })
    .register({ id: "public-catalog-root", pattern: "/public/catalog", methods: ["GET", "HEAD"], access: "public" })
    .register({ id: "public-catalog-resource", pattern: "/public/catalog/*catalogPath", methods: ["GET", "HEAD"], access: "public" })
    .register({
      id: "tenant-admin-control",
      pattern: "/v1/tenants/:tenantId/admin/*adminPath",
      methods: ["GET", "HEAD", "POST", "PUT", "DELETE"],
      access: "tenant-admin",
      requiredRole: "admin",
      methodScopes: { GET: "admin:read", HEAD: "admin:read", POST: "admin:write", PUT: "admin:write", DELETE: "admin:write" },
    })
    .register({
      id: "tenant-items-collection",
      pattern: "/v1/tenants/:tenantId/items",
      methods: ["GET", "HEAD", "POST"],
      access: "tenant",
      methodScopes: { GET: "items:read", HEAD: "items:read", POST: "items:write" },
    })
    .register({
      id: "tenant-item-resource",
      pattern: "/v1/tenants/:tenantId/items/:itemSlug",
      methods: ["GET", "HEAD", "PUT", "DELETE"],
      access: "tenant",
      methodScopes: { GET: "items:read", HEAD: "items:read", PUT: "items:write", DELETE: "items:write" },
    })
    .register({
      id: "tenant-webhook-resource",
      pattern: "/v1/tenants/:tenantId/webhooks/:hookId",
      methods: ["GET", "HEAD", "POST", "DELETE"],
      access: "tenant",
      methodScopes: { GET: "webhooks:read", HEAD: "webhooks:read", POST: "webhooks:write", DELETE: "webhooks:write" },
    })
    .register({ id: "internal-mesh-plane", pattern: "/internal/*internalPath", methods: ["GET", "HEAD", "POST", "PUT", "DELETE"], access: "internal" });
}
