/**
 * Federated GraphQL Gateway Engine & HTTP `/graphql` Transport Server.
 */

import http from "node:http";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import { Buffer } from "node:buffer";

import {
  coerceVariables,
  GraphQLError,
  parseGraphQL,
  selectOperation,
} from "./ast.ts";
import {
  AuthorizationError,
  authorizeOperation,
  type GatewayPrincipal,
} from "./auth_policy.ts";
import {
  analyzeQueryCost,
  DEFAULT_COST_LIMITS,
  QueryCostError,
  type CostLimits,
} from "./cost_analyzer.ts";
import { EntityResolutionCache, type EntityCacheOptions } from "./entity_cache.ts";
import { executeFederatedOperation } from "./entity_planner.ts";
import { buildCommerceSupergraph, SupergraphSchema } from "./schema.ts";
import { InMemorySubgraphCluster, type SubgraphService } from "./subgraphs.ts";

export interface GatewayOptions {
  schema?: SupergraphSchema;
  services?: ReadonlyMap<string, SubgraphService>;
  costLimits?: CostLimits;
  cacheOptions?: EntityCacheOptions;
  maxBodyBytes?: number;
}

export interface GraphQLRequestEnvelope {
  query: string;
  operationName?: string;
  variables?: Record<string, unknown>;
}

export interface GraphQLFormattedError {
  message: string;
  extensions: {
    code: string;
  };
}

export interface GraphQLExecutionResult {
  statusCode: number;
  body: {
    data: Record<string, unknown> | null;
    errors?: GraphQLFormattedError[];
    extensions?: {
      cost: number;
      depth: number;
    };
  };
}

function parseScopesHeader(raw: string | string[] | undefined): ReadonlySet<string> {
  if (!raw) return new Set();
  const list = Array.isArray(raw) ? raw : [raw];
  const out = new Set<string>();
  for (const item of list) {
    for (const tok of item.split(/[\s,]+/)) {
      const trimmed = tok.trim();
      if (trimmed) out.add(trimmed);
    }
  }
  return out;
}

function firstSingleHeader(
  headers: http.IncomingHttpHeaders,
  name: string,
): string | undefined {
  const val = headers[name.toLowerCase()];
  if (Array.isArray(val)) {
    return val.length === 1 ? val[0].trim() : undefined;
  }
  return typeof val === "string" ? val.trim() : undefined;
}

export class FederatedGateway {
  public readonly schema: SupergraphSchema;
  public readonly services: ReadonlyMap<string, SubgraphService>;
  public readonly costLimits: CostLimits;
  public readonly cache: EntityResolutionCache;
  private readonly maxBodyBytes: number;
  private server: http.Server | null = null;

  constructor(options: GatewayOptions = {}) {
    this.schema = options.schema ?? buildCommerceSupergraph();
    this.services = options.services ?? new InMemorySubgraphCluster().createServices();
    this.costLimits = options.costLimits ?? DEFAULT_COST_LIMITS;
    this.cache = new EntityResolutionCache(options.cacheOptions);
    this.maxBodyBytes = options.maxBodyBytes ?? 256 * 1024;
  }

  async execute(
    envelope: GraphQLRequestEnvelope,
    principal: GatewayPrincipal,
  ): Promise<GraphQLExecutionResult> {
    try {
      if (!principal.tenantId || !principal.principalId) {
        throw new AuthorizationError("Missing authenticated tenant or principal identity", "UNAUTHENTICATED");
      }
      const doc = parseGraphQL(envelope.query);
      const op = selectOperation(doc, envelope.operationName);
      const variables = coerceVariables(op, envelope.variables);

      const costInfo = analyzeQueryCost(doc, op, this.schema, variables, this.costLimits);
      authorizeOperation(doc, op, this.schema, principal);

      const data = await executeFederatedOperation({
        doc,
        op,
        schema: this.schema,
        variables,
        services: this.services,
        cache: this.cache,
        ctx: {
          tenantId: principal.tenantId,
          principalId: principal.principalId,
          requestId: crypto.randomUUID(),
        },
      });

      return {
        statusCode: 200,
        body: {
          data,
          extensions: {
            cost: costInfo.totalCost,
            depth: costInfo.maxDepthObserved,
          },
        },
      };
    } catch (err: unknown) {
      if (err instanceof AuthorizationError) {
        const status = err.code === "UNAUTHENTICATED" ? 401 : 403;
        return {
          statusCode: status,
          body: {
            data: null,
            errors: [{ message: err.message, extensions: { code: err.code } }],
          },
        };
      }
      if (err instanceof QueryCostError) {
        return {
          statusCode: 429,
          body: {
            data: null,
            errors: [{ message: err.message, extensions: { code: err.code } }],
          },
        };
      }
      if (err instanceof GraphQLError) {
        return {
          statusCode: 400,
          body: {
            data: null,
            errors: [{ message: err.message, extensions: { code: err.code } }],
          },
        };
      }
      const message = err instanceof Error ? err.message : "Internal gateway error";
      return {
        statusCode: 500,
        body: {
          data: null,
          errors: [{ message, extensions: { code: "INTERNAL_SERVER_ERROR" } }],
        },
      };
    }
  }

  async listen(port = 0, host = "127.0.0.1"): Promise<number> {
    if (this.server) {
      throw new Error("FederatedGateway HTTP server is already listening");
    }
    const srv = http.createServer((req, res) => {
      void this.handleHttpRequest(req, res);
    });
    this.server = srv;
    await new Promise<void>((resolve, reject) => {
      srv.once("error", reject);
      srv.listen(port, host, () => resolve());
    });
    return (srv.address() as AddressInfo).port;
  }

  async close(): Promise<void> {
    const srv = this.server;
    if (!srv) return;
    this.server = null;
    await new Promise<void>((resolve) => srv.close(() => resolve()));
  }

  private async handleHttpRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const urlPath = (req.url ?? "/").split("?")[0];
    if (req.method === "GET" && urlPath === "/healthz") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    if (req.method !== "POST" || urlPath !== "/graphql") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: null, errors: [{ message: "Not found", extensions: { code: "NOT_FOUND" } }] }));
      return;
    }

    const chunks: Buffer[] = [];
    let totalBytes = 0;
    try {
      for await (const chunk of req) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
        totalBytes += buf.length;
        if (totalBytes > this.maxBodyBytes) {
          res.writeHead(413, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              data: null,
              errors: [{ message: "Request body exceeds limit", extensions: { code: "PAYLOAD_TOO_LARGE" } }],
            }),
          );
          return;
        }
        chunks.push(buf);
      }
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: null, errors: [{ message: "Stream read error", extensions: { code: "BAD_REQUEST" } }] }));
      return;
    }

    let parsedBody: Record<string, unknown>;
    try {
      const rawJson = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
      if (!rawJson || typeof rawJson !== "object" || Array.isArray(rawJson)) {
        throw new Error("Root JSON payload must be an object");
      }
      parsedBody = rawJson as Record<string, unknown>;
    } catch (err: unknown) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          data: null,
          errors: [
            {
              message: err instanceof Error ? err.message : "Invalid JSON body",
              extensions: { code: "BAD_JSON" },
            },
          ],
        }),
      );
      return;
    }

    const tenantId = firstSingleHeader(req.headers, "x-tenant-id") ?? "";
    const principalId = firstSingleHeader(req.headers, "x-principal-id") ?? "";
    const role = firstSingleHeader(req.headers, "x-principal-role") ?? "member";
    const scopes = parseScopesHeader(req.headers["x-principal-scopes"]);

    const envelope: GraphQLRequestEnvelope = {
      query: typeof parsedBody.query === "string" ? parsedBody.query : "",
      operationName: typeof parsedBody.operationName === "string" ? parsedBody.operationName : undefined,
      variables:
        parsedBody.variables && typeof parsedBody.variables === "object" && !Array.isArray(parsedBody.variables)
          ? (parsedBody.variables as Record<string, unknown>)
          : undefined,
    };

    const result = await this.execute(envelope, { tenantId, principalId, role, scopes });
    res.writeHead(result.statusCode, { "content-type": "application/json" });
    res.end(JSON.stringify(result.body));
  }
}
