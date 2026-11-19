import http from "node:http";
import { Buffer } from "node:buffer";
import type { NormalizedTarget } from "./path_norm.ts";
import type { PolicyDecision } from "./policy.ts";

export interface UpstreamConfig {
  readonly host: string;
  readonly port: number;
  readonly timeoutMs?: number;
  readonly keepAlive?: boolean;
}

export interface ForwardRequestInput {
  readonly method: string;
  readonly rawTarget: string;
  readonly normalizedTarget: NormalizedTarget;
  readonly headersDistinct: Readonly<Record<string, string[] | undefined>>;
  readonly body: Buffer;
  readonly clientIp?: string;
  readonly decision: PolicyDecision;
}

export interface UpstreamResponse {
  readonly statusCode: number;
  readonly headers: http.IncomingHttpHeaders;
  readonly body: Buffer;
}

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export function buildUpstreamPath(rawTarget: string): string {
  const qIdx = rawTarget.indexOf("?");
  const rawPath = qIdx === -1 ? rawTarget : rawTarget.slice(0, qIdx);
  const rawQuery = qIdx === -1 ? null : rawTarget.slice(qIdx + 1);

  const decodedStage = rawPath
    .replace(/%5c/gi, "/")
    .replace(/\\/g, "/")
    .split("/")
    .map((seg) => {
      const semi = seg.indexOf(";");
      const clean = semi === -1 ? seg : seg.slice(0, semi);
      try {
        return decodeURIComponent(clean);
      } catch {
        return clean;
      }
    })
    .join("/");

  const resolved: string[] = [];
  for (const part of decodedStage.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (resolved.length > 0) resolved.pop();
      continue;
    }
    resolved.push(encodeURIComponent(part));
  }
  const finalPath = resolved.length === 0 ? "/" : "/" + resolved.join("/");
  return rawQuery === null ? finalPath : `${finalPath}?${rawQuery}`;
}

function buildOutboundHeaders(input: ForwardRequestInput): Record<string, string> {
  const outbound: Record<string, string> = {};
  for (const [lowerName, values] of Object.entries(input.headersDistinct)) {
    if (!values || values.length === 0) continue;
    if (HOP_BY_HOP_HEADERS.has(lowerName) || lowerName.startsWith("x-gateway-")) continue;
    outbound[lowerName] = values[values.length - 1].trim();
  }
  outbound["x-gateway-verified"] = "true";
  if (input.decision.matchedRoute) {
    outbound["x-gateway-route-id"] = input.decision.matchedRoute.route.id;
    outbound["x-gateway-access"] = input.decision.matchedRoute.route.access;
  }
  if (input.decision.tenantId) outbound["x-gateway-tenant"] = input.decision.tenantId;
  if (input.decision.keyId) outbound["x-gateway-keyid"] = input.decision.keyId;
  if (input.decision.effectiveRole) outbound["x-gateway-role"] = input.decision.effectiveRole;
  if (input.clientIp) outbound["x-forwarded-for"] = input.clientIp;
  outbound["content-length"] = String(input.body.length);
  return outbound;
}

export class UpstreamForwarder {
  private readonly config: UpstreamConfig;
  private readonly agent: http.Agent;
  private readonly timeoutMs: number;

  constructor(config: UpstreamConfig) {
    this.config = config;
    this.timeoutMs = config.timeoutMs ?? 5000;
    this.agent = new http.Agent({ keepAlive: config.keepAlive ?? true, maxSockets: 64 });
  }

  forward(input: ForwardRequestInput): Promise<UpstreamResponse> {
    const upstreamPath = buildUpstreamPath(input.rawTarget);
    const headers = buildOutboundHeaders(input);

    return new Promise<UpstreamResponse>((resolve, reject) => {
      const req = http.request(
        { host: this.config.host, port: this.config.port, method: input.method.toUpperCase(), path: upstreamPath, headers, agent: this.agent, timeout: this.timeoutMs },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
          res.on("end", () => {
            const responseHeaders: http.IncomingHttpHeaders = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (!HOP_BY_HOP_HEADERS.has(k.toLowerCase())) responseHeaders[k] = v;
            }
            resolve({ statusCode: res.statusCode ?? 502, headers: responseHeaders, body: Buffer.concat(chunks) });
          });
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new Error("Upstream request timed out")));
      req.on("error", reject);
      if (input.body.length > 0) req.write(input.body);
      req.end();
    });
  }

  destroy(): void {
    this.agent.destroy();
  }
}
