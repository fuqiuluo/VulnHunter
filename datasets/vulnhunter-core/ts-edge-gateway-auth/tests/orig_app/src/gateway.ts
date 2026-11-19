import http from "node:http";
import type { AddressInfo } from "node:net";
import { Buffer } from "node:buffer";
import { createDefaultRouter, GatewayRouter } from "./router.ts";
import { TenantKeyRing } from "./key_ring.ts";
import { HttpSignatureVerifier, type SignatureVerifierOptions } from "./http_sig.ts";
import { PolicyEngine } from "./policy.ts";
import { UpstreamForwarder, type UpstreamConfig } from "./upstream_forwarder.ts";

export interface EdgeGatewayOptions {
  readonly router?: GatewayRouter;
  readonly keyRing: TenantKeyRing;
  readonly upstream: UpstreamConfig;
  readonly verifierOptions?: SignatureVerifierOptions;
  readonly maxBodyBytes?: number;
  readonly allowInternalIngress?: boolean;
  readonly nowProvider?: () => number;
}

export interface GatewayMetrics {
  totalRequests: number;
  allowedRequests: number;
  deniedByPolicy: number;
  deniedBySignature: number;
  upstreamErrors: number;
}

class PayloadTooLargeError extends Error {
  constructor(limit: number) {
    super(`Request body exceeds limit of ${limit} bytes`);
    this.name = "PayloadTooLargeError";
  }
}

function readRequestBody(req: http.IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let received = 0;
    let aborted = false;
    req.on("data", (chunk: Buffer) => {
      if (aborted) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      received += buf.length;
      if (received > maxBytes) {
        aborted = true;
        reject(new PayloadTooLargeError(maxBytes));
        return;
      }
      chunks.push(buf);
    });
    req.on("end", () => !aborted && resolve(Buffer.concat(chunks)));
    req.on("error", (err) => !aborted && reject(err));
  });
}

function writeJsonError(res: http.ServerResponse, statusCode: number, errorCode: string, message: string, extra?: Record<string, string>): void {
  const body = Buffer.from(JSON.stringify({ error: errorCode, message }), "utf8");
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8", "content-length": String(body.length), "cache-control": "no-store", ...extra });
  res.end(body);
}

export class EdgeGateway {
  private readonly router: GatewayRouter;
  private readonly keyRing: TenantKeyRing;
  private readonly verifier: HttpSignatureVerifier;
  private readonly policy: PolicyEngine;
  private readonly forwarder: UpstreamForwarder;
  private readonly server: http.Server;
  private readonly maxBodyBytes: number;
  private readonly nowProvider: () => number;
  private readonly metrics: GatewayMetrics = { totalRequests: 0, allowedRequests: 0, deniedByPolicy: 0, deniedBySignature: 0, upstreamErrors: 0 };

  constructor(options: EdgeGatewayOptions) {
    this.router = options.router ?? createDefaultRouter();
    this.keyRing = options.keyRing;
    this.verifier = new HttpSignatureVerifier(this.keyRing, options.verifierOptions);
    this.policy = new PolicyEngine({ router: this.router, verifier: this.verifier, allowInternalIngress: options.allowInternalIngress ?? false });
    this.forwarder = new UpstreamForwarder(options.upstream);
    this.maxBodyBytes = options.maxBodyBytes ?? 1024 * 1024;
    this.nowProvider = options.nowProvider ?? (() => Math.floor(Date.now() / 1000));
    this.server = http.createServer((req, res) => void this.handleRequest(req, res));
  }

  async listen(port = 0, host = "127.0.0.1"): Promise<number> {
    return new Promise<number>((resolve, reject) => {
      const onError = (err: Error) => {
        this.server.off("listening", onListening);
        reject(err);
      };
      const onListening = () => {
        this.server.off("error", onError);
        const addr = this.server.address() as AddressInfo | null;
        if (!addr) reject(new Error("Gateway server failed to bind address"));
        else resolve(addr.port);
      };
      this.server.once("error", onError);
      this.server.once("listening", onListening);
      this.server.listen(port, host);
    });
  }

  async close(): Promise<void> {
    this.forwarder.destroy();
    if (!this.server.listening) return;
    return new Promise<void>((resolve, reject) => this.server.close((err) => (err ? reject(err) : resolve())));
  }

  getMetrics(): Readonly<GatewayMetrics> {
    return { ...this.metrics };
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    this.metrics.totalRequests += 1;
    const method = req.method ?? "GET";
    const rawTarget = req.url ?? "/";
    const hostValues = req.headersDistinct["host"];
    if (!hostValues || hostValues.length !== 1 || !hostValues[0].trim()) {
      this.metrics.deniedByPolicy += 1;
      writeJsonError(res, 400, "INVALID_HOST_HEADER", "Request must include exactly one valid Host header");
      return;
    }

    let body: Buffer;
    try {
      body = await readRequestBody(req, this.maxBodyBytes);
    } catch (err) {
      this.metrics.deniedByPolicy += 1;
      writeJsonError(res, err instanceof PayloadTooLargeError ? 413 : 400, err instanceof PayloadTooLargeError ? "PAYLOAD_TOO_LARGE" : "BODY_READ_ERROR", (err as Error).message);
      return;
    }

    const decision = this.policy.evaluate({
      method,
      rawTarget,
      authority: hostValues[0].trim(),
      headersDistinct: req.headersDistinct,
      body,
      remoteAddress: req.socket.remoteAddress,
      isInternalMesh: false,
      nowSec: this.nowProvider(),
    });

    if (!decision.allowed || !decision.normalizedTarget) {
      if (decision.statusCode === 401) this.metrics.deniedBySignature += 1;
      else this.metrics.deniedByPolicy += 1;
      const extra = decision.allowedMethods?.length ? { allow: decision.allowedMethods.join(", ") } : undefined;
      writeJsonError(res, decision.statusCode, decision.errorCode ?? "ACCESS_DENIED", decision.message ?? "Access denied", extra);
      return;
    }

    this.metrics.allowedRequests += 1;
    try {
      const upstreamRes = await this.forwarder.forward({ method, rawTarget, normalizedTarget: decision.normalizedTarget, headersDistinct: req.headersDistinct, body, clientIp: req.socket.remoteAddress, decision });
      res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
      res.end(method.toUpperCase() === "HEAD" ? undefined : upstreamRes.body);
    } catch {
      this.metrics.upstreamErrors += 1;
      writeJsonError(res, 502, "UPSTREAM_UNAVAILABLE", "Failed to forward request to upstream origin");
    }
  }
}
