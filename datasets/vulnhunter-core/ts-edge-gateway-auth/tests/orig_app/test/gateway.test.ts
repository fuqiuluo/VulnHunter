import http from "node:http";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import { Buffer } from "node:buffer";
import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";

import { EdgeGateway } from "../src/gateway.ts";
import { TenantKeyRing } from "../src/key_ring.ts";
import { signRequest } from "../src/http_sig.ts";
import { decodeSlugParam, normalizeRoutePath } from "../src/path_norm.ts";

interface HttpResult {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function generateEd25519Pair(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

function sendHttpRequest(opts: { port: number; method: string; path: string; headers?: Record<string, string>; body?: string }): Promise<HttpResult> {
  return new Promise<HttpResult>((resolve, reject) => {
    const data = opts.body ? Buffer.from(opts.body, "utf8") : Buffer.alloc(0);
    const headers: Record<string, string> = { host: `127.0.0.1:${opts.port}`, ...opts.headers };
    if (data.length > 0 && !headers["content-length"]) headers["content-length"] = String(data.length);
    const req = http.request({ host: "127.0.0.1", port: opts.port, method: opts.method, path: opts.path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on("end", () => resolve({ statusCode: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    if (data.length > 0) req.write(data);
    req.end();
  });
}

describe("EdgeGateway baseline functional behavior", () => {
  const capturedUrls: string[] = [];
  let upstreamServer: http.Server;
  let gateway: EdgeGateway;
  let gatewayPort = 0;
  let keyRing: TenantKeyRing;
  const currentNowSec = 1_750_000_000;

  const acmeV1 = generateEd25519Pair();
  const acmeV2 = generateEd25519Pair();
  const nimbusSecretB64 = Buffer.from("0123456789abcdef0123456789abcdef", "utf8").toString("base64");

  before(async () => {
    upstreamServer = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        capturedUrls.push(req.url ?? "/");
        res.writeHead(req.method === "POST" ? 201 : 200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, upstreamUrl: req.url, tenant: req.headers["x-gateway-tenant"] ?? null }));
      });
    });
    await new Promise<void>((resolve) => upstreamServer.listen(0, "127.0.0.1", () => resolve()));
    const upstreamPort = (upstreamServer.address() as AddressInfo).port;

    keyRing = new TenantKeyRing();
    keyRing.registerKey("acme", { keyId: "k-v1", algorithm: "ed25519", publicKeyPem: acmeV1.publicKeyPem });
    keyRing.registerKey("nimbus", { keyId: "hmac-main", algorithm: "hmac-sha256", secretBase64: nimbusSecretB64, allowedScopes: ["webhooks:read", "webhooks:write"] });
    gateway = new EdgeGateway({ keyRing, upstream: { host: "127.0.0.1", port: upstreamPort }, nowProvider: () => currentNowSec });
    gatewayPort = await gateway.listen(0, "127.0.0.1");
  });

  after(async () => {
    await gateway.close();
    await new Promise<void>((resolve) => upstreamServer.close(() => resolve()));
  });

  it("normalizes canonical route targets while preserving encoded slug slashes and query parameters", () => {
    const parsed = normalizeRoutePath("/v1/tenants/acme/items/release%2f2026-q4?filter=tier%3Dga;region=eu&next=%2Fcatalog%2Fpage2");
    assert.equal(parsed.canonicalPath, "/v1/tenants/acme/items/release%2F2026-q4");
    assert.equal(parsed.rawQuery, "filter=tier%3Dga;region=eu&next=%2Fcatalog%2Fpage2");
    assert.equal(decodeSlugParam(parsed.segments[4]), "release/2026-q4");
  });

  it("serves public health and catalog routes without authentication", async () => {
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/healthz" })).statusCode, 200);
    const catalogPath = "/public/catalog/compute/edge-proxy?filter=tier%3Dpro;zone=us&next=%2Fdocs";
    const catalog = await sendHttpRequest({ port: gatewayPort, method: "GET", path: catalogPath });
    assert.equal(catalog.statusCode, 200);
    assert.equal((JSON.parse(catalog.body) as { upstreamUrl: string }).upstreamUrl, catalogPath);
  });

  it("denies direct external access to internal control-plane endpoints", async () => {
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/internal/keys" })).statusCode, 403);
  });

  it("verifies signed Ed25519 GET and POST tenant requests with Content-Digest", async () => {
    const authority = `127.0.0.1:${gatewayPort}`;
    const body = JSON.stringify({ name: "sensor-pack", sku: "sp-100" });
    const signedPost = signRequest({
      method: "POST",
      authority,
      target: "/v1/tenants/acme/items",
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:write", "content-type": "application/json" },
      body,
      keyId: "k-v1",
      algorithm: "ed25519",
      privateKeyPem: acmeV1.privateKeyPem,
      created: currentNowSec,
    });
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "POST", path: "/v1/tenants/acme/items", headers: signedPost.headers, body })).statusCode, 201);

    const signedGet = signRequest({
      method: "GET",
      authority,
      target: "/v1/tenants/acme/items/pkg%40core%2B2.1",
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:read" },
      keyId: "k-v1",
      algorithm: "ed25519",
      privateKeyPem: acmeV1.privateKeyPem,
      created: currentNowSec,
    });
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/v1/tenants/acme/items/pkg%40core%2B2.1", headers: signedGet.headers })).statusCode, 200);
  });

  it("supports HMAC-SHA256 tenant keys and per-tenant key rotation grace windows", async () => {
    const authority = `127.0.0.1:${gatewayPort}`;
    const hmacSigned = signRequest({
      method: "GET",
      authority,
      target: "/v1/tenants/nimbus/webhooks/hk-daily",
      headers: { "x-tenant-id": "nimbus", "x-forwarded-scope": "webhooks:read" },
      keyId: "hmac-main",
      algorithm: "hmac-sha256",
      secretBase64: nimbusSecretB64,
      created: currentNowSec,
    });
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/v1/tenants/nimbus/webhooks/hk-daily", headers: hmacSigned.headers })).statusCode, 200);

    keyRing.rotateKey("acme", "k-v1", { keyId: "k-v2", algorithm: "ed25519", publicKeyPem: acmeV2.publicKeyPem }, 120, currentNowSec);
    for (const [keyId, pem] of [["k-v1", acmeV1.privateKeyPem], ["k-v2", acmeV2.privateKeyPem]] as const) {
      const signed = signRequest({
        method: "GET",
        authority,
        target: "/v1/tenants/acme/items",
        headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:read" },
        keyId,
        algorithm: "ed25519",
        privateKeyPem: pem,
        created: currentNowSec,
      });
      assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/v1/tenants/acme/items", headers: signed.headers })).statusCode, 200);
    }
  });

  it("rejects expired signatures and non-admin callers on tenant admin routes", async () => {
    const authority = `127.0.0.1:${gatewayPort}`;
    const expired = signRequest({
      method: "GET",
      authority,
      target: "/v1/tenants/acme/items",
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:read" },
      keyId: "k-v2",
      algorithm: "ed25519",
      privateKeyPem: acmeV2.privateKeyPem,
      created: currentNowSec - 100,
      expires: currentNowSec - 10,
    });
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/v1/tenants/acme/items", headers: expired.headers })).statusCode, 401);

    const nonAdmin = signRequest({
      method: "GET",
      authority,
      target: "/v1/tenants/acme/admin/config",
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "admin:read", "x-role": "viewer" },
      keyId: "k-v2",
      algorithm: "ed25519",
      privateKeyPem: acmeV2.privateKeyPem,
      created: currentNowSec,
    });
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/v1/tenants/acme/admin/config", headers: nonAdmin.headers })).statusCode, 403);
    assert.ok(capturedUrls.length >= 5);
  });
});
