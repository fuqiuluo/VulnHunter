#!/usr/bin/env python3
"""Deterministic end-to-end verifier for task: ts-edge-gateway-auth."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HARNESS_TS = r"""
import http from "node:http";
import net from "node:net";
import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import { Buffer } from "node:buffer";

import { EdgeGateway } from "./src/gateway.ts";
import { TenantKeyRing } from "./src/key_ring.ts";

interface UpstreamHit {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

interface WireResponse {
  statusCode: number;
  body: string;
}

function genEd25519(): { publicKeyPem: string; privateKeyPem: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

function sha256DigestHeader(body: string | Buffer): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return `sha-256=:${crypto.createHash("sha256").update(buf).digest("base64")}:`;
}

function signWireHeaders(opts: {
  method: string;
  authority: string;
  sigPath: string;
  rawQuery?: string;
  hasQuery?: boolean;
  headerPairs: ReadonlyArray<readonly [string, string]>;
  body?: string;
  keyId: string;
  alg: "ed25519" | "hmac-sha256";
  privateKeyPem?: string;
  secretBase64?: string;
  created: number;
  expires?: number;
  nonce?: string | null;
  components?: ReadonlyArray<string>;
  includeContentDigestHeader?: boolean;
}): Array<[string, string]> {
  const pairs: Array<[string, string]> = opts.headerPairs.map(([k, v]) => [k, v]);
  const bodyStr = opts.body ?? "";
  const bodyBuf = Buffer.from(bodyStr, "utf8");

  if ((opts.includeContentDigestHeader ?? bodyBuf.length > 0) && !pairs.some(([k]) => k.toLowerCase() === "content-digest")) {
    pairs.push(["Content-Digest", sha256DigestHeader(bodyBuf)]);
  }

  const distinct: Record<string, string[]> = {};
  for (const [k, v] of pairs) {
    (distinct[k.toLowerCase()] ??= []).push(v);
  }

  const hasQuery = opts.hasQuery ?? opts.rawQuery !== undefined;
  const rawQuery = opts.rawQuery ?? "";
  const comps = opts.components
    ? [...opts.components]
    : [
        "@method",
        "@authority",
        "@path",
        ...(hasQuery ? ["@query"] : []),
        ...["x-tenant-id", "x-forwarded-scope", "x-role", "content-type", "content-encoding"].filter((h) => distinct[h]?.length),
        ...(distinct["content-digest"]?.length ? ["content-digest"] : []),
      ];

  let paramsVal = `(${comps.map((c) => `"${c}"`).join(" ")});created=${opts.created}`;
  if (opts.expires !== undefined) paramsVal += `;expires=${opts.expires}`;
  paramsVal += `;keyid="${opts.keyId}";alg="${opts.alg}"`;
  const nonceVal = opts.nonce === undefined ? crypto.randomBytes(10).toString("hex") : opts.nonce;
  if (nonceVal !== null && nonceVal.length > 0) {
    paramsVal += `;nonce="${nonceVal}"`;
  }

  const lines: string[] = [];
  for (const c of comps) {
    if (c === "@method") lines.push(`"@method": ${opts.method.toUpperCase()}`);
    else if (c === "@authority") lines.push(`"@authority": ${opts.authority.toLowerCase()}`);
    else if (c === "@path") lines.push(`"@path": ${opts.sigPath}`);
    else if (c === "@query") lines.push(`"@query": ?${rawQuery}`);
    else {
      const joined = (distinct[c] ?? []).map((v) => v.trim().replace(/\s+/g, " ")).join(", ");
      lines.push(`"${c}": ${joined}`);
    }
  }
  lines.push(`"@signature-params": ${paramsVal}`);
  const baseBuf = Buffer.from(lines.join("\n"), "utf8");

  const sigBytes =
    opts.alg === "ed25519"
      ? crypto.sign(null, baseBuf, crypto.createPrivateKey(opts.privateKeyPem ?? ""))
      : crypto.createHmac("sha256", Buffer.from(opts.secretBase64 ?? "", "base64")).update(baseBuf).digest();

  pairs.push(["Signature-Input", `sig1=${paramsVal}`]);
  pairs.push(["Signature", `sig1=:${sigBytes.toString("base64")}:`]);
  return pairs;
}

function decodeWireBody(rawHead: string, bodyBuf: Buffer): string {
  if (!/transfer-encoding:\s*chunked/i.test(rawHead)) return bodyBuf.toString("utf8");
  const out: Buffer[] = [];
  let offset = 0;
  while (offset < bodyBuf.length) {
    const lineEnd = bodyBuf.indexOf("\r\n", offset);
    if (lineEnd === -1) break;
    const chunkSize = Number.parseInt(bodyBuf.slice(offset, lineEnd).toString("ascii").split(";")[0].trim(), 16);
    if (!Number.isFinite(chunkSize) || chunkSize === 0) break;
    out.push(bodyBuf.slice(lineEnd + 2, lineEnd + 2 + chunkSize));
    offset = lineEnd + 2 + chunkSize + 2;
  }
  return Buffer.concat(out).toString("utf8");
}

function sendWire(port: number, method: string, rawTarget: string, headerPairs: ReadonlyArray<readonly [string, string]>, body = ""): Promise<WireResponse> {
  return new Promise<WireResponse>((resolve, reject) => {
    const bodyBuf = Buffer.from(body, "utf8");
    const lines = [
      `${method} ${rawTarget} HTTP/1.1`,
      `Host: 127.0.0.1:${port}`,
      `Connection: close`,
      ...headerPairs.map(([k, v]) => `${k}: ${v}`),
    ];
    if (bodyBuf.length > 0 && !headerPairs.some(([k]) => k.toLowerCase() === "content-length")) {
      lines.push(`Content-Length: ${bodyBuf.length}`);
    }
    const reqHead = Buffer.from(lines.join("\r\n") + "\r\n\r\n", "utf8");

    const socket = net.createConnection({ host: "127.0.0.1", port }, () => {
      socket.write(reqHead);
      if (bodyBuf.length > 0) socket.write(bodyBuf);
    });
    const chunks: Buffer[] = [];
    socket.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    socket.on("error", reject);
    socket.on("end", () => {
      const full = Buffer.concat(chunks);
      const sep = full.indexOf("\r\n\r\n");
      const head = sep === -1 ? full.toString("utf8") : full.slice(0, sep).toString("utf8");
      const respBody = sep === -1 ? "" : decodeWireBody(head, full.slice(sep + 4));
      const m = /^HTTP\/1\.\d\s+(\d{3})/.exec(head);
      resolve({ statusCode: m ? Number.parseInt(m[1], 10) : 0, body: respBody });
    });
  });
}

function assertCond(cond: boolean, msg: string): void {
  if (!cond) throw new Error(msg);
}

async function runSuite(): Promise<{ allPassed: boolean; groups: Record<string, { passed: boolean; message: string }> }> {
  const hits: UpstreamHit[] = [];
  const upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on("end", () => {
      const bodyStr = Buffer.concat(chunks).toString("utf8");
      const urlStr = req.url ?? "/";
      hits.push({ method: req.method ?? "GET", url: urlStr, headers: req.headers, body: bodyStr });

      // Single-segment item route check on mock origin: /v1/tenants/:t/items/:slug must have 5 path segments
      const pathOnly = urlStr.split("?")[0];
      const segs = pathOnly.split("/").filter(Boolean);
      if (segs[0] === "v1" && segs[1] === "tenants" && segs[3] === "items" && segs.length > 5) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "ORIGIN_EXTRA_SEGMENTS", pathOnly }));
        return;
      }

      res.writeHead(req.method === "POST" ? 201 : 200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          ok: true,
          url: urlStr,
          tenant: req.headers["x-gateway-tenant"] ?? null,
          forwardedScope: req.headers["x-forwarded-scope"] ?? null,
          bodyEcho: bodyStr,
        }),
      );
    });
  });

  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", () => resolve()));
  const upstreamPort = (upstream.address() as AddressInfo).port;

  let nowSec = 1_760_000_000;
  const keyRing = new TenantKeyRing();

  const acmeMember = genEd25519();
  const acmeAdmin = genEd25519();
  const acmeRot1 = genEd25519();
  const acmeRot2 = genEd25519();
  const acmeShared = genEd25519();
  const globexShared = genEd25519();
  const acmeEphemeral = genEd25519();
  const nimbusSecret = Buffer.from("nimbus-shared-hmac-secret-32byte!", "utf8").toString("base64");

  keyRing.registerKey("acme", { keyId: "k-member", algorithm: "ed25519", publicKeyPem: acmeMember.publicKeyPem });
  keyRing.registerKey("acme", { keyId: "k-admin", algorithm: "ed25519", publicKeyPem: acmeAdmin.publicKeyPem });
  keyRing.registerKey("acme", { keyId: "k-rot-1", algorithm: "ed25519", publicKeyPem: acmeRot1.publicKeyPem });
  keyRing.registerKey("acme", { keyId: "k-primary", algorithm: "ed25519", publicKeyPem: acmeShared.publicKeyPem });
  keyRing.registerKey("globex", { keyId: "k-primary", algorithm: "ed25519", publicKeyPem: globexShared.publicKeyPem });
  keyRing.registerKey("acme", { keyId: "k-ephemeral", algorithm: "ed25519", publicKeyPem: acmeEphemeral.publicKeyPem });
  keyRing.registerKey("nimbus", {
    keyId: "hmac-v1",
    algorithm: "hmac-sha256",
    secretBase64: nimbusSecret,
    allowedScopes: ["webhooks:read", "webhooks:write"],
  });

  const gateway = new EdgeGateway({
    keyRing,
    upstream: { host: "127.0.0.1", port: upstreamPort },
    nowProvider: () => nowSec,
  });
  const gwPort = await gateway.listen(0, "127.0.0.1");
  const authority = `127.0.0.1:${gwPort}`;

  const out: Record<string, { passed: boolean; message: string }> = {};
  let allPassed = true;
  const runGroup = async (name: string, fn: () => Promise<string>) => {
    try {
      const msg = await fn();
      out[name] = { passed: true, message: msg };
    } catch (err: unknown) {
      allPassed = false;
      out[name] = { passed: false, message: err instanceof Error ? err.message : String(err) };
    }
  };

  try {
    // 1. Functional baseline & tight constraints
    await runGroup("functional", async () => {
      const hRes = await sendWire(gwPort, "GET", "/healthz", []);
      assertCond(hRes.statusCode === 200, `Expected 200 on /healthz, got ${hRes.statusCode}`);

      const catTarget = "/public/catalog/networking/load-balancer?filter=tier%3Dga;region=us-east&next=%2Fcatalog%2Fpage2";
      const catRes = await sendWire(gwPort, "GET", catTarget, []);
      assertCond(catRes.statusCode === 200, `Expected 200 on public catalog query, got ${catRes.statusCode}`);
      assertCond((JSON.parse(catRes.body) as { url: string }).url === catTarget, "Query string with ';' and '%2F' was altered");

      // Encoded %2F inside itemSlug + ';' in query string
      const slugPath = "/v1/tenants/acme/items/release%2F2026-q4";
      const slugQuery = "format=summary;v=2&ref=%2Fmain";
      const slugFull = `${slugPath}?${slugQuery}`;
      const slugHeaders = signWireHeaders({
        method: "GET",
        authority,
        sigPath: slugPath,
        rawQuery: slugQuery,
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-member",
        alg: "ed25519",
        privateKeyPem: acmeMember.privateKeyPem,
        created: nowSec,
      });
      const slugRes = await sendWire(gwPort, "GET", slugFull, slugHeaders);
      assertCond(slugRes.statusCode === 200, `Encoded %2F itemSlug failed with status ${slugRes.statusCode}: ${slugRes.body}`);
      assertCond((JSON.parse(slugRes.body) as { url: string }).url === slugFull, `Encoded %2F itemSlug upstream URL mismatch: ${slugRes.body}`);

      // POST with valid Content-Digest
      const postBody = JSON.stringify({ item: "edge-sensor", count: 4 });
      const postHeaders = signWireHeaders({
        method: "POST",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:write"],
          ["Content-Type", "application/json"],
        ],
        body: postBody,
        keyId: "k-member",
        alg: "ed25519",
        privateKeyPem: acmeMember.privateKeyPem,
        created: nowSec,
      });
      const postRes = await sendWire(gwPort, "POST", "/v1/tenants/acme/items", postHeaders, postBody);
      assertCond(postRes.statusCode === 201, `Valid signed POST failed: ${postRes.statusCode}`);

      // Empty-body DELETE
      const delHeaders = signWireHeaders({
        method: "DELETE",
        authority,
        sigPath: "/v1/tenants/acme/items/pkg%40core%2B2.1",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:write"],
        ],
        keyId: "k-member",
        alg: "ed25519",
        privateKeyPem: acmeMember.privateKeyPem,
        created: nowSec,
      });
      const delRes = await sendWire(gwPort, "DELETE", "/v1/tenants/acme/items/pkg%40core%2B2.1", delHeaders);
      assertCond(delRes.statusCode === 200, `Valid signed DELETE failed: ${delRes.statusCode}`);

      // Multi-header signed request (two X-Forwarded-Scope headers)
      const multiHeaders = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/webhooks/hk-alpha",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
          ["X-Forwarded-Scope", "webhooks:read"],
        ],
        keyId: "k-member",
        alg: "ed25519",
        privateKeyPem: acmeMember.privateKeyPem,
        created: nowSec,
      });
      const multiRes = await sendWire(gwPort, "GET", "/v1/tenants/acme/webhooks/hk-alpha", multiHeaders);
      assertCond(multiRes.statusCode === 200, `Multi-header signed GET failed: ${multiRes.statusCode} ${multiRes.body}`);
      const multiJson = JSON.parse(multiRes.body) as { forwardedScope: string | null };
      const scopeTokens = (multiJson.forwardedScope ?? "")
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .sort();
      assertCond(
        scopeTokens.length === 2 && scopeTokens[0] === "items:read" && scopeTokens[1] === "webhooks:read",
        `Expected forwardedScope to preserve both 'items:read' and 'webhooks:read', got ${JSON.stringify(multiJson.forwardedScope)}`,
      );

      // HMAC-SHA256 tenant signing
      const hmacHeaders = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/nimbus/webhooks/hk-beta",
        headerPairs: [
          ["X-Tenant-Id", "nimbus"],
          ["X-Forwarded-Scope", "webhooks:read"],
        ],
        keyId: "hmac-v1",
        alg: "hmac-sha256",
        secretBase64: nimbusSecret,
        created: nowSec,
      });
      assertCond((await sendWire(gwPort, "GET", "/v1/tenants/nimbus/webhooks/hk-beta", hmacHeaders)).statusCode === 200, "HMAC GET failed");

      // Legitimate tenant admin request
      const adminBody = JSON.stringify({ auditLevel: "strict" });
      const adminHeaders = signWireHeaders({
        method: "POST",
        authority,
        sigPath: "/v1/tenants/acme/admin/config",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "admin:write"],
          ["X-Role", "admin"],
          ["Content-Type", "application/json"],
        ],
        body: adminBody,
        keyId: "k-admin",
        alg: "ed25519",
        privateKeyPem: acmeAdmin.privateKeyPem,
        created: nowSec,
      });
      assertCond(
        (await sendWire(gwPort, "POST", "/v1/tenants/acme/admin/config", adminHeaders, adminBody)).statusCode === 201,
        "Legitimate tenant admin POST failed",
      );

      // Key rotation k-rot-1 -> k-rot-2
      keyRing.rotateKey("acme", "k-rot-1", { keyId: "k-rot-2", algorithm: "ed25519", publicKeyPem: acmeRot2.publicKeyPem }, 60, nowSec);
      for (const [kid, priv] of [["k-rot-1", acmeRot1.privateKeyPem], ["k-rot-2", acmeRot2.privateKeyPem]] as const) {
        const rotH = signWireHeaders({
          method: "GET",
          authority,
          sigPath: "/v1/tenants/acme/items",
          headerPairs: [
            ["X-Tenant-Id", "acme"],
            ["X-Forwarded-Scope", "items:read"],
          ],
          keyId: kid,
          alg: "ed25519",
          privateKeyPem: priv,
          created: nowSec,
        });
        assertCond((await sendWire(gwPort, "GET", "/v1/tenants/acme/items", rotH)).statusCode === 200, `Rotated key ${kid} failed during grace window`);
      }

      return "All public, encoded-slug, multi-header, HMAC, admin, and key-rotation flows passed";
    });

    // 2. Defect A: Auth-vs-Forwarder Path Normalization Differential
    await runGroup("path_differential", async () => {
      const internalHitsBefore = hits.filter((h) => h.url.startsWith("/internal")).length;
      const adminHitsBefore = hits.filter((h) => h.url.includes("/admin/")).length;

      const publicProbes = [
        "/public/catalog/..;v=1/..;v=2/internal/keys",
        "/public/catalog/%2e%2e/%2e%2e/internal/keys",
        "/public/catalog/%2e%2e%2f%2e%2e%2finternal%2fkeys",
        "/public/catalog/..%5c..%5cinternal%5ckeys",
        "/public/catalog/.%2e/.%2e/internal/metrics",
      ];
      for (const p of publicProbes) {
        const r = await sendWire(gwPort, "GET", p, []);
        assertCond(r.statusCode >= 400 && r.statusCode < 500, `Unauthenticated path differential '${p}' returned ${r.statusCode}`);
      }

      // Authenticated non-admin member attempting to reach /v1/tenants/acme/admin/config
      for (const [wireTarget, sigPath] of [
        ["/v1/tenants/acme/items/%2e%2e%2fadmin%2fconfig", "/v1/tenants/acme/items/%2E%2E%2Fadmin%2Fconfig"],
        ["/v1/tenants/acme/items/..;v=1/admin/config", "/v1/tenants/acme/items/..;v=1/admin/config"],
        ["/v1/tenants/acme/items/%2e%2e/admin/config", "/v1/tenants/acme/items/%2E%2E/admin/config"],
      ] as const) {
        const h = signWireHeaders({
          method: "GET",
          authority,
          sigPath,
          headerPairs: [
            ["X-Tenant-Id", "acme"],
            ["X-Forwarded-Scope", "items:read"],
          ],
          keyId: "k-member",
          alg: "ed25519",
          privateKeyPem: acmeMember.privateKeyPem,
          created: nowSec,
        });
        const r = await sendWire(gwPort, "GET", wireTarget, h);
        assertCond(r.statusCode >= 400 && r.statusCode < 500, `Member-to-admin path differential '${wireTarget}' returned ${r.statusCode}`);
      }

      // Cross-tenant path differential from globex -> acme
      const crossTarget = "/v1/tenants/globex/items/%2e%2e%2f%2e%2e%2facme%2fitems%2fvault";
      const crossHeaders = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/globex/items/%2E%2E%2F%2E%2E%2Facme%2Fitems%2Fvault",
        headerPairs: [
          ["X-Tenant-Id", "globex"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-primary",
        alg: "ed25519",
        privateKeyPem: globexShared.privateKeyPem,
        created: nowSec,
      });
      const crossRes = await sendWire(gwPort, "GET", crossTarget, crossHeaders);
      assertCond(crossRes.statusCode >= 400 && crossRes.statusCode < 500, `Cross-tenant path differential returned ${crossRes.statusCode}`);

      const internalHitsAfter = hits.filter((h) => h.url.startsWith("/internal")).length;
      const adminHitsAfter = hits.filter((h) => h.url.includes("/admin/")).length;
      assertCond(internalHitsAfter === internalHitsBefore, "Upstream received unauthorized /internal request");
      assertCond(adminHitsAfter === adminHitsBefore, "Upstream received unauthorized /admin request");
      assertCond(!hits.some((h) => h.url.includes("/acme/items/vault")), "Upstream received cross-tenant /acme/items/vault request");

      return "All matrix-parameter, encoded-dot, backslash, and cross-tenant path differentials blocked";
    });

    // 3. Defect B: HTTP Signature Covered Components & Header Canonicalization
    await runGroup("signature_canonicalization", async () => {
      const adminHitsBefore = hits.filter((h) => h.url.includes("/admin/")).length;

      // B1a: POST body tampering when content-digest is omitted from covered components
      const origBody = JSON.stringify({ amount: 10 });
      const tamperedBody = JSON.stringify({ amount: 999999 });
      const noDigestCov = signWireHeaders({
        method: "POST",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:write"],
          ["Content-Type", "application/json"],
        ],
        body: origBody,
        keyId: "k-member",
        alg: "ed25519",
        privateKeyPem: acmeMember.privateKeyPem,
        created: nowSec,
        components: ["@method", "@authority", "@path", "x-tenant-id", "x-forwarded-scope"],
        includeContentDigestHeader: false,
      });
      const tamperRes = await sendWire(gwPort, "POST", "/v1/tenants/acme/items", noDigestCov, tamperedBody);
      assertCond(tamperRes.statusCode >= 400 && tamperRes.statusCode < 500, `POST omitting content-digest coverage returned ${tamperRes.statusCode}`);

      // B1b: Missing @authority or x-tenant-id in covered components
      const missingAuthCov = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-member",
        alg: "ed25519",
        privateKeyPem: acmeMember.privateKeyPem,
        created: nowSec,
        components: ["@method", "@path"],
      });
      const noAuthRes = await sendWire(gwPort, "GET", "/v1/tenants/acme/items", missingAuthCov);
      assertCond(noAuthRes.statusCode === 401, `Signature omitting @authority and x-tenant-id returned ${noAuthRes.statusCode}`);

      // B1c: Missing @query when query string is present
      const missingQueryCov = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/items",
        rawQuery: "limit=1",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-member",
        alg: "ed25519",
        privateKeyPem: acmeMember.privateKeyPem,
        created: nowSec,
        components: ["@method", "@authority", "@path", "x-tenant-id", "x-forwarded-scope"],
      });
      const noQueryRes = await sendWire(gwPort, "GET", "/v1/tenants/acme/items?limit=9999", missingQueryCov);
      assertCond(noQueryRes.statusCode === 401, `Signature omitting @query on query target returned ${noQueryRes.statusCode}`);

      // B1d: Appending unsigned X-Role: admin header when x-role was absent at signing time
      const unsignedRoleHeaders = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/admin/config",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "admin:read"],
        ],
        keyId: "k-admin",
        alg: "ed25519",
        privateKeyPem: acmeAdmin.privateKeyPem,
        created: nowSec,
      });
      unsignedRoleHeaders.push(["X-Role", "admin"]);
      const unsignedRoleRes = await sendWire(gwPort, "GET", "/v1/tenants/acme/admin/config", unsignedRoleHeaders);
      assertCond(unsignedRoleRes.statusCode >= 400 && unsignedRoleRes.statusCode < 500, `Unsigned X-Role header accepted: ${unsignedRoleRes.statusCode}`);

      // B2: Duplicate header canonicalization differential (first value signed, second value smuggled)
      const dupRoleHeaders = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/admin/config",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
          ["X-Role", "viewer"],
        ],
        keyId: "k-member",
        alg: "ed25519",
        privateKeyPem: acmeMember.privateKeyPem,
        created: nowSec,
      });
      dupRoleHeaders.push(["X-Role", "admin"], ["X-Forwarded-Scope", "tenant:admin"]);
      const dupRes = await sendWire(gwPort, "GET", "/v1/tenants/acme/admin/config", dupRoleHeaders);
      assertCond(dupRes.statusCode >= 400 && dupRes.statusCode < 500, `Duplicate X-Role/X-Forwarded-Scope differential accepted: ${dupRes.statusCode}`);
      assertCond(hits.filter((h) => h.url.includes("/admin/")).length === adminHitsBefore, "Upstream received smuggled admin request");

      return "Covered-component completeness, Content-Digest, and duplicate header canonicalization enforced";
    });

    // 4. Defect C: Multi-Tenant Key-Ring Cache Isolation, Revocation & Replay Nonce Window
    await runGroup("keyring_and_replay", async () => {
      // C1: Warm LRU cache with globex's k-primary
      const globexWarm = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/globex/items",
        headerPairs: [
          ["X-Tenant-Id", "globex"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-primary",
        alg: "ed25519",
        privateKeyPem: globexShared.privateKeyPem,
        created: nowSec,
      });
      assertCond((await sendWire(gwPort, "GET", "/v1/tenants/globex/items", globexWarm)).statusCode === 200, "Globex warm request failed");

      // Attempt cross-tenant authentication against acme using globex's private key under colliding keyId="k-primary"
      const crossKeyHeaders = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-primary",
        alg: "ed25519",
        privateKeyPem: globexShared.privateKeyPem,
        created: nowSec,
      });
      const crossKeyRes = await sendWire(gwPort, "GET", "/v1/tenants/acme/items", crossKeyHeaders);
      assertCond(crossKeyRes.statusCode === 401, `Cross-tenant keyid cache collision accepted with status ${crossKeyRes.statusCode}`);

      // Confirm acme's own k-primary still works
      const acmeOwn = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-primary",
        alg: "ed25519",
        privateKeyPem: acmeShared.privateKeyPem,
        created: nowSec,
      });
      assertCond((await sendWire(gwPort, "GET", "/v1/tenants/acme/items", acmeOwn)).statusCode === 200, "Acme genuine k-primary failed");

      // C2: Revocation evicts warm cached key immediately
      const ephWarm = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-ephemeral",
        alg: "ed25519",
        privateKeyPem: acmeEphemeral.privateKeyPem,
        created: nowSec,
      });
      assertCond((await sendWire(gwPort, "GET", "/v1/tenants/acme/items", ephWarm)).statusCode === 200, "Ephemeral key initial request failed");
      keyRing.revokeKey("acme", "k-ephemeral");
      const ephAfterRevoke = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-ephemeral",
        alg: "ed25519",
        privateKeyPem: acmeEphemeral.privateKeyPem,
        created: nowSec,
      });
      assertCond((await sendWire(gwPort, "GET", "/v1/tenants/acme/items", ephAfterRevoke)).statusCode === 401, "Revoked cached key was still accepted");

      // C3: Replay nonce window enforcement
      const replayBody = JSON.stringify({ op: "transfer", units: 5 });
      const replayHeaders = signWireHeaders({
        method: "POST",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:write"],
          ["Content-Type", "application/json"],
        ],
        body: replayBody,
        keyId: "k-primary",
        alg: "ed25519",
        privateKeyPem: acmeShared.privateKeyPem,
        created: nowSec,
        nonce: "replay-check-nonce-9001",
      });
      const firstSend = await sendWire(gwPort, "POST", "/v1/tenants/acme/items", replayHeaders, replayBody);
      assertCond(firstSend.statusCode === 201, `Initial nonced POST failed: ${firstSend.statusCode}`);
      nowSec += 2;
      const secondSend = await sendWire(gwPort, "POST", "/v1/tenants/acme/items", replayHeaders, replayBody);
      assertCond(secondSend.statusCode === 401, `Replayed nonced POST within window returned ${secondSend.statusCode}`);

      // Stale created timestamp without expires & missing nonce check
      const staleHeaders = signWireHeaders({
        method: "GET",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:read"],
        ],
        keyId: "k-primary",
        alg: "ed25519",
        privateKeyPem: acmeShared.privateKeyPem,
        created: nowSec - 7200,
      });
      assertCond((await sendWire(gwPort, "GET", "/v1/tenants/acme/items", staleHeaders)).statusCode === 401, "Stale signature created 2h ago was accepted");

      const noNonceHeaders = signWireHeaders({
        method: "POST",
        authority,
        sigPath: "/v1/tenants/acme/items",
        headerPairs: [
          ["X-Tenant-Id", "acme"],
          ["X-Forwarded-Scope", "items:write"],
          ["Content-Type", "application/json"],
        ],
        body: replayBody,
        keyId: "k-primary",
        alg: "ed25519",
        privateKeyPem: acmeShared.privateKeyPem,
        created: nowSec,
        nonce: null,
      });
      assertCond((await sendWire(gwPort, "POST", "/v1/tenants/acme/items", noNonceHeaders, replayBody)).statusCode === 401, "POST without nonce was accepted");

      return "Per-tenant key cache isolation, revocation eviction, nonce replay window, and age bounds verified";
    });

    return { allPassed, groups: out };
  } finally {
    await gateway.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  }
}

runSuite()
  .then(({ allPassed, groups }) => {
    process.stdout.write(JSON.stringify({ ok: allPassed, groups }) + "\n");
    process.exit(allPassed ? 0 : 1);
  })
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stdout.write(JSON.stringify({ ok: false, error: message }) + "\n");
    process.exit(1);
  });
"""


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    if not isinstance(data, dict):
        return False, "report.json root must be a JSON object"

    raw_entries: list[str] = []
    raw_files = data.get("files")
    if isinstance(raw_files, str):
        raw_entries.append(raw_files)
    elif isinstance(raw_files, list):
        raw_entries.extend(str(item) for item in raw_files)

    names = {
        Path(tok).name
        for entry in raw_entries
        for tok in re.findall(r"[\w./-]+\.ts", entry)
    }
    if "http_sig.ts" not in names or "key_ring.ts" not in names:
        return False, f"Expected report.json files to include http_sig.ts and key_ring.ts, got {sorted(names)}"
    if not (names & {"path_norm.ts", "upstream_forwarder.ts", "policy.ts"}):
        return False, f"Expected report.json files to cover path/forwarding policy module, got {sorted(names)}"

    findings = data.get("findings")
    if not isinstance(findings, list) or len(findings) < 3:
        return False, "Expected at least 3 documented findings in report.json"
    for item in findings:
        text = str(item).strip()
        if len(text) < 20 or "placeholder" in text.lower():
            return False, f"Finding entry is too brief or invalid: {text!r}"

    summary = data.get("summary")
    if not isinstance(summary, str) or len(summary.strip()) < 15 or "placeholder" in summary.lower():
        return False, "Expected a concise non-empty 'summary' string in report.json"

    return True, "Technical review report validated"


def check_regression_suite(app_dir: Path, orig_app: Path) -> tuple[bool, str]:
    suite_file = app_dir / "test" / "gateway.test.ts"
    if not suite_file.is_file():
        return False, "Missing /app/test/gateway.test.ts"

    try:
        pass_run = subprocess.run(
            ["node", "--experimental-strip-types", "--test", str(suite_file)],
            cwd=str(app_dir),
            capture_output=True,
            text=True,
            timeout=45,
        )
    except subprocess.TimeoutExpired:
        return False, "gateway.test.ts timed out after 45s against updated /app"
    if pass_run.returncode != 0:
        return False, f"gateway.test.ts failed against updated /app:\n{pass_run.stdout}\n{pass_run.stderr}"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        shutil.copy2(orig_app / "package.json", tmp / "package.json")
        shutil.copytree(orig_app / "src", tmp / "src")
        (tmp / "test").mkdir(parents=True, exist_ok=True)
        shutil.copy2(suite_file, tmp / "test" / "gateway.test.ts")

        try:
            fail_run = subprocess.run(
                ["node", "--experimental-strip-types", "--test", str(tmp / "test" / "gateway.test.ts")],
                cwd=str(tmp),
                capture_output=True,
                text=True,
                timeout=45,
            )
        except subprocess.TimeoutExpired:
            return True, "Regression suite passes on hardened code and fails (timed out after assertion failure) on original unmodified code"
        if fail_run.returncode == 0:
            return False, "Updated gateway.test.ts unexpectedly passed against original unpatched src/"

    return True, "Regression suite passes on hardened code and fails on original unmodified code"


def check_live_gateway(app_dir: Path) -> tuple[bool, dict[str, object]]:
    src_dir = app_dir / "src"
    pkg_file = app_dir / "package.json"
    if not src_dir.is_dir() or not pkg_file.is_file():
        return False, {"error": "Missing /app/src or /app/package.json"}

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        shutil.copy2(pkg_file, tmp / "package.json")
        shutil.copytree(src_dir, tmp / "src")
        harness_path = tmp / "verify_harness.ts"
        harness_path.write_text(HARNESS_TS, encoding="utf-8")

        try:
            proc = subprocess.run(
                ["node", "--experimental-strip-types", str(harness_path)],
                cwd=str(tmp),
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return False, {"error": "verify_harness.ts timed out after 60s"}
        stdout_lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        payload: dict[str, object] = {}
        if stdout_lines:
            try:
                payload = json.loads(stdout_lines[-1])
            except Exception:
                payload = {"raw_stdout": proc.stdout, "raw_stderr": proc.stderr}
        else:
            payload = {"raw_stdout": proc.stdout, "raw_stderr": proc.stderr}

        if proc.returncode != 0 or not payload.get("ok"):
            return False, payload
        return True, payload


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    ok_suite, msg_suite = check_regression_suite(app_dir, tests_dir / "orig_app")
    results["regression_suite"] = {"passed": ok_suite, "message": msg_suite}
    if not ok_suite:
        return False, results

    ok_live, live_details = check_live_gateway(app_dir)
    results["live_gateway"] = live_details
    if not ok_live:
        return False, results

    return True, results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    tests_dir = Path(__file__).resolve().parent
    reward_dir = Path(args.reward_dir)
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir, tests_dir)
    (reward_dir / "details.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "details": details}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
