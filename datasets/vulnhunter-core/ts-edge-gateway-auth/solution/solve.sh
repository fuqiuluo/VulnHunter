#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# 1. Write technical review report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "src/path_norm.ts",
    "src/upstream_forwarder.ts",
    "src/http_sig.ts",
    "src/policy.ts",
    "src/key_ring.ts"
  ],
  "findings": [
    "Path normalization differential between policy evaluation and upstream forwarding: normalizeRoutePath in src/path_norm.ts leaves percent-encoded unreserved dot characters (%2e), backslashes (%5c), matrix parameters (;v=1), and encoded dot-slash segments (%2e%2e%2f) unresolved during route ACL matching, whereas buildUpstreamPath in src/upstream_forwarder.ts strips matrix parameters, converts backslashes, percent-decodes segments, and resolves dot-segments before forwarding to the upstream origin.",
    "Incomplete HTTP Message Signature coverage and duplicate header canonicalization mismatch: HttpSignatureVerifier.verify in src/http_sig.ts only requires @method and @path coverage (omitting @authority, @query when query parameters exist, x-tenant-id, present authorization headers, and mandatory content-digest coverage on requests with bodies), and canonicalizes repeated headers using only the first header value while PolicyEngine and UpstreamForwarder use the last header value.",
    "Multi-tenant verification key cache collision and inverted replay nonce window check: TenantKeyRing.resolveVerificationKey in src/key_ring.ts indexes the in-memory LRU cache solely by keyId without tenantId scoping (and mismatches the tenantId:keyId eviction key used by registerKey/rotateKey/revokeKey), while consumeNonce rejects nonces only when elapsed time exceeds nonceWindowSec instead of rejecting duplicate nonces within the active replay window."
  ],
  "summary": "Unified request target canonicalization across route policy, signature verification, and upstream forwarding while preserving encoded slug slashes and query parameters; enforced RFC 9421 header value joining, mandatory covered components, Content-Digest verification, timestamp age bounds, and single-valued tenant/role headers; scoped TenantKeyRing cache keys by tenantId and fixed replay window nonce rejection."
}
EOF

# 2. Harden src/path_norm.ts
cat > "$APP_DIR/src/path_norm.ts" <<'EOF'
export class PathNormalizationError extends Error {
  readonly code: string;

  constructor(message: string, code = "INVALID_REQUEST_TARGET") {
    super(message);
    this.name = "PathNormalizationError";
    this.code = code;
  }
}

export interface NormalizedTarget {
  readonly rawTarget: string;
  readonly canonicalPath: string;
  readonly rawQuery: string;
  readonly hasQuery: boolean;
  readonly search: string;
  readonly segments: ReadonlyArray<string>;
}

export interface SplitTargetParts {
  readonly rawPath: string;
  readonly rawQuery: string;
  readonly hasQuery: boolean;
}

function hasControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function isHexChar(code: number): boolean {
  return (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x46) || (code >= 0x61 && code <= 0x66);
}

function isUnreservedAsciiByte(byteVal: number): boolean {
  return (
    (byteVal >= 0x41 && byteVal <= 0x5a) ||
    (byteVal >= 0x61 && byteVal <= 0x7a) ||
    (byteVal >= 0x30 && byteVal <= 0x39) ||
    byteVal === 0x2d ||
    byteVal === 0x2e ||
    byteVal === 0x5f ||
    byteVal === 0x7e
  );
}

export function validatePercentEncoding(input: string): void {
  for (let i = 0; i < input.length; i += 1) {
    if (input.charCodeAt(i) !== 0x25) continue;
    if (i + 2 >= input.length || !isHexChar(input.charCodeAt(i + 1)) || !isHexChar(input.charCodeAt(i + 2))) {
      throw new PathNormalizationError("Invalid percent-encoding triplet in path");
    }
    const byteVal = Number.parseInt(input.slice(i + 1, i + 3), 16);
    if (byteVal <= 0x1f || byteVal === 0x7f) {
      throw new PathNormalizationError("Encoded control byte is not permitted in path");
    }
    if (byteVal === 0x5c) {
      throw new PathNormalizationError("Encoded backslash separator is not permitted in path", "INVALID_PATH_SEPARATOR");
    }
    i += 2;
  }
}

export function uppercasePercentTriplets(segment: string): string {
  if (!segment.includes("%")) return segment;
  let out = "";
  for (let i = 0; i < segment.length; i += 1) {
    if (segment.charCodeAt(i) === 0x25 && i + 2 < segment.length) {
      const hex = segment.slice(i + 1, i + 3).toUpperCase();
      const byteVal = Number.parseInt(hex, 16);
      if (isUnreservedAsciiByte(byteVal)) {
        out += String.fromCharCode(byteVal);
      } else {
        out += `%${hex}`;
      }
      i += 2;
    } else {
      out += segment[i];
    }
  }
  return out;
}

export function splitTarget(rawTarget: string): SplitTargetParts {
  if (!rawTarget || typeof rawTarget !== "string") {
    throw new PathNormalizationError("Request target must be a non-empty string");
  }
  if (hasControlChars(rawTarget) || rawTarget.includes("#")) {
    throw new PathNormalizationError("Request target contains disallowed characters");
  }
  if (!rawTarget.startsWith("/")) {
    throw new PathNormalizationError("Origin-form request target must begin with '/'");
  }
  const qIdx = rawTarget.indexOf("?");
  if (qIdx === -1) {
    return { rawPath: rawTarget, rawQuery: "", hasQuery: false };
  }
  return { rawPath: rawTarget.slice(0, qIdx), rawQuery: rawTarget.slice(qIdx + 1), hasQuery: true };
}

export function decodeSlugParam(encodedSegment: string): string {
  validatePercentEncoding(encodedSegment);
  let decoded: string;
  try {
    decoded = decodeURIComponent(encodedSegment);
  } catch {
    throw new PathNormalizationError("Malformed UTF-8 sequence in route parameter");
  }
  if (decoded.length === 0 || hasControlChars(decoded)) {
    throw new PathNormalizationError("Decoded route parameter is empty or invalid");
  }
  return decoded;
}

export function normalizeRoutePath(rawTarget: string): NormalizedTarget {
  const { rawPath, rawQuery, hasQuery } = splitTarget(rawTarget);
  if (rawPath.includes("\\")) {
    throw new PathNormalizationError("Backslash separator is not permitted in path", "INVALID_PATH_SEPARATOR");
  }
  if (rawPath.includes(";")) {
    throw new PathNormalizationError("Path matrix parameters are not permitted", "MATRIX_PARAM_FORBIDDEN");
  }
  validatePercentEncoding(rawPath);

  const normalizedRawPath = uppercasePercentTriplets(rawPath);
  const stack: string[] = [];

  for (const part of normalizedRawPath.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (stack.length === 0) {
        throw new PathNormalizationError("Path resolution cannot traverse above root", "PATH_TRAVERSAL");
      }
      stack.pop();
      continue;
    }

    if (part.includes("%2F")) {
      const subSegments = part.split("%2F");
      for (const sub of subSegments) {
        if (sub === "" || sub === "." || sub === "..") {
          throw new PathNormalizationError("Ambiguous encoded slash dot-segment in path", "PATH_TRAVERSAL");
        }
      }
    }

    stack.push(part);
  }

  const canonicalPath = stack.length === 0 ? "/" : "/" + stack.join("/");
  return {
    rawTarget,
    canonicalPath,
    rawQuery,
    hasQuery,
    search: hasQuery ? `?${rawQuery}` : "",
    segments: stack,
  };
}

export function joinCanonicalTarget(target: NormalizedTarget): string {
  return `${target.canonicalPath}${target.search}`;
}
EOF

# 3. Harden src/upstream_forwarder.ts
cat > "$APP_DIR/src/upstream_forwarder.ts" <<'EOF'
import http from "node:http";
import { Buffer } from "node:buffer";
import { joinCanonicalTarget, normalizeRoutePath, type NormalizedTarget } from "./path_norm.ts";
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
  return joinCanonicalTarget(normalizeRoutePath(rawTarget));
}

function canonicalizeHeaderValues(values: ReadonlyArray<string>): string {
  return values.map((v) => v.trim().replace(/\s+/g, " ")).join(", ");
}

function buildOutboundHeaders(input: ForwardRequestInput): Record<string, string> {
  const outbound: Record<string, string> = {};
  for (const [lowerName, values] of Object.entries(input.headersDistinct)) {
    if (!values || values.length === 0) continue;
    if (HOP_BY_HOP_HEADERS.has(lowerName) || lowerName.startsWith("x-gateway-")) continue;
    outbound[lowerName] = canonicalizeHeaderValues(values);
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
    const upstreamPath = joinCanonicalTarget(input.normalizedTarget);
    const headers = buildOutboundHeaders(input);

    return new Promise<UpstreamResponse>((resolve, reject) => {
      const req = http.request(
        {
          host: this.config.host,
          port: this.config.port,
          method: input.method.toUpperCase(),
          path: upstreamPath,
          headers,
          agent: this.agent,
          timeout: this.timeoutMs,
        },
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
EOF

# 4. Harden src/http_sig.ts
cat > "$APP_DIR/src/http_sig.ts" <<'EOF'
import crypto from "node:crypto";
import { Buffer } from "node:buffer";
import { normalizeRoutePath, type NormalizedTarget } from "./path_norm.ts";
import { KeyRingError, TenantKeyRing, type ResolvedVerificationKey, type SignatureAlgorithm } from "./key_ring.ts";

export class SignatureVerificationError extends Error {
  readonly code: string;
  constructor(message: string, code = "SIGNATURE_INVALID") {
    super(message);
    this.name = "SignatureVerificationError";
    this.code = code;
  }
}

export interface SignatureParams {
  readonly label: string;
  readonly components: ReadonlyArray<string>;
  readonly keyId: string;
  readonly alg?: SignatureAlgorithm;
  readonly created: number;
  readonly expires?: number;
  readonly nonce?: string;
  readonly rawParamsValue: string;
}

export interface SignatureVerifierOptions {
  readonly maxClockSkewSec?: number;
  readonly maxSignatureAgeSec?: number;
  readonly requireNonce?: boolean;
  readonly protectedHeaders?: ReadonlyArray<string>;
}

export interface VerifySignatureInput {
  readonly method: string;
  readonly authority: string;
  readonly normalizedTarget: NormalizedTarget;
  readonly headersDistinct: Readonly<Record<string, string[] | undefined>>;
  readonly body: Buffer;
  readonly tenantId: string;
  readonly nowSec?: number;
}

export interface VerifiedSignatureContext {
  readonly label: string;
  readonly key: ResolvedVerificationKey;
  readonly params: SignatureParams;
  readonly coveredComponents: ReadonlySet<string>;
}

export interface SignRequestInput {
  readonly method: string;
  readonly authority: string;
  readonly target: string;
  readonly headers?: Readonly<Record<string, string | ReadonlyArray<string>>> | ReadonlyArray<readonly [string, string]>;
  readonly body?: Buffer | string;
  readonly keyId: string;
  readonly algorithm: SignatureAlgorithm;
  readonly privateKeyPem?: string;
  readonly secretBase64?: string;
  readonly created?: number;
  readonly expires?: number;
  readonly nonce?: string;
  readonly label?: string;
  readonly components?: ReadonlyArray<string>;
}

export interface SignedRequestArtifacts {
  readonly headers: Record<string, string>;
  readonly rawHeaderPairs: Array<[string, string]>;
  readonly signatureInput: string;
  readonly signature: string;
  readonly contentDigest?: string;
  readonly signatureBase: string;
}

const DEFAULT_PROTECTED_HEADERS = ["x-tenant-id", "x-forwarded-scope", "x-role"];

export function computeContentDigest(body: Buffer | string): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return `sha-256=:${crypto.createHash("sha256").update(buf).digest("base64")}:`;
}

export function verifyContentDigestHeader(body: Buffer, digestHeader: string): boolean {
  const match = /^sha-256=:([A-Za-z0-9+/=]+):$/i.exec(digestHeader.trim());
  if (!match) return false;
  const provided = Buffer.from(match[1], "base64");
  const expected = crypto.createHash("sha256").update(body).digest();
  return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}

function unquoteParam(raw: string | undefined, errMsg: string, errCode: string): string {
  if (!raw || raw.length < 2 || !raw.startsWith('"') || !raw.endsWith('"')) {
    throw new SignatureVerificationError(errMsg, errCode);
  }
  return raw.slice(1, -1);
}

export function parseSignatureInputHeader(headerValue: string): SignatureParams {
  const trimmed = headerValue.trim();
  const eqIdx = trimmed.indexOf("=");
  if (eqIdx <= 0) throw new SignatureVerificationError("Malformed Signature-Input field", "MALFORMED_SIGNATURE_INPUT");
  const label = trimmed.slice(0, eqIdx).trim();
  if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,31}$/.test(label)) {
    throw new SignatureVerificationError("Invalid signature label", "MALFORMED_SIGNATURE_INPUT");
  }
  const rawParamsValue = trimmed.slice(eqIdx + 1).trim();
  const closeParen = rawParamsValue.indexOf(")");
  if (!rawParamsValue.startsWith("(") || closeParen < 0) {
    throw new SignatureVerificationError("Signature-Input missing component list", "MALFORMED_SIGNATURE_INPUT");
  }

  const inner = rawParamsValue.slice(1, closeParen).trim();
  const components: string[] = [];
  if (inner.length > 0) {
    const tokens = inner.match(/"([^"]+)"/g);
    if (!tokens || tokens.join(" ") !== inner.replace(/\s+/g, " ")) {
      throw new SignatureVerificationError("Invalid component tokens in Signature-Input", "MALFORMED_SIGNATURE_INPUT");
    }
    for (const tok of tokens) components.push(tok.slice(1, -1).toLowerCase());
  }

  const tail = rawParamsValue.slice(closeParen + 1);
  const paramMap = new Map<string, string>();
  if (tail.length > 0) {
    if (!tail.startsWith(";")) throw new SignatureVerificationError("Invalid parameter delimiter", "MALFORMED_SIGNATURE_INPUT");
    for (const rawPart of tail.slice(1).split(";")) {
      const p = rawPart.trim();
      const pEq = p.indexOf("=");
      if (!p || pEq <= 0) throw new SignatureVerificationError("Malformed signature parameter", "MALFORMED_SIGNATURE_INPUT");
      const paramKey = p.slice(0, pEq).trim().toLowerCase();
      if (paramMap.has(paramKey)) {
        throw new SignatureVerificationError(`Duplicate signature parameter: ${paramKey}`, "MALFORMED_SIGNATURE_INPUT");
      }
      paramMap.set(paramKey, p.slice(pEq + 1).trim());
    }
  }

  const keyId = unquoteParam(paramMap.get("keyid"), "Missing quoted keyid", "MISSING_KEYID");
  const rawCreated = paramMap.get("created");
  if (!rawCreated || !/^\d+$/.test(rawCreated)) throw new SignatureVerificationError("Missing created timestamp", "MISSING_CREATED");

  let expires: number | undefined;
  if (paramMap.has("expires")) {
    const rawExp = paramMap.get("expires")!;
    if (!/^\d+$/.test(rawExp)) throw new SignatureVerificationError("Invalid expires timestamp", "INVALID_EXPIRES");
    expires = Number.parseInt(rawExp, 10);
  }
  const nonce = paramMap.has("nonce") ? unquoteParam(paramMap.get("nonce"), "Nonce must be quoted", "INVALID_NONCE") : undefined;

  let alg: SignatureAlgorithm | undefined;
  if (paramMap.has("alg")) {
    const cleanAlg = unquoteParam(paramMap.get("alg"), "Alg must be quoted", "INVALID_ALG").toLowerCase();
    if (cleanAlg !== "ed25519" && cleanAlg !== "hmac-sha256") {
      throw new SignatureVerificationError(`Unsupported signature algorithm: ${cleanAlg}`, "UNSUPPORTED_ALG");
    }
    alg = cleanAlg;
  }
  return { label, components, keyId, alg, created: Number.parseInt(rawCreated, 10), expires, nonce, rawParamsValue };
}

export function parseSignatureHeader(headerValue: string, expectedLabel: string): Buffer {
  const trimmed = headerValue.trim();
  const prefix = `${expectedLabel}=`;
  if (!trimmed.startsWith(prefix)) throw new SignatureVerificationError("Signature label mismatch", "SIGNATURE_LABEL_MISMATCH");
  const match = /^:([A-Za-z0-9+/=]+):$/.exec(trimmed.slice(prefix.length).trim());
  if (!match) throw new SignatureVerificationError("Malformed byte-sequence in Signature field", "MALFORMED_SIGNATURE");
  return Buffer.from(match[1], "base64");
}

function resolveDerivedComponent(comp: string, method: string, authority: string, target: NormalizedTarget): string {
  if (comp === "@method") return method.toUpperCase();
  if (comp === "@authority") return authority.trim().toLowerCase();
  if (comp === "@path") return target.canonicalPath;
  if (comp === "@query") return `?${target.rawQuery}`;
  if (comp === "@target-uri") return `http://${authority.trim().toLowerCase()}${target.canonicalPath}${target.search}`;
  throw new SignatureVerificationError(`Unsupported derived component: ${comp}`, "UNSUPPORTED_COMPONENT");
}

function extractMessageHeader(headersDistinct: Readonly<Record<string, string[] | undefined>>, lowerName: string): string | undefined {
  const values = headersDistinct[lowerName];
  if (!values || values.length === 0) return undefined;
  return values.map((v) => v.trim().replace(/\s+/g, " ")).join(", ");
}

function extractSingletonHeader(headersDistinct: Readonly<Record<string, string[] | undefined>>, lowerName: string): string | undefined {
  const values = headersDistinct[lowerName];
  if (!values || values.length === 0) return undefined;
  if (values.length !== 1) {
    throw new SignatureVerificationError(`Multiple '${lowerName}' headers are not permitted`, "DUPLICATE_SIGNATURE_HEADER");
  }
  return values[0].trim();
}

function buildSignatureBase(
  components: ReadonlyArray<string>,
  rawParamsValue: string,
  method: string,
  authority: string,
  target: NormalizedTarget,
  headerResolver: (lowerName: string) => string | undefined,
): string {
  const lines = components.map((comp) => {
    if (comp.startsWith("@")) return `"${comp}": ${resolveDerivedComponent(comp, method, authority, target)}`;
    const headerVal = headerResolver(comp);
    if (headerVal === undefined) throw new SignatureVerificationError(`Missing covered HTTP header '${comp}'`, "MISSING_COVERED_HEADER");
    return `"${comp}": ${headerVal}`;
  });
  lines.push(`"@signature-params": ${rawParamsValue}`);
  return lines.join("\n");
}

function verifyCryptographicSignature(key: ResolvedVerificationKey, base: string, sigBytes: Buffer): boolean {
  const payload = Buffer.from(base, "utf8");
  if (key.algorithm === "ed25519") return Boolean(key.publicKey && crypto.verify(null, payload, key.publicKey, sigBytes));
  if (!key.hmacSecret) return false;
  const mac = crypto.createHmac("sha256", key.hmacSecret).update(payload).digest();
  return mac.length === sigBytes.length && crypto.timingSafeEqual(mac, sigBytes);
}

export class HttpSignatureVerifier {
  private readonly keyRing: TenantKeyRing;
  private readonly config: Required<SignatureVerifierOptions>;

  constructor(keyRing: TenantKeyRing, options: SignatureVerifierOptions = {}) {
    this.keyRing = keyRing;
    this.config = {
      maxClockSkewSec: options.maxClockSkewSec ?? 60,
      maxSignatureAgeSec: options.maxSignatureAgeSec ?? 300,
      requireNonce: options.requireNonce ?? true,
      protectedHeaders: (options.protectedHeaders ?? DEFAULT_PROTECTED_HEADERS).map((h) => h.toLowerCase()),
    };
  }

  getVerifierPolicy(): Readonly<Required<SignatureVerifierOptions>> {
    return this.config;
  }

  verify(input: VerifySignatureInput): VerifiedSignatureContext {
    const nowSec = input.nowSec ?? Math.floor(Date.now() / 1000);
    const sigInputHeader = extractSingletonHeader(input.headersDistinct, "signature-input");
    const sigHeader = extractSingletonHeader(input.headersDistinct, "signature");
    if (!sigInputHeader || !sigHeader) throw new SignatureVerificationError("Missing signature headers", "MISSING_SIGNATURE");

    const params = parseSignatureInputHeader(sigInputHeader);
    const sigBytes = parseSignatureHeader(sigHeader, params.label);

    if (params.created > nowSec + this.config.maxClockSkewSec) {
      throw new SignatureVerificationError("Signature created timestamp is in the future", "SIGNATURE_FUTURE");
    }
    if (nowSec - params.created > this.config.maxSignatureAgeSec) {
      throw new SignatureVerificationError("Signature created timestamp exceeds maximum age", "SIGNATURE_STALE");
    }
    if (params.expires !== undefined && (nowSec > params.expires || params.expires < params.created)) {
      throw new SignatureVerificationError("Signature has expired", "SIGNATURE_EXPIRED");
    }

    const coveredSet = new Set(params.components);
    if (coveredSet.size !== params.components.length) {
      throw new SignatureVerificationError("Duplicate component identifiers in Signature-Input", "DUPLICATE_COMPONENT");
    }

    if (!coveredSet.has("@method") || !coveredSet.has("@authority") || !coveredSet.has("@path")) {
      throw new SignatureVerificationError("Signature must cover @method, @authority, and @path", "INCOMPLETE_COVERAGE");
    }
    if (input.normalizedTarget.hasQuery && !coveredSet.has("@query")) {
      throw new SignatureVerificationError("Signature must cover @query when query parameters are present", "INCOMPLETE_COVERAGE");
    }
    if (!coveredSet.has("x-tenant-id") || !input.headersDistinct["x-tenant-id"]?.length) {
      throw new SignatureVerificationError("Signature must cover x-tenant-id header", "INCOMPLETE_COVERAGE");
    }

    for (const protectedHeader of this.config.protectedHeaders) {
      if (input.headersDistinct[protectedHeader]?.length && !coveredSet.has(protectedHeader)) {
        throw new SignatureVerificationError(`Present header '${protectedHeader}' must be covered by signature`, "UNSIGNED_PROTECTED_HEADER");
      }
    }

    const hasContentDigestHeader = Boolean(input.headersDistinct["content-digest"]?.length);
    if (input.body.length > 0 || hasContentDigestHeader || coveredSet.has("content-digest")) {
      if (!coveredSet.has("content-digest")) {
        throw new SignatureVerificationError("Non-empty body and Content-Digest must be covered by signature", "INCOMPLETE_COVERAGE");
      }
      const digestHeader = extractSingletonHeader(input.headersDistinct, "content-digest");
      if (!digestHeader || !verifyContentDigestHeader(input.body, digestHeader)) {
        throw new SignatureVerificationError("Content-Digest verification failed", "DIGEST_MISMATCH");
      }
    }

    if (this.config.requireNonce && (!params.nonce || !params.nonce.trim())) {
      throw new SignatureVerificationError("Signature-Input must include a non-empty nonce", "MISSING_NONCE");
    }

    let resolvedKey: ResolvedVerificationKey;
    try {
      resolvedKey = this.keyRing.resolveVerificationKey(input.tenantId, params.keyId, nowSec);
    } catch (err) {
      if (err instanceof KeyRingError) throw new SignatureVerificationError(err.message, err.code);
      throw err;
    }
    if (params.alg && params.alg !== resolvedKey.algorithm) {
      throw new SignatureVerificationError("Signature algorithm mismatch", "ALG_MISMATCH");
    }

    const signatureBase = buildSignatureBase(params.components, params.rawParamsValue, input.method, input.authority, input.normalizedTarget, (h) =>
      extractMessageHeader(input.headersDistinct, h),
    );
    if (!verifyCryptographicSignature(resolvedKey, signatureBase, sigBytes)) {
      throw new SignatureVerificationError("Cryptographic signature verification failed", "BAD_SIGNATURE");
    }
    if (params.nonce && !this.keyRing.consumeNonce(input.tenantId, resolvedKey.keyId, params.nonce, nowSec)) {
      throw new SignatureVerificationError("Replayed signature nonce rejected", "NONCE_REPLAYED");
    }
    return { label: params.label, key: resolvedKey, params, coveredComponents: coveredSet };
  }
}

export function signRequest(input: SignRequestInput): SignedRequestArtifacts {
  const label = input.label ?? "sig1";
  const created = input.created ?? Math.floor(Date.now() / 1000);
  const nonce = input.nonce ?? crypto.randomBytes(12).toString("hex");
  const bodyBuf = input.body === undefined ? Buffer.alloc(0) : typeof input.body === "string" ? Buffer.from(input.body, "utf8") : input.body;

  const distinct: Record<string, string[]> = {};
  const rawPairs: Array<[string, string]> = [];
  if (Array.isArray(input.headers)) {
    for (const [k, v] of input.headers) {
      (distinct[k.toLowerCase()] ??= []).push(v);
      rawPairs.push([k, v]);
    }
  } else if (input.headers) {
    for (const [k, v] of Object.entries(input.headers as Readonly<Record<string, string | ReadonlyArray<string>>>)) {
      const bucket = (distinct[k.toLowerCase()] ??= []);
      for (const item of typeof v === "string" ? [v] : v) {
        bucket.push(item);
        rawPairs.push([k, item]);
      }
    }
  }

  let contentDigest: string | undefined;
  if (bodyBuf.length > 0 && !distinct["content-digest"]) {
    contentDigest = computeContentDigest(bodyBuf);
    distinct["content-digest"] = [contentDigest];
    rawPairs.push(["Content-Digest", contentDigest]);
  } else if (distinct["content-digest"]) {
    contentDigest = distinct["content-digest"][0];
  }

  const normalizedTarget = normalizeRoutePath(input.target);
  const components = input.components
    ? input.components.map((c) => c.toLowerCase())
    : ["@method", "@authority", "@path", ...(normalizedTarget.hasQuery ? ["@query"] : []), ...DEFAULT_PROTECTED_HEADERS.filter((h) => distinct[h]?.length), ...(distinct["content-digest"]?.length ? ["content-digest"] : [])];

  let rawParamsValue = `(${components.map((c) => `"${c}"`).join(" ")});created=${created}`;
  if (input.expires !== undefined) rawParamsValue += `;expires=${input.expires}`;
  rawParamsValue += `;keyid="${input.keyId}";alg="${input.algorithm}"${nonce.length > 0 ? `;nonce="${nonce}"` : ""}`;

  const signatureBase = buildSignatureBase(components, rawParamsValue, input.method, input.authority, normalizedTarget, (h) => distinct[h]?.map((v) => v.trim().replace(/\s+/g, " ")).join(", "));
  const payload = Buffer.from(signatureBase, "utf8");
  const sigBuf = input.algorithm === "ed25519" ? crypto.sign(null, payload, crypto.createPrivateKey(input.privateKeyPem ?? "")) : crypto.createHmac("sha256", Buffer.from(input.secretBase64 ?? "", "base64")).update(payload).digest();

  const signatureInput = `${label}=${rawParamsValue}`;
  const signature = `${label}=:${sigBuf.toString("base64")}:`;
  rawPairs.push(["Signature-Input", signatureInput], ["Signature", signature]);

  const joinedHeaders: Record<string, string> = {};
  for (const [k, vals] of Object.entries(distinct)) joinedHeaders[k] = vals.map((v) => v.trim().replace(/\s+/g, " ")).join(", ");
  joinedHeaders["signature-input"] = signatureInput;
  joinedHeaders["signature"] = signature;
  return { headers: joinedHeaders, rawHeaderPairs: rawPairs, signatureInput, signature, contentDigest, signatureBase };
}
EOF

# 5. Harden src/policy.ts
cat > "$APP_DIR/src/policy.ts" <<'EOF'
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

function extractValidatedRole(values: ReadonlyArray<string> | undefined): string | null {
  if (!values || values.length === 0) return "member";
  if (values.length !== 1) return null;
  const raw = values[0].trim().toLowerCase();
  if (!raw) return "member";
  if (!/^[a-z0-9_-]+$/.test(raw)) return null;
  return raw;
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
    if (!tenantHeaderVals || tenantHeaderVals.length === 0) {
      return deny(401, "MISSING_TENANT_HEADER", "Signed tenant requests must include x-tenant-id header", { matchedRoute: matched, normalizedTarget });
    }
    if (tenantHeaderVals.length !== 1 || tenantHeaderVals[0].trim() !== routeTenantId) {
      return deny(403, "TENANT_HEADER_MISMATCH", "Header x-tenant-id does not match target tenant route", { matchedRoute: matched, normalizedTarget });
    }

    let verified;
    try {
      verified = this.verifier.verify({ method: ctx.method, authority: ctx.authority, normalizedTarget, headersDistinct: ctx.headersDistinct, body: ctx.body, tenantId: routeTenantId, nowSec: ctx.nowSec });
    } catch (err) {
      return deny(401, err instanceof SignatureVerificationError ? err.code : "SIGNATURE_INVALID", (err as Error).message, { matchedRoute: matched, normalizedTarget });
    }

    const effectiveRole = extractValidatedRole(ctx.headersDistinct["x-role"]);
    if (effectiveRole === null) {
      return deny(403, "AMBIGUOUS_ROLE_HEADER", "Multiple or malformed x-role header values are not permitted", {
        matchedRoute: matched,
        normalizedTarget,
        tenantId: routeTenantId,
        keyId: verified.key.keyId,
      });
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

    if (matched.requiredRole && effectiveRole !== matched.requiredRole) {
      return deny(403, "INSUFFICIENT_ROLE", `Endpoint requires role '${matched.requiredRole}'`, { matchedRoute: matched, normalizedTarget, tenantId: routeTenantId, keyId: verified.key.keyId });
    }
    if (matched.requiredScope && !grantedScopes.has("tenant:admin") && !grantedScopes.has(matched.requiredScope.toLowerCase())) {
      return deny(403, "INSUFFICIENT_SCOPE", `Endpoint requires scope '${matched.requiredScope}'`, { matchedRoute: matched, normalizedTarget, tenantId: routeTenantId, keyId: verified.key.keyId });
    }

    return { allowed: true, statusCode: 200, matchedRoute: matched, normalizedTarget, tenantId: routeTenantId, keyId: verified.key.keyId, grantedScopes: Array.from(grantedScopes).sort(), effectiveRole };
  }
}
EOF

# 6. Harden src/key_ring.ts
cat > "$APP_DIR/src/key_ring.ts" <<'EOF'
import crypto from "node:crypto";
import { Buffer } from "node:buffer";

export type SignatureAlgorithm = "ed25519" | "hmac-sha256";
export type KeyLifecycleState = "active" | "retiring" | "revoked";

export class KeyRingError extends Error {
  readonly code: string;
  constructor(message: string, code = "KEY_RING_ERROR") {
    super(message);
    this.name = "KeyRingError";
    this.code = code;
  }
}

export interface TenantKeyInput {
  readonly keyId: string;
  readonly algorithm: SignatureAlgorithm;
  readonly publicKeyPem?: string;
  readonly secretBase64?: string;
  readonly state?: KeyLifecycleState;
  readonly notBeforeSec?: number;
  readonly expiresAtSec?: number;
  readonly allowedScopes?: ReadonlyArray<string>;
}

export interface TenantKeyMetadata {
  readonly tenantId: string;
  readonly keyId: string;
  readonly algorithm: SignatureAlgorithm;
  readonly state: KeyLifecycleState;
  readonly notBeforeSec?: number;
  readonly expiresAtSec?: number;
  readonly allowedScopes?: ReadonlyArray<string>;
}

export interface ResolvedVerificationKey {
  readonly tenantId: string;
  readonly keyId: string;
  readonly algorithm: SignatureAlgorithm;
  readonly publicKey?: crypto.KeyObject;
  readonly hmacSecret?: Buffer;
  readonly state: KeyLifecycleState;
  readonly notBeforeSec?: number;
  readonly expiresAtSec?: number;
  readonly allowedScopes?: ReadonlySet<string>;
}

export interface KeyRingOptions {
  readonly cacheMaxEntries?: number;
  readonly cacheTtlSec?: number;
  readonly nonceWindowSec?: number;
  readonly maxTrackedNonces?: number;
}

interface StoredKeyRecord {
  tenantId: string;
  keyId: string;
  algorithm: SignatureAlgorithm;
  publicKeyPem?: string;
  secretBase64?: string;
  state: KeyLifecycleState;
  notBeforeSec?: number;
  expiresAtSec?: number;
  allowedScopes?: ReadonlySet<string>;
}

interface CachedVerificationEntry {
  readonly key: ResolvedVerificationKey;
  readonly cacheExpiresAtSec: number;
}

const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const KEY_ID_PATTERN = /^[a-zA-Z0-9._:-]{1,64}$/;

function validateIdentifiers(tenantId: string, keyId: string): void {
  if (!TENANT_ID_PATTERN.test(tenantId)) throw new KeyRingError(`Invalid tenant identifier: ${tenantId}`, "INVALID_TENANT_ID");
  if (!KEY_ID_PATTERN.test(keyId)) throw new KeyRingError(`Invalid key identifier: ${keyId}`, "INVALID_KEY_ID");
}

function buildTenantCacheKey(tenantId: string, keyId: string): string {
  return `${tenantId}\0${keyId}`;
}

function materializeKey(r: StoredKeyRecord): ResolvedVerificationKey {
  const base = { tenantId: r.tenantId, keyId: r.keyId, state: r.state, notBeforeSec: r.notBeforeSec, expiresAtSec: r.expiresAtSec, allowedScopes: r.allowedScopes };
  if (r.algorithm === "ed25519") {
    if (!r.publicKeyPem) throw new KeyRingError("Missing Ed25519 public key PEM", "INVALID_KEY_MATERIAL");
    const pubKey = crypto.createPublicKey(r.publicKeyPem);
    if (pubKey.asymmetricKeyType !== "ed25519") throw new KeyRingError("Public key must use Ed25519", "INVALID_KEY_MATERIAL");
    return { ...base, algorithm: "ed25519", publicKey: pubKey };
  }
  if (!recordHasSecret(r)) throw new KeyRingError("Missing HMAC-SHA256 shared secret", "INVALID_KEY_MATERIAL");
  const secretBuf = Buffer.from(r.secretBase64, "base64");
  if (secretBuf.length < 16) throw new KeyRingError("HMAC-SHA256 secret must be at least 16 bytes", "INVALID_KEY_MATERIAL");
  return { ...base, algorithm: "hmac-sha256", hmacSecret: secretBuf };
}

function recordHasSecret(r: StoredKeyRecord): r is StoredKeyRecord & { secretBase64: string } {
  return typeof r.secretBase64 === "string" && r.secretBase64.length > 0;
}

export class TenantKeyRing {
  private readonly registry = new Map<string, Map<string, StoredKeyRecord>>();
  private readonly resolvedCache = new Map<string, CachedVerificationEntry>();
  private readonly seenNonces = new Map<string, number>();
  private readonly cacheMaxEntries: number;
  private readonly cacheTtlSec: number;
  private readonly nonceWindowSec: number;
  private readonly maxTrackedNonces: number;

  constructor(options: KeyRingOptions = {}) {
    this.cacheMaxEntries = Math.max(8, options.cacheMaxEntries ?? 256);
    this.cacheTtlSec = Math.max(5, options.cacheTtlSec ?? 120);
    this.nonceWindowSec = Math.max(10, options.nonceWindowSec ?? 300);
    this.maxTrackedNonces = Math.max(64, options.maxTrackedNonces ?? 8192);
  }

  registerKey(tenantId: string, input: TenantKeyInput): void {
    const cleanKeyId = input.keyId.trim();
    validateIdentifiers(tenantId, cleanKeyId);
    const record: StoredKeyRecord = {
      tenantId,
      keyId: cleanKeyId,
      algorithm: input.algorithm,
      publicKeyPem: input.publicKeyPem,
      secretBase64: input.secretBase64,
      state: input.state ?? "active",
      notBeforeSec: input.notBeforeSec,
      expiresAtSec: input.expiresAtSec,
      allowedScopes: input.allowedScopes ? new Set(input.allowedScopes) : undefined,
    };
    materializeKey(record);
    let tenantMap = this.registry.get(tenantId);
    if (!tenantMap) {
      tenantMap = new Map<string, StoredKeyRecord>();
      this.registry.set(tenantId, tenantMap);
    }
    tenantMap.set(cleanKeyId, record);
    this.resolvedCache.delete(buildTenantCacheKey(tenantId, cleanKeyId));
  }

  rotateKey(tenantId: string, retiringKeyId: string, replacement: TenantKeyInput, gracePeriodSec = 120, nowSec = Math.floor(Date.now() / 1000)): void {
    const cleanOldId = retiringKeyId.trim();
    validateIdentifiers(tenantId, cleanOldId);
    const existing = this.registry.get(tenantId)?.get(cleanOldId);
    if (!existing) throw new KeyRingError(`Cannot rotate unknown key '${cleanOldId}'`, "KEY_NOT_FOUND");
    if (existing.state === "revoked") throw new KeyRingError(`Cannot rotate revoked key '${cleanOldId}'`, "KEY_REVOKED");
    this.registerKey(tenantId, { ...replacement, state: "active" });
    existing.state = "retiring";
    existing.expiresAtSec = nowSec + Math.max(1, gracePeriodSec);
    this.resolvedCache.delete(buildTenantCacheKey(tenantId, cleanOldId));
  }

  revokeKey(tenantId: string, keyId: string): boolean {
    const cleanKeyId = keyId.trim();
    const existing = this.registry.get(tenantId)?.get(cleanKeyId);
    if (!existing) return false;
    existing.state = "revoked";
    this.resolvedCache.delete(buildTenantCacheKey(tenantId, cleanKeyId));
    return true;
  }

  listTenantKeys(tenantId: string): TenantKeyMetadata[] {
    const tenantMap = this.registry.get(tenantId);
    if (!tenantMap) return [];
    return Array.from(tenantMap.values()).map((r) => ({
      tenantId: r.tenantId,
      keyId: r.keyId,
      algorithm: r.algorithm,
      state: r.state,
      notBeforeSec: r.notBeforeSec,
      expiresAtSec: r.expiresAtSec,
      allowedScopes: r.allowedScopes ? Array.from(r.allowedScopes) : undefined,
    }));
  }

  resolveVerificationKey(tenantId: string, keyId: string, nowSec = Math.floor(Date.now() / 1000)): ResolvedVerificationKey {
    const cleanKeyId = keyId.trim();
    validateIdentifiers(tenantId, cleanKeyId);
    const cacheKey = buildTenantCacheKey(tenantId, cleanKeyId);
    const cached = this.resolvedCache.get(cacheKey);
    if (cached) {
      const validWindow =
        cached.key.tenantId === tenantId &&
        cached.cacheExpiresAtSec > nowSec &&
        cached.key.state !== "revoked" &&
        (cached.key.notBeforeSec === undefined || cached.key.notBeforeSec <= nowSec) &&
        (cached.key.expiresAtSec === undefined || cached.key.expiresAtSec > nowSec);
      this.resolvedCache.delete(cacheKey);
      if (validWindow) {
        this.resolvedCache.set(cacheKey, cached);
        return cached.key;
      }
    }

    const record = this.registry.get(tenantId)?.get(cleanKeyId);
    if (!record) throw new KeyRingError(`Unknown verification key '${cleanKeyId}'`, "KEY_NOT_FOUND");
    if (record.state === "revoked") throw new KeyRingError(`Verification key '${cleanKeyId}' has been revoked`, "KEY_REVOKED");
    if (record.notBeforeSec !== undefined && nowSec < record.notBeforeSec) throw new KeyRingError("Key not yet active", "KEY_NOT_ACTIVE");
    if (record.expiresAtSec !== undefined && nowSec >= record.expiresAtSec) throw new KeyRingError("Key has expired", "KEY_EXPIRED");

    const resolved = materializeKey(record);
    if (this.resolvedCache.size >= this.cacheMaxEntries) {
      const oldestKey = this.resolvedCache.keys().next().value;
      if (oldestKey !== undefined) this.resolvedCache.delete(oldestKey);
    }
    this.resolvedCache.set(cacheKey, { key: resolved, cacheExpiresAtSec: nowSec + this.cacheTtlSec });
    return resolved;
  }

  consumeNonce(tenantId: string, keyId: string, nonce: string, nowSec = Math.floor(Date.now() / 1000)): boolean {
    const cleanNonce = nonce.trim();
    if (!cleanNonce || cleanNonce.length > 128) return false;
    for (const [key, ts] of this.seenNonces.entries()) {
      if (nowSec - ts > this.nonceWindowSec) this.seenNonces.delete(key);
      else break;
    }
    const composite = `${tenantId}\0${keyId}\0${cleanNonce}`;
    const recordedAt = this.seenNonces.get(composite);
    if (recordedAt !== undefined && nowSec - recordedAt <= this.nonceWindowSec) {
      return false;
    }
    if (this.seenNonces.size >= this.maxTrackedNonces) {
      const oldest = this.seenNonces.keys().next().value;
      if (oldest !== undefined) this.seenNonces.delete(oldest);
    }
    this.seenNonces.set(composite, nowSec);
    return true;
  }
}
EOF

# 7. Extend test/gateway.test.ts with comprehensive security & regression tests
cat > "$APP_DIR/test/gateway.test.ts" <<'EOF'
import http from "node:http";
import net from "node:net";
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

function sendRawWireRequest(port: number, method: string, rawTarget: string, headerLines: ReadonlyArray<readonly [string, string]>, body = ""): Promise<HttpResult> {
  return new Promise<HttpResult>((resolve, reject) => {
    const bodyBuf = Buffer.from(body, "utf8");
    const lines = [
      `${method} ${rawTarget} HTTP/1.1`,
      `Host: 127.0.0.1:${port}`,
      `Connection: close`,
      ...headerLines.map(([k, v]) => `${k}: ${v}`),
    ];
    if (bodyBuf.length > 0) lines.push(`Content-Length: ${bodyBuf.length}`);
    const headBuf = Buffer.from(lines.join("\r\n") + "\r\n\r\n", "utf8");

    const sock = net.createConnection({ host: "127.0.0.1", port }, () => {
      sock.write(headBuf);
      if (bodyBuf.length > 0) sock.write(bodyBuf);
    });
    const chunks: Buffer[] = [];
    sock.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    sock.on("error", reject);
    sock.on("end", () => {
      const full = Buffer.concat(chunks);
      const splitIdx = full.indexOf("\r\n\r\n");
      const head = splitIdx === -1 ? full.toString("utf8") : full.slice(0, splitIdx).toString("utf8");
      const respBody = splitIdx === -1 ? "" : decodeWireBody(head, full.slice(splitIdx + 4));
      const statusMatch = /^HTTP\/1\.\d\s+(\d{3})/.exec(head);
      resolve({ statusCode: statusMatch ? Number.parseInt(statusMatch[1], 10) : 0, headers: {}, body: respBody });
    });
  });
}

describe("EdgeGateway baseline and hardened security invariants", () => {
  const captured: Array<{ method: string; url: string; headers: http.IncomingHttpHeaders }> = [];
  let upstreamServer: http.Server;
  let gateway: EdgeGateway;
  let gatewayPort = 0;
  let keyRing: TenantKeyRing;
  const currentNowSec = 1_750_000_000;

  const acmeV1 = generateEd25519Pair();
  const acmeV2 = generateEd25519Pair();
  const globexPrimary = generateEd25519Pair();
  const acmePrimary = generateEd25519Pair();
  const nimbusSecretB64 = Buffer.from("0123456789abcdef0123456789abcdef", "utf8").toString("base64");

  before(async () => {
    upstreamServer = http.createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        captured.push({ method: req.method ?? "GET", url: req.url ?? "/", headers: req.headers });
        res.writeHead(req.method === "POST" ? 201 : 200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            ok: true,
            upstreamUrl: req.url,
            tenant: req.headers["x-gateway-tenant"] ?? null,
            forwardedScope: req.headers["x-forwarded-scope"] ?? null,
          }),
        );
      });
    });
    await new Promise<void>((resolve) => upstreamServer.listen(0, "127.0.0.1", () => resolve()));
    const upstreamPort = (upstreamServer.address() as AddressInfo).port;

    keyRing = new TenantKeyRing();
    keyRing.registerKey("acme", { keyId: "k-v1", algorithm: "ed25519", publicKeyPem: acmeV1.publicKeyPem });
    keyRing.registerKey("acme", { keyId: "k-primary", algorithm: "ed25519", publicKeyPem: acmePrimary.publicKeyPem });
    keyRing.registerKey("globex", { keyId: "k-primary", algorithm: "ed25519", publicKeyPem: globexPrimary.publicKeyPem });
    keyRing.registerKey("nimbus", {
      keyId: "hmac-main",
      algorithm: "hmac-sha256",
      secretBase64: nimbusSecretB64,
      allowedScopes: ["webhooks:read", "webhooks:write"],
    });

    gateway = new EdgeGateway({ keyRing, upstream: { host: "127.0.0.1", port: upstreamPort }, nowProvider: () => currentNowSec });
    gatewayPort = await gateway.listen(0, "127.0.0.1");
  });

  after(async () => {
    await gateway.close();
    await new Promise<void>((resolve) => upstreamServer.close(() => resolve()));
  });

  it("normalizes canonical route targets while preserving encoded slug slashes and query parameters", async () => {
    const parsed = normalizeRoutePath("/v1/tenants/acme/items/release%2f2026-q4?filter=tier%3Dga;region=eu&next=%2Fcatalog%2Fpage2");
    assert.equal(parsed.canonicalPath, "/v1/tenants/acme/items/release%2F2026-q4");
    assert.equal(parsed.rawQuery, "filter=tier%3Dga;region=eu&next=%2Fcatalog%2Fpage2");
    assert.equal(decodeSlugParam(parsed.segments[4]), "release/2026-q4");

    const authority = `127.0.0.1:${gatewayPort}`;
    const slugTarget = "/v1/tenants/acme/items/release%2F2026-q4?view=summary;compact=1";
    const signed = signRequest({
      method: "GET",
      authority,
      target: slugTarget,
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:read" },
      keyId: "k-v1",
      algorithm: "ed25519",
      privateKeyPem: acmeV1.privateKeyPem,
      created: currentNowSec,
    });
    const res = await sendHttpRequest({ port: gatewayPort, method: "GET", path: slugTarget, headers: signed.headers });
    assert.equal(res.statusCode, 200);
    assert.equal((JSON.parse(res.body) as { upstreamUrl: string }).upstreamUrl, slugTarget);
  });

  it("serves public routes and blocks matrix-param, encoded-dot, and backslash path differentials", async () => {
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/healthz" })).statusCode, 200);
    const catalogPath = "/public/catalog/compute/edge-proxy?filter=tier%3Dpro;zone=us&next=%2Fdocs";
    const catalog = await sendHttpRequest({ port: gatewayPort, method: "GET", path: catalogPath });
    assert.equal(catalog.statusCode, 200);

    const beforeCount = captured.length;
    for (const rawProbe of [
      "/public/catalog/..;v=1/..;v=2/internal/keys",
      "/public/catalog/%2e%2e/%2e%2e/internal/keys",
      "/public/catalog/%2e%2e%2f%2e%2e%2finternal%2fkeys",
      "/public/catalog/..%5c..%5cinternal%5ckeys",
    ]) {
      const probeRes = await sendRawWireRequest(gatewayPort, "GET", rawProbe, []);
      assert.ok(probeRes.statusCode >= 400 && probeRes.statusCode < 500, `Expected 4xx for ${rawProbe}, got ${probeRes.statusCode}`);
    }
    assert.equal(captured.length, beforeCount);

    const authority = `127.0.0.1:${gatewayPort}`;
    const memberAdminProbe = "/v1/tenants/acme/items/%2e%2e%2fadmin%2fconfig";
    const memberHeaders = {
      "x-tenant-id": "acme",
      "x-forwarded-scope": "items:read",
    };
    const badRes = await sendRawWireRequest(gatewayPort, "GET", memberAdminProbe, Object.entries(memberHeaders));
    assert.ok(badRes.statusCode >= 400 && badRes.statusCode < 500);
    assert.equal(captured.filter((c) => c.url.includes("/admin/")).length, 0);
    void authority;
  });

  it("enforces Content-Digest coverage, required components, and RFC 9421 duplicate header canonicalization", async () => {
    const authority = `127.0.0.1:${gatewayPort}`;
    const body = JSON.stringify({ name: "sensor-pack", sku: "sp-100" });

    const missingDigestCoverage = signRequest({
      method: "POST",
      authority,
      target: "/v1/tenants/acme/items",
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:write", "content-type": "application/json" },
      body,
      keyId: "k-v1",
      algorithm: "ed25519",
      privateKeyPem: acmeV1.privateKeyPem,
      created: currentNowSec,
      components: ["@method", "@authority", "@path", "x-tenant-id", "x-forwarded-scope"],
    });
    const noDigestRes = await sendHttpRequest({
      port: gatewayPort,
      method: "POST",
      path: "/v1/tenants/acme/items",
      headers: missingDigestCoverage.headers,
      body: JSON.stringify({ name: "modified-body", sku: "sp-999" }),
    });
    assert.equal(noDigestRes.statusCode, 401);

    const smuggledBase = signRequest({
      method: "GET",
      authority,
      target: "/v1/tenants/acme/admin/config",
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:read", "x-role": "viewer" },
      keyId: "k-v1",
      algorithm: "ed25519",
      privateKeyPem: acmeV1.privateKeyPem,
      created: currentNowSec,
    });
    const smuggledPairs: Array<[string, string]> = [
      ...smuggledBase.rawHeaderPairs,
      ["X-Role", "admin"],
      ["X-Forwarded-Scope", "tenant:admin"],
    ];
    const smuggledRes = await sendRawWireRequest(gatewayPort, "GET", "/v1/tenants/acme/admin/config", smuggledPairs);
    assert.equal(smuggledRes.statusCode, 401);

    const multiScope = signRequest({
      method: "GET",
      authority,
      target: "/v1/tenants/acme/webhooks/hk-prod",
      headers: [
        ["X-Tenant-Id", "acme"],
        ["X-Forwarded-Scope", "items:read"],
        ["X-Forwarded-Scope", "webhooks:read"],
      ],
      keyId: "k-v1",
      algorithm: "ed25519",
      privateKeyPem: acmeV1.privateKeyPem,
      created: currentNowSec,
    });
    const multiRes = await sendRawWireRequest(gatewayPort, "GET", "/v1/tenants/acme/webhooks/hk-prod", multiScope.rawHeaderPairs);
    assert.equal(multiRes.statusCode, 200);
    assert.equal((JSON.parse(multiRes.body) as { forwardedScope: string }).forwardedScope, "items:read, webhooks:read");
  });

  it("isolates verification key cache across tenants, enforces revocation, and blocks nonce replay", async () => {
    const authority = `127.0.0.1:${gatewayPort}`;

    const globexValid = signRequest({
      method: "GET",
      authority,
      target: "/v1/tenants/globex/items",
      headers: { "x-tenant-id": "globex", "x-forwarded-scope": "items:read" },
      keyId: "k-primary",
      algorithm: "ed25519",
      privateKeyPem: globexPrimary.privateKeyPem,
      created: currentNowSec,
    });
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/v1/tenants/globex/items", headers: globexValid.headers })).statusCode, 200);

    const crossTenantAttempt = signRequest({
      method: "GET",
      authority,
      target: "/v1/tenants/acme/items",
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:read" },
      keyId: "k-primary",
      algorithm: "ed25519",
      privateKeyPem: globexPrimary.privateKeyPem,
      created: currentNowSec,
    });
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "GET", path: "/v1/tenants/acme/items", headers: crossTenantAttempt.headers })).statusCode, 401);

    const body = JSON.stringify({ name: "once-only" });
    const replayCandidate = signRequest({
      method: "POST",
      authority,
      target: "/v1/tenants/acme/items",
      headers: { "x-tenant-id": "acme", "x-forwarded-scope": "items:write", "content-type": "application/json" },
      body,
      keyId: "k-primary",
      algorithm: "ed25519",
      privateKeyPem: acmePrimary.privateKeyPem,
      created: currentNowSec,
      nonce: "fixed-nonce-0001",
    });
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "POST", path: "/v1/tenants/acme/items", headers: replayCandidate.headers, body })).statusCode, 201);
    assert.equal((await sendHttpRequest({ port: gatewayPort, method: "POST", path: "/v1/tenants/acme/items", headers: replayCandidate.headers, body })).statusCode, 401);

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
});
EOF

node --experimental-strip-types --test "$APP_DIR/test/gateway.test.ts"
