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
      paramMap.set(p.slice(0, pEq).trim().toLowerCase(), p.slice(pEq + 1).trim());
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
  return values && values.length > 0 ? values[0].trim().replace(/\s+/g, " ") : undefined;
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
    const sigInputHeader = extractMessageHeader(input.headersDistinct, "signature-input");
    const sigHeader = extractMessageHeader(input.headersDistinct, "signature");
    if (!sigInputHeader || !sigHeader) throw new SignatureVerificationError("Missing signature headers", "MISSING_SIGNATURE");

    const params = parseSignatureInputHeader(sigInputHeader);
    const sigBytes = parseSignatureHeader(sigHeader, params.label);

    if (params.created > nowSec + this.config.maxClockSkewSec) {
      throw new SignatureVerificationError("Signature created timestamp is in the future", "SIGNATURE_FUTURE");
    }
    if (params.expires !== undefined && nowSec > params.expires) {
      throw new SignatureVerificationError("Signature has expired", "SIGNATURE_EXPIRED");
    }

    const coveredSet = new Set(params.components);
    if (!coveredSet.has("@method") || !coveredSet.has("@path")) {
      throw new SignatureVerificationError("Signature must cover @method and @path", "INCOMPLETE_COVERAGE");
    }
    if (coveredSet.has("content-digest")) {
      const digestHeader = extractMessageHeader(input.headersDistinct, "content-digest");
      if (!digestHeader || !verifyContentDigestHeader(input.body, digestHeader)) {
        throw new SignatureVerificationError("Content-Digest verification failed", "DIGEST_MISMATCH");
      }
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
