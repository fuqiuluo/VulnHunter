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

function materializeKey(r: StoredKeyRecord): ResolvedVerificationKey {
  const base = { tenantId: r.tenantId, keyId: r.keyId, state: r.state, notBeforeSec: r.notBeforeSec, expiresAtSec: r.expiresAtSec, allowedScopes: r.allowedScopes };
  if (r.algorithm === "ed25519") {
    if (!r.publicKeyPem) throw new KeyRingError("Missing Ed25519 public key PEM", "INVALID_KEY_MATERIAL");
    const pubKey = crypto.createPublicKey(r.publicKeyPem);
    if (pubKey.asymmetricKeyType !== "ed25519") throw new KeyRingError("Public key must use Ed25519", "INVALID_KEY_MATERIAL");
    return { ...base, algorithm: "ed25519", publicKey: pubKey };
  }
  if (!r.secretBase64) throw new KeyRingError("Missing HMAC-SHA256 shared secret", "INVALID_KEY_MATERIAL");
  const secretBuf = Buffer.from(r.secretBase64, "base64");
  if (secretBuf.length < 16) throw new KeyRingError("HMAC-SHA256 secret must be at least 16 bytes", "INVALID_KEY_MATERIAL");
  return { ...base, algorithm: "hmac-sha256", hmacSecret: secretBuf };
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
    this.resolvedCache.delete(`${tenantId}:${cleanKeyId}`);
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
    this.resolvedCache.delete(`${tenantId}:${cleanOldId}`);
  }

  revokeKey(tenantId: string, keyId: string): boolean {
    const cleanKeyId = keyId.trim();
    const existing = this.registry.get(tenantId)?.get(cleanKeyId);
    if (!existing) return false;
    existing.state = "revoked";
    this.resolvedCache.delete(`${tenantId}:${cleanKeyId}`);
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
    const cacheKey = cleanKeyId;
    const cached = this.resolvedCache.get(cacheKey);
    if (cached) {
      const validWindow =
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
    if (recordedAt !== undefined && nowSec - recordedAt > this.nonceWindowSec) return false;
    if (this.seenNonces.size >= this.maxTrackedNonces && !this.seenNonces.has(composite)) {
      const oldest = this.seenNonces.keys().next().value;
      if (oldest !== undefined) this.seenNonces.delete(oldest);
    }
    this.seenNonces.set(composite, nowSec);
    return true;
  }
}
