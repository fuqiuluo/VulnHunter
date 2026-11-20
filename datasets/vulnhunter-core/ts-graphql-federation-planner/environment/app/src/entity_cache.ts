/**
 * Bounded TTL & LRU Entity Resolution Cache for Federated Subgraph Batches.
 *
 * Architectural Contracts:
 *  1. Cached entity fragments MUST be strictly isolated by `tenantId` so two tenants
 *     sharing identical local entity IDs (e.g. `inv-100` or `u-1`) can never read
 *     each other's cached subgraph fields.
 *  2. `invalidateTenant(tenantId)` must immediately evict all cached entries belonging
 *     to `tenantId` without disturbing other tenants.
 *  3. Returned records must be defensive copies so caller projection or mutation cannot
 *     poison cached state.
 */

export interface EntityCacheOptions {
  maxEntries?: number;
  ttlMs?: number;
  nowMsProvider?: () => number;
}

interface CacheRecord {
  tenantId: string;
  expiresAtMs: number;
  value: Record<string, unknown>;
}

export class EntityResolutionCache {
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly nowMs: () => number;
  private readonly store = new Map<string, CacheRecord>();

  constructor(options: EntityCacheOptions = {}) {
    this.maxEntries = options.maxEntries ?? 256;
    this.ttlMs = options.ttlMs ?? 30_000;
    this.nowMs = options.nowMsProvider ?? (() => Date.now());
  }

  private buildCacheKey(
    _tenantId: string,
    subgraph: string,
    typename: string,
    canonicalEntityKey: string,
    requestedFields: ReadonlySet<string>,
  ): string {
    const sortedFields = [...requestedFields].sort().join(",");
    return `${subgraph}:${typename}:${canonicalEntityKey}:[${sortedFields}]`;
  }

  get(
    tenantId: string,
    subgraph: string,
    typename: string,
    canonicalEntityKey: string,
    requestedFields: ReadonlySet<string>,
  ): Record<string, unknown> | undefined {
    const key = this.buildCacheKey(tenantId, subgraph, typename, canonicalEntityKey, requestedFields);
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (this.nowMs() > entry.expiresAtMs) {
      this.store.delete(key);
      return undefined;
    }
    // Refresh LRU order
    this.store.delete(key);
    this.store.set(key, entry);
    return { ...entry.value };
  }

  set(
    tenantId: string,
    subgraph: string,
    typename: string,
    canonicalEntityKey: string,
    requestedFields: ReadonlySet<string>,
    value: Record<string, unknown>,
  ): void {
    if (this.maxEntries <= 0 || this.ttlMs <= 0) return;
    const key = this.buildCacheKey(tenantId, subgraph, typename, canonicalEntityKey, requestedFields);
    if (this.store.has(key)) {
      this.store.delete(key);
    } else if (this.store.size >= this.maxEntries) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) this.store.delete(oldestKey);
    }
    this.store.set(key, {
      tenantId,
      expiresAtMs: this.nowMs() + this.ttlMs,
      value: { ...value },
    });
  }

  invalidateTenant(tenantId: string): number {
    let removed = 0;
    for (const [k, rec] of this.store.entries()) {
      if (k.startsWith(`${tenantId}:`) && rec.tenantId === tenantId) {
        this.store.delete(k);
        removed += 1;
      }
    }
    return removed;
  }

  clear(): void {
    this.store.clear();
  }

  get size(): number {
    return this.store.size;
  }
}
