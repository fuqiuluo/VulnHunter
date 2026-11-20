/**
 * Multi-Subgraph Service Registry & Deterministic In-Memory Subgraph Backends.
 *
 * Models three independent microservices (`accounts`, `billing`, `orders`) backing
 * the federated supergraph. Each subgraph stores tenant-partitioned records and
 * exposes:
 *  - `resolveRootField(fieldName, args, ctx)` for root `Query` fields it owns, and
 *  - `resolveEntities(typename, representations, requestedFields, ctx)` for Apollo
 *    Federation `_entities` batch joins.
 */

export interface SubgraphRequestContext {
  tenantId: string;
  principalId: string;
  requestId: string;
}

export type EntityRepresentation = Record<string, unknown> & {
  __typename: string;
};

export interface SubgraphService {
  readonly name: string;
  resolveRootField(
    fieldName: string,
    args: Readonly<Record<string, unknown>>,
    ctx: SubgraphRequestContext,
  ): Promise<unknown>;
  resolveEntities(
    typename: string,
    representations: ReadonlyArray<EntityRepresentation>,
    requestedFields: ReadonlySet<string>,
    ctx: SubgraphRequestContext,
  ): Promise<Array<Record<string, unknown> | null>>;
}

export interface TenantFixtures {
  users: Record<
    string,
    {
      id: string;
      email: string;
      displayName: string;
      tier: string;
      taxSsn: string;
      rawCreditScore: number;
      payoutIban: string;
    }
  >;
  invoices: Record<
    string,
    {
      id: string;
      invoiceNumber: string;
      amountCents: number;
      status: string;
      settlementIban: string;
      internalAuditNotes: string;
    }
  >;
  creditMemos: Record<
    string,
    {
      id: string;
      amountCents: number;
      reasonCode: string;
      settlementIban: string;
    }
  >;
  orders: Array<{
    id: string;
    reference: string;
    totalCents: number;
    buyerId: string | null;
    invoiceId: string | null;
    lines: Array<{ sku: string; quantity: number; unitPriceCents: number }>;
  }>;
}

export function createDefaultTenantFixtures(): Record<string, TenantFixtures> {
  return {
    acme: {
      users: {
        "u-1": {
          id: "u-1",
          email: "alice@acme.example",
          displayName: "Alice Chen (Acme)",
          tier: "enterprise",
          taxSsn: "900-11-4401",
          rawCreditScore: 790,
          payoutIban: "DE89370400440532013000",
        },
        "u-2": {
          id: "u-2",
          email: "bob@acme.example",
          displayName: "Bob Singh (Acme)",
          tier: "growth",
          taxSsn: "900-22-8802",
          rawCreditScore: 645,
          payoutIban: "FR7630006000011234567890189",
        },
        "u-3": {
          id: "u-3",
          email: "carol@acme.example",
          displayName: "Carol Diaz (Acme)",
          tier: "starter",
          taxSsn: "900-33-9903",
          rawCreditScore: 540,
          payoutIban: "NL91ABNA0417164300",
        },
      },
      invoices: {
        "inv-100": {
          id: "inv-100",
          invoiceNumber: "ACME-INV-2026-100",
          amountCents: 480_000,
          status: "PAID",
          settlementIban: "DE44500105175407324931",
          internalAuditNotes: "Acme VIP enterprise discount approved by CFO",
        },
        "inv-101": {
          id: "inv-101",
          invoiceNumber: "ACME-INV-2026-101",
          amountCents: 125_000,
          status: "OPEN",
          settlementIban: "DE44500105175407324931",
          internalAuditNotes: "Net-30 standard",
        },
      },
      creditMemos: {
        "cm-200": {
          id: "cm-200",
          amountCents: 25_000,
          reasonCode: "SLA_REBATE",
          settlementIban: "DE44500105175407324931",
        },
      },
      orders: [
        {
          id: "ord-1",
          reference: "ACME-ORD-01",
          totalCents: 480_000,
          buyerId: "u-1",
          invoiceId: "inv-100",
          lines: [
            { sku: "EDGE-GW-PRO", quantity: 2, unitPriceCents: 200_000 },
            { sku: "SUP-24X7", quantity: 1, unitPriceCents: 80_000 },
          ],
        },
        {
          id: "ord-2",
          reference: "ACME-ORD-02-GUEST",
          totalCents: 19_500,
          buyerId: null,
          invoiceId: null,
          lines: [{ sku: "DOC-TOKEN", quantity: 3, unitPriceCents: 6_500 }],
        },
        {
          id: "ord-3",
          reference: "ACME-ORD-03",
          totalCents: 125_000,
          buyerId: "u-1",
          invoiceId: "inv-101",
          lines: [{ sku: "EDGE-SENSOR", quantity: 5, unitPriceCents: 25_000 }],
        },
        {
          id: "ord-4",
          reference: "ACME-ORD-04",
          totalCents: 75_000,
          buyerId: "u-2",
          invoiceId: null,
          lines: [{ sku: "EDGE-SENSOR", quantity: 3, unitPriceCents: 25_000 }],
        },
      ],
    },
    globex: {
      users: {
        "u-1": {
          id: "u-1",
          email: "dana@globex.example",
          displayName: "Dana Park (Globex)",
          tier: "enterprise",
          taxSsn: "811-77-1001",
          rawCreditScore: 710,
          payoutIban: "GB29NWBK60161331926819",
        },
      },
      invoices: {
        "inv-100": {
          id: "inv-100",
          invoiceNumber: "GLOBEX-INV-2026-100",
          amountCents: 910_000,
          status: "PENDING_WIRE",
          settlementIban: "GB82WEST12345698765432",
          internalAuditNotes: "Globex sovereign contract hold",
        },
      },
      creditMemos: {},
      orders: [
        {
          id: "ord-1",
          reference: "GLOBEX-ORD-01",
          totalCents: 910_000,
          buyerId: "u-1",
          invoiceId: "inv-100",
          lines: [{ sku: "CLUSTER-XL", quantity: 1, unitPriceCents: 910_000 }],
        },
      ],
    },
  };
}

function computeRiskBand(rawCreditScore: number): string {
  if (rawCreditScore >= 750) return "LOW_RISK_PRIME";
  if (rawCreditScore >= 620) return "MEDIUM_RISK_STANDARD";
  return "HIGH_RISK_REVIEW";
}

export class InMemorySubgraphCluster {
  public readonly data: Record<string, TenantFixtures>;
  public entityBatchCalls = 0;

  constructor(fixtures?: Record<string, TenantFixtures>) {
    this.data = fixtures ?? createDefaultTenantFixtures();
  }

  createServices(): Map<string, SubgraphService> {
    const services = new Map<string, SubgraphService>();

    const accountsService: SubgraphService = {
      name: "accounts",
      resolveRootField: async (fieldName, args, ctx) => {
        const tenant = this.data[ctx.tenantId];
        if (!tenant) return null;
        if (fieldName === "user") {
          const id = String(args.id ?? "");
          const u = tenant.users[id];
          if (!u) return null;
          return {
            __typename: "User",
            id: u.id,
            email: u.email,
            displayName: u.displayName,
            tier: u.tier,
            taxSsn: u.taxSsn,
            rawCreditScore: u.rawCreditScore,
          };
        }
        if (fieldName === "node") {
          const id = String(args.id ?? "");
          if (tenant.users[id]) {
            const u = tenant.users[id];
            return {
              __typename: "User",
              id: u.id,
              email: u.email,
              displayName: u.displayName,
              tier: u.tier,
              taxSsn: u.taxSsn,
              rawCreditScore: u.rawCreditScore,
            };
          }
          if (tenant.invoices[id]) {
            return { __typename: "Invoice", id };
          }
          const ord = tenant.orders.find((o) => o.id === id);
          if (ord) {
            return { __typename: "Order", id: ord.id };
          }
          return null;
        }
        return null;
      },
      resolveEntities: async (typename, representations, requestedFields, ctx) => {
        this.entityBatchCalls += 1;
        const tenant = this.data[ctx.tenantId];
        return representations.map((rep) => {
          if (!tenant || typename !== "User") return null;
          const id = String(rep.id ?? "");
          const u = tenant.users[id];
          if (!u) return null;
          const out: Record<string, unknown> = { __typename: "User", id: u.id };
          if (requestedFields.has("email")) out.email = u.email;
          if (requestedFields.has("displayName")) out.displayName = u.displayName;
          if (requestedFields.has("tier")) out.tier = u.tier;
          if (requestedFields.has("taxSsn")) out.taxSsn = u.taxSsn;
          if (requestedFields.has("rawCreditScore")) out.rawCreditScore = u.rawCreditScore;
          return out;
        });
      },
    };

    const billingService: SubgraphService = {
      name: "billing",
      resolveRootField: async (fieldName, args, ctx) => {
        const tenant = this.data[ctx.tenantId];
        if (!tenant) return fieldName === "billableDocuments" ? [] : null;
        if (fieldName === "invoice") {
          const id = String(args.id ?? "");
          const inv = tenant.invoices[id];
          return inv ? { __typename: "Invoice", ...inv } : null;
        }
        if (fieldName === "billableDocuments") {
          const first = typeof args.first === "number" ? args.first : 5;
          const docs: Array<Record<string, unknown>> = [];
          for (const inv of Object.values(tenant.invoices)) {
            docs.push({ __typename: "Invoice", ...inv });
          }
          for (const cm of Object.values(tenant.creditMemos)) {
            docs.push({ __typename: "CreditMemo", ...cm });
          }
          return docs.slice(0, Math.max(0, first));
        }
        return null;
      },
      resolveEntities: async (typename, representations, requestedFields, ctx) => {
        this.entityBatchCalls += 1;
        const tenant = this.data[ctx.tenantId];
        return representations.map((rep) => {
          if (!tenant) return null;
          if (typename === "User") {
            const id = String(rep.id ?? "");
            const u = tenant.users[id];
            if (!u) return null;
            const out: Record<string, unknown> = { __typename: "User", id: u.id };
            if (requestedFields.has("netRiskBand")) {
              // `@requires(fields: "rawCreditScore")` supplied by gateway planner in representation
              const score = typeof rep.rawCreditScore === "number" ? rep.rawCreditScore : u.rawCreditScore;
              out.netRiskBand = computeRiskBand(score);
            }
            if (requestedFields.has("payoutIban")) {
              out.payoutIban = u.payoutIban;
            }
            return out;
          }
          if (typename === "Invoice") {
            const id = String(rep.id ?? "");
            const inv = tenant.invoices[id];
            if (!inv) return null;
            const out: Record<string, unknown> = { __typename: "Invoice", id: inv.id };
            for (const f of requestedFields) {
              if (f in inv) out[f] = (inv as Record<string, unknown>)[f];
            }
            return out;
          }
          return null;
        });
      },
    };

    const ordersService: SubgraphService = {
      name: "orders",
      resolveRootField: async (fieldName, args, ctx) => {
        const tenant = this.data[ctx.tenantId];
        if (!tenant) return fieldName === "orders" || fieldName === "search" ? [] : null;
        const mapOrder = (ord: TenantFixtures["orders"][number]) => ({
          __typename: "Order",
          id: ord.id,
          reference: ord.reference,
          totalCents: ord.totalCents,
          buyer: ord.buyerId ? { __typename: "User", id: ord.buyerId } : null,
          invoice: ord.invoiceId ? { __typename: "Invoice", id: ord.invoiceId } : null,
          lines: ord.lines.map((l) => ({ __typename: "OrderLine", ...l })),
        });

        if (fieldName === "order") {
          const id = String(args.id ?? "");
          const found = tenant.orders.find((o) => o.id === id);
          return found ? mapOrder(found) : null;
        }
        if (fieldName === "orders") {
          const limit = typeof args.limit === "number" ? args.limit : 10;
          return tenant.orders.slice(0, Math.max(0, limit)).map(mapOrder);
        }
        if (fieldName === "search") {
          const q = String(args.text ?? "").toLowerCase();
          const limit = typeof args.limit === "number" ? args.limit : 5;
          const results: Array<Record<string, unknown>> = [];
          for (const u of Object.values(tenant.users)) {
            if (!q || u.displayName.toLowerCase().includes(q) || u.email.toLowerCase().includes(q)) {
              results.push({ __typename: "User", id: u.id });
            }
          }
          for (const o of tenant.orders) {
            if (!q || o.reference.toLowerCase().includes(q)) {
              results.push(mapOrder(o));
            }
          }
          for (const inv of Object.values(tenant.invoices)) {
            if (!q || inv.invoiceNumber.toLowerCase().includes(q)) {
              results.push({ __typename: "Invoice", id: inv.id });
            }
          }
          return results.slice(0, Math.max(0, limit));
        }
        return null;
      },
      resolveEntities: async (typename, representations, requestedFields, ctx) => {
        this.entityBatchCalls += 1;
        const tenant = this.data[ctx.tenantId];
        return representations.map((rep) => {
          if (!tenant || typename !== "Order") return null;
          const id = String(rep.id ?? "");
          const ord = tenant.orders.find((o) => o.id === id);
          if (!ord) return null;
          const out: Record<string, unknown> = { __typename: "Order", id: ord.id };
          if (requestedFields.has("reference")) out.reference = ord.reference;
          if (requestedFields.has("totalCents")) out.totalCents = ord.totalCents;
          if (requestedFields.has("buyer")) {
            out.buyer = ord.buyerId ? { __typename: "User", id: ord.buyerId } : null;
          }
          if (requestedFields.has("invoice")) {
            out.invoice = ord.invoiceId ? { __typename: "Invoice", id: ord.invoiceId } : null;
          }
          if (requestedFields.has("lines")) {
            out.lines = ord.lines.map((l) => ({ __typename: "OrderLine", ...l }));
          }
          return out;
        });
      },
    };

    services.set("accounts", accountsService);
    services.set("billing", billingService);
    services.set("orders", ordersService);
    return services;
  }
}
