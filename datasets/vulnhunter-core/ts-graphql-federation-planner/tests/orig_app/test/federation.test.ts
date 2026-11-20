import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { FederatedGateway } from "../src/gateway.ts";
import { InMemorySubgraphCluster } from "../src/subgraphs.ts";

describe("FederatedGateway baseline behavior", () => {
  it("resolves cross-subgraph Order -> User + Invoice joins and aliases", async () => {
    const cluster = new InMemorySubgraphCluster();
    const gw = new FederatedGateway({ services: cluster.createServices() });

    const res = await gw.execute(
      {
        query: `
          query GetOrderDetails($orderId: ID!) {
            primaryOrder: order(id: $orderId) {
              id
              ref: reference
              totalCents
              buyer {
                id
                email
                displayName
                netRiskBand
              }
              invoice {
                id
                invoiceNumber
                status
              }
              lines(limit: 2) {
                sku
                quantity
              }
            }
          }
        `,
        variables: { orderId: "ord-1" },
      },
      {
        tenantId: "acme",
        principalId: "usr-member-1",
        role: "member",
        scopes: new Set(["orders:read"]),
      },
    );

    assert.equal(res.statusCode, 200);
    const ord = res.body.data?.primaryOrder as Record<string, unknown>;
    assert.equal(ord.id, "ord-1");
    assert.equal(ord.ref, "ACME-ORD-01");
    const buyer = ord.buyer as Record<string, unknown>;
    assert.equal(buyer.email, "alice@acme.example");
    assert.equal(buyer.netRiskBand, "LOW_RISK_PRIME");
    const inv = ord.invoice as Record<string, unknown>;
    assert.equal(inv.invoiceNumber, "ACME-INV-2026-100");
  });

  it("denies direct unauthorized field selection on protected User.taxSsn", async () => {
    const gw = new FederatedGateway();
    const res = await gw.execute(
      {
        query: `{ user(id: "u-1") { id email taxSsn } }`,
      },
      {
        tenantId: "acme",
        principalId: "usr-member-1",
        role: "member",
        scopes: new Set(["orders:read"]),
      },
    );
    assert.equal(res.statusCode, 403);
    assert.equal(res.body.errors?.[0]?.extensions.code, "FORBIDDEN_FIELD");
  });

  it("permits compliance principal with required role and scope to query User.taxSsn", async () => {
    const gw = new FederatedGateway();
    const res = await gw.execute(
      {
        query: `{ user(id: "u-1") { id taxSsn } }`,
      },
      {
        tenantId: "acme",
        principalId: "usr-compliance-1",
        role: "compliance",
        scopes: new Set(["pii:tax:read"]),
      },
    );
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.body.data, {
      user: { id: "u-1", taxSsn: "900-11-4401" },
    });
  });

  it("enforces maxDepth and literal list-multiplier cost limits", async () => {
    const gw = new FederatedGateway({ costLimits: { maxDepth: 4, maxCost: 50 } });

    const overCost = await gw.execute(
      {
        query: `{ orders(limit: 40) { id buyer { id email } } }`,
      },
      {
        tenantId: "acme",
        principalId: "usr-member-1",
        role: "member",
        scopes: new Set(),
      },
    );
    assert.equal(overCost.statusCode, 429);
    assert.equal(overCost.body.errors?.[0]?.extensions.code, "MAX_COST_EXCEEDED");
  });

  it("serves GraphQL over HTTP POST /graphql and GET /healthz", async () => {
    const gw = new FederatedGateway();
    const port = await gw.listen(0, "127.0.0.1");
    try {
      const health = await fetch(`http://127.0.0.1:${port}/healthz`);
      assert.equal(health.status, 200);

      const post = await fetch(`http://127.0.0.1:${port}/graphql`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-tenant-id": "acme",
          "x-principal-id": "u-http",
          "x-principal-role": "member",
        },
        body: JSON.stringify({
          query: `fragment UserSummary on User { id displayName tier } { user(id: "u-2") { ...UserSummary } }`,
        }),
      });
      assert.equal(post.status, 200);
      const payload = (await post.json()) as { data: Record<string, unknown> };
      assert.deepEqual(payload.data, {
        user: { id: "u-2", displayName: "Bob Singh (Acme)", tier: "growth" },
      });
    } finally {
      await gw.close();
    }
  });
});
