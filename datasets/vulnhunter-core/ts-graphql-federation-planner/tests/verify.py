#!/usr/bin/env python3
"""Deterministic verifier for task: ts-graphql-federation-planner."""

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

CORE_FILES = {"cost_analyzer.ts", "auth_policy.ts", "entity_planner.ts", "entity_cache.ts"}

HARNESS_TS = r"""
import { FederatedGateway } from "./src/gateway.ts";
import { InMemorySubgraphCluster } from "./src/subgraphs.ts";

function assertCond(cond: boolean, msg: string): void {
  if (!cond) throw new Error(msg);
}

async function runSuite(): Promise<{ ok: boolean; groups: Record<string, { passed: boolean; message: string }> }> {
  const groups: Record<string, { passed: boolean; message: string }> = {};
  let allPassed = true;

  const runGroup = async (name: string, fn: () => Promise<string>) => {
    try {
      const msg = await fn();
      groups[name] = { passed: true, message: msg };
    } catch (err: unknown) {
      allPassed = false;
      groups[name] = { passed: false, message: err instanceof Error ? err.message : String(err) };
    }
  };

  // 1. Functional parity: multi-subgraph joins, interfaces, unions, @requires, HTTP transport
  await runGroup("functional", async () => {
    const cluster = new InMemorySubgraphCluster();
    const gw = new FederatedGateway({
      services: cluster.createServices(),
      costLimits: { maxDepth: 8, maxCost: 150 },
    });

    // Authorized member querying computed @requires field netRiskBand without needing risk:internal scope
    const riskRes = await gw.execute(
      {
        query: `
          query MemberUserRisk($uid: ID!) {
            user(id: $uid) {
              id
              email
              netRiskBand
            }
          }
        `,
        variables: { uid: "u-1" },
      },
      { tenantId: "acme", principalId: "m-1", role: "member", scopes: new Set() },
    );
    assertCond(riskRes.statusCode === 200, `Expected 200 on MemberUserRisk, got ${riskRes.statusCode}: ${JSON.stringify(riskRes.body)}`);
    assertCond(
      JSON.stringify(riskRes.body.data) === JSON.stringify({
        user: { id: "u-1", email: "alice@acme.example", netRiskBand: "LOW_RISK_PRIME" },
      }),
      `Unexpected MemberUserRisk data: ${JSON.stringify(riskRes.body.data)}`,
    );

    // Search union with typed inline fragments + authorized finance reading settlementIban via interface
    const finRes = await gw.execute(
      {
        query: `
          query FinanceAudit {
            billableDocuments(first: 3) {
              __typename
              id
              amountCents
              settlementIban
              ... on Invoice {
                invoiceNumber
              }
              ... on CreditMemo {
                reasonCode
              }
            }
            search(text: "ACME", limit: 4) {
              __typename
              ... on User { id displayName }
              ... on Order { id reference }
              ... on Invoice { id status }
            }
          }
        `,
      },
      {
        tenantId: "acme",
        principalId: "fin-1",
        role: "finance",
        scopes: new Set(["billing:settlement:read"]),
      },
    );
    assertCond(finRes.statusCode === 200, `Expected 200 on FinanceAudit, got ${finRes.statusCode}: ${JSON.stringify(finRes.body)}`);
    const docs = (finRes.body.data?.billableDocuments ?? []) as Array<Record<string, unknown>>;
    assertCond(docs.length === 3, `Expected 3 billableDocuments, got ${docs.length}`);
    assertCond(docs.every((d) => d.settlementIban === "DE44500105175407324931"), "Expected settlementIban for authorized finance user");

    // HTTP POST /graphql check
    const port = await gw.listen(0, "127.0.0.1");
    try {
      const resp = await fetch(`http://127.0.0.1:${port}/graphql`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-tenant-id": "globex",
          "x-principal-id": "g-1",
          "x-principal-role": "member",
        },
        body: JSON.stringify({
          query: `{ order(id: "ord-1") { id reference buyer { id email netRiskBand } } }`,
        }),
      });
      assertCond(resp.status === 200, `HTTP POST /graphql failed: ${resp.status}`);
      const json = (await resp.json()) as { data: Record<string, unknown> };
      const ord = json.data.order as Record<string, unknown>;
      assertCond(ord.reference === "GLOBEX-ORD-01", `Unexpected Globex order: ${JSON.stringify(ord)}`);
      assertCond((ord.buyer as Record<string, unknown>).netRiskBand === "MEDIUM_RISK_STANDARD", "Unexpected Globex netRiskBand");
    } finally {
      await gw.close();
    }

    return "Multi-subgraph joins, @requires computed fields, union/interface fragments, and HTTP transport verified";
  });

  // 2. Defect 1: Repeated Named-Fragment Cost Amplification & Variable Multiplier Bypass
  await runGroup("cost_amplification", async () => {
    const gw = new FederatedGateway({ costLimits: { maxDepth: 8, maxCost: 80 } });

    // A: Spreading the same named fragment across 12 aliased root fields must charge 12x fragment cost (> 80)
    const aliases = Array.from({ length: 12 }, (_, idx) => `o${idx}: order(id: "ord-1") { ...HeavyOrderFrag }`).join("\n");
    const fragAmplifyRes = await gw.execute(
      {
        query: `
          fragment HeavyOrderFrag on Order {
            id
            totalCents
            buyer { id email netRiskBand }
            invoice { id amountCents }
            lines(limit: 2) { sku unitPriceCents }
          }
          query Amplified {
            ${aliases}
          }
        `,
      },
      { tenantId: "acme", principalId: "m-1", role: "member", scopes: new Set() },
    );
    assertCond(
      fragAmplifyRes.statusCode === 429 && fragAmplifyRes.body.errors?.[0]?.extensions.code === "MAX_COST_EXCEEDED",
      `Aliased repeated fragment spread should exceed maxCost=80 (429), got status=${fragAmplifyRes.statusCode} body=${JSON.stringify(fragAmplifyRes.body)}`,
    );

    // B: Variable-supplied list multiplier ($n = 100) must be multiplied just like literal IntValue
    const varMultRes = await gw.execute(
      {
        query: `
          query VarMult($n: Int!) {
            orders(limit: $n) {
              id
              totalCents
              buyer { id email }
            }
          }
        `,
        variables: { n: 100 },
      },
      { tenantId: "acme", principalId: "m-1", role: "member", scopes: new Set() },
    );
    assertCond(
      varMultRes.statusCode === 429 && varMultRes.body.errors?.[0]?.extensions.code === "MAX_COST_EXCEEDED",
      `Variable list multiplier $n=100 should exceed maxCost=80 (429), got status=${varMultRes.statusCode} body=${JSON.stringify(varMultRes.body)}`,
    );

    // C: Negative or non-integer variable multiplier must be rejected (429 INVALID_COST_MULTIPLIER or 400)
    const negVarRes = await gw.execute(
      {
        query: `query NegMult($n: Int!) { orders(limit: $n) { id buyer { id email } } }`,
        variables: { n: -50 },
      },
      { tenantId: "acme", principalId: "m-1", role: "member", scopes: new Set() },
    );
    assertCond(
      negVarRes.statusCode >= 400 && negVarRes.statusCode < 500,
      `Negative variable multiplier $n=-50 was accepted with status ${negVarRes.statusCode}`,
    );

    // D: Cyclic fragments must still be cleanly rejected with FRAGMENT_CYCLE
    const cycleRes = await gw.execute(
      {
        query: `
          fragment A on User { id ...B }
          fragment B on User { email ...A }
          { user(id: "u-1") { ...A } }
        `,
      },
      { tenantId: "acme", principalId: "m-1", role: "member", scopes: new Set() },
    );
    assertCond(cycleRes.statusCode === 429, `Fragment cycle should return 429, got ${cycleRes.statusCode}`);

    return "Repeated fragment spread accounting, variable list multipliers, negative bounds, and cycle rejection verified";
  });

  // 3. Defect 2: Untyped Inline Fragment, Concrete Interface Implementation, & Protocol Root Authorization
  await runGroup("directive_authorization", async () => {
    const gw = new FederatedGateway();
    const unpriv = { tenantId: "acme", principalId: "m-1", role: "member", scopes: new Set<string>() };

    // A: Untyped inline fragment `{ user(id: "u-1") { ... { taxSsn } } }`
    const untypedInline = await gw.execute(
      { query: `{ user(id: "u-1") { id ... { taxSsn payoutIban } } }` },
      unpriv,
    );
    assertCond(
      untypedInline.statusCode === 403,
      `Untyped inline fragment leaked @auth fields: status=${untypedInline.statusCode} body=${JSON.stringify(untypedInline.body)}`,
    );

    // B: Abstract interface field (`BillableDocument.settlementIban`) gated on concrete `Invoice`/`CreditMemo`
    const ifaceAuth = await gw.execute(
      { query: `{ billableDocuments(first: 2) { id amountCents settlementIban } }` },
      unpriv,
    );
    assertCond(
      ifaceAuth.statusCode === 403,
      `Interface selection bypassed concrete @auth on settlementIban: status=${ifaceAuth.statusCode} body=${JSON.stringify(ifaceAuth.body)}`,
    );

    // C: Union -> Interface inline fragment (`SearchItem` -> `... on BillableDocument { settlementIban }`)
    const unionToIface = await gw.execute(
      { query: `{ search(text: "INV", limit: 3) { ... on BillableDocument { id settlementIban } } }` },
      unpriv,
    );
    assertCond(
      unionToIface.statusCode === 403,
      `Union->Interface inline fragment bypassed @auth on settlementIban: status=${unionToIface.statusCode}`,
    );

    // D: Direct client invocation of internal federation protocol fields `_entities` and `_service`
    const entitiesCall = await gw.execute(
      {
        query: `
          query SmuggleEntities($reps: JSON) {
            _entities(representations: $reps) {
              id
              ... on User { email netRiskBand }
            }
          }
        `,
        variables: {
          reps: [{ __typename: "User", id: "u-3", rawCreditScore: 999 }],
        },
      },
      { tenantId: "acme", principalId: "admin-1", role: "admin", scopes: new Set(["pii:tax:read", "risk:internal"]) },
    );
    assertCond(
      entitiesCall.statusCode === 403 || entitiesCall.statusCode === 400,
      `External client query to internal _entities field was permitted: status=${entitiesCall.statusCode} body=${JSON.stringify(entitiesCall.body)}`,
    );

    const serviceCall = await gw.execute(
      { query: `{ _service }` },
      { tenantId: "acme", principalId: "admin-1", role: "admin", scopes: new Set() },
    );
    assertCond(
      serviceCall.statusCode === 403 || serviceCall.statusCode === 400,
      `External client query to internal _service field was permitted: status=${serviceCall.statusCode}`,
    );

    return "Untyped inline fragments, concrete interface @auth propagation, and _entities/_service isolation verified";
  });

  // 4. Defect 3: Sparse/Duplicate Batch Entity Correlation & Unselected `@requires` Response Leak
  await runGroup("entity_batch_and_projection", async () => {
    const cluster = new InMemorySubgraphCluster();
    const gw = new FederatedGateway({ services: cluster.createServices() });

    // Acme orders have buyer sequence: [u-1, null, u-1, u-2]!
    // Deduplicating [u-1, u-2] and merging by sequential index corrupts ord-3 (u-1) with u-2's profile!
    const ordersRes = await gw.execute(
      {
        query: `
          {
            orders(limit: 4) {
              id
              buyer {
                id
                email
                displayName
                netRiskBand
              }
            }
          }
        `,
      },
      { tenantId: "acme", principalId: "m-1", role: "member", scopes: new Set() },
    );
    assertCond(ordersRes.statusCode === 200, `orders query failed: ${ordersRes.statusCode}`);
    const orders = (ordersRes.body.data?.orders ?? []) as Array<Record<string, unknown>>;
    assertCond(orders.length === 4, `Expected 4 orders, got ${orders.length}`);

    const b0 = orders[0].buyer as Record<string, unknown>;
    const b1 = orders[1].buyer;
    const b2 = orders[2].buyer as Record<string, unknown>;
    const b3 = orders[3].buyer as Record<string, unknown>;

    assertCond(b1 === null, `Expected ord-2 guest buyer to be null, got ${JSON.stringify(b1)}`);
    assertCond(
      b0.id === "u-1" && b0.email === "alice@acme.example" && b0.netRiskBand === "LOW_RISK_PRIME",
      `ord-1 buyer mismatch: ${JSON.stringify(b0)}`,
    );
    assertCond(
      b2.id === "u-1" && b2.email === "alice@acme.example" && b2.netRiskBand === "LOW_RISK_PRIME",
      `ord-3 duplicate buyer (u-1) was corrupted with wrong entity data: ${JSON.stringify(b2)}`,
    );
    assertCond(
      b3.id === "u-2" && b3.email === "bob@acme.example" && b3.netRiskBand === "MEDIUM_RISK_STANDARD",
      `ord-4 buyer (u-2) mismatch: ${JSON.stringify(b3)}`,
    );

    // Ensure internal `@requires` field `rawCreditScore` NEVER leaks into client response when unrequested!
    for (const [label, b] of [["ord-1", b0], ["ord-3", b2], ["ord-4", b3]] as const) {
      assertCond(
        !("rawCreditScore" in b),
        `Internal @requires field 'rawCreditScore' leaked into projected response on ${label}: ${JSON.stringify(b)}`,
      );
      assertCond(
        Object.keys(b).sort().join(",") === "displayName,email,id,netRiskBand",
        `Unexpected extra fields projected on ${label}: ${JSON.stringify(b)}`,
      );
    }

    return "Duplicate/sparse batch entity @key correlation and strict @requires projection stripping verified";
  });

  // 5. Defect 4: Multi-Tenant Entity Resolution Cache Isolation & Tenant Invalidation
  await runGroup("tenant_cache_isolation", async () => {
    const cluster = new InMemorySubgraphCluster();
    const gw = new FederatedGateway({
      services: cluster.createServices(),
      cacheOptions: { maxEntries: 128, ttlMs: 60_000 },
    });

    const query = `
      {
        order(id: "ord-1") {
          id
          buyer { id email displayName }
          invoice { id invoiceNumber amountCents status }
        }
      }
    `;

    // 1) Warm entity cache with tenant `acme` (which resolves User `u-1` and Invoice `inv-100`)
    const acmeRes = await gw.execute(
      { query },
      { tenantId: "acme", principalId: "a-1", role: "member", scopes: new Set() },
    );
    assertCond(acmeRes.statusCode === 200, "Acme warm query failed");
    const acmeOrder = acmeRes.body.data?.order as Record<string, unknown>;
    assertCond((acmeOrder.buyer as Record<string, unknown>).email === "alice@acme.example", "Acme buyer mismatch");
    assertCond((acmeOrder.invoice as Record<string, unknown>).invoiceNumber === "ACME-INV-2026-100", "Acme invoice mismatch");

    // 2) Query colliding `ord-1` -> `u-1` & `inv-100` under tenant `globex`
    const globexRes = await gw.execute(
      { query },
      { tenantId: "globex", principalId: "g-1", role: "member", scopes: new Set() },
    );
    assertCond(globexRes.statusCode === 200, "Globex query failed");
    const globexOrder = globexRes.body.data?.order as Record<string, unknown>;
    assertCond(
      (globexOrder.buyer as Record<string, unknown>).email === "dana@globex.example",
      `Cross-tenant cache bleed on User u-1! Got ${JSON.stringify(globexOrder.buyer)}`,
    );
    assertCond(
      (globexOrder.invoice as Record<string, unknown>).invoiceNumber === "GLOBEX-INV-2026-100",
      `Cross-tenant cache bleed on Invoice inv-100! Got ${JSON.stringify(globexOrder.invoice)}`,
    );

    // 3) Mutate backing Acme fixture and verify `gw.cache.invalidateTenant("acme")` evicts Acme entries cleanly
    const callsBeforeHit = cluster.entityBatchCalls;
    await gw.execute(
      { query },
      { tenantId: "acme", principalId: "a-1", role: "member", scopes: new Set() },
    );
    assertCond(cluster.entityBatchCalls === callsBeforeHit, "Expected warm cache hit for repeated Acme query");

    cluster.data.acme.invoices["inv-100"].status = "REFUNDED";
    const evicted = gw.cache.invalidateTenant("acme");
    assertCond(evicted >= 1, `Expected invalidateTenant('acme') to evict >= 1 entry, got ${evicted}`);

    const acmeAfterInvalidation = await gw.execute(
      { query },
      { tenantId: "acme", principalId: "a-1", role: "member", scopes: new Set() },
    );
    const updatedInv = ((acmeAfterInvalidation.body.data?.order as Record<string, unknown>).invoice as Record<string, unknown>);
    assertCond(
      updatedInv.status === "REFUNDED",
      `Expected fresh Invoice status 'REFUNDED' after invalidateTenant('acme'), got ${JSON.stringify(updatedInv)}`,
    );

    return "Per-tenant entity cache namespace isolation, hit reuse, and invalidateTenant eviction verified";
  });

  return { ok: allPassed, groups };
}

runSuite()
  .then((res) => {
    process.stdout.write(JSON.stringify(res) + "\n");
    process.exit(res.ok ? 0 : 1);
  })
  .catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    process.stdout.write(JSON.stringify({ ok: false, error: msg }) + "\n");
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

    raw_blobs: list[str] = []
    for key in ("files", "file"):
        val = data.get(key)
        if isinstance(val, str):
            raw_blobs.append(val)
        elif isinstance(val, list):
            raw_blobs.extend(json.dumps(x) if isinstance(x, dict) else str(x) for x in val)

    findings = data.get("findings")
    if isinstance(findings, list):
        for item in findings:
            raw_blobs.append(json.dumps(item) if isinstance(item, dict) else str(item))

    mentioned = {
        Path(tok).name
        for blob in raw_blobs
        for tok in re.findall(r"[\w./-]+\.ts", blob)
    }
    matched_core = mentioned & CORE_FILES
    if len(matched_core) < 3:
        return False, f"Expected report.json to reference at least 3 core modules from {sorted(CORE_FILES)}, got {sorted(mentioned)}"

    if not isinstance(findings, list) or len(findings) < 3:
        return False, "Expected at least 3 documented findings in report.json"
    for item in findings:
        text = json.dumps(item) if isinstance(item, dict) else str(item)
        if len(text.strip()) < 20 or "placeholder" in text.lower():
            return False, f"Finding entry is too brief or invalid: {text!r}"

    summary = data.get("summary")
    if not isinstance(summary, str) or len(summary.strip()) < 15:
        return False, "Expected a non-empty 'summary' string in report.json"

    return True, f"Report validated (covered {sorted(matched_core)})"


def check_regression_suite(app_dir: Path, orig_app: Path) -> tuple[bool, str]:
    suite_file = app_dir / "test" / "federation.test.ts"
    if not suite_file.is_file():
        return False, "Missing /app/test/federation.test.ts"

    try:
        pass_run = subprocess.run(
            ["node", "--experimental-strip-types", "--test", str(suite_file)],
            cwd=str(app_dir),
            capture_output=True,
            text=True,
            timeout=45,
        )
    except subprocess.TimeoutExpired:
        return False, "federation.test.ts timed out after 45s against updated /app"
    if pass_run.returncode != 0:
        return False, f"federation.test.ts failed against updated /app:\n{(pass_run.stdout + pass_run.stderr)[-1500:]}"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        shutil.copy2(orig_app / "package.json", tmp / "package.json")
        shutil.copytree(orig_app / "src", tmp / "src")
        (tmp / "test").mkdir(parents=True, exist_ok=True)
        shutil.copy2(suite_file, tmp / "test" / "federation.test.ts")

        try:
            fail_run = subprocess.run(
                ["node", "--experimental-strip-types", "--test", str(tmp / "test" / "federation.test.ts")],
                cwd=str(tmp),
                capture_output=True,
                text=True,
                timeout=45,
            )
        except subprocess.TimeoutExpired:
            return True, "Regression suite passes on hardened code and fails (timed out after assertion failure) on original code"
        if fail_run.returncode == 0:
            return False, "Updated federation.test.ts unexpectedly passed against original unpatched src/"

    return True, "Regression suite passes on hardened code and fails on original unmodified code"


def check_live_planner(app_dir: Path) -> tuple[bool, dict[str, object]]:
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

    ok_live, live_details = check_live_planner(app_dir)
    results["live_planner"] = live_details
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
