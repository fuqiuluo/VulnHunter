#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "src/cost_analyzer.ts",
    "src/auth_policy.ts",
    "src/entity_planner.ts",
    "src/entity_cache.ts"
  ],
  "findings": [
    "Static query complexity analysis tracked expanded named fragments in a query-global Set rather than per recursion stack, skipping cost accounting on repeated fragment spreads across aliases, and ignored runtime $variable bindings on list-multiplier arguments.",
    "Directive authorization skipped untyped inline fragments (`... { field }`), evaluated interface field selections solely against interface stubs without checking concrete implementing object `@auth` rules, and permitted external clients to invoke internal `_entities` and `_service` protocol fields.",
    "Federated entity batch hydration correlated deduplicated `_entities` subgraph responses back onto target entities by sequential array offset rather than canonical `@key`, corrupting lists containing `null` or duplicate entity references, and leaked unrequested `@requires` prerequisite fields into projected client responses.",
    "EntityResolutionCache constructed lookup keys without scoping by `tenantId`, causing cross-tenant entity data bleed on colliding entity IDs and preventing `invalidateTenant()` from matching stored cache entries."
  ],
  "summary": "Hardened query cost accounting for repeated fragment spreads and variable multipliers, enforced `@auth` across untyped inline fragments and concrete interface implementations while blocking external `_entities`/`_service` queries, correlated subgraph batch joins by canonical `@key` without leaking unrequested `@requires` fields, and isolated entity cache keys by tenant."
}
EOF

python3 - "$APP_DIR" <<'PY'
from pathlib import Path
import sys

app = Path(sys.argv[1])

# 1. Patch src/cost_analyzer.ts
ca_path = app / "src" / "cost_analyzer.ts"
ca = ca_path.read_text(encoding="utf-8")

old_mult = """function resolveListMultiplier(
  field: FieldNode,
  costSpec: CostSpec,
  _variables: Readonly<Record<string, unknown>>,
): number {
  if (!costSpec.multipliers || costSpec.multipliers.length === 0) {
    return 1;
  }
  for (const multArgName of costSpec.multipliers) {
    const argNode = field.arguments.find((a) => a.name === multArgName);
    if (!argNode) continue;
    if (argNode.value.kind === "IntValue") {
      if (argNode.value.value < 0) {
        throw new QueryCostError(
          `Multiplier argument '${multArgName}' on field '${field.name}' cannot be negative`,
          "INVALID_COST_MULTIPLIER",
        );
      }
      return Math.max(1, argNode.value.value);
    }
    // Falls back to 1 when non-IntValue (e.g. Variable) is supplied
    return 1;
  }
  return Math.max(1, costSpec.defaultMultiplier ?? 1);
}"""

new_mult = """function resolveListMultiplier(
  field: FieldNode,
  costSpec: CostSpec,
  variables: Readonly<Record<string, unknown>>,
): number {
  if (!costSpec.multipliers || costSpec.multipliers.length === 0) {
    return 1;
  }
  for (const multArgName of costSpec.multipliers) {
    const argNode = field.arguments.find((a) => a.name === multArgName);
    if (!argNode) continue;
    let rawVal: unknown;
    if (argNode.value.kind === "IntValue") {
      rawVal = argNode.value.value;
    } else if (argNode.value.kind === "Variable") {
      rawVal = Object.prototype.hasOwnProperty.call(variables, argNode.value.name)
        ? variables[argNode.value.name]
        : undefined;
      if (rawVal === undefined || rawVal === null) continue;
    } else if (argNode.value.kind === "NullValue") {
      continue;
    } else {
      throw new QueryCostError(
        `Multiplier argument '${multArgName}' on field '${field.name}' must be an integer`,
        "INVALID_COST_MULTIPLIER",
      );
    }
    if (typeof rawVal !== "number" || !Number.isSafeInteger(rawVal) || rawVal < 0) {
      throw new QueryCostError(
        `Multiplier argument '${multArgName}' on field '${field.name}' must be a non-negative integer`,
        "INVALID_COST_MULTIPLIER",
      );
    }
    return Math.max(1, rawVal);
  }
  return Math.max(1, costSpec.defaultMultiplier ?? 1);
}"""

assert old_mult in ca, "resolveListMultiplier block not found"
ca = ca.replace(old_mult, new_mult, 1)

old_frag_cost = """        if (expandedFragments.has(frag.name)) {
          continue;
        }
        expandedFragments.add(frag.name);
        sum += evaluateTypeSelections(frag.typeCondition, frag.selectionSet, currentDepth);"""

new_frag_cost = """        if (expandedFragments.has(frag.name)) {
          throw new QueryCostError(`Cyclic fragment spread involving '${frag.name}'`, "FRAGMENT_CYCLE");
        }
        expandedFragments.add(frag.name);
        try {
          sum += evaluateTypeSelections(frag.typeCondition, frag.selectionSet, currentDepth);
        } finally {
          expandedFragments.delete(frag.name);
        }"""

assert old_frag_cost in ca, "FragmentSpread cost block not found"
ca = ca.replace(old_frag_cost, new_frag_cost, 1)
ca_path.write_text(ca, encoding="utf-8")

# 2. Patch src/auth_policy.ts
ap_path = app / "src" / "auth_policy.ts"
ap = ap_path.read_text(encoding="utf-8")

old_auth_obj = """        if (parentType.kind === "OBJECT") {
          const fieldDef = parentType.fields[sel.name];
          if (!fieldDef) {
            throw new GraphQLError(
              `Cannot query field '${sel.name}' on type '${parentType.name}'`,
              "GRAPHQL_VALIDATION_FAILED",
            );
          }
          if (!satisfiesAuthRule(principal, fieldDef.auth)) {"""

new_auth_obj = """        if (parentType.kind === "OBJECT") {
          const fieldDef = parentType.fields[sel.name];
          if (!fieldDef) {
            throw new GraphQLError(
              `Cannot query field '${sel.name}' on type '${parentType.name}'`,
              "GRAPHQL_VALIDATION_FAILED",
            );
          }
          if (fieldDef.internalProtocolField) {
            throw new AuthorizationError(
              `Internal federation field '${parentType.name}.${sel.name}' is not accessible to external clients`,
              "FORBIDDEN_PROTOCOL_FIELD",
            );
          }
          if (!satisfiesAuthRule(principal, fieldDef.auth)) {"""

assert old_auth_obj in ap, "auth_policy OBJECT block not found"
ap = ap.replace(old_auth_obj, new_auth_obj, 1)

old_auth_iface = """          if (!satisfiesAuthRule(principal, ifaceField.auth)) {
            throw new AuthorizationError(
              `Principal '${principal.principalId}' is not authorized to read '${parentType.name}.${sel.name}'`,
            );
          }
          if (sel.selectionSet.length > 0) {"""

new_auth_iface = """          if (!satisfiesAuthRule(principal, ifaceField.auth)) {
            throw new AuthorizationError(
              `Principal '${principal.principalId}' is not authorized to read '${parentType.name}.${sel.name}'`,
            );
          }
          for (const implName of parentType.implementedBy) {
            const implObj = schema.getObjectType(implName);
            if (!implObj) continue;
            if (!satisfiesAuthRule(principal, implObj.auth)) {
              throw new AuthorizationError(`Principal lacks access to implementing type '${implObj.name}'`);
            }
            const implField = implObj.fields[sel.name];
            if (implField && !satisfiesAuthRule(principal, implField.auth)) {
              throw new AuthorizationError(
                `Principal '${principal.principalId}' is not authorized to read '${implObj.name}.${sel.name}' via interface '${parentType.name}'`,
              );
            }
          }
          if (sel.selectionSet.length > 0) {"""

assert old_auth_iface in ap, "auth_policy INTERFACE block not found"
ap = ap.replace(old_auth_iface, new_auth_iface, 1)

old_auth_inline = """      } else if (sel.kind === "InlineFragment") {
        if (!sel.typeCondition) {
          continue;
        }
        checkSelections(sel.typeCondition, sel.selectionSet);"""

new_auth_inline = """      } else if (sel.kind === "InlineFragment") {
        const targetType = sel.typeCondition ?? parentTypeName;
        checkSelections(targetType, sel.selectionSet);"""

assert old_auth_inline in ap, "auth_policy InlineFragment block not found"
ap = ap.replace(old_auth_inline, new_auth_inline, 1)
ap_path.write_text(ap, encoding="utf-8")

# 3. Patch src/entity_planner.ts
ep_path = app / "src" / "entity_planner.ts"
ep = ep_path.read_text(encoding="utf-8")

old_merge = """  const resolvedRows = await svc.resolveEntities(objType.name, uniqueReps, neededFields, ctx);

  // Merge resolved rows back onto uncached targets
  for (let i = 0; i < uncachedTargets.length; i += 1) {
    const row = resolvedRows[i] ?? resolvedRows[resolvedRows.length - 1];
    if (!row) continue;
    Object.assign(uncachedTargets[i].entity, row);
    if (requiredInputs.size === 0) {
      cache.set(ctx.tenantId, subgraphName, objType.name, uncachedTargets[i].keyStr, neededFields, row);
    }
  }"""

new_merge = """  const resolvedRows = await svc.resolveEntities(objType.name, uniqueReps, neededFields, ctx);

  const resolvedByKey = new Map<string, Record<string, unknown>>();
  for (let i = 0; i < uniqueReps.length; i += 1) {
    const row = resolvedRows[i];
    if (!row) continue;
    const repKey = serializeEntityKey(objType, uniqueReps[i]);
    if (repKey) {
      resolvedByKey.set(repKey, row);
      if (requiredInputs.size === 0) {
        cache.set(ctx.tenantId, subgraphName, objType.name, repKey, neededFields, row);
      }
    }
  }

  for (const target of uncachedTargets) {
    const row = resolvedByKey.get(target.keyStr);
    if (row) {
      Object.assign(target.entity, row);
    }
  }"""

assert old_merge in ep, "entity_planner batch merge block not found"
ep = ep.replace(old_merge, new_merge, 1)

old_proj = """    const collected = collectConcreteFields(doc, schema, objType, selections);
    // Start with any prefetched `@requires` metadata needed by selected computed fields
    const out: Record<string, unknown> = {};
    for (const entry of collected.values()) {
      const fDef = objType.fields[entry.fieldName];
      if (fDef?.requires) {
        for (const reqName of fDef.requires) {
          if (reqName in entity) {
            out[reqName] = entity[reqName];
          }
        }
      }
    }"""

new_proj = """    const collected = collectConcreteFields(doc, schema, objType, selections);
    const out: Record<string, unknown> = {};"""

assert old_proj in ep, "entity_planner projectSingleEntity block not found"
ep = ep.replace(old_proj, new_proj, 1)
ep_path.write_text(ep, encoding="utf-8")

# 4. Patch src/entity_cache.ts
ec_path = app / "src" / "entity_cache.ts"
ec = ec_path.read_text(encoding="utf-8")

old_cache_key = """  private buildCacheKey(
    _tenantId: string,
    subgraph: string,
    typename: string,
    canonicalEntityKey: string,
    requestedFields: ReadonlySet<string>,
  ): string {
    const sortedFields = [...requestedFields].sort().join(",");
    return `${subgraph}:${typename}:${canonicalEntityKey}:[${sortedFields}]`;
  }"""

new_cache_key = """  private buildCacheKey(
    tenantId: string,
    subgraph: string,
    typename: string,
    canonicalEntityKey: string,
    requestedFields: ReadonlySet<string>,
  ): string {
    if (!tenantId) {
      throw new Error("EntityResolutionCache requires a non-empty tenantId");
    }
    const sortedFields = [...requestedFields].sort().join(",");
    return `${JSON.stringify(tenantId)}:${subgraph}:${typename}:${canonicalEntityKey}:[${sortedFields}]`;
  }"""

assert old_cache_key in ec, "entity_cache buildCacheKey not found"
ec = ec.replace(old_cache_key, new_cache_key, 1)

old_inval = """      if (k.startsWith(`${tenantId}:`) && rec.tenantId === tenantId) {"""
new_inval = """      if (rec.tenantId === tenantId) {"""
assert old_inval in ec, "entity_cache invalidateTenant check not found"
ec = ec.replace(old_inval, new_inval, 1)
ec_path.write_text(ec, encoding="utf-8")

# 5. Append regression tests to test/federation.test.ts
test_path = app / "test" / "federation.test.ts"
tests_append = """

describe("FederatedGateway security and planner hardening regressions", () => {
  it("charges repeated fragment spreads across aliases and variable list multipliers", async () => {
    const gw = new FederatedGateway({ costLimits: { maxDepth: 8, maxCost: 60 } });
    const spreadRes = await gw.execute(
      {
        query: `
          fragment Heavy on Order { id totalCents buyer { id email netRiskBand } invoice { id amountCents } }
          {
            a1: order(id: "ord-1") { ...Heavy }
            a2: order(id: "ord-1") { ...Heavy }
            a3: order(id: "ord-1") { ...Heavy }
            a4: order(id: "ord-1") { ...Heavy }
            a5: order(id: "ord-1") { ...Heavy }
            a6: order(id: "ord-1") { ...Heavy }
            a7: order(id: "ord-1") { ...Heavy }
          }
        `,
      },
      { tenantId: "acme", principalId: "u1", role: "member", scopes: new Set() },
    );
    assert.equal(spreadRes.statusCode, 429);

    const varRes = await gw.execute(
      {
        query: `query BigOrders($n: Int!) { orders(limit: $n) { id buyer { id email } } }`,
        variables: { n: 50 },
      },
      { tenantId: "acme", principalId: "u1", role: "member", scopes: new Set() },
    );
    assert.equal(varRes.statusCode, 429);
  });

  it("enforces @auth on untyped inline fragments, concrete interface implementations, and blocks _entities", async () => {
    const gw = new FederatedGateway();
    const member = { tenantId: "acme", principalId: "u1", role: "member", scopes: new Set<string>() };

    const r1 = await gw.execute({ query: `{ user(id: "u-1") { ... { taxSsn } } }` }, member);
    assert.equal(r1.statusCode, 403);

    const r2 = await gw.execute({ query: `{ billableDocuments(first: 2) { id settlementIban } }` }, member);
    assert.equal(r2.statusCode, 403);

    const r3 = await gw.execute(
      {
        query: `query E($reps: JSON) { _entities(representations: $reps) { id } }`,
        variables: { reps: [{ __typename: "User", id: "u-1" }] },
      },
      { tenantId: "acme", principalId: "adm", role: "admin", scopes: new Set(["pii:tax:read"]) },
    );
    assert.equal(r3.statusCode, 403);
  });

  it("correlates duplicate/null entity batches by @key, strips unrequested @requires fields, and isolates tenant cache", async () => {
    const cluster = new InMemorySubgraphCluster();
    const gw = new FederatedGateway({ services: cluster.createServices() });

    const ordRes = await gw.execute(
      { query: `{ orders(limit: 4) { id buyer { id email netRiskBand } } }` },
      { tenantId: "acme", principalId: "u1", role: "member", scopes: new Set() },
    );
    assert.equal(ordRes.statusCode, 200);
    const list = ordRes.body.data?.orders as Array<{ id: string; buyer: Record<string, unknown> | null }>;
    assert.equal(list[1].buyer, null);
    assert.equal(list[2].buyer?.email, "alice@acme.example");
    assert.equal(list[3].buyer?.email, "bob@acme.example");
    assert.equal("rawCreditScore" in (list[0].buyer ?? {}), false);

    const globexRes = await gw.execute(
      { query: `{ order(id: "ord-1") { buyer { email } } }` },
      { tenantId: "globex", principalId: "g1", role: "member", scopes: new Set() },
    );
    assert.equal(
      ((globexRes.body.data?.order as Record<string, unknown>).buyer as Record<string, unknown>).email,
      "dana@globex.example",
    );
  });
});
"""
test_path.write_text(test_path.read_text(encoding="utf-8") + tests_append, encoding="utf-8")
PY

npm test
