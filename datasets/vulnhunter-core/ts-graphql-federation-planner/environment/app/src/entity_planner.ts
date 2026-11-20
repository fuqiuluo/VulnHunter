/**
 * Federated Query Execution Planner, `_entities` Batch Resolver, and Output Projector.
 *
 * Architectural Contracts:
 *  1. Root query fields dispatch to their owning subgraph, then cross-subgraph entity
 *     fields (including `@requires` prerequisites from the entity's owner subgraph)
 *     are batch-resolved in topological order.
 *  2. When resolving a list of entities containing `null` slots or duplicate `@key`
 *     references (for example `[u-1, null, u-1, u-2]`), deduplicated subgraph batch
 *     results MUST be correlated back to every entity slot by its exact `@key` value.
 *  3. Response projection MUST emit ONLY the fields and aliases explicitly selected by
 *     the client operation — internal `@key` or `@requires` prerequisite fields fetched
 *     solely to satisfy downstream subgraph joins (such as `rawCreditScore` when computing
 *     `netRiskBand`) must NEVER leak into the client's JSON response unless the client
 *     explicitly selected (and was authorized for) them.
 */

import {
  GraphQLError,
  resolveFieldArguments,
  type DocumentNode,
  type FieldNode,
  type OperationDefinitionNode,
  type SelectionNode,
} from "./ast.ts";
import { EntityResolutionCache } from "./entity_cache.ts";
import { SupergraphSchema, type ObjectTypeDef } from "./schema.ts";
import type { EntityRepresentation, SubgraphRequestContext, SubgraphService } from "./subgraphs.ts";

interface CollectedFieldEntry {
  responseKey: string;
  fieldName: string;
  fieldNodes: FieldNode[];
}

function collectConcreteFields(
  doc: DocumentNode,
  schema: SupergraphSchema,
  concreteType: ObjectTypeDef,
  selections: ReadonlyArray<SelectionNode>,
  visitedFrags = new Set<string>(),
): Map<string, CollectedFieldEntry> {
  const grouped = new Map<string, CollectedFieldEntry>();

  const visit = (sels: ReadonlyArray<SelectionNode>) => {
    for (const sel of sels) {
      if (sel.kind === "Field") {
        const responseKey = sel.alias ?? sel.name;
        const existing = grouped.get(responseKey);
        if (existing) {
          existing.fieldNodes.push(sel);
        } else {
          grouped.set(responseKey, {
            responseKey,
            fieldName: sel.name,
            fieldNodes: [sel],
          });
        }
      } else if (sel.kind === "InlineFragment") {
        if (!sel.typeCondition || schema.doesFragmentTypeApply(concreteType.name, sel.typeCondition)) {
          visit(sel.selectionSet);
        }
      } else if (sel.kind === "FragmentSpread") {
        const frag = doc.fragments.get(sel.name);
        if (!frag) continue;
        if (visitedFrags.has(frag.name)) continue;
        if (schema.doesFragmentTypeApply(concreteType.name, frag.typeCondition)) {
          visitedFrags.add(frag.name);
          visit(frag.selectionSet);
          visitedFrags.delete(frag.name);
        }
      }
    }
  };

  visit(selections);
  return grouped;
}

function serializeEntityKey(objType: ObjectTypeDef, record: Record<string, unknown>): string | null {
  if (!objType.keyFields || objType.keyFields.length === 0) return null;
  const parts: string[] = [];
  for (const kf of objType.keyFields) {
    const val = record[kf];
    if (val === undefined || val === null) return null;
    parts.push(`${kf}=${JSON.stringify(val)}`);
  }
  return parts.join("&");
}

async function batchHydrateSubgraphFields(
  subgraphName: string,
  objType: ObjectTypeDef,
  entities: Array<Record<string, unknown> | null>,
  neededFields: ReadonlySet<string>,
  requiredInputs: ReadonlySet<string>,
  services: ReadonlyMap<string, SubgraphService>,
  cache: EntityResolutionCache,
  ctx: SubgraphRequestContext,
): Promise<void> {
  if (neededFields.size === 0) return;
  const svc = services.get(subgraphName);
  if (!svc) {
    throw new GraphQLError(`Missing subgraph service '${subgraphName}'`, "SUBGRAPH_UNAVAILABLE");
  }

  // Identify entities missing at least one needed field
  const targets: Array<{ entity: Record<string, unknown>; keyStr: string }> = [];
  for (const ent of entities) {
    if (!ent || ent.__typename !== objType.name) continue;
    const missing = [...neededFields].some((f) => !(f in ent));
    if (!missing) continue;
    const keyStr = serializeEntityKey(objType, ent);
    if (!keyStr) continue;
    targets.push({ entity: ent, keyStr });
  }
  if (targets.length === 0) return;

  // Deduplicate representations before calling subgraph (skipping cache hits)
  const uniqueReps: EntityRepresentation[] = [];
  const seenKeys = new Set<string>();
  const uncachedTargets: Array<{ entity: Record<string, unknown>; keyStr: string }> = [];

  for (const item of targets) {
    const canUseCache = requiredInputs.size === 0;
    if (canUseCache) {
      const cached = cache.get(ctx.tenantId, subgraphName, objType.name, item.keyStr, neededFields);
      if (cached) {
        Object.assign(item.entity, cached);
        continue;
      }
    }
    uncachedTargets.push(item);
    if (!seenKeys.has(item.keyStr)) {
      seenKeys.add(item.keyStr);
      const rep: EntityRepresentation = { __typename: objType.name };
      for (const kf of objType.keyFields ?? []) {
        rep[kf] = item.entity[kf];
      }
      for (const reqField of requiredInputs) {
        rep[reqField] = item.entity[reqField];
      }
      uniqueReps.push(rep);
    }
  }

  if (uniqueReps.length === 0) return;

  const resolvedRows = await svc.resolveEntities(objType.name, uniqueReps, neededFields, ctx);

  // Merge resolved rows back onto uncached targets
  for (let i = 0; i < uncachedTargets.length; i += 1) {
    const row = resolvedRows[i] ?? resolvedRows[resolvedRows.length - 1];
    if (!row) continue;
    Object.assign(uncachedTargets[i].entity, row);
    if (requiredInputs.size === 0) {
      cache.set(ctx.tenantId, subgraphName, objType.name, uncachedTargets[i].keyStr, neededFields, row);
    }
  }
}

export interface ExecutePlanInput {
  doc: DocumentNode;
  op: OperationDefinitionNode;
  schema: SupergraphSchema;
  variables: Readonly<Record<string, unknown>>;
  services: ReadonlyMap<string, SubgraphService>;
  cache: EntityResolutionCache;
  ctx: SubgraphRequestContext;
}

export async function executeFederatedOperation(
  input: ExecutePlanInput,
): Promise<Record<string, unknown>> {
  const { doc, op, schema, variables, services, cache, ctx } = input;
  const queryObjType = schema.getObjectType(schema.queryTypeName);
  if (!queryObjType) {
    throw new GraphQLError("Schema missing Query root type");
  }

  const hydrateAndProjectValue = async (
    rawVal: unknown,
    declaredTypeName: string,
    isList: boolean,
    selections: ReadonlyArray<SelectionNode>,
  ): Promise<unknown> => {
    if (rawVal === null || rawVal === undefined) return null;
    if (!schema.isCompositeType(declaredTypeName)) {
      return rawVal;
    }

    if (isList) {
      if (!Array.isArray(rawVal)) return null;
      const listRecords = rawVal as Array<Record<string, unknown> | null>;
      await hydrateEntityCollection(listRecords, selections);
      const projectedList: unknown[] = [];
      for (const item of listRecords) {
        if (item === null || item === undefined) {
          projectedList.push(null);
        } else {
          projectedList.push(await projectSingleEntity(item, selections));
        }
      }
      return projectedList;
    }

    const singleRecord = rawVal as Record<string, unknown>;
    await hydrateEntityCollection([singleRecord], selections);
    return projectSingleEntity(singleRecord, selections);
  };

  const hydrateEntityCollection = async (
    records: Array<Record<string, unknown> | null>,
    selections: ReadonlyArray<SelectionNode>,
  ): Promise<void> => {
    // Group records by runtime `__typename`
    const byType = new Map<string, Array<Record<string, unknown>>>();
    for (const rec of records) {
      if (!rec || typeof rec.__typename !== "string") continue;
      const list = byType.get(rec.__typename) ?? [];
      list.push(rec);
      byType.set(rec.__typename, list);
    }

    for (const [typeName, group] of byType.entries()) {
      const objType = schema.getObjectType(typeName);
      if (!objType) continue;

      const collected = collectConcreteFields(doc, schema, objType, selections);
      const bySubgraph = new Map<string, Set<string>>();
      const requiredPrereqs = new Set<string>();
      const requiredBySubgraph = new Map<string, Set<string>>();

      for (const entry of collected.values()) {
        if (entry.fieldName === "__typename") continue;
        const fDef = objType.fields[entry.fieldName];
        if (!fDef) continue;
        const sgSet = bySubgraph.get(fDef.subgraph) ?? new Set<string>();
        sgSet.add(fDef.name);
        bySubgraph.set(fDef.subgraph, sgSet);

        if (fDef.requires && fDef.requires.length > 0) {
          const reqSet = requiredBySubgraph.get(fDef.subgraph) ?? new Set<string>();
          for (const r of fDef.requires) {
            requiredPrereqs.add(r);
            reqSet.add(r);
          }
          requiredBySubgraph.set(fDef.subgraph, reqSet);
        }
      }

      // Phase 1: Hydrate owner subgraph fields (including any `@requires` prerequisites)
      const ownerNeeded = new Set<string>(bySubgraph.get(objType.ownerSubgraph) ?? []);
      for (const r of requiredPrereqs) {
        ownerNeeded.add(r);
      }
      if (ownerNeeded.size > 0) {
        await batchHydrateSubgraphFields(
          objType.ownerSubgraph,
          objType,
          records,
          ownerNeeded,
          new Set(),
          services,
          cache,
          ctx,
        );
      }

      // Phase 2: Hydrate extending subgraphs now that `@requires` fields are populated
      for (const [sgName, sgFields] of bySubgraph.entries()) {
        if (sgName === objType.ownerSubgraph) continue;
        const reqs = requiredBySubgraph.get(sgName) ?? new Set<string>();
        await batchHydrateSubgraphFields(
          sgName,
          objType,
          records,
          sgFields,
          reqs,
          services,
          cache,
          ctx,
        );
      }
    }
  };

  const projectSingleEntity = async (
    entity: Record<string, unknown>,
    selections: ReadonlyArray<SelectionNode>,
  ): Promise<Record<string, unknown>> => {
    const typeName = String(entity.__typename ?? "");
    const objType = schema.getObjectType(typeName);
    if (!objType) {
      throw new GraphQLError(`Cannot resolve runtime object type '${typeName}'`);
    }

    const collected = collectConcreteFields(doc, schema, objType, selections);
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
    }

    for (const [responseKey, entry] of collected.entries()) {
      if (entry.fieldName === "__typename") {
        out[responseKey] = objType.name;
        continue;
      }
      const fDef = objType.fields[entry.fieldName];
      if (!fDef) continue;

      let rawFieldVal = entity[fDef.name];
      // Apply list slice argument if field is an embedded list (e.g. `Order.lines(limit: ...)`)
      if (fDef.isList && Array.isArray(rawFieldVal) && fDef.args?.limit) {
        const defaults: Record<string, unknown> = { limit: fDef.args.limit.defaultValue };
        const fArgs = resolveFieldArguments(entry.fieldNodes[0], variables, defaults);
        if (typeof fArgs.limit === "number") {
          rawFieldVal = rawFieldVal.slice(0, Math.max(0, fArgs.limit));
        }
      }

      if (schema.isCompositeType(fDef.typeName)) {
        const mergedChildSelections: SelectionNode[] = [];
        for (const fn of entry.fieldNodes) {
          mergedChildSelections.push(...fn.selectionSet);
        }
        out[responseKey] = await hydrateAndProjectValue(
          rawFieldVal,
          fDef.typeName,
          Boolean(fDef.isList),
          mergedChildSelections,
        );
      } else {
        out[responseKey] = rawFieldVal ?? null;
      }
    }

    return out;
  };

  // Root Query execution
  const rootCollected = collectConcreteFields(doc, schema, queryObjType, op.selectionSet);
  const dataOut: Record<string, unknown> = {};

  for (const [responseKey, entry] of rootCollected.entries()) {
    if (entry.fieldName === "__typename") {
      dataOut[responseKey] = queryObjType.name;
      continue;
    }
    const rootFieldDef = queryObjType.fields[entry.fieldName];
    if (!rootFieldDef) {
      throw new GraphQLError(
        `Cannot query field '${entry.fieldName}' on type 'Query'`,
        "GRAPHQL_VALIDATION_FAILED",
      );
    }

    const argDefaults: Record<string, unknown> = {};
    if (rootFieldDef.args) {
      for (const [k, spec] of Object.entries(rootFieldDef.args)) {
        if (spec.defaultValue !== undefined) argDefaults[k] = spec.defaultValue;
      }
    }
    const resolvedArgs = resolveFieldArguments(entry.fieldNodes[0], variables, argDefaults);

    if (rootFieldDef.name === "_entities") {
      const reps = Array.isArray(resolvedArgs.representations)
        ? (resolvedArgs.representations as Array<Record<string, unknown>>)
        : [];
      const cloned = reps.map((r) => (r && typeof r === "object" ? { ...r } : null));
      const mergedSels: SelectionNode[] = [];
      for (const fn of entry.fieldNodes) mergedSels.push(...fn.selectionSet);
      dataOut[responseKey] = await hydrateAndProjectValue(cloned, rootFieldDef.typeName, true, mergedSels);
      continue;
    }

    const svc = services.get(rootFieldDef.subgraph);
    if (!svc) {
      throw new GraphQLError(`Subgraph '${rootFieldDef.subgraph}' not registered`, "SUBGRAPH_UNAVAILABLE");
    }

    const rawRootVal = await svc.resolveRootField(rootFieldDef.name, resolvedArgs, ctx);
    const mergedChildSelections: SelectionNode[] = [];
    for (const fn of entry.fieldNodes) {
      mergedChildSelections.push(...fn.selectionSet);
    }

    dataOut[responseKey] = await hydrateAndProjectValue(
      rawRootVal,
      rootFieldDef.typeName,
      Boolean(rootFieldDef.isList),
      mergedChildSelections,
    );
  }

  return dataOut;
}
