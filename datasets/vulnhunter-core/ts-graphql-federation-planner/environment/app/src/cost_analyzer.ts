/**
 * Static GraphQL Query Depth & Complexity Cost Analyzer.
 *
 * Architectural Contracts:
 *  1. Every field selection in the expanded execution tree contributes
 *     `fieldWeight + listMultiplier * childSelectionCost`.
 *  2. Named fragment spreads (`...Frag`) charge their full subtree cost on EVERY
 *     spread site (including aliased siblings), while cyclic fragment graphs
 *     (`FragA -> FragB -> FragA`) must be rejected with `FRAGMENT_CYCLE`.
 *  3. List multiplier arguments (`limit`, `first`, etc.) must evaluate both literal
 *     `IntValue` arguments AND runtime `$variable` bindings (falling back to
 *     `defaultMultiplier` when omitted), rejecting negative or non-integer values
 *     with `INVALID_COST_MULTIPLIER`.
 *  4. For abstract parent types (`Interface` / `Union`), the cost of an selection set
 *     evaluates the maximum cost across possible concrete object types.
 */

import {
  GraphQLError,
  type DocumentNode,
  type FieldNode,
  type OperationDefinitionNode,
  type SelectionNode,
} from "./ast.ts";
import { SupergraphSchema, type CostSpec, type FieldDef } from "./schema.ts";

export interface CostLimits {
  maxDepth: number;
  maxCost: number;
}

export interface CostAnalysisResult {
  totalCost: number;
  maxDepthObserved: number;
}

export const DEFAULT_COST_LIMITS: CostLimits = {
  maxDepth: 8,
  maxCost: 120,
};

export class QueryCostError extends GraphQLError {
  constructor(message: string, code: "MAX_DEPTH_EXCEEDED" | "MAX_COST_EXCEEDED" | "FRAGMENT_CYCLE" | "INVALID_COST_MULTIPLIER") {
    super(message, code);
    this.name = "QueryCostError";
  }
}

function lookupFieldCostSpec(
  schema: SupergraphSchema,
  parentTypeName: string,
  fieldName: string,
): { cost: CostSpec; returnType: string; isList: boolean; fieldDef?: FieldDef } | undefined {
  if (fieldName === "__typename") {
    return { cost: { weight: 0 }, returnType: "String", isList: false };
  }
  const obj = schema.getObjectType(parentTypeName);
  if (obj) {
    const f = obj.fields[fieldName];
    if (!f) return undefined;
    const defaultWeight = schema.isCompositeType(f.typeName) ? 1 : 0;
    return {
      cost: f.cost ?? { weight: defaultWeight },
      returnType: f.typeName,
      isList: Boolean(f.isList),
      fieldDef: f,
    };
  }
  const t = schema.getType(parentTypeName);
  if (t?.kind === "INTERFACE") {
    const f = t.fields[fieldName];
    if (!f) return undefined;
    const defaultWeight = schema.isCompositeType(f.typeName) ? 1 : 0;
    return {
      cost: f.cost ?? { weight: defaultWeight },
      returnType: f.typeName,
      isList: Boolean(f.isList),
    };
  }
  return undefined;
}

function resolveListMultiplier(
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
}

function assertNoFragmentCycles(doc: DocumentNode): void {
  const visiting = new Set<string>();
  const verified = new Set<string>();

  const walkSelections = (selections: ReadonlyArray<SelectionNode>) => {
    for (const sel of selections) {
      if (sel.kind === "Field" && sel.selectionSet.length > 0) {
        walkSelections(sel.selectionSet);
      } else if (sel.kind === "InlineFragment") {
        walkSelections(sel.selectionSet);
      } else if (sel.kind === "FragmentSpread") {
        visitFrag(sel.name);
      }
    }
  };

  const visitFrag = (name: string) => {
    if (verified.has(name)) return;
    if (visiting.has(name)) {
      throw new QueryCostError(`Cyclic fragment spread involving '${name}'`, "FRAGMENT_CYCLE");
    }
    const frag = doc.fragments.get(name);
    if (!frag) {
      throw new GraphQLError(`Unknown fragment '${name}'`, "UNKNOWN_FRAGMENT");
    }
    visiting.add(name);
    walkSelections(frag.selectionSet);
    visiting.delete(name);
    verified.add(name);
  };

  for (const op of doc.operations) {
    walkSelections(op.selectionSet);
  }
}

export function analyzeQueryCost(
  doc: DocumentNode,
  op: OperationDefinitionNode,
  schema: SupergraphSchema,
  variables: Readonly<Record<string, unknown>>,
  limits: CostLimits = DEFAULT_COST_LIMITS,
): CostAnalysisResult {
  assertNoFragmentCycles(doc);

  let maxDepthObserved = 0;
  const expandedFragments = new Set<string>();

  const evaluateSelectionSet = (
    parentTypeName: string,
    selections: ReadonlyArray<SelectionNode>,
    currentDepth: number,
  ): number => {
    let sum = 0;
    for (const sel of selections) {
      if (sel.kind === "Field") {
        const fieldDepth = sel.name === "__typename" ? currentDepth : currentDepth + 1;
        if (fieldDepth > maxDepthObserved) maxDepthObserved = fieldDepth;
        if (fieldDepth > limits.maxDepth) {
          throw new QueryCostError(
            `Query depth ${fieldDepth} exceeds maximum allowed depth ${limits.maxDepth}`,
            "MAX_DEPTH_EXCEEDED",
          );
        }

        const spec = lookupFieldCostSpec(schema, parentTypeName, sel.name);
        if (!spec) {
          throw new GraphQLError(
            `Cannot query field '${sel.name}' on type '${parentTypeName}'`,
            "GRAPHQL_VALIDATION_FAILED",
          );
        }

        const multiplier = resolveListMultiplier(sel, spec.cost, variables);
        let childCost = 0;
        if (sel.selectionSet.length > 0) {
          childCost = evaluateTypeSelections(spec.returnType, sel.selectionSet, fieldDepth);
        }
        sum += spec.cost.weight + multiplier * childCost;
      } else if (sel.kind === "InlineFragment") {
        const targetType = sel.typeCondition ?? parentTypeName;
        if (sel.typeCondition && !schema.doesFragmentTypeApply(parentTypeName, sel.typeCondition)) {
          throw new GraphQLError(
            `Fragment on '${sel.typeCondition}' cannot be spread within '${parentTypeName}'`,
            "GRAPHQL_VALIDATION_FAILED",
          );
        }
        sum += evaluateTypeSelections(targetType, sel.selectionSet, currentDepth);
      } else if (sel.kind === "FragmentSpread") {
        const frag = doc.fragments.get(sel.name);
        if (!frag) {
          throw new GraphQLError(`Unknown fragment '${sel.name}'`, "UNKNOWN_FRAGMENT");
        }
        if (!schema.doesFragmentTypeApply(parentTypeName, frag.typeCondition)) {
          throw new GraphQLError(
            `Fragment '${frag.name}' on '${frag.typeCondition}' cannot be spread within '${parentTypeName}'`,
            "GRAPHQL_VALIDATION_FAILED",
          );
        }
        if (expandedFragments.has(frag.name)) {
          continue;
        }
        expandedFragments.add(frag.name);
        sum += evaluateTypeSelections(frag.typeCondition, frag.selectionSet, currentDepth);
      }
    }
    return sum;
  };

  const evaluateTypeSelections = (
    typeName: string,
    selections: ReadonlyArray<SelectionNode>,
    currentDepth: number,
  ): number => {
    const t = schema.getType(typeName);
    if (!t) {
      throw new GraphQLError(`Unknown schema type '${typeName}'`, "GRAPHQL_VALIDATION_FAILED");
    }
    if (t.kind === "OBJECT") {
      return evaluateSelectionSet(t.name, selections, currentDepth);
    }
    if (t.kind === "INTERFACE" || t.kind === "UNION") {
      const concretes = schema.getPossibleConcreteTypes(typeName);
      let worstCase = 0;
      for (const concreteName of concretes) {
        const filtered = selections.filter((s) => {
          if (s.kind === "InlineFragment" && s.typeCondition) {
            return schema.doesFragmentTypeApply(concreteName, s.typeCondition);
          }
          if (s.kind === "FragmentSpread") {
            const f = doc.fragments.get(s.name);
            return f ? schema.doesFragmentTypeApply(concreteName, f.typeCondition) : false;
          }
          return true;
        });
        if (filtered.length > 0) {
          const c = evaluateSelectionSet(concreteName, filtered, currentDepth);
          if (c > worstCase) worstCase = c;
        }
      }
      return worstCase;
    }
    return 0;
  };

  const rootTypeName = op.operation === "mutation" ? schema.mutationTypeName : schema.queryTypeName;
  const totalCost = evaluateTypeSelections(rootTypeName, op.selectionSet, 0);
  if (totalCost > limits.maxCost) {
    throw new QueryCostError(
      `Query complexity cost ${totalCost} exceeds budget ${limits.maxCost}`,
      "MAX_COST_EXCEEDED",
    );
  }
  return { totalCost, maxDepthObserved };
}
