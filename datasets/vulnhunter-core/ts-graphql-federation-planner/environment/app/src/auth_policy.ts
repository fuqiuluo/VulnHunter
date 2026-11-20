/**
 * Supergraph Field & Type Directive Authorization Policy Engine.
 *
 * Architectural Contracts:
 *  1. External gateway clients may NEVER select internal subgraph protocol fields
 *     (`_entities`, `_service`) on `Query`; those exist strictly for gateway-to-subgraph
 *     internal resolution.
 *  2. Every client-selected field must satisfy `@auth(roles, scopes)` across ALL
 *     selection syntax forms: direct fields, named fragment spreads, typed inline
 *     fragments (`... on User`), untyped inline fragments (`... { field }`), and
 *     abstract interface selections (`BillableDocument.settlementIban` must satisfy
 *     the `@auth` rules declared on every concrete implementing object type!).
 *  3. Note on `@requires`: when a client selects a public/authorized computed field
 *     such as `User.netRiskBand` (`@requires(fields: "rawCreditScore")`), the client
 *     does NOT need `@auth` permission for `rawCreditScore` UNLESS the client also
 *     explicitly selects `rawCreditScore` in the query selection set.
 */

import {
  GraphQLError,
  type DocumentNode,
  type OperationDefinitionNode,
  type SelectionNode,
} from "./ast.ts";
import { SupergraphSchema, type AuthRule } from "./schema.ts";

export interface GatewayPrincipal {
  tenantId: string;
  principalId: string;
  role: string;
  scopes: ReadonlySet<string>;
}

export class AuthorizationError extends GraphQLError {
  constructor(message: string, code: "FORBIDDEN_FIELD" | "FORBIDDEN_PROTOCOL_FIELD" | "UNAUTHENTICATED" = "FORBIDDEN_FIELD") {
    super(message, code);
    this.name = "AuthorizationError";
  }
}

export function satisfiesAuthRule(principal: GatewayPrincipal, rule: AuthRule | undefined): boolean {
  if (!rule) return true;
  if (rule.roles && rule.roles.length > 0) {
    const normalizedRole = principal.role.trim().toLowerCase();
    if (!rule.roles.some((r) => r.toLowerCase() === normalizedRole)) {
      return false;
    }
  }
  if (rule.scopes && rule.scopes.length > 0) {
    for (const reqScope of rule.scopes) {
      if (!principal.scopes.has(reqScope)) {
        return false;
      }
    }
  }
  return true;
}

export function authorizeOperation(
  doc: DocumentNode,
  op: OperationDefinitionNode,
  schema: SupergraphSchema,
  principal: GatewayPrincipal,
): void {
  if (!principal.tenantId || !principal.principalId) {
    throw new AuthorizationError("Authenticated tenant principal required", "UNAUTHENTICATED");
  }

  const activeFragments = new Set<string>();

  const checkSelections = (parentTypeName: string, selections: ReadonlyArray<SelectionNode>): void => {
    const parentType = schema.getType(parentTypeName);
    if (!parentType) {
      throw new GraphQLError(`Unknown type '${parentTypeName}'`, "GRAPHQL_VALIDATION_FAILED");
    }

    if (parentType.kind === "OBJECT" && !satisfiesAuthRule(principal, parentType.auth)) {
      throw new AuthorizationError(`Principal lacks access to object type '${parentType.name}'`);
    }

    for (const sel of selections) {
      if (sel.kind === "Field") {
        if (sel.name === "__typename") continue;

        if (parentType.kind === "OBJECT") {
          const fieldDef = parentType.fields[sel.name];
          if (!fieldDef) {
            throw new GraphQLError(
              `Cannot query field '${sel.name}' on type '${parentType.name}'`,
              "GRAPHQL_VALIDATION_FAILED",
            );
          }
          if (!satisfiesAuthRule(principal, fieldDef.auth)) {
            throw new AuthorizationError(
              `Principal '${principal.principalId}' (role=${principal.role}) is not authorized to read '${parentType.name}.${sel.name}'`,
            );
          }
          if (sel.selectionSet.length > 0) {
            checkSelections(fieldDef.typeName, sel.selectionSet);
          }
        } else if (parentType.kind === "INTERFACE") {
          const ifaceField = parentType.fields[sel.name];
          if (!ifaceField) {
            throw new GraphQLError(
              `Cannot query field '${sel.name}' on interface '${parentType.name}'`,
              "GRAPHQL_VALIDATION_FAILED",
            );
          }
          if (!satisfiesAuthRule(principal, ifaceField.auth)) {
            throw new AuthorizationError(
              `Principal '${principal.principalId}' is not authorized to read '${parentType.name}.${sel.name}'`,
            );
          }
          if (sel.selectionSet.length > 0) {
            checkSelections(ifaceField.typeName, sel.selectionSet);
          }
        } else {
          throw new GraphQLError(
            `Cannot directly select field '${sel.name}' on union '${parentTypeName}' without inline or named fragment`,
            "GRAPHQL_VALIDATION_FAILED",
          );
        }
      } else if (sel.kind === "InlineFragment") {
        if (!sel.typeCondition) {
          continue;
        }
        checkSelections(sel.typeCondition, sel.selectionSet);
      } else if (sel.kind === "FragmentSpread") {
        const frag = doc.fragments.get(sel.name);
        if (!frag) {
          throw new GraphQLError(`Unknown fragment '${sel.name}'`, "UNKNOWN_FRAGMENT");
        }
        if (activeFragments.has(frag.name)) continue;
        activeFragments.add(frag.name);
        checkSelections(frag.typeCondition, frag.selectionSet);
        activeFragments.delete(frag.name);
      }
    }
  };

  const rootTypeName = op.operation === "mutation" ? schema.mutationTypeName : schema.queryTypeName;
  checkSelections(rootTypeName, op.selectionSet);
}
