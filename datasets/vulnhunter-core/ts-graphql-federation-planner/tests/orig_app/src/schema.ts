/**
 * Federated Supergraph Schema Model and Default Enterprise Commerce Supergraph.
 *
 * Models Apollo-Federation-style ownership across subgraphs (`accounts`, `billing`,
 * `orders`), entity keys (`@key`), cross-subgraph field dependencies (`@external`,
 * `@requires`), field/type access control (`@auth`), and static cost weights (`@cost`).
 */

export interface AuthRule {
  /** Allowed principal roles (any match satisfies role gate if non-empty). */
  roles?: ReadonlyArray<string>;
  /** Required OAuth/API scopes (ALL listed scopes must be held by the principal). */
  scopes?: ReadonlyArray<string>;
}

export interface CostSpec {
  /** Base complexity points charged each time this field is evaluated. */
  weight: number;
  /** Argument names that multiply child selection complexity (e.g. `limit`, `first`). */
  multipliers?: ReadonlyArray<string>;
  /** Default multiplier when none of the multiplier arguments are provided. */
  defaultMultiplier?: number;
}

export interface ArgSchemaDef {
  typeName: string;
  defaultValue?: unknown;
  maxIntValue?: number;
}

export interface FieldDef {
  name: string;
  /** Named return type (`String`, `Int`, `Boolean`, `Float`, `ID`, or composite type name). */
  typeName: string;
  isList?: boolean;
  /** Subgraph responsible for resolving this field (`accounts`, `billing`, `orders`, or `gateway`). */
  subgraph: string;
  /** Marked `@external` on extending subgraphs; resolved by the owning subgraph. */
  external?: boolean;
  /** Sibling fields from the entity's base subgraph required as representation inputs (`@requires`). */
  requires?: ReadonlyArray<string>;
  /** Optional `@auth` directive restricting access to this field. */
  auth?: AuthRule;
  /** Optional `@cost` specification. Defaults to `{ weight: 1 }` for composite/root fields, `0` for scalars. */
  cost?: CostSpec;
  /** Argument defaults and constraints. */
  args?: Readonly<Record<string, ArgSchemaDef>>;
  /** True only for internal federation protocol root fields (`_entities`, `_service`). */
  internalProtocolField?: boolean;
}

export interface ObjectTypeDef {
  kind: "OBJECT";
  name: string;
  /** Primary subgraph owning the base entity and `@key`. */
  ownerSubgraph: string;
  /** Primary key field names (`@key(fields: ...)`), e.g. `["id"]`. */
  keyFields?: ReadonlyArray<string>;
  implementsInterfaces?: ReadonlyArray<string>;
  auth?: AuthRule;
  fields: Record<string, FieldDef>;
}

export interface InterfaceTypeDef {
  kind: "INTERFACE";
  name: string;
  implementedBy: ReadonlyArray<string>;
  fields: Record<string, { name: string; typeName: string; isList?: boolean; auth?: AuthRule; cost?: CostSpec }>;
}

export interface UnionTypeDef {
  kind: "UNION";
  name: string;
  memberTypes: ReadonlyArray<string>;
}

export interface ScalarTypeDef {
  kind: "SCALAR";
  name: string;
}

export type TypeDef = ObjectTypeDef | InterfaceTypeDef | UnionTypeDef | ScalarTypeDef;

const BUILTIN_SCALARS = ["String", "Int", "Float", "Boolean", "ID", "JSON"];

export class SupergraphSchema {
  public readonly queryTypeName = "Query";
  public readonly mutationTypeName = "Mutation";
  private readonly types = new Map<string, TypeDef>();

  constructor(typeDefs: ReadonlyArray<TypeDef>) {
    for (const sc of BUILTIN_SCALARS) {
      this.types.set(sc, { kind: "SCALAR", name: sc });
    }
    for (const def of typeDefs) {
      this.types.set(def.name, def);
    }
  }

  getType(name: string): TypeDef | undefined {
    return this.types.get(name);
  }

  getObjectType(name: string): ObjectTypeDef | undefined {
    const t = this.types.get(name);
    return t?.kind === "OBJECT" ? t : undefined;
  }

  isCompositeType(name: string): boolean {
    const t = this.types.get(name);
    return t?.kind === "OBJECT" || t?.kind === "INTERFACE" || t?.kind === "UNION";
  }

  isScalarType(name: string): boolean {
    const t = this.types.get(name);
    return t?.kind === "SCALAR";
  }

  /**
   * Returns all concrete OBJECT type names that may inhabit `abstractOrConcreteType`.
   */
  getPossibleConcreteTypes(typeName: string): ReadonlyArray<string> {
    const t = this.types.get(typeName);
    if (!t) return [];
    if (t.kind === "OBJECT") return [t.name];
    if (t.kind === "INTERFACE") return t.implementedBy;
    if (t.kind === "UNION") return t.memberTypes;
    return [];
  }

  /**
   * Checks whether `fragmentType` is a valid runtime subtype or supertype overlap with `parentType`.
   */
  doesFragmentTypeApply(parentTypeName: string, fragmentTypeName: string): boolean {
    const parentPossible = new Set(this.getPossibleConcreteTypes(parentTypeName));
    const fragPossible = this.getPossibleConcreteTypes(fragmentTypeName);
    return fragPossible.some((concrete) => parentPossible.has(concrete));
  }
}

/**
 * Constructs the standard multi-subgraph enterprise commerce & billing supergraph:
 *  - `accounts` subgraph: owns `User` (`@key(fields: "id")`, `taxSsn`, `rawCreditScore`)
 *  - `billing` subgraph: owns `Invoice` (`@key(fields: "id")`, `settlementIban`) and extends `User`
 *    with `netRiskBand @requires(fields: "rawCreditScore")` and `payoutIban`
 *  - `orders` subgraph: owns `Order` (`@key(fields: "id")`) referencing `User` & `Invoice`
 *  - Abstract types: `Node` interface, `BillableDocument` interface, `SearchItem` union
 */
export function buildCommerceSupergraph(): SupergraphSchema {
  const nodeInterface: InterfaceTypeDef = {
    kind: "INTERFACE",
    name: "Node",
    implementedBy: ["User", "Order", "Invoice"],
    fields: {
      id: { name: "id", typeName: "ID" },
    },
  };

  const billableInterface: InterfaceTypeDef = {
    kind: "INTERFACE",
    name: "BillableDocument",
    implementedBy: ["Invoice", "CreditMemo"],
    fields: {
      id: { name: "id", typeName: "ID" },
      amountCents: { name: "amountCents", typeName: "Int", cost: { weight: 1 } },
      // Concrete implementations carry sensitive banking destination metadata gated by `@auth`
      settlementIban: { name: "settlementIban", typeName: "String", cost: { weight: 2 } },
    },
  };

  const searchUnion: UnionTypeDef = {
    kind: "UNION",
    name: "SearchItem",
    memberTypes: ["User", "Order", "Invoice"],
  };

  const userType: ObjectTypeDef = {
    kind: "OBJECT",
    name: "User",
    ownerSubgraph: "accounts",
    keyFields: ["id"],
    implementsInterfaces: ["Node"],
    fields: {
      id: { name: "id", typeName: "ID", subgraph: "accounts" },
      email: { name: "email", typeName: "String", subgraph: "accounts", cost: { weight: 1 } },
      displayName: { name: "displayName", typeName: "String", subgraph: "accounts" },
      tier: { name: "tier", typeName: "String", subgraph: "accounts" },
      taxSsn: {
        name: "taxSsn",
        typeName: "String",
        subgraph: "accounts",
        auth: { roles: ["admin", "compliance"], scopes: ["pii:tax:read"] },
        cost: { weight: 3 },
      },
      rawCreditScore: {
        name: "rawCreditScore",
        typeName: "Int",
        subgraph: "accounts",
        auth: { roles: ["admin", "underwriter"], scopes: ["risk:internal"] },
        cost: { weight: 3 },
      },
      // Computed on `billing` subgraph via `@requires(fields: "rawCreditScore")` without exposing `rawCreditScore`
      netRiskBand: {
        name: "netRiskBand",
        typeName: "String",
        subgraph: "billing",
        requires: ["rawCreditScore"],
        cost: { weight: 2 },
      },
      payoutIban: {
        name: "payoutIban",
        typeName: "String",
        subgraph: "billing",
        auth: { roles: ["admin", "finance"], scopes: ["billing:payout:read"] },
        cost: { weight: 3 },
      },
    },
  };

  const invoiceType: ObjectTypeDef = {
    kind: "OBJECT",
    name: "Invoice",
    ownerSubgraph: "billing",
    keyFields: ["id"],
    implementsInterfaces: ["Node", "BillableDocument"],
    fields: {
      id: { name: "id", typeName: "ID", subgraph: "billing" },
      invoiceNumber: { name: "invoiceNumber", typeName: "String", subgraph: "billing" },
      amountCents: { name: "amountCents", typeName: "Int", subgraph: "billing", cost: { weight: 1 } },
      status: { name: "status", typeName: "String", subgraph: "billing" },
      settlementIban: {
        name: "settlementIban",
        typeName: "String",
        subgraph: "billing",
        auth: { roles: ["admin", "finance"], scopes: ["billing:settlement:read"] },
        cost: { weight: 3 },
      },
      internalAuditNotes: {
        name: "internalAuditNotes",
        typeName: "String",
        subgraph: "billing",
        auth: { roles: ["admin"], scopes: ["audit:read"] },
        cost: { weight: 2 },
      },
    },
  };

  const creditMemoType: ObjectTypeDef = {
    kind: "OBJECT",
    name: "CreditMemo",
    ownerSubgraph: "billing",
    keyFields: ["id"],
    implementsInterfaces: ["BillableDocument"],
    fields: {
      id: { name: "id", typeName: "ID", subgraph: "billing" },
      amountCents: { name: "amountCents", typeName: "Int", subgraph: "billing", cost: { weight: 1 } },
      reasonCode: { name: "reasonCode", typeName: "String", subgraph: "billing" },
      settlementIban: {
        name: "settlementIban",
        typeName: "String",
        subgraph: "billing",
        auth: { roles: ["admin", "finance"], scopes: ["billing:settlement:read"] },
        cost: { weight: 3 },
      },
    },
  };

  const orderLineType: ObjectTypeDef = {
    kind: "OBJECT",
    name: "OrderLine",
    ownerSubgraph: "orders",
    fields: {
      sku: { name: "sku", typeName: "String", subgraph: "orders" },
      quantity: { name: "quantity", typeName: "Int", subgraph: "orders" },
      unitPriceCents: { name: "unitPriceCents", typeName: "Int", subgraph: "orders", cost: { weight: 1 } },
    },
  };

  const orderType: ObjectTypeDef = {
    kind: "OBJECT",
    name: "Order",
    ownerSubgraph: "orders",
    keyFields: ["id"],
    implementsInterfaces: ["Node"],
    fields: {
      id: { name: "id", typeName: "ID", subgraph: "orders" },
      reference: { name: "reference", typeName: "String", subgraph: "orders" },
      totalCents: { name: "totalCents", typeName: "Int", subgraph: "orders", cost: { weight: 1 } },
      buyer: { name: "buyer", typeName: "User", subgraph: "orders", cost: { weight: 2 } },
      invoice: { name: "invoice", typeName: "Invoice", subgraph: "orders", cost: { weight: 2 } },
      lines: {
        name: "lines",
        typeName: "OrderLine",
        isList: true,
        subgraph: "orders",
        args: { limit: { typeName: "Int", defaultValue: 5, maxIntValue: 100 } },
        cost: { weight: 2, multipliers: ["limit"], defaultMultiplier: 5 },
      },
    },
  };

  const queryType: ObjectTypeDef = {
    kind: "OBJECT",
    name: "Query",
    ownerSubgraph: "gateway",
    fields: {
      user: {
        name: "user",
        typeName: "User",
        subgraph: "accounts",
        args: { id: { typeName: "ID" } },
        cost: { weight: 2 },
      },
      order: {
        name: "order",
        typeName: "Order",
        subgraph: "orders",
        args: { id: { typeName: "ID" } },
        cost: { weight: 2 },
      },
      orders: {
        name: "orders",
        typeName: "Order",
        isList: true,
        subgraph: "orders",
        args: { limit: { typeName: "Int", defaultValue: 10, maxIntValue: 200 } },
        cost: { weight: 3, multipliers: ["limit"], defaultMultiplier: 10 },
      },
      invoice: {
        name: "invoice",
        typeName: "Invoice",
        subgraph: "billing",
        args: { id: { typeName: "ID" } },
        cost: { weight: 2 },
      },
      billableDocuments: {
        name: "billableDocuments",
        typeName: "BillableDocument",
        isList: true,
        subgraph: "billing",
        args: { first: { typeName: "Int", defaultValue: 5, maxIntValue: 100 } },
        cost: { weight: 2, multipliers: ["first"], defaultMultiplier: 5 },
      },
      node: {
        name: "node",
        typeName: "Node",
        subgraph: "accounts",
        args: { id: { typeName: "ID" } },
        cost: { weight: 2 },
      },
      search: {
        name: "search",
        typeName: "SearchItem",
        isList: true,
        subgraph: "orders",
        args: { text: { typeName: "String" }, limit: { typeName: "Int", defaultValue: 5, maxIntValue: 100 } },
        cost: { weight: 3, multipliers: ["limit"], defaultMultiplier: 5 },
      },
      // Internal subgraph protocol entrypoints — never callable by external gateway clients
      _entities: {
        name: "_entities",
        typeName: "Node",
        isList: true,
        subgraph: "gateway",
        internalProtocolField: true,
        args: { representations: { typeName: "JSON" } },
        cost: { weight: 1 },
      },
      _service: {
        name: "_service",
        typeName: "String",
        subgraph: "gateway",
        internalProtocolField: true,
        cost: { weight: 1 },
      },
    },
  };

  return new SupergraphSchema([
    nodeInterface,
    billableInterface,
    searchUnion,
    userType,
    invoiceType,
    creditMemoType,
    orderLineType,
    orderType,
    queryType,
  ]);
}
