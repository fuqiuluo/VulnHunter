/**
 * GraphQL Executable Document Lexer, Recursive-Descent Parser, and Value Coercion.
 *
 * Supports query/mutation operations, variable definitions with defaults,
 * field aliases, arguments, directives, named fragments, typed and untyped
 * inline fragments (`... on Type { ... }` and `... { ... }`), and full GraphQL
 * input value literals (Int, Float, String, Boolean, Null, Enum, List, Object, Variable).
 */

export class GraphQLError extends Error {
  public readonly code: string;

  constructor(message: string, code = "GRAPHQL_SYNTAX_ERROR") {
    super(message);
    this.name = "GraphQLError";
    this.code = code;
  }
}

export type ValueNode =
  | { kind: "Variable"; name: string }
  | { kind: "IntValue"; value: number }
  | { kind: "FloatValue"; value: number }
  | { kind: "StringValue"; value: string }
  | { kind: "BooleanValue"; value: boolean }
  | { kind: "NullValue" }
  | { kind: "EnumValue"; value: string }
  | { kind: "ListValue"; values: ValueNode[] }
  | { kind: "ObjectValue"; fields: Array<{ name: string; value: ValueNode }> };

export interface ArgumentNode {
  name: string;
  value: ValueNode;
}

export interface DirectiveNode {
  name: string;
  arguments: ArgumentNode[];
}

export type SelectionNode = FieldNode | InlineFragmentNode | FragmentSpreadNode;

export interface FieldNode {
  kind: "Field";
  alias?: string;
  name: string;
  arguments: ArgumentNode[];
  directives: DirectiveNode[];
  selectionSet: SelectionNode[];
}

export interface InlineFragmentNode {
  kind: "InlineFragment";
  typeCondition?: string;
  directives: DirectiveNode[];
  selectionSet: SelectionNode[];
}

export interface FragmentSpreadNode {
  kind: "FragmentSpread";
  name: string;
  directives: DirectiveNode[];
}

export interface VariableDefinitionNode {
  name: string;
  typeName: string;
  nonNull: boolean;
  isList: boolean;
  defaultValue?: ValueNode;
}

export interface OperationDefinitionNode {
  kind: "OperationDefinition";
  operation: "query" | "mutation";
  name?: string;
  variableDefinitions: VariableDefinitionNode[];
  directives: DirectiveNode[];
  selectionSet: SelectionNode[];
}

export interface FragmentDefinitionNode {
  kind: "FragmentDefinition";
  name: string;
  typeCondition: string;
  directives: DirectiveNode[];
  selectionSet: SelectionNode[];
}

export interface DocumentNode {
  operations: OperationDefinitionNode[];
  fragments: Map<string, FragmentDefinitionNode>;
}

type TokenKind =
  | "PUNCT"
  | "SPREAD"
  | "NAME"
  | "INT"
  | "FLOAT"
  | "STRING"
  | "EOF";

interface Token {
  kind: TokenKind;
  value: string;
  pos: number;
}

const SINGLE_CHAR_PUNCTS = new Set(["!", "$", "(", ")", ":", "=", "@", "[", "]", "{", "|", "}"]);

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = source.length;

  while (i < n) {
    const ch = source[i];
    // Ignored whitespace, BOM, and commas per GraphQL spec
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n" || ch === "," || ch === "\ufeff") {
      i += 1;
      continue;
    }
    // Line comments
    if (ch === "#") {
      while (i < n && source[i] !== "\n" && source[i] !== "\r") i += 1;
      continue;
    }
    if (ch === "." && source[i + 1] === "." && source[i + 2] === ".") {
      tokens.push({ kind: "SPREAD", value: "...", pos: i });
      i += 3;
      continue;
    }
    if (SINGLE_CHAR_PUNCTS.has(ch)) {
      tokens.push({ kind: "PUNCT", value: ch, pos: i });
      i += 1;
      continue;
    }
    if (ch === '"') {
      const start = i;
      i += 1;
      let out = "";
      while (i < n && source[i] !== '"') {
        if (source[i] === "\n" || source[i] === "\r") {
          throw new GraphQLError(`Unterminated string literal at position ${start}`);
        }
        if (source[i] === "\\") {
          i += 1;
          if (i >= n) throw new GraphQLError(`Invalid escape at end of input`);
          const esc = source[i];
          if (esc === '"') out += '"';
          else if (esc === "\\") out += "\\";
          else if (esc === "/") out += "/";
          else if (esc === "b") out += "\b";
          else if (esc === "f") out += "\f";
          else if (esc === "n") out += "\n";
          else if (esc === "r") out += "\r";
          else if (esc === "t") out += "\t";
          else if (esc === "u") {
            const hex = source.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
              throw new GraphQLError(`Invalid unicode escape \\u${hex} at position ${i}`);
            }
            out += String.fromCharCode(Number.parseInt(hex, 16));
            i += 4;
          } else {
            throw new GraphQLError(`Invalid escape sequence \\${esc} at position ${i}`);
          }
          i += 1;
        } else {
          out += source[i];
          i += 1;
        }
      }
      if (i >= n || source[i] !== '"') {
        throw new GraphQLError(`Unterminated string literal at position ${start}`);
      }
      i += 1;
      tokens.push({ kind: "STRING", value: out, pos: start });
      continue;
    }
    if (ch === "-" || (ch >= "0" && ch <= "9")) {
      const start = i;
      if (source[i] === "-") i += 1;
      if (i >= n || source[i] < "0" || source[i] > "9") {
        throw new GraphQLError(`Invalid number literal at position ${start}`);
      }
      if (source[i] === "0") {
        i += 1;
      } else {
        while (i < n && source[i] >= "0" && source[i] <= "9") i += 1;
      }
      let isFloat = false;
      if (i < n && source[i] === ".") {
        isFloat = true;
        i += 1;
        if (i >= n || source[i] < "0" || source[i] > "9") {
          throw new GraphQLError(`Invalid fractional part at position ${start}`);
        }
        while (i < n && source[i] >= "0" && source[i] <= "9") i += 1;
      }
      if (i < n && (source[i] === "e" || source[i] === "E")) {
        isFloat = true;
        i += 1;
        if (i < n && (source[i] === "+" || source[i] === "-")) i += 1;
        if (i >= n || source[i] < "0" || source[i] > "9") {
          throw new GraphQLError(`Invalid exponent at position ${start}`);
        }
        while (i < n && source[i] >= "0" && source[i] <= "9") i += 1;
      }
      tokens.push({ kind: isFloat ? "FLOAT" : "INT", value: source.slice(start, i), pos: start });
      continue;
    }
    if ((ch >= "A" && ch <= "Z") || (ch >= "a" && ch <= "z") || ch === "_") {
      const start = i;
      i += 1;
      while (
        i < n &&
        ((source[i] >= "A" && source[i] <= "Z") ||
          (source[i] >= "a" && source[i] <= "z") ||
          (source[i] >= "0" && source[i] <= "9") ||
          source[i] === "_")
      ) {
        i += 1;
      }
      tokens.push({ kind: "NAME", value: source.slice(start, i), pos: start });
      continue;
    }
    throw new GraphQLError(`Unexpected character '${ch}' at position ${i}`);
  }

  tokens.push({ kind: "EOF", value: "", pos: n });
  return tokens;
}

class Parser {
  private readonly tokens: Token[];
  private cursor = 0;

  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }

  private peek(offset = 0): Token {
    return this.tokens[Math.min(this.cursor + offset, this.tokens.length - 1)];
  }

  private next(): Token {
    const tok = this.peek();
    if (tok.kind !== "EOF") this.cursor += 1;
    return tok;
  }

  private expectPunct(val: string): Token {
    const tok = this.peek();
    if (tok.kind !== "PUNCT" || tok.value !== val) {
      throw new GraphQLError(`Expected '${val}' at position ${tok.pos}, got '${tok.value || tok.kind}'`);
    }
    return this.next();
  }

  private expectName(): string {
    const tok = this.peek();
    if (tok.kind !== "NAME") {
      throw new GraphQLError(`Expected identifier at position ${tok.pos}, got '${tok.value || tok.kind}'`);
    }
    return this.next().value;
  }

  parseDocument(): DocumentNode {
    const operations: OperationDefinitionNode[] = [];
    const fragments = new Map<string, FragmentDefinitionNode>();

    while (this.peek().kind !== "EOF") {
      const tok = this.peek();
      if (tok.kind === "PUNCT" && tok.value === "{") {
        operations.push({
          kind: "OperationDefinition",
          operation: "query",
          variableDefinitions: [],
          directives: [],
          selectionSet: this.parseSelectionSet(),
        });
      } else if (tok.kind === "NAME" && (tok.value === "query" || tok.value === "mutation")) {
        operations.push(this.parseOperationDefinition());
      } else if (tok.kind === "NAME" && tok.value === "fragment") {
        const frag = this.parseFragmentDefinition();
        if (fragments.has(frag.name)) {
          throw new GraphQLError(`Duplicate fragment definition '${frag.name}'`, "DUPLICATE_FRAGMENT");
        }
        fragments.set(frag.name, frag);
      } else {
        throw new GraphQLError(`Unexpected top-level token '${tok.value}' at position ${tok.pos}`);
      }
    }

    if (operations.length === 0) {
      throw new GraphQLError("Executable GraphQL document must contain at least one operation", "NO_OPERATIONS");
    }
    return { operations, fragments };
  }

  private parseOperationDefinition(): OperationDefinitionNode {
    const opKeyword = this.expectName();
    if (opKeyword !== "query" && opKeyword !== "mutation") {
      throw new GraphQLError(`Unsupported operation '${opKeyword}'`);
    }
    let name: string | undefined;
    if (this.peek().kind === "NAME") {
      name = this.expectName();
    }
    const variableDefinitions = this.parseVariableDefinitions();
    const directives = this.parseDirectives();
    const selectionSet = this.parseSelectionSet();
    return {
      kind: "OperationDefinition",
      operation: opKeyword,
      name,
      variableDefinitions,
      directives,
      selectionSet,
    };
  }

  private parseVariableDefinitions(): VariableDefinitionNode[] {
    const defs: VariableDefinitionNode[] = [];
    if (this.peek().kind !== "PUNCT" || this.peek().value !== "(") return defs;
    this.expectPunct("(");
    while (this.peek().kind !== "PUNCT" || this.peek().value !== ")") {
      this.expectPunct("$");
      const name = this.expectName();
      this.expectPunct(":");
      let isList = false;
      if (this.peek().kind === "PUNCT" && this.peek().value === "[") {
        isList = true;
        this.expectPunct("[");
      }
      const typeName = this.expectName();
      if (isList) {
        if (this.peek().kind === "PUNCT" && this.peek().value === "!") this.next();
        this.expectPunct("]");
      }
      let nonNull = false;
      if (this.peek().kind === "PUNCT" && this.peek().value === "!") {
        nonNull = true;
        this.next();
      }
      let defaultValue: ValueNode | undefined;
      if (this.peek().kind === "PUNCT" && this.peek().value === "=") {
        this.next();
        defaultValue = this.parseValueLiteral(true);
      }
      this.parseDirectives();
      defs.push({ name, typeName, nonNull, isList, defaultValue });
    }
    this.expectPunct(")");
    return defs;
  }

  private parseFragmentDefinition(): FragmentDefinitionNode {
    this.expectName(); // "fragment"
    const name = this.expectName();
    if (name === "on") {
      throw new GraphQLError("Fragment cannot be named 'on'");
    }
    const onKw = this.expectName();
    if (onKw !== "on") {
      throw new GraphQLError(`Expected 'on' in fragment '${name}', got '${onKw}'`);
    }
    const typeCondition = this.expectName();
    const directives = this.parseDirectives();
    const selectionSet = this.parseSelectionSet();
    return {
      kind: "FragmentDefinition",
      name,
      typeCondition,
      directives,
      selectionSet,
    };
  }

  private parseSelectionSet(): SelectionNode[] {
    this.expectPunct("{");
    const selections: SelectionNode[] = [];
    while (this.peek().kind !== "PUNCT" || this.peek().value !== "}") {
      if (this.peek().kind === "EOF") {
        throw new GraphQLError("Unterminated selection set");
      }
      if (this.peek().kind === "SPREAD") {
        this.next();
        if (this.peek().kind === "NAME" && this.peek().value === "on") {
          this.next();
          const typeCondition = this.expectName();
          const directives = this.parseDirectives();
          const selectionSet = this.parseSelectionSet();
          selections.push({
            kind: "InlineFragment",
            typeCondition,
            directives,
            selectionSet,
          });
        } else if (
          (this.peek().kind === "PUNCT" && (this.peek().value === "@" || this.peek().value === "{"))
        ) {
          // Untyped inline fragment: `... @dir { field }` or `... { field }`
          const directives = this.parseDirectives();
          const selectionSet = this.parseSelectionSet();
          selections.push({
            kind: "InlineFragment",
            directives,
            selectionSet,
          });
        } else {
          const fragName = this.expectName();
          const directives = this.parseDirectives();
          selections.push({
            kind: "FragmentSpread",
            name: fragName,
            directives,
          });
        }
      } else {
        selections.push(this.parseField());
      }
    }
    this.expectPunct("}");
    if (selections.length === 0) {
      throw new GraphQLError("Selection set must not be empty");
    }
    return selections;
  }

  private parseField(): FieldNode {
    const first = this.expectName();
    let alias: string | undefined;
    let name = first;
    if (this.peek().kind === "PUNCT" && this.peek().value === ":") {
      this.next();
      alias = first;
      name = this.expectName();
    }
    const args = this.parseArguments();
    const directives = this.parseDirectives();
    const selectionSet =
      this.peek().kind === "PUNCT" && this.peek().value === "{"
        ? this.parseSelectionSet()
        : [];
    return {
      kind: "Field",
      alias,
      name,
      arguments: args,
      directives,
      selectionSet,
    };
  }

  private parseArguments(): ArgumentNode[] {
    const args: ArgumentNode[] = [];
    if (this.peek().kind !== "PUNCT" || this.peek().value !== "(") return args;
    this.expectPunct("(");
    const seen = new Set<string>();
    while (this.peek().kind !== "PUNCT" || this.peek().value !== ")") {
      const name = this.expectName();
      if (seen.has(name)) {
        throw new GraphQLError(`Duplicate argument '${name}'`, "DUPLICATE_ARGUMENT");
      }
      seen.add(name);
      this.expectPunct(":");
      const value = this.parseValueLiteral(false);
      args.push({ name, value });
    }
    this.expectPunct(")");
    return args;
  }

  private parseDirectives(): DirectiveNode[] {
    const dirs: DirectiveNode[] = [];
    while (this.peek().kind === "PUNCT" && this.peek().value === "@") {
      this.next();
      const name = this.expectName();
      const args = this.parseArguments();
      dirs.push({ name, arguments: args });
    }
    return dirs;
  }

  private parseValueLiteral(isConst: boolean): ValueNode {
    const tok = this.peek();
    if (tok.kind === "PUNCT" && tok.value === "$") {
      if (isConst) {
        throw new GraphQLError(`Variables are not permitted in constant default values at position ${tok.pos}`);
      }
      this.next();
      return { kind: "Variable", name: this.expectName() };
    }
    if (tok.kind === "INT") {
      this.next();
      const parsed = Number.parseInt(tok.value, 10);
      if (!Number.isSafeInteger(parsed)) {
        throw new GraphQLError(`Integer literal out of safe range: ${tok.value}`);
      }
      return { kind: "IntValue", value: parsed };
    }
    if (tok.kind === "FLOAT") {
      this.next();
      return { kind: "FloatValue", value: Number.parseFloat(tok.value) };
    }
    if (tok.kind === "STRING") {
      this.next();
      return { kind: "StringValue", value: tok.value };
    }
    if (tok.kind === "NAME") {
      this.next();
      if (tok.value === "true") return { kind: "BooleanValue", value: true };
      if (tok.value === "false") return { kind: "BooleanValue", value: false };
      if (tok.value === "null") return { kind: "NullValue" };
      return { kind: "EnumValue", value: tok.value };
    }
    if (tok.kind === "PUNCT" && tok.value === "[") {
      this.next();
      const values: ValueNode[] = [];
      while (this.peek().kind !== "PUNCT" || this.peek().value !== "]") {
        values.push(this.parseValueLiteral(isConst));
      }
      this.expectPunct("]");
      return { kind: "ListValue", values };
    }
    if (tok.kind === "PUNCT" && tok.value === "{") {
      this.next();
      const fields: Array<{ name: string; value: ValueNode }> = [];
      const seen = new Set<string>();
      while (this.peek().kind !== "PUNCT" || this.peek().value !== "}") {
        const fname = this.expectName();
        if (seen.has(fname)) {
          throw new GraphQLError(`Duplicate input object field '${fname}'`);
        }
        seen.add(fname);
        this.expectPunct(":");
        fields.push({ name: fname, value: this.parseValueLiteral(isConst) });
      }
      this.expectPunct("}");
      return { kind: "ObjectValue", fields };
    }
    throw new GraphQLError(`Unexpected value token '${tok.value || tok.kind}' at position ${tok.pos}`);
  }
}

export function parseGraphQL(source: string): DocumentNode {
  if (typeof source !== "string" || source.trim().length === 0) {
    throw new GraphQLError("GraphQL query must be a non-empty string", "EMPTY_QUERY");
  }
  const parser = new Parser(tokenize(source));
  return parser.parseDocument();
}

export function selectOperation(doc: DocumentNode, operationName?: string): OperationDefinitionNode {
  if (!operationName) {
    if (doc.operations.length !== 1) {
      throw new GraphQLError(
        "operationName is required when document defines multiple operations",
        "AMBIGUOUS_OPERATION",
      );
    }
    return doc.operations[0];
  }
  const found = doc.operations.find((op) => op.name === operationName);
  if (!found) {
    throw new GraphQLError(`Unknown operation '${operationName}'`, "UNKNOWN_OPERATION");
  }
  return found;
}

export function coerceVariables(
  op: OperationDefinitionNode,
  rawVariables: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const provided = rawVariables ?? {};
  const out: Record<string, unknown> = Object.create(null);

  for (const [k, v] of Object.entries(provided)) {
    out[k] = v;
  }

  for (const def of op.variableDefinitions) {
    if (out[def.name] === undefined && def.defaultValue !== undefined) {
      out[def.name] = resolveValueNode(def.defaultValue, {});
    }
    if ((out[def.name] === undefined || out[def.name] === null) && def.nonNull) {
      throw new GraphQLError(`Missing required non-null variable '$${def.name}'`, "BAD_USER_INPUT");
    }
  }
  return out;
}

export function resolveValueNode(node: ValueNode, variables: Readonly<Record<string, unknown>>): unknown {
  switch (node.kind) {
    case "IntValue":
    case "FloatValue":
    case "StringValue":
    case "BooleanValue":
    case "EnumValue":
      return node.value;
    case "NullValue":
      return null;
    case "Variable":
      return Object.prototype.hasOwnProperty.call(variables, node.name) ? variables[node.name] : undefined;
    case "ListValue":
      return node.values.map((item) => resolveValueNode(item, variables));
    case "ObjectValue": {
      const obj: Record<string, unknown> = Object.create(null);
      for (const f of node.fields) {
        obj[f.name] = resolveValueNode(f.value, variables);
      }
      return obj;
    }
  }
}

export function resolveFieldArguments(
  field: FieldNode,
  variables: Readonly<Record<string, unknown>>,
  argDefaults?: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  const resolved: Record<string, unknown> = Object.create(null);
  if (argDefaults) {
    for (const [k, v] of Object.entries(argDefaults)) {
      resolved[k] = v;
    }
  }
  for (const arg of field.arguments) {
    const val = resolveValueNode(arg.value, variables);
    if (val !== undefined) {
      resolved[arg.name] = val;
    }
  }
  return resolved;
}
