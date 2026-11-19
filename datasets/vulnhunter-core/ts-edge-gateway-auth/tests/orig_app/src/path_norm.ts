export class PathNormalizationError extends Error {
  readonly code: string;

  constructor(message: string, code = "INVALID_REQUEST_TARGET") {
    super(message);
    this.name = "PathNormalizationError";
    this.code = code;
  }
}

export interface NormalizedTarget {
  readonly rawTarget: string;
  readonly canonicalPath: string;
  readonly rawQuery: string;
  readonly hasQuery: boolean;
  readonly search: string;
  readonly segments: ReadonlyArray<string>;
}

export interface SplitTargetParts {
  readonly rawPath: string;
  readonly rawQuery: string;
  readonly hasQuery: boolean;
}

function hasControlChars(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function isHexChar(code: number): boolean {
  return (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x46) || (code >= 0x61 && code <= 0x66);
}

export function validatePercentEncoding(input: string): void {
  for (let i = 0; i < input.length; i += 1) {
    if (input.charCodeAt(i) !== 0x25) continue;
    if (i + 2 >= input.length || !isHexChar(input.charCodeAt(i + 1)) || !isHexChar(input.charCodeAt(i + 2))) {
      throw new PathNormalizationError("Invalid percent-encoding triplet in path");
    }
    const byteVal = Number.parseInt(input.slice(i + 1, i + 3), 16);
    if (byteVal <= 0x1f || byteVal === 0x7f) {
      throw new PathNormalizationError("Encoded control byte is not permitted in path");
    }
    i += 2;
  }
}

export function uppercasePercentTriplets(segment: string): string {
  if (!segment.includes("%")) return segment;
  let out = "";
  for (let i = 0; i < segment.length; i += 1) {
    if (segment.charCodeAt(i) === 0x25 && i + 2 < segment.length) {
      out += "%" + segment.slice(i + 1, i + 3).toUpperCase();
      i += 2;
    } else {
      out += segment[i];
    }
  }
  return out;
}

export function splitTarget(rawTarget: string): SplitTargetParts {
  if (!rawTarget || typeof rawTarget !== "string") {
    throw new PathNormalizationError("Request target must be a non-empty string");
  }
  if (hasControlChars(rawTarget) || rawTarget.includes("#")) {
    throw new PathNormalizationError("Request target contains disallowed characters");
  }
  if (!rawTarget.startsWith("/")) {
    throw new PathNormalizationError("Origin-form request target must begin with '/'");
  }
  const qIdx = rawTarget.indexOf("?");
  if (qIdx === -1) {
    return { rawPath: rawTarget, rawQuery: "", hasQuery: false };
  }
  return { rawPath: rawTarget.slice(0, qIdx), rawQuery: rawTarget.slice(qIdx + 1), hasQuery: true };
}

export function decodeSlugParam(encodedSegment: string): string {
  validatePercentEncoding(encodedSegment);
  let decoded: string;
  try {
    decoded = decodeURIComponent(encodedSegment);
  } catch {
    throw new PathNormalizationError("Malformed UTF-8 sequence in route parameter");
  }
  if (decoded.length === 0 || hasControlChars(decoded)) {
    throw new PathNormalizationError("Decoded route parameter is empty or invalid");
  }
  return decoded;
}

/**
 * Canonicalizes an incoming request target into its normalized route path
 * and preserved raw query string. Encoded slash sequences (%2F) within a
 * single path segment represent literal characters inside a resource slug
 * rather than path separators.
 */
export function normalizeRoutePath(rawTarget: string): NormalizedTarget {
  const { rawPath, rawQuery, hasQuery } = splitTarget(rawTarget);
  validatePercentEncoding(rawPath);

  const stack: string[] = [];
  for (const part of rawPath.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (stack.length === 0) {
        throw new PathNormalizationError("Path resolution cannot traverse above root", "PATH_TRAVERSAL");
      }
      stack.pop();
      continue;
    }
    stack.push(uppercasePercentTriplets(part));
  }

  const canonicalPath = stack.length === 0 ? "/" : "/" + stack.join("/");
  return {
    rawTarget,
    canonicalPath,
    rawQuery,
    hasQuery,
    search: hasQuery ? `?${rawQuery}` : "",
    segments: stack,
  };
}

export function joinCanonicalTarget(target: NormalizedTarget): string {
  return `${target.canonicalPath}${target.search}`;
}
