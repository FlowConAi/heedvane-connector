import { sign as ed25519Sign, verify as ed25519Verify, type KeyObject } from "node:crypto";

import { isBase64String, isNonEmptyString, isRecord, isStringList } from "./guards.js";

export const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

export function isHttpMethod(value: unknown): value is HttpMethod {
  return typeof value === "string" && (HTTP_METHODS as readonly string[]).includes(value);
}

export interface AllowlistEntry {
  readonly methods: readonly HttpMethod[];
  readonly pathPattern: string;
  readonly allowedQueryParams: readonly string[];
}

export const CAPABILITY_PROFILES = ["read-only", "read-write"] as const;
export type CapabilityProfile = (typeof CAPABILITY_PROFILES)[number];

export class AllowlistValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AllowlistValidationError";
  }
}

// Push access is the one capability the connector must never gain, because the hub only
// ever fetches. The marker is refused at document validation, at request matching, and
// at profile checks, so a server bug or a forged document cannot open it.
const RECEIVE_PACK_MARKER = "git-receive-pack";

function isForbiddenEntry(entry: AllowlistEntry): boolean {
  return (
    staticPatternTargetsReceivePack(entry.pathPattern) ||
    pathPatternMatches(entry.pathPattern, "/namespace/project.git/git-receive-pack")
  );
}

function staticPatternTargetsReceivePack(pathPattern: string): boolean {
  const decodedPattern = fullyDecodeStaticPattern(pathPattern);
  return SMART_HTTP_RECEIVE_PACK_PATTERN.test(decodedPattern);
}

function fullyDecodeStaticPattern(pathPattern: string): string {
  let decodedPattern = pathPattern;
  while (true) {
    const nextPattern = decodedPattern.replace(
      /%([0-9A-Fa-f]{2})/g,
      (_match, octet: string) => String.fromCharCode(Number.parseInt(octet, 16)),
    );
    if (nextPattern === decodedPattern) return decodedPattern;
    decodedPattern = nextPattern;
  }
}

const PATH_PATTERN_FORMAT = /^\/[A-Za-z0-9/:._~%-]+$/;
const QUERY_PARAM_NAME_FORMAT = /^[A-Za-z0-9_.[\]~-]+$/;
const PARAM_SEGMENT_FORMAT = /^:[A-Za-z][A-Za-z0-9]*([^:]*)$/;

function patternSegmentFailure(pathPattern: string): string | null {
  const segments = pathPattern.split("/").slice(1);
  for (const segment of segments) {
    if (segment.length === 0) return "pathPattern must not contain empty segments";
    if (segment.startsWith(":") && !PARAM_SEGMENT_FORMAT.test(segment)) {
      return `pathPattern segment "${segment}" is not a valid :name parameter`;
    }
  }
  return null;
}

function entryFailure(value: unknown): string | null {
  if (!isRecord(value)) return "entry is not an object";
  if (!Array.isArray(value.methods) || value.methods.length === 0) return "methods must be a non-empty array";
  if (!value.methods.every(isHttpMethod)) return `methods must be one of ${HTTP_METHODS.join(", ")}`;
  if (!isNonEmptyString(value.pathPattern)) return "pathPattern must be a non-empty string";
  if (!PATH_PATTERN_FORMAT.test(value.pathPattern)) return "pathPattern must start with / and use only URL path characters";
  const segmentFailure = patternSegmentFailure(value.pathPattern);
  if (segmentFailure !== null) return segmentFailure;
  if (!isStringList(value.allowedQueryParams)) return "allowedQueryParams must be an array of strings";
  if (!value.allowedQueryParams.every(isQueryParamName)) return "allowedQueryParams entries must be plain parameter names";
  if (isForbiddenEntry(value as unknown as AllowlistEntry)) {
    return `pathPattern must not match "${RECEIVE_PACK_MARKER}": push access is never permitted`;
  }
  return null;
}

function isQueryParamName(value: string): boolean {
  return QUERY_PARAM_NAME_FORMAT.test(value);
}

export function isAllowlistEntry(value: unknown): value is AllowlistEntry {
  return entryFailure(value) === null;
}

export function validateAllowlistEntries(value: unknown): AllowlistEntry[] {
  if (!Array.isArray(value)) throw new AllowlistValidationError("allowlist entries must be an array");
  return value.map((entry, index) => {
    const failure = entryFailure(entry);
    if (failure !== null) throw new AllowlistValidationError(`allowlist entry ${index}: ${failure}`);
    return entry as AllowlistEntry;
  });
}

function seedEntry(
  methods: readonly HttpMethod[],
  pathPattern: string,
  allowedQueryParams: readonly string[],
): AllowlistEntry {
  return Object.freeze({
    methods: Object.freeze([...methods]),
    pathPattern,
    allowedQueryParams: Object.freeze([...allowedQueryParams]),
  });
}

export const SEED_ALLOWLIST_VERSION = "1";

// The seed mirrors the hub's actual GitLab call set (apps/web/src/lib/code-host/gitlab/):
// the design doc's table plus the reads the review and activity paths also make
// (branches, single commit, note and discussion lists). Entries are split so that each
// entry carries one capability: the capability profile can then refuse a write without
// touching the matching read. Allowed query params are the decoded parameter names the
// hub sends today; values are unrestricted.
export const SEED_ALLOWLIST: readonly AllowlistEntry[] = Object.freeze([
  seedEntry(["GET"], "/api/v4/version", []),
  seedEntry(["GET"], "/api/v4/user", []),
  // GitLab's keyset next-page Link URL echoes its default filter set as explicit
  // params (18.11 observed: imported, owned, simple, starred, statistics,
  // with_custom_attributes, with_issues_enabled, with_merge_requests_enabled); the hub
  // follows that URL verbatim, so the entry must permit every name GitLab echoes. All
  // are read filters/display flags on a read-only list; values stay unrestricted.
  seedEntry(["GET"], "/api/v4/projects", ["id_after", "imported", "membership", "order_by", "owned", "page", "pagination", "per_page", "simple", "sort", "starred", "statistics", "with_custom_attributes", "with_issues_enabled", "with_merge_requests_enabled"]),
  seedEntry(["GET"], "/api/v4/projects/:id", []),
  seedEntry(["GET"], "/api/v4/projects/:id/merge_requests", ["order_by", "page", "per_page", "sort", "state", "updated_after", "updated_before"]),
  seedEntry(["GET"], "/api/v4/projects/:id/merge_requests/:iid", []),
  seedEntry(["GET"], "/api/v4/projects/:id/merge_requests/:iid/diffs", ["page", "per_page", "unidiff"]),
  seedEntry(["GET"], "/api/v4/projects/:id/merge_requests/:iid/discussions", ["page", "per_page"]),
  seedEntry(["POST"], "/api/v4/projects/:id/merge_requests/:iid/discussions", []),
  seedEntry(["GET"], "/api/v4/projects/:id/merge_requests/:iid/notes", ["page", "per_page"]),
  seedEntry(["POST"], "/api/v4/projects/:id/merge_requests/:iid/notes", []),
  seedEntry(["GET"], "/api/v4/projects/:id/repository/compare", ["from", "to"]),
  seedEntry(["GET"], "/api/v4/projects/:id/repository/merge_base", ["refs[]"]),
  seedEntry(["GET"], "/api/v4/projects/:id/repository/commits", ["page", "per_page", "ref_name", "since", "until"]),
  seedEntry(["GET"], "/api/v4/projects/:id/repository/commits/:sha", []),
  seedEntry(["GET"], "/api/v4/projects/:id/repository/branches", ["page", "per_page"]),
  seedEntry(["GET"], "/api/v4/projects/:id/repository/branches/:branch", []),
  seedEntry(["GET"], "/api/v4/projects/:id/hooks", ["page", "per_page"]),
  seedEntry(["POST"], "/api/v4/projects/:id/hooks", []),
  seedEntry(["GET"], "/api/v4/projects/:id/hooks/:hookId", []),
  seedEntry(["PUT"], "/api/v4/projects/:id/hooks/:hookId", []),
  seedEntry(["DELETE"], "/api/v4/projects/:id/hooks/:hookId", []),
  seedEntry(["POST"], "/api/v4/projects/:id/hooks/:hookId/test/push_events", []),
  seedEntry(["GET"], "/:namespace/:project.git/info/refs", ["service"]),
  seedEntry(["POST"], "/:namespace/:project.git/git-upload-pack", []),
]);

export interface AllowlistRequest {
  readonly method: HttpMethod;
  readonly path: string;
  readonly query: readonly (readonly [string, string])[];
}

export function matchesAllowlist(
  entries: readonly AllowlistEntry[],
  request: AllowlistRequest,
): AllowlistEntry | null {
  if (!isCanonicalRequestPath(request.path) || isForbiddenRequest(request)) return null;
  for (const entry of entries) {
    if (isForbiddenEntry(entry)) continue;
    if (entryMatches(entry, request)) return entry;
  }
  return null;
}

function entryMatches(entry: AllowlistEntry, request: AllowlistRequest): boolean {
  if (!entry.methods.includes(request.method)) return false;
  if (!pathPatternMatches(entry.pathPattern, request.path)) return false;
  return queryParamsAllowed(entry.allowedQueryParams, request.query) && gitInfoRefsQueryAllowed(request);
}

function queryParamsAllowed(allowed: readonly string[], query: readonly (readonly [string, string])[]): boolean {
  return query.every(([name]) => allowed.includes(name));
}

const REQUEST_PATH_BASE_URL = "https://connector.invalid";
const SMART_HTTP_INFO_REFS_PATTERN = /^\/[^/]+\/[^/]+\.git\/info\/refs\/?$/;
const SMART_HTTP_RECEIVE_PACK_PATTERN = /\/[^/]+\.git\/git-receive-pack\/?$/;
const SMART_HTTP_SERVICE_QUERY_PARAM = "service";

export function isCanonicalRequestPath(path: string): boolean {
  if (!path.startsWith("/")) return false;
  let parsed: URL;
  try {
    parsed = new URL(path, REQUEST_PATH_BASE_URL);
  } catch {
    return false;
  }
  const decodedPath = decodedRequestPath(path);
  if (decodedPath === null) return false;
  return (
    parsed.origin === REQUEST_PATH_BASE_URL &&
    parsed.pathname === path &&
    parsed.search === "" &&
    parsed.hash === "" &&
    !decodedPath.includes("\\") &&
    !hasDotPathSegment(decodedPath)
  );
}

function hasDotPathSegment(path: string): boolean {
  return path.split("/").some((segment) => segment === "." || segment === "..");
}

function isForbiddenRequest(request: AllowlistRequest): boolean {
  if (pathTargetsReceivePack(request.path)) return true;
  return request.query.some(
    ([name, value]) => name === SMART_HTTP_SERVICE_QUERY_PARAM && value === RECEIVE_PACK_MARKER,
  );
}

function pathTargetsReceivePack(path: string): boolean {
  const decodedPath = decodedRequestPath(path);
  return decodedPath === null || SMART_HTTP_RECEIVE_PACK_PATTERN.test(decodedPath);
}

function decodedRequestPath(path: string): string | null {
  try {
    return decodeURIComponent(path);
  } catch {
    return null;
  }
}

function gitInfoRefsQueryAllowed(request: AllowlistRequest): boolean {
  if (!SMART_HTTP_INFO_REFS_PATTERN.test(request.path)) return true;
  return (
    request.query.length === 1 &&
    request.query[0]?.[0] === SMART_HTTP_SERVICE_QUERY_PARAM &&
    request.query[0]?.[1] === GIT_UPLOAD_PACK_MARKER
  );
}

export function pathPatternMatches(pathPattern: string, path: string): boolean {
  const patternSegments = splitPathSegments(pathPattern);
  const pathSegments = splitPathSegments(path);
  if (patternSegments.length !== pathSegments.length) return false;
  return patternSegments.every((segment, index) => segmentMatches(segment, pathSegments[index] ?? ""));
}

function splitPathSegments(path: string): string[] {
  const withoutLeading = path.startsWith("/") ? path.slice(1) : path;
  const withoutTrailing = withoutLeading.endsWith("/") ? withoutLeading.slice(0, -1) : withoutLeading;
  if (withoutTrailing.length === 0) return [];
  return withoutTrailing.split("/");
}

function segmentMatches(patternSegment: string, pathSegment: string): boolean {
  if (!patternSegment.startsWith(":")) return patternSegment === pathSegment;
  const parsed = PARAM_SEGMENT_FORMAT.exec(patternSegment);
  if (!parsed) return false;
  const suffix = parsed[1] ?? "";
  if (suffix.length === 0) return pathSegment.length > 0;
  return pathSegment.length > suffix.length && pathSegment.endsWith(suffix);
}

const SAFE_METHODS: readonly HttpMethod[] = ["GET", "HEAD"];
const GIT_UPLOAD_PACK_MARKER = "git-upload-pack";
const GIT_UPLOAD_PACK_PATH_PATTERN = "/:namespace/:project.git/git-upload-pack";

export function profilePermits(profile: CapabilityProfile, entry: AllowlistEntry): boolean {
  if (isForbiddenEntry(entry)) return false;
  if (profile === "read-write") return true;
  return isReadEntry(entry);
}

function isReadEntry(entry: AllowlistEntry): boolean {
  if (entry.methods.every((method) => SAFE_METHODS.includes(method))) return true;
  return isGitFetchEntry(entry);
}

// Clone is a read even though smart HTTP fetch uses POST, so the git-upload-pack entry
// is the single exception to the safe-method rule. Anything else with a write method is
// outside the read-only profile.
function isGitFetchEntry(entry: AllowlistEntry): boolean {
  if (entry.pathPattern !== GIT_UPLOAD_PACK_PATH_PATTERN) return false;
  return entry.methods.every((method) => method === "POST");
}

// Canonical form: one header line, one version line, then one canonical JSON line
// per entry. Object keys, the two set-valued contract fields, and entries are sorted.
// JSON escaping keeps the encoding injective while preserving order in unknown arrays.
const CANONICAL_HEADER = "heedvane-connector-allowlist/v1";

export function canonicalizeAllowlist(version: string, entries: readonly AllowlistEntry[]): string {
  if (!isNonEmptyString(version) || /[\r\n]/.test(version)) {
    throw new AllowlistValidationError("allowlist version must be a single-line string");
  }
  const lines = entries.map(canonicalEntryLine).sort();
  return [CANONICAL_HEADER, `version=${JSON.stringify(version)}`, ...lines].join("\n");
}

function canonicalEntryLine(entry: AllowlistEntry): string {
  const normalized: Record<string, unknown> = {
    ...entry,
    methods: [...entry.methods].sort(),
    allowedQueryParams: [...entry.allowedQueryParams].sort(),
  };
  return `entry=${canonicalJson(normalized)}`;
}

function canonicalJson(value: unknown, ancestors = new Set<object>()): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new AllowlistValidationError("allowlist extension fields must be JSON values");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new AllowlistValidationError("allowlist extension fields must be JSON values");
  }
  if (ancestors.has(value)) {
    throw new AllowlistValidationError("allowlist extension fields must not contain cycles");
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonicalJson(entry, ancestors)).join(",")}]`;
    }
    if (!isRecord(value)) {
      throw new AllowlistValidationError("allowlist extension fields must be JSON objects");
    }
    const properties = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key], ancestors)}`);
    return `{${properties.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function signAllowlist(
  version: string,
  entries: readonly AllowlistEntry[],
  privateKey: KeyObject,
): string {
  const payload = Buffer.from(canonicalizeAllowlist(version, entries), "utf8");
  return ed25519Sign(null, payload, privateKey).toString("base64");
}

const ED25519_SIGNATURE_BYTES = 64;

export interface AllowlistSignaturePayload {
  readonly version: string;
  readonly entries: readonly AllowlistEntry[];
  readonly signature: string;
}

export function verifyAllowlistSignature(payload: AllowlistSignaturePayload, publicKey: KeyObject): boolean {
  if (!isBase64String(payload.signature)) return false;
  const signature = Buffer.from(payload.signature, "base64");
  if (signature.length !== ED25519_SIGNATURE_BYTES) return false;
  const data = Buffer.from(canonicalizeAllowlist(payload.version, payload.entries), "utf8");
  return ed25519Verify(null, data, publicKey, signature);
}

export interface SignedAllowlist {
  readonly version: string;
  readonly signature: string;
  readonly entries: unknown;
}

export interface VerifiedAllowlist {
  readonly version: string;
  readonly entries: readonly AllowlistEntry[];
}

// The connector's acceptance path for a server-supplied allowlist: entries are
// validated before the signature is trusted, so a valid signature can never
// legitimize a document that carries the forbidden push capability.
export function verifySignedAllowlist(document: SignedAllowlist, publicKey: KeyObject): VerifiedAllowlist {
  if (!isNonEmptyString(document.version)) {
    throw new AllowlistValidationError("allowlist version must be a non-empty string");
  }
  if (!isBase64String(document.signature)) {
    throw new AllowlistValidationError("allowlist signature must be base64");
  }
  const entries = validateAllowlistEntries(document.entries);
  const payload = { version: document.version, entries, signature: document.signature };
  if (!verifyAllowlistSignature(payload, publicKey)) {
    throw new AllowlistValidationError("allowlist signature does not match the document");
  }
  return { version: document.version, entries };
}
