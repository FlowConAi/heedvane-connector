import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  AllowlistValidationError,
  SEED_ALLOWLIST,
  SEED_ALLOWLIST_VERSION,
  canonicalizeAllowlist,
  matchesAllowlist,
  profilePermits,
  signAllowlist,
  validateAllowlistEntries,
  verifyAllowlistSignature,
  verifySignedAllowlist,
  type AllowlistEntry,
} from "./allowlist.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");

function request(method: string, path: string, query: readonly (readonly [string, string])[] = []) {
  return { method: method as AllowlistEntry["methods"][number], path, query };
}

function seedEntry(pathPattern: string): AllowlistEntry {
  const entry = SEED_ALLOWLIST.find((candidate) => candidate.pathPattern === pathPattern);
  assert.ok(entry, `seed allowlist is expected to contain ${pathPattern}`);
  return entry;
}

test("seed allowlist passes its own validation", () => {
  const entries = validateAllowlistEntries(SEED_ALLOWLIST);
  assert.equal(entries.length, SEED_ALLOWLIST.length);
});

test("seed allowlist matches every read the hub makes", () => {
  const allowed: readonly (readonly [string, string, readonly (readonly [string, string])[]])[] = [
    ["GET", "/api/v4/version", []],
    ["GET", "/api/v4/user", []],
    ["GET", "/api/v4/projects", [["membership", "true"], ["pagination", "keyset"], ["order_by", "id"], ["sort", "asc"], ["per_page", "100"], ["id_after", "42"]]],
    // The keyset next-page URL the hub follows verbatim from GitLab's Link header:
    // GitLab 18.11 echoes its full default filter set back as explicit params
    // (observed on gitlab/gitlab-ce:18.11.7-ce.0, 2026-07-30).
    ["GET", "/api/v4/projects", [["id_after", "1"], ["imported", "false"], ["membership", "true"], ["order_by", "id"], ["owned", "false"], ["page", "1"], ["pagination", "keyset"], ["per_page", "100"], ["simple", "false"], ["sort", "asc"], ["starred", "false"], ["statistics", "false"], ["with_custom_attributes", "false"], ["with_issues_enabled", "false"], ["with_merge_requests_enabled", "false"]]],
    ["GET", "/api/v4/projects/42", []],
    ["GET", "/api/v4/projects/group%2Fsub%2Fproject", []],
    ["GET", "/api/v4/projects/42/merge_requests", [["state", "opened"], ["updated_after", "2026-07-01T00:00:00Z"], ["updated_before", "2026-07-29T00:00:00Z"], ["order_by", "updated_at"], ["sort", "desc"], ["per_page", "100"], ["page", "2"]]],
    ["GET", "/api/v4/projects/42/merge_requests/7", []],
    ["GET", "/api/v4/projects/42/merge_requests/7/diffs", [["unidiff", "true"], ["per_page", "100"], ["page", "1"]]],
    ["GET", "/api/v4/projects/42/merge_requests/7/discussions", [["per_page", "100"], ["page", "1"]]],
    ["GET", "/api/v4/projects/42/merge_requests/7/notes", [["per_page", "100"], ["page", "1"]]],
    ["GET", "/api/v4/projects/42/repository/compare", [["from", "base-sha"], ["to", "head-sha"]]],
    ["GET", "/api/v4/projects/42/repository/merge_base", [["refs[]", "base-sha"], ["refs[]", "head-sha"]]],
    ["GET", "/api/v4/projects/42/repository/commits", [["since", "2026-07-01T00:00:00Z"], ["until", "2026-07-29T00:00:00Z"], ["ref_name", "main"], ["per_page", "100"], ["page", "1"]]],
    ["GET", "/api/v4/projects/42/repository/commits/abc123", []],
    ["GET", "/api/v4/projects/42/repository/branches", [["per_page", "100"], ["page", "1"]]],
    ["GET", "/api/v4/projects/42/repository/branches/feature%2Freview-x", []],
    ["GET", "/api/v4/projects/42/hooks", [["per_page", "100"], ["page", "1"]]],
    ["GET", "/api/v4/projects/42/hooks/13", []],
  ];
  for (const [method, path, query] of allowed) {
    assert.ok(matchesAllowlist(SEED_ALLOWLIST, request(method, path, query)), `${method} ${path} should be allowed`);
  }
});

test("seed allowlist matches the mutations the hub makes", () => {
  const allowed: readonly (readonly [string, string])[] = [
    ["POST", "/api/v4/projects/42/hooks"],
    ["PUT", "/api/v4/projects/42/hooks/13"],
    ["DELETE", "/api/v4/projects/42/hooks/13"],
    ["POST", "/api/v4/projects/42/hooks/13/test/push_events"],
    ["POST", "/api/v4/projects/42/merge_requests/7/discussions"],
    ["POST", "/api/v4/projects/42/merge_requests/7/notes"],
  ];
  for (const [method, path] of allowed) {
    assert.ok(matchesAllowlist(SEED_ALLOWLIST, request(method, path)), `${method} ${path} should be allowed`);
  }
});

test("seed allowlist matches git fetch and never git push", () => {
  assert.ok(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/acme/widget.git/info/refs", [["service", "git-upload-pack"]])));
  assert.ok(matchesAllowlist(SEED_ALLOWLIST, request("POST", "/acme/widget.git/git-upload-pack")));
  assert.equal(
    matchesAllowlist(SEED_ALLOWLIST, request("GET", "/acme/widget.git/info/refs", [["service", "git-receive-pack"]])),
    null,
  );
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("POST", "/acme/widget.git/git-receive-pack")), null);
});

test("requests outside the allowlist are refused", () => {
  const refused: readonly (readonly [string, string])[] = [
    ["GET", "/api/v4/groups"],
    ["GET", "/api/v4/projects/42/repository/files/README.md/raw"],
    ["POST", "/api/v4/projects"],
    ["PUT", "/api/v4/projects/42"],
    ["DELETE", "/api/v4/projects/42"],
    ["DELETE", "/api/v4/projects/42/merge_requests/7"],
    ["POST", "/api/v4/projects/42/merge_requests/7/merge"],
    ["GET", "/api/v4/projects/42/merge_requests/7/diffs/extra"],
  ];
  for (const [method, path] of refused) {
    assert.equal(matchesAllowlist(SEED_ALLOWLIST, request(method, path)), null, `${method} ${path} should be refused`);
  }
});

test("query param filtering refuses unlisted params and tolerates duplicates of listed ones", () => {
  const mergeBase = "/api/v4/projects/42/repository/merge_base";
  assert.ok(matchesAllowlist(SEED_ALLOWLIST, request("GET", mergeBase, [["refs[]", "a"], ["refs[]", "b"]])));
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", mergeBase, [["refs[]", "a"], ["scope", "all"]])), null);
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/api/v4/version", [["page", "1"]])), null);
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/acme/widget.git/info/refs", [["service", "git-upload-pack"], ["debug", "1"]])), null);
  assert.equal(
    matchesAllowlist(SEED_ALLOWLIST, request("GET", "/acme/widget.git/info/refs", [["service", "git-upload-pack"], ["service", "git-receive-pack"]])),
    null,
  );
});

test("path params match exactly one segment", () => {
  assert.ok(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/api/v4/projects/42/merge_requests/7")));
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/api/v4/projects/42/0/merge_requests/7")), null);
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/api/v4/projects//merge_requests")), null);
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/acme/widget.git/info/refs/extra", [["service", "git-upload-pack"]])), null);
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/acme/widget/info/refs", [["service", "git-upload-pack"]])), null);
  assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", "/acme/.git/info/refs", [["service", "git-upload-pack"]])), null);
  assert.ok(
    matchesAllowlist(
      SEED_ALLOWLIST,
      request("GET", "/api/v4/projects/42/repository/branches/feature%25coverage"),
    ),
  );
});

test("request paths cannot change meaning when the connector constructs the upstream URL", () => {
  const refused = [
    "/api/v4/projects/..\\groups",
    "/api/v4/projects/42%5cgroups",
    "/api/v4/projects/%2e%2e",
    "/api/v4/projects/..%2Fuser",
    "/api/v4/projects/42?sudo=1",
    "/api/v4/projects/%",
    "//attacker.example/api/v4/version",
  ];
  for (const path of refused) {
    assert.equal(matchesAllowlist(SEED_ALLOWLIST, request("GET", path)), null, `${path} should be refused`);
  }
});

test("git-receive-pack cannot be added by a malformed list", () => {
  // The push capability must stay structurally absent: a list carrying a receive-pack
  // entry fails validation, and even an unvalidated list never matches a receive-pack
  // request, so neither a server bug nor a forged document can open push access.
  const receivePackEntry = { methods: ["POST"], pathPattern: "/:namespace/:project.git/git-receive-pack", allowedQueryParams: [] };
  assert.throws(
    () => validateAllowlistEntries([...SEED_ALLOWLIST, receivePackEntry]),
    (error: unknown) => {
      if (!(error instanceof AllowlistValidationError)) throw error;
      assert.match(error.message, /git-receive-pack/);
      return true;
    },
  );
  const rawList = [...SEED_ALLOWLIST, receivePackEntry] as unknown as readonly AllowlistEntry[];
  assert.equal(matchesAllowlist(rawList, request("POST", "/acme/widget.git/git-receive-pack")), null);

  const wildcardService = {
    methods: ["POST"],
    pathPattern: "/:namespace/:project.git/:service",
    allowedQueryParams: [],
  };
  assert.throws(() => validateAllowlistEntries([wildcardService]), /git-receive-pack/);
  const rawWildcard = [wildcardService] as unknown as readonly AllowlistEntry[];
  assert.equal(matchesAllowlist(rawWildcard, request("POST", "/acme/widget.git/git-receive-pack")), null);
  assert.equal(matchesAllowlist(rawWildcard, request("POST", "/acme/widget.git/%67it-receive-pack")), null);
  assert.equal(
    matchesAllowlist(rawWildcard, request("POST", "/acme%2Fsubgroup/widget.git/git-receive-pack")),
    null,
  );
  assert.equal(profilePermits("read-only", rawWildcard[0]), false);
  assert.equal(profilePermits("read-write", rawWildcard[0]), false);

  const encodedReceivePackEntry = {
    methods: ["POST"],
    pathPattern: "/:namespace/:project.git/%67it-receive-pack",
    allowedQueryParams: [],
  };
  assert.throws(() => validateAllowlistEntries([encodedReceivePackEntry]), /git-receive-pack/);

  const doubleEncodedReceivePackEntry = {
    methods: ["POST"],
    pathPattern: "/:namespace/:project.git/%2567it-receive-pack",
    allowedQueryParams: [],
  };
  assert.throws(() => validateAllowlistEntries([doubleEncodedReceivePackEntry]), /git-receive-pack/);
  const rawDoubleEncoded = [doubleEncodedReceivePackEntry] as unknown as readonly AllowlistEntry[];
  assert.equal(matchesAllowlist(rawDoubleEncoded, request("POST", "/acme/widget.git/%2567it-receive-pack")), null);
  assert.equal(profilePermits("read-only", rawDoubleEncoded[0]), false);
  assert.equal(profilePermits("read-write", rawDoubleEncoded[0]), false);

  const literalPercentEntry = {
    methods: ["GET"],
    pathPattern: "/api/v4/projects/:id/repository/branches/feature%25coverage",
    allowedQueryParams: [],
  };
  assert.doesNotThrow(() => validateAllowlistEntries([literalPercentEntry]));

  const mixedPercentReceivePackEntry = {
    methods: ["POST"],
    pathPattern: "/:namespace/:project%25coverage.git/%2567it-receive-pack",
    allowedQueryParams: [],
  };
  assert.throws(() => validateAllowlistEntries([mixedPercentReceivePackEntry]), /git-receive-pack/);
  const rawMixedPercent = [mixedPercentReceivePackEntry] as unknown as readonly AllowlistEntry[];
  assert.equal(
    matchesAllowlist(
      rawMixedPercent,
      request("POST", "/acme/widget%25coverage.git/%2567it-receive-pack"),
    ),
    null,
  );
  assert.equal(profilePermits("read-only", rawMixedPercent[0]), false);
  assert.equal(profilePermits("read-write", rawMixedPercent[0]), false);
});

test("read-write profile permits every seed entry", () => {
  for (const entry of SEED_ALLOWLIST) {
    assert.ok(profilePermits("read-write", entry), `read-write should permit ${entry.methods.join(",")} ${entry.pathPattern}`);
  }
});

test("read-only profile permits every read including git fetch", () => {
  const permittedPatterns = [
    "/api/v4/version",
    "/api/v4/user",
    "/api/v4/projects",
    "/api/v4/projects/:id",
    "/api/v4/projects/:id/merge_requests",
    "/api/v4/projects/:id/merge_requests/:iid",
    "/api/v4/projects/:id/merge_requests/:iid/diffs",
    "/api/v4/projects/:id/merge_requests/:iid/discussions",
    "/api/v4/projects/:id/merge_requests/:iid/notes",
    "/api/v4/projects/:id/repository/compare",
    "/api/v4/projects/:id/repository/merge_base",
    "/api/v4/projects/:id/repository/commits",
    "/api/v4/projects/:id/repository/commits/:sha",
    "/api/v4/projects/:id/repository/branches",
    "/api/v4/projects/:id/repository/branches/:branch",
    "/api/v4/projects/:id/hooks",
    "/api/v4/projects/:id/hooks/:hookId",
    "/:namespace/:project.git/info/refs",
    "/:namespace/:project.git/git-upload-pack",
  ];
  for (const pattern of permittedPatterns) {
    assert.ok(profilePermits("read-only", seedEntry(pattern)), `read-only should permit ${pattern}`);
  }
});

test("read-only profile refuses hook mutations and merge-request writes", () => {
  const refused: readonly AllowlistEntry[] = [
    { methods: ["POST"], pathPattern: "/api/v4/projects/:id/hooks", allowedQueryParams: [] },
    { methods: ["PUT"], pathPattern: "/api/v4/projects/:id/hooks/:hookId", allowedQueryParams: [] },
    { methods: ["DELETE"], pathPattern: "/api/v4/projects/:id/hooks/:hookId", allowedQueryParams: [] },
    { methods: ["POST"], pathPattern: "/api/v4/projects/:id/hooks/:hookId/test/push_events", allowedQueryParams: [] },
    { methods: ["POST"], pathPattern: "/api/v4/projects/:id/merge_requests/:iid/discussions", allowedQueryParams: [] },
    { methods: ["POST"], pathPattern: "/api/v4/projects/:id/merge_requests/:iid/notes", allowedQueryParams: [] },
  ];
  for (const entry of refused) {
    assert.equal(profilePermits("read-only", entry), false, `read-only should refuse ${entry.methods.join(",")} ${entry.pathPattern}`);
  }
  assert.equal(
    profilePermits("read-only", {
      methods: ["POST"],
      pathPattern: "/api/v4/admin/git-upload-pack",
      allowedQueryParams: [],
    }),
    false,
  );
});

test("no profile ever permits a receive-pack entry", () => {
  const entry: AllowlistEntry = { methods: ["POST"], pathPattern: "/:namespace/:project.git/git-receive-pack", allowedQueryParams: [] };
  assert.equal(profilePermits("read-only", entry), false);
  assert.equal(profilePermits("read-write", entry), false);
});

test("entry validation rejects malformed shapes", () => {
  const invalid: readonly unknown[] = [
    "not-an-entry",
    { pathPattern: "/x", allowedQueryParams: [] },
    { methods: [], pathPattern: "/x", allowedQueryParams: [] },
    { methods: ["TELEPORT"], pathPattern: "/x", allowedQueryParams: [] },
    { methods: ["GET"], pathPattern: "x", allowedQueryParams: [] },
    { methods: ["GET"], pathPattern: "/x", allowedQueryParams: [42] },
    { methods: ["GET"], pathPattern: "/x", allowedQueryParams: ["a,b"] },
    { methods: ["GET"], pathPattern: "/x|y", allowedQueryParams: [] },
    { methods: ["GET"], pathPattern: "/api/v4/:", allowedQueryParams: [] },
  ];
  for (const value of invalid) {
    assert.throws(() => validateAllowlistEntries([value]), AllowlistValidationError);
  }
});

test("canonicalization is stable across entry, method, and param ordering", () => {
  const first: AllowlistEntry = { methods: ["POST", "GET"], pathPattern: "/b", allowedQueryParams: ["z", "a"] };
  const second: AllowlistEntry = { methods: ["GET"], pathPattern: "/a", allowedQueryParams: [] };
  const reorderedFirst: AllowlistEntry = { methods: ["GET", "POST"], pathPattern: "/b", allowedQueryParams: ["a", "z"] };
  assert.equal(
    canonicalizeAllowlist("1", [first, second]),
    canonicalizeAllowlist("1", [second, reorderedFirst]),
  );
  assert.match(canonicalizeAllowlist("1", [first]), /"methods":\["GET","POST"\]/);
  assert.match(canonicalizeAllowlist("1", [first]), /"allowedQueryParams":\["a","z"\]/);
  assert.match(canonicalizeAllowlist("1", [first]), /version="1"\n/);
});

test("ed25519 sign and verify round-trips the seed allowlist", () => {
  const signature = signAllowlist(SEED_ALLOWLIST_VERSION, SEED_ALLOWLIST, privateKey);
  const payload = { version: SEED_ALLOWLIST_VERSION, entries: SEED_ALLOWLIST, signature };
  assert.ok(verifyAllowlistSignature(payload, publicKey));
});

test("signature verification rejects every tamper", () => {
  const signature = signAllowlist(SEED_ALLOWLIST_VERSION, SEED_ALLOWLIST, privateKey);
  const extraEntry: AllowlistEntry = { methods: ["GET"], pathPattern: "/api/v4/groups", allowedQueryParams: [] };
  const tamperedEntries = [...SEED_ALLOWLIST, extraEntry];
  assert.equal(verifyAllowlistSignature({ version: SEED_ALLOWLIST_VERSION, entries: tamperedEntries, signature }, publicKey), false);
  assert.equal(verifyAllowlistSignature({ version: "2", entries: SEED_ALLOWLIST, signature }, publicKey), false);

  const other = generateKeyPairSync("ed25519");
  const honest = { version: SEED_ALLOWLIST_VERSION, entries: SEED_ALLOWLIST, signature };
  assert.equal(verifyAllowlistSignature(honest, other.publicKey), false);

  const foreignSignature = signAllowlist("other", [{ methods: ["GET"], pathPattern: "/x", allowedQueryParams: [] }], privateKey);
  assert.equal(verifyAllowlistSignature({ version: SEED_ALLOWLIST_VERSION, entries: SEED_ALLOWLIST, signature: foreignSignature }, publicKey), false);

  assert.equal(verifyAllowlistSignature({ version: SEED_ALLOWLIST_VERSION, entries: SEED_ALLOWLIST, signature: "not-base64!!!" }, publicKey), false);
  assert.equal(verifyAllowlistSignature({ version: SEED_ALLOWLIST_VERSION, entries: SEED_ALLOWLIST, signature: "c2hvcnQ=" }, publicKey), false);

  const extensionEntry = {
    methods: ["GET"],
    pathPattern: "/api/v4/version",
    allowedQueryParams: [],
    futureCapability: "read",
  } as AllowlistEntry;
  const extensionSignature = signAllowlist("future", [extensionEntry], privateKey);
  const changedExtension = { ...extensionEntry, futureCapability: "write" } as AllowlistEntry;
  assert.equal(
    verifyAllowlistSignature({
      version: "future",
      entries: [changedExtension],
      signature: extensionSignature,
    }, publicKey),
    false,
  );

  const orderedExtension = { ...extensionEntry, futureSteps: ["first", "second"] } as AllowlistEntry;
  const orderedSignature = signAllowlist("future", [orderedExtension], privateKey);
  const reorderedExtension = { ...orderedExtension, futureSteps: ["second", "first"] } as AllowlistEntry;
  assert.equal(
    verifyAllowlistSignature({
      version: "future",
      entries: [reorderedExtension],
      signature: orderedSignature,
    }, publicKey),
    false,
  );
});

test("verifySignedAllowlist returns validated entries and rejects bad documents", () => {
  const signature = signAllowlist(SEED_ALLOWLIST_VERSION, SEED_ALLOWLIST, privateKey);
  const verified = verifySignedAllowlist(
    { version: SEED_ALLOWLIST_VERSION, signature, entries: SEED_ALLOWLIST },
    publicKey,
  );
  assert.equal(verified.version, SEED_ALLOWLIST_VERSION);
  assert.equal(verified.entries.length, SEED_ALLOWLIST.length);

  assert.throws(
    () => verifySignedAllowlist({ version: SEED_ALLOWLIST_VERSION, signature: "c2hvcnQ=", entries: SEED_ALLOWLIST }, publicKey),
    AllowlistValidationError,
  );
});

test("a valid signature cannot legitimize a receive-pack entry", () => {
  // The connector validates the document before trusting the signature, so even a
  // correctly signed list is refused when it carries the forbidden capability.
  const receivePackEntry: AllowlistEntry = { methods: ["POST"], pathPattern: "/:n/:p.git/git-receive-pack", allowedQueryParams: [] };
  const entries = [...SEED_ALLOWLIST, receivePackEntry];
  const signature = signAllowlist("1", entries, privateKey);
  assert.throws(
    () => verifySignedAllowlist({ version: "1", signature, entries }, publicKey),
    /git-receive-pack/,
  );
});
