import assert from "node:assert/strict";
import { test } from "node:test";

import { parseGitLabMajorVersion, requireSupportedGitLabVersion } from "./gitlab-version.js";

test("GitLab 19 and later satisfy the connector product floor", () => {
  assert.equal(parseGitLabMajorVersion("19.0.0-ee"), 19);
  assert.equal(parseGitLabMajorVersion("20.1.2"), 20);
  assert.doesNotThrow(() => requireSupportedGitLabVersion("19.0.0-ee"));
});

test("GitLab 18 is refused with the supported floor in the error", () => {
  assert.throws(
    () => requireSupportedGitLabVersion("18.11.7-ee"),
    /GitLab 18\.11\.7-ee is unsupported; heedvane-connector requires GitLab 19\.0 or newer/,
  );
});

test("an unreadable GitLab version is refused instead of guessed", () => {
  assert.throws(() => parseGitLabMajorVersion("release-current"), /did not contain a numeric major version/);
});
