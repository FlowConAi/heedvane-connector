import assert from "node:assert/strict";
import { test } from "node:test";

import {
  parseGitLabMajorVersion,
  requireSupportedGitLabVersion,
  webhookVerificationSchemeForGitLabVersion,
} from "./gitlab-version.js";

test("GitLab 18.11 and later satisfy the connector product floor", () => {
  assert.doesNotThrow(() => requireSupportedGitLabVersion("18.11.7-ee"));
  assert.equal(parseGitLabMajorVersion("19.0.0-ee"), 19);
  assert.equal(parseGitLabMajorVersion("20.1.2"), 20);
  assert.doesNotThrow(() => requireSupportedGitLabVersion("19.0.0-ee"));
});

test("GitLab before 18.11 is refused with the supported floor in the error", () => {
  assert.throws(
    () => requireSupportedGitLabVersion("18.10.9-ee"),
    /GitLab 18\.10\.9-ee is unsupported; heedvane-connector requires GitLab 18\.11 or newer/,
  );
});

test("the authenticated GitLab version selects one webhook scheme without fallback", () => {
  assert.equal(webhookVerificationSchemeForGitLabVersion("18.11.7-ee"), "secret-token");
  assert.equal(webhookVerificationSchemeForGitLabVersion("19.2.0-ee"), "signing-token");
});

test("an unreadable GitLab version is refused instead of guessed", () => {
  assert.throws(() => parseGitLabMajorVersion("release-current"), /did not contain a numeric major version/);
});
