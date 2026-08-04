import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const dockerfile = readFileSync(new URL("../Dockerfile", import.meta.url), "utf8");

test("the image persists enrollment credentials in its connector-owned volume", () => {
  assert.match(
    dockerfile,
    /ENV HEEDVANE_CREDENTIAL_FILE=\/var\/lib\/heedvane-connector\/credential/,
  );
  assert.match(dockerfile, /VOLUME \["\/var\/lib\/heedvane-connector"\]/);
  assert.match(
    dockerfile,
    /mkdir -p \/var\/lib\/heedvane-connector && chown connector:connector \/var\/lib\/heedvane-connector/,
  );
});
