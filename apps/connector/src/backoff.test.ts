import assert from "node:assert/strict";
import { test } from "node:test";

import { backoffDelayMs, DEFAULT_BACKOFF, type BackoffOptions } from "./backoff.js";

const OPTIONS: BackoffOptions = { baseMs: 1_000, capMs: 60_000, jitterRatio: 0.5 };

test("the delay grows exponentially while under the cap", () => {
  // random() = 1 applies zero downward jitter, so the raw exponential shows through.
  const random = () => 1;
  assert.equal(backoffDelayMs(0, OPTIONS, random), 1_000);
  assert.equal(backoffDelayMs(1, OPTIONS, random), 2_000);
  assert.equal(backoffDelayMs(2, OPTIONS, random), 4_000);
  assert.equal(backoffDelayMs(3, OPTIONS, random), 8_000);
});

test("the delay never exceeds the cap no matter how many attempts have passed", () => {
  const random = () => 1;
  assert.equal(backoffDelayMs(10, OPTIONS, random), 60_000);
  assert.equal(backoffDelayMs(31, OPTIONS, random), 60_000);
  assert.equal(backoffDelayMs(100, OPTIONS, random), 60_000);
});

test("jitter keeps the delay inside [1 - jitterRatio, 1] of the exponential value", () => {
  const low = backoffDelayMs(2, OPTIONS, () => 0);
  const high = backoffDelayMs(2, OPTIONS, () => 1);
  assert.equal(low, 2_000);
  assert.equal(high, 4_000);
});

test("the default backoff reaches its cap and stays a positive integer", () => {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const delay = backoffDelayMs(attempt, DEFAULT_BACKOFF, () => 0.25);
    assert.ok(Number.isInteger(delay), `attempt ${attempt} produced a non-integer delay`);
    assert.ok(delay > 0, `attempt ${attempt} produced a non-positive delay`);
    assert.ok(delay <= DEFAULT_BACKOFF.capMs, `attempt ${attempt} exceeded the cap`);
  }
});
