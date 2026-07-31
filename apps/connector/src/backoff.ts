// Reconnect pacing for the tunnel: capped exponential backoff with downward jitter, so
// a fleet of connectors does not stampede the gateway after an outage. Pure and
// deterministic under an injected random source so the caps stay testable.

export interface BackoffOptions {
  readonly baseMs: number;
  readonly capMs: number;
  readonly jitterRatio: number;
}

export const DEFAULT_BACKOFF: BackoffOptions = { baseMs: 1_000, capMs: 60_000, jitterRatio: 0.5 };

/** Delay before retry attempt `attempt` (0 is the first retry). The exponential value is
 *  capped, then scaled into [1 - jitterRatio, 1] of itself by the random source. */
export function backoffDelayMs(attempt: number, options: BackoffOptions, random: () => number = Math.random): number {
  const exponential = options.baseMs * 2 ** Math.min(attempt, 30);
  const capped = Math.min(options.capMs, exponential);
  const scale = 1 - options.jitterRatio + random() * options.jitterRatio;
  return Math.max(1, Math.round(capped * scale));
}
