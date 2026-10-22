/**
 * PII masking settings, read from the environment.
 *
 *   PII_MODE                  on | off (default off). Any other value is an error,
 *                             so a typo cannot switch masking off by accident.
 *   PII_KEY                   HMAC secret for tokens, 16 or more characters. Required when on.
 *   PII_PRESIDIO_URL          Base URL of the Presidio analyzer. Optional. Without it only
 *                             field rules and the pattern scan run (no names in free text).
 *   PII_PRESIDIO_TIMEOUT_MS   Default 5000.
 *   PII_TTL_SECONDS           How long a token can be turned back into its value. Default 86400.
 *   PII_SCORE_THRESHOLD       Lowest analyzer score that counts. Default 0.4.
 *
 * Never log these values. This module is side-effect free.
 */

import { MIN_KEY_LENGTH } from "./tokenizer.js";

export interface PiiConfig {
  key: string;
  presidioUrl?: string;
  presidioTimeoutMs: number;
  ttlSeconds: number;
  scoreThreshold: number;
}

type Env = Record<string, string | undefined>;

function positiveNumber(env: Env, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`${name} must be a positive number`);
  return n;
}

/** Returns undefined when masking is off. Throws on a bad setting. */
export function loadPiiConfig(
  env: Env = typeof process !== "undefined" ? process.env : {},
): PiiConfig | undefined {
  const mode = (env.PII_MODE ?? "off").trim().toLowerCase();
  if (mode === "off") return undefined;
  if (mode !== "on") throw new Error("PII_MODE must be 'on' or 'off'");

  const key = env.PII_KEY ?? "";
  if (key.length < MIN_KEY_LENGTH) {
    throw new Error(`PII_KEY is required when PII_MODE=on (at least ${MIN_KEY_LENGTH} characters)`);
  }
  const presidioUrl = env.PII_PRESIDIO_URL?.trim() || undefined;
  if (presidioUrl && !/^https?:\/\//i.test(presidioUrl)) {
    throw new Error("PII_PRESIDIO_URL must start with http:// or https://");
  }
  return {
    key,
    presidioUrl,
    presidioTimeoutMs: positiveNumber(env, "PII_PRESIDIO_TIMEOUT_MS", 5000),
    ttlSeconds: positiveNumber(env, "PII_TTL_SECONDS", 86400),
    scoreThreshold: positiveNumber(env, "PII_SCORE_THRESHOLD", 0.4),
  };
}
