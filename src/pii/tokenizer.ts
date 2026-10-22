/**
 * Deterministic PII tokens.
 *
 * A token is `<TYPE_xxxxxxxxxx>`. The suffix is a truncated HMAC-SHA256 of the
 * type and the exact value, so the same value gives the same token on every
 * request, replica and conversation. No per-session counter is needed, which
 * suits the stateless HTTP transports. The token cannot be reversed by
 * itself: the real value comes back only through a TokenStore.
 *
 * This module is side-effect free.
 */

import { createHmac } from "node:crypto";

/** Hex characters kept from the HMAC. 40 bits keeps collisions very unlikely. */
export const TOKEN_SUFFIX_LENGTH = 10;
export const MIN_KEY_LENGTH = 16;

/** Matches one token anywhere in a string. Use with `matchAll` or `replace`. */
export const TOKEN_PATTERN = /<([A-Z]+)_([0-9a-f]{10})>/g;

export type EntityType = "PERSON" | "EMAIL" | "PHONE" | "ADDRESS" | "IP" | "MAC";

export interface Tokenizer {
  token(type: EntityType, value: string): string;
}

export function createTokenizer(key: string): Tokenizer {
  if (!key || key.length < MIN_KEY_LENGTH) {
    throw new Error(`PII key must be at least ${MIN_KEY_LENGTH} characters`);
  }
  return {
    token(type, value) {
      const digest = createHmac("sha256", key)
        .update(`${type}\u0000${value}`)
        .digest("hex")
        .slice(0, TOKEN_SUFFIX_LENGTH);
      return `<${type}_${digest}>`;
    },
  };
}
