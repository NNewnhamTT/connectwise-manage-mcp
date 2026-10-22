/**
 * Public entry for the PII layer: build a context from config and attach it.
 *
 * The HTTP transports build a new server per request, so the token store is a
 * module-level singleton. A process restart empties it. Tokens stay stable
 * (they are derived from PII_KEY) but cannot be reversed until the record is
 * fetched again.
 */

import { createHash } from "node:crypto";
import type { PiiConfig } from "./config.js";
import { createTokenizer } from "./tokenizer.js";
import { MemoryTokenStore, type TokenStore } from "./store.js";
import { createPresidioAnalyzer } from "./presidio-client.js";
import type { PiiContext } from "./mask-json.js";

export { loadPiiConfig, type PiiConfig } from "./config.js";
export { withPii } from "./wrap-server.js";

let sharedStore: TokenStore | undefined;

export function getSharedStore(): TokenStore {
  sharedStore ??= new MemoryTokenStore();
  return sharedStore;
}

/** Test hook: drop the shared store. */
export function resetSharedStore(): void {
  sharedStore = undefined;
}

/**
 * @param tenantSeed Identifies whose tokens these are, so one API member can
 *   never resolve tokens made for another. Hashed before use.
 */
export function createPiiContext(config: PiiConfig, tenantSeed: string): PiiContext {
  return {
    tokenizer: createTokenizer(config.key),
    store: getSharedStore(),
    tenant: createHash("sha256").update(tenantSeed).digest("hex").slice(0, 32),
    ttlSeconds: config.ttlSeconds,
    scoreThreshold: config.scoreThreshold,
    analyzer: config.presidioUrl
      ? createPresidioAnalyzer({ baseUrl: config.presidioUrl, timeoutMs: config.presidioTimeoutMs })
      : undefined,
  };
}
