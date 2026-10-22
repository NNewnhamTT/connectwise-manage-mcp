/**
 * Token store: maps a token back to the real value, per tenant.
 *
 * Keyed by tenant, not by MCP session, because the HTTP transports build a
 * new server for every request. The interface is async so a Redis store can
 * replace the in-memory one when the server runs on more than one replica.
 *
 * This module is side-effect free.
 */

export interface TokenStore {
  /** Save a token. Throws on a collision (same token, different value). */
  put(tenant: string, token: string, value: string, ttlSeconds: number): Promise<void>;
  get(tenant: string, token: string): Promise<string | undefined>;
}

export interface MemoryTokenStoreOptions {
  now?: () => number;
  /** Most entries kept. The oldest entry is dropped first. */
  maxEntries?: number;
}

interface Entry {
  value: string;
  expiresAt: number;
}

export class MemoryTokenStore implements TokenStore {
  private readonly entries = new Map<string, Entry>();
  private readonly now: () => number;
  private readonly maxEntries: number;

  constructor(options: MemoryTokenStoreOptions = {}) {
    this.now = options.now ?? Date.now;
    this.maxEntries = options.maxEntries ?? 100_000;
  }

  async put(tenant: string, token: string, value: string, ttlSeconds: number): Promise<void> {
    const key = `${tenant}\u0000${token}`;
    const existing = this.entries.get(key);
    if (existing && existing.expiresAt > this.now() && existing.value !== value) {
      throw new Error("PII token collision");
    }
    // Delete first so a refreshed entry moves to the back of the eviction order.
    this.entries.delete(key);
    this.entries.set(key, { value, expiresAt: this.now() + ttlSeconds * 1000 });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  async get(tenant: string, token: string): Promise<string | undefined> {
    const key = `${tenant}\u0000${token}`;
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt <= this.now()) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.value;
  }
}
