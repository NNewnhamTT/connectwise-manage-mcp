/**
 * Audit log lines: one JSON object per tool call.
 *
 * A line says who called which tool, with which ids, and what happened. It
 * never holds a string value from the arguments or anything from the result.
 * Claude can type real names into a search or a note, so string values may be
 * PII. A line keeps only the length of a string, plus any PII tokens found in
 * it (a token is not PII). Numbers and booleans are kept as they are.
 *
 * This module is side-effect free.
 */

import { TOKEN_PATTERN } from "../pii/tokenizer.js";
import type { Identity } from "./identity.js";

export type AuditStatus = "ok" | "error" | "denied";

export interface AuditEvent {
  ts: string;
  requestId: string;
  identity: Identity;
  tool: string;
  toolClass: string;
  args: Record<string, unknown>;
  tokens: string[];
  status: AuditStatus;
  /** Which ConnectWise credentials the server uses: one shared key or one per person. */
  credential?: "shared" | "per-user";
  /** Why a call was denied. A fixed phrase, never user data. */
  reason?: string;
  /** Argument names the write policy added to the call. Names only, never values. */
  injected?: string[];
  ms: number;
  bytes: number;
}

const MAX_KEYS = 30;
const MAX_TOKENS = 50;
const MAX_DEPTH = 8;

const MAX_PATHS = 20;
const SAFE_PATH = /^[A-Za-z0-9/_.-]{1,60}$/;

/**
 * An array is logged as its length. A JSON Patch array (every item has a string
 * `path`) also lists its paths, so the log shows which fields a patch touched.
 * A path is a field name, not a value, and only plain field-name characters are kept.
 */
function summarizeArray(items: unknown[]): Record<string, unknown> {
  const paths = items.map((item) =>
    item !== null && typeof item === "object" ? (item as Record<string, unknown>).path : undefined,
  );
  if (items.length === 0 || !paths.every((p) => typeof p === "string")) return { array: items.length };
  return {
    array: items.length,
    paths: (paths as string[]).slice(0, MAX_PATHS).map((p) => (SAFE_PATH.test(p) ? p : "(invalid)")),
  };
}

export function summarizeArgs(args: unknown): Record<string, unknown> {
  if (args === null || typeof args !== "object" || Array.isArray(args)) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args as Record<string, unknown>).slice(0, MAX_KEYS)) {
    if (typeof value === "number" || typeof value === "boolean" || value === null) out[key] = value;
    else if (typeof value === "string") out[key] = { len: value.length };
    else if (Array.isArray(value)) out[key] = summarizeArray(value);
    else if (value === undefined) continue;
    else out[key] = "object";
  }
  return out;
}

/** Every PII token found in any string of `value`, once each. */
export function collectTokens(value: unknown): string[] {
  const found = new Set<string>();
  const walk = (node: unknown, depth: number): void => {
    if (found.size >= MAX_TOKENS || depth > MAX_DEPTH) return;
    if (typeof node === "string") {
      for (const token of node.match(TOKEN_PATTERN) ?? []) {
        found.add(token);
        if (found.size >= MAX_TOKENS) return;
      }
    } else if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
    } else if (node !== null && typeof node === "object") {
      for (const item of Object.values(node as Record<string, unknown>)) walk(item, depth + 1);
    }
  };
  walk(value, 0);
  return [...found];
}

export function formatAuditLine(e: AuditEvent): string {
  return JSON.stringify({
    type: "audit",
    ts: e.ts,
    requestId: e.requestId,
    user: e.identity.user,
    role: e.identity.role ?? null,
    source: e.identity.source,
    tool: e.tool,
    class: e.toolClass,
    args: e.args,
    tokens: e.tokens,
    status: e.status,
    ...(e.credential ? { credential: e.credential } : {}),
    ...(e.reason ? { reason: e.reason } : {}),
    ...(e.injected && e.injected.length > 0 ? { injected: e.injected } : {}),
    ms: e.ms,
    bytes: e.bytes,
  });
}
