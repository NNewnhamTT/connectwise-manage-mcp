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
  ms: number;
  bytes: number;
}

const MAX_KEYS = 30;
const MAX_TOKENS = 50;
const MAX_DEPTH = 8;

export function summarizeArgs(args: unknown): Record<string, unknown> {
  if (args === null || typeof args !== "object" || Array.isArray(args)) return {};
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args as Record<string, unknown>).slice(0, MAX_KEYS)) {
    if (typeof value === "number" || typeof value === "boolean" || value === null) out[key] = value;
    else if (typeof value === "string") out[key] = { len: value.length };
    else if (Array.isArray(value)) out[key] = { array: value.length };
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
    ms: e.ms,
    bytes: e.bytes,
  });
}
