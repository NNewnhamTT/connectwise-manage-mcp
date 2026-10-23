/**
 * Audit log and access policy for every tool, without editing the tools.
 *
 * `withGuard` replaces `server.tool` and `server.registerTool` on the
 * instance, like `withPii` does. Each handler registered afterwards runs as:
 *
 *   policy check -> original handler -> audit line
 *
 * Call it BEFORE withPii and before any tool is registered. The patch applied
 * first ends up outermost, so the guard sees the arguments exactly as Claude
 * sent them (PII tokens, not real values) and the result after masking. A
 * denied call is stopped here, before any token is turned back into a real
 * value.
 *
 * Settings (environment), read by loadGuardConfig:
 *   MCP_AUDIT   on | off (default off). One JSON line per tool call on stderr.
 *   MCP_POLICY  read | write | admin. Default access level for callers without
 *               a role of their own. Unset: no restriction for such callers.
 * A bad value throws, so a typo cannot switch a control off.
 */

import { randomUUID } from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  collectTokens,
  formatAuditLine,
  summarizeArgs,
  type AuditStatus,
} from "./audit.js";
import { parseAccessLevel, type AccessLevel, type Identity } from "./identity.js";
import { classifyTool, isAllowed } from "./policy.js";

export interface GuardConfig {
  audit: boolean;
  /** Level for callers whose identity has no role. Undefined: unrestricted. */
  defaultLevel?: AccessLevel;
}

type Env = Record<string, string | undefined>;

/** Returns undefined when both controls are off. Throws on a bad setting. */
export function loadGuardConfig(
  env: Env = typeof process !== "undefined" ? process.env : {},
): GuardConfig | undefined {
  const auditRaw = (env.MCP_AUDIT ?? "off").trim().toLowerCase();
  if (auditRaw !== "on" && auditRaw !== "off") throw new Error("MCP_AUDIT must be 'on' or 'off'");

  const policyRaw = env.MCP_POLICY?.trim();
  let defaultLevel: AccessLevel | undefined;
  if (policyRaw) {
    defaultLevel = parseAccessLevel(policyRaw);
    if (!defaultLevel) throw new Error("MCP_POLICY must be 'read', 'write' or 'admin'");
  }
  const audit = auditRaw === "on";
  return audit || defaultLevel ? { audit, defaultLevel } : undefined;
}

export interface GuardOptions {
  identity: Identity;
  config: GuardConfig;
  /** Which ConnectWise credentials this server uses. Shown in the audit line. */
  credentials?: "shared" | "per-user";
  /**
   * When set, every tool call is refused, before the access policy and before
   * any PII token is unmasked. Used when a person has no ConnectWise key on file.
   */
  blocked?: { reason: string; message: string };
  /** Where audit lines go. Default: stderr. */
  emit?: (line: string) => void;
}

type Handler = (...args: unknown[]) => unknown;

interface ToolResultLike {
  isError?: boolean;
  content?: unknown;
}

function resultBytes(result: unknown): number {
  try {
    return JSON.stringify((result as ToolResultLike | undefined)?.content ?? "").length;
  } catch {
    return 0;
  }
}

function deniedResult(message: string) {
  return { isError: true, content: [{ type: "text", text: message }] };
}

function wrapHandler(name: string, handler: Handler, hasArgs: boolean, opts: GuardOptions): Handler {
  const { identity, config } = opts;
  const emit = opts.emit ?? ((line: string) => console.error(line));
  const toolClass = classifyTool(name);

  return async (...a: unknown[]) => {
    const started = performance.now();
    const requestId = randomUUID();
    const args = hasArgs ? a[0] : undefined;

    const enforce = config.defaultLevel !== undefined || identity.role !== undefined;
    const level: AccessLevel = identity.role ?? config.defaultLevel ?? "admin";

    const log = (status: AuditStatus, result: unknown, reason?: string): void => {
      if (!config.audit) return;
      emit(
        formatAuditLine({
          ts: new Date().toISOString(),
          requestId,
          identity,
          tool: name,
          toolClass,
          args: summarizeArgs(args),
          tokens: collectTokens(args),
          status,
          credential: opts.credentials,
          reason,
          ms: Math.round(performance.now() - started),
          bytes: resultBytes(result),
        }),
      );
    };

    if (opts.blocked) {
      const denied = deniedResult(opts.blocked.message);
      log("denied", denied, opts.blocked.reason);
      return denied;
    }

    if (enforce && !isAllowed(level, name)) {
      const denied = deniedResult(
        `Blocked by access policy: ${name} is a ${toolClass} tool and this caller's access level is "${level}". ` +
          "Nothing was sent to ConnectWise.",
      );
      log("denied", denied, `policy:${level}`);
      return denied;
    }

    let result: unknown;
    try {
      result = await handler(...a);
    } catch (err) {
      log("error", undefined);
      throw err;
    }
    log((result as ToolResultLike | undefined)?.isError ? "error" : "ok", result);
    return result;
  };
}

export function withGuard(server: McpServer, opts: GuardOptions): void {
  const originalTool = server.tool.bind(server) as unknown as (...a: unknown[]) => unknown;
  const originalRegister = server.registerTool.bind(server) as unknown as (...a: unknown[]) => unknown;

  (server as unknown as { tool: unknown }).tool = (...args: unknown[]) => {
    const last = args.length - 1;
    // tool(name, [description], [schema], [annotations], cb): a middle object is a schema.
    const hasArgs = args.slice(1, last).some((v) => v !== null && typeof v === "object");
    args[last] = wrapHandler(String(args[0]), args[last] as Handler, hasArgs, opts);
    return originalTool(...args);
  };

  (server as unknown as { registerTool: unknown }).registerTool = (
    name: string,
    config: Record<string, unknown>,
    cb: Handler,
  ) => originalRegister(name, config, wrapHandler(name, cb, config.inputSchema !== undefined, opts));
}
