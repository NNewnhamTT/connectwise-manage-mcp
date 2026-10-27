/**
 * Write policy: which write tools may run, and with which arguments.
 *
 * The access level (policy.ts) only says "this caller may write". This file
 * narrows that. It is a JSON file named by MCP_WRITE_POLICY_FILE:
 *
 *   {
 *     "version": 1,
 *     "exemptUsers": [],
 *     "tools": {
 *       "cw_add_ticket_note": {
 *         "require":   { "internalAnalysisFlag": true, "processNotifications": false },
 *         "denyTrue":  ["customerUpdatedFlag", "detailDescriptionFlag"]
 *       },
 *       "cw_update_ticket": {
 *         "patch": { "allowPaths": ["summary", "status/id"], "allowValues": { "status/id": [12, 14] } }
 *       }
 *     }
 *   }
 *
 * When a policy is loaded, it is a default-deny allow-list: a write or
 * destructive tool that is not under "tools" is refused. Read tools are never
 * touched. Rules per tool:
 *   require      { arg: value }  deny if the arg is set to anything else; add it when missing.
 *   requireArgs  [arg]           deny if the arg is missing.
 *   denyTrue     [arg]           deny if the arg is true. Never adds anything, so it cannot
 *                                overwrite state (for example customerUpdatedFlag).
 *   denyArgs     [arg]           deny if the arg is set at all.
 *   allowValues  { arg: [v] }    deny if the arg is set to a value not in the list.
 *   patch        JSON Patch rules for an array of { op, path, value } (arg name "operations"):
 *                  allowOps (default ["replace"]), allowPaths (exact, leading "/" ignored),
 *                  allowValues { path: [v] }. A path that is not listed is refused.
 *
 * "exemptUsers" skip the policy (break-glass). Empty by default.
 *
 * This module has no side effects except `loadWritePolicyFile`, which reads one file.
 */

import { readFileSync } from "node:fs";
import { classifyTool } from "./policy.js";

export type Scalar = string | number | boolean;
type PatchOp = "replace" | "add" | "remove";

export interface PatchRule {
  /** Name of the argument that holds the operations array. */
  arg: string;
  allowOps: PatchOp[];
  allowPaths: string[];
  allowValues: Record<string, Scalar[]>;
}

export interface ToolRule {
  require: Record<string, Scalar>;
  requireArgs: string[];
  denyTrue: string[];
  denyArgs: string[];
  allowValues: Record<string, Scalar[]>;
  patch?: PatchRule;
}

export interface WritePolicy {
  version: 1;
  exemptUsers: string[];
  tools: Record<string, ToolRule>;
}

export type WriteDecision =
  | { allowed: true; args: unknown; injected: string[] }
  | { allowed: false; reason: string; message: string };

const SETTING = "MCP_WRITE_POLICY_FILE";

function fail(problem: string): never {
  throw new Error(`${SETTING}: ${problem}`);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isScalar(v: unknown): v is Scalar {
  return typeof v === "string" || typeof v === "number" || typeof v === "boolean";
}

function onlyKeys(obj: Record<string, unknown>, allowed: string[], where: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) fail(`unknown key "${key}" in ${where}`);
  }
}

function stringList(v: unknown, where: string): string[] {
  if (v === undefined) return [];
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x.length > 0)) {
    fail(`${where} must be a list of non-empty strings`);
  }
  return v as string[];
}

function scalarList(v: unknown, where: string): Scalar[] {
  if (!Array.isArray(v) || v.length === 0 || !v.every(isScalar)) {
    fail(`${where} must be a non-empty list of strings, numbers or booleans`);
  }
  return v as Scalar[];
}

function valueLists(v: unknown, where: string): Record<string, Scalar[]> {
  if (v === undefined) return {};
  if (!isRecord(v)) fail(`${where} must be an object of lists`);
  const out: Record<string, Scalar[]> = {};
  for (const [key, list] of Object.entries(v)) out[key] = scalarList(list, `${where}.${key}`);
  return out;
}

function stripSlash(path: string): string {
  return path.replace(/^\/+/, "");
}

function parsePatch(v: unknown, where: string): PatchRule {
  if (!isRecord(v)) fail(`${where} must be an object`);
  onlyKeys(v, ["arg", "allowOps", "allowPaths", "allowValues"], where);
  const arg = v.arg === undefined ? "operations" : v.arg;
  if (typeof arg !== "string" || !arg) fail(`${where}.arg must be a string`);
  const ops = v.allowOps === undefined ? ["replace"] : v.allowOps;
  if (!Array.isArray(ops) || !ops.every((o) => o === "replace" || o === "add" || o === "remove")) {
    fail(`${where}.allowOps must be a list of "replace", "add" or "remove"`);
  }
  const allowPaths = stringList(v.allowPaths, `${where}.allowPaths`).map(stripSlash);
  const allowValues: Record<string, Scalar[]> = {};
  for (const [path, list] of Object.entries(valueLists(v.allowValues, `${where}.allowValues`))) {
    const key = stripSlash(path);
    if (!allowPaths.includes(key)) fail(`${where}.allowValues path "${path}" is not in allowPaths`);
    allowValues[key] = list;
  }
  return { arg, allowOps: ops as PatchOp[], allowPaths, allowValues };
}

function parseToolRule(v: unknown, tool: string): ToolRule {
  const where = `tools.${tool}`;
  if (!isRecord(v)) fail(`${where} must be an object`);
  onlyKeys(v, ["require", "requireArgs", "denyTrue", "denyArgs", "allowValues", "patch"], where);
  let require: Record<string, Scalar> = {};
  if (v.require !== undefined) {
    if (!isRecord(v.require) || !Object.values(v.require).every(isScalar)) {
      fail(`${where}.require must be an object of strings, numbers or booleans`);
    }
    require = v.require as Record<string, Scalar>;
  }
  return {
    require,
    requireArgs: stringList(v.requireArgs, `${where}.requireArgs`),
    denyTrue: stringList(v.denyTrue, `${where}.denyTrue`),
    denyArgs: stringList(v.denyArgs, `${where}.denyArgs`),
    allowValues: valueLists(v.allowValues, `${where}.allowValues`),
    patch: v.patch === undefined ? undefined : parsePatch(v.patch, `${where}.patch`),
  };
}

/** Validates a parsed policy. Throws a message that names the problem and never repeats values. */
export function parseWritePolicy(raw: unknown): WritePolicy {
  if (!isRecord(raw)) fail("the file must hold a JSON object");
  onlyKeys(raw, ["version", "comment", "exemptUsers", "tools"], "the top level");
  if (raw.version !== 1) fail('"version" must be 1');
  if (raw.comment !== undefined && typeof raw.comment !== "string") fail('"comment" must be a string');
  if (!isRecord(raw.tools)) fail('"tools" must be an object');
  const tools: Record<string, ToolRule> = {};
  for (const [name, rule] of Object.entries(raw.tools)) {
    if (classifyTool(name) === "read") {
      fail(`tools.${name} is a read tool. Remove it: read tools are not covered by this policy`);
    }
    tools[name] = parseToolRule(rule, name);
  }
  return { version: 1, exemptUsers: stringList(raw.exemptUsers, "exemptUsers"), tools };
}

/** Reads and validates the file at `path`. A bad file stops the server (fails closed). */
export function loadWritePolicyFile(path: string): WritePolicy {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    fail("the file cannot be read");
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    fail("the file is not valid JSON");
  }
  return parseWritePolicy(json);
}

/** A name safe to put in a log line or message: field-name characters only. */
function safeName(value: unknown): string {
  return typeof value === "string" && /^[A-Za-z0-9/_.-]{1,60}$/.test(value) ? value : "(invalid)";
}

function deny(tool: string, rule: string, detail: string): WriteDecision {
  return {
    allowed: false,
    reason: `rule:${tool}:${rule}`,
    message: `Blocked by write policy: ${detail} (${tool}). Nothing was sent to ConnectWise.`,
  };
}

function matches(list: Scalar[], value: unknown): boolean {
  return list.some((item) => item === value);
}

function checkPatch(tool: string, rule: PatchRule, args: Record<string, unknown>): WriteDecision | undefined {
  const ops = args[rule.arg];
  if (ops === undefined) return undefined;
  if (!Array.isArray(ops)) return deny(tool, `patch:${rule.arg}`, `${rule.arg} must be a list of patch operations`);
  for (const op of ops) {
    if (!isRecord(op) || typeof op.path !== "string" || typeof op.op !== "string") {
      return deny(tool, `patch:${rule.arg}`, "a patch operation is malformed");
    }
    const path = stripSlash(op.path);
    if (!rule.allowOps.includes(op.op as PatchOp)) {
      return deny(tool, `patch-op:${safeName(op.op)}`, `patch operation "${safeName(op.op)}" is not allowed`);
    }
    if (!rule.allowPaths.includes(path)) {
      return deny(tool, `patch-path:${safeName(path)}`, `changing "${safeName(path)}" is not allowed`);
    }
    const allowed = rule.allowValues[path];
    if (allowed && !matches(allowed, op.value)) {
      return deny(tool, `patch-value:${safeName(path)}`, `that value for "${safeName(path)}" is not on the allowed list`);
    }
  }
  return undefined;
}

/**
 * Decides one write call. `args` is the tool's argument object as the guard sees it
 * (PII tokens, never real values; ids are plain numbers). On allow, `args` may be a
 * copy with required values added, and `injected` names them.
 */
export function checkWrite(policy: WritePolicy, tool: string, args: unknown, user: string): WriteDecision {
  if (policy.exemptUsers.includes(user)) return { allowed: true, args, injected: [] };
  const rule = policy.tools[tool];
  if (!rule) return deny(tool, "not-listed", "this tool is not allowed");

  const input: Record<string, unknown> = isRecord(args) ? args : {};
  const set = (k: string): boolean => input[k] !== undefined && input[k] !== null;

  for (const k of rule.denyTrue) {
    if (input[k] === true) return deny(tool, `deny-true:${k}`, `${k} must not be true`);
  }
  for (const k of rule.denyArgs) {
    if (set(k)) return deny(tool, `deny-arg:${k}`, `${k} must not be set`);
  }
  for (const k of rule.requireArgs) {
    if (!set(k)) return deny(tool, `require-arg:${k}`, `${k} is required`);
  }
  for (const [k, list] of Object.entries(rule.allowValues)) {
    if (set(k) && !matches(list, input[k])) {
      return deny(tool, `allow-values:${k}`, `that value for ${k} is not on the allowed list`);
    }
  }
  const injected: string[] = [];
  const next: Record<string, unknown> = { ...input };
  for (const [k, value] of Object.entries(rule.require)) {
    if (!set(k)) {
      next[k] = value;
      injected.push(k);
    } else if (input[k] !== value) {
      return deny(tool, `require:${k}`, `${k} must be ${String(value)}`);
    }
  }
  if (rule.patch) {
    const denied = checkPatch(tool, rule.patch, input);
    if (denied) return denied;
  }
  return { allowed: true, args: injected.length > 0 ? next : args, injected };
}
