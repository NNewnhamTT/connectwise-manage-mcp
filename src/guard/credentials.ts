/**
 * ConnectWise credentials per person.
 *
 * Shared mode (default): every caller uses the one API member from the
 * CW_MANAGE_* settings.
 *
 * Per-user mode (CW_CREDENTIALS=per-user): each person's calls use that
 * person's own CW API key, chosen by who is signed in. ConnectWise's own audit
 * trail can then name the person, and that person's CW security role limits
 * what their Claude can do. The shared CW_MANAGE_PUBLIC_KEY and
 * CW_MANAGE_PRIVATE_KEY are never used in this mode. A person with no key on
 * file is refused (the server blocks every call): there is no fallback to a
 * shared key.
 *
 *   CW_CREDENTIALS   shared (default) | per-user. Any other value is an error,
 *                    so a typo cannot fall back to the shared key.
 *   CW_USER_KEYS     name=publicKey:privateKey, separated by ";" or newlines.
 *                    The name is the identity's user name (Entra sign-in name,
 *                    or the PROXY_USERS name), matched without regard to case.
 *   CW_MANAGE_COMPANY_ID, CW_MANAGE_CLIENT_ID, CW_MANAGE_URL: shared by everyone.
 *
 * Error messages never repeat an entry, because an entry holds a key.
 * This module is side-effect free.
 */

import type { CwManageConfig } from "../api-client.js";
import { isValidUserName, type Identity } from "./identity.js";

export interface CredentialSource {
  /** Config for this caller's own key, or undefined when none is on file. */
  configFor(identity: Identity): CwManageConfig | undefined;
  /** Config with no keys, for a server that refuses every call. */
  withoutKeys(): CwManageConfig;
}

type Env = Record<string, string | undefined>;

const DEFAULT_BASE_URL = "https://api-na.myconnectwise.net";
/** CW keys are plain tokens. Reject anything that could break the entry format. */
const KEY_PATTERN = /^[^\s:;=]{1,200}$/;

function parseUserKeys(raw: string): Map<string, { publicKey: string; privateKey: string }> {
  const keys = new Map<string, { publicKey: string; privateKey: string }>();
  const entries = raw
    .split(/[;\n\r]+/)
    .map((e) => e.trim())
    .filter(Boolean);
  entries.forEach((entry, i) => {
    const bad = (why: string): never => {
      throw new Error(`CW_USER_KEYS entry ${i + 1} is invalid: ${why}`);
    };
    const eq = entry.indexOf("=");
    if (eq < 1) return bad("expected name=publicKey:privateKey");
    const name = entry.slice(0, eq).trim();
    const pair = entry.slice(eq + 1).split(":");
    if (pair.length !== 2) return bad("expected publicKey:privateKey after the name");
    const [publicKey, privateKey] = pair.map((p) => p.trim()) as [string, string];
    if (!isValidUserName(name)) return bad("the name has characters that are not allowed");
    if (!KEY_PATTERN.test(publicKey) || !KEY_PATTERN.test(privateKey)) return bad("a key is empty or has a bad character");
    const lower = name.toLowerCase();
    if (keys.has(lower)) return bad("the name is listed twice");
    keys.set(lower, { publicKey, privateKey });
  });
  return keys;
}

/** Returns undefined in shared mode. Throws on a bad setting. */
export function loadCredentialSource(
  env: Env = typeof process !== "undefined" ? process.env : {},
): CredentialSource | undefined {
  const mode = (env.CW_CREDENTIALS ?? "shared").trim().toLowerCase();
  if (mode === "shared") return undefined;
  if (mode !== "per-user") throw new Error("CW_CREDENTIALS must be 'shared' or 'per-user'");

  const keys = parseUserKeys(env.CW_USER_KEYS ?? "");
  if (keys.size === 0) throw new Error("CW_CREDENTIALS=per-user needs at least one entry in CW_USER_KEYS");

  const companyId = env.CW_MANAGE_COMPANY_ID?.trim();
  const clientId = env.CW_MANAGE_CLIENT_ID?.trim();
  if (!companyId) throw new Error("CW_CREDENTIALS=per-user needs CW_MANAGE_COMPANY_ID");
  if (!clientId) throw new Error("CW_CREDENTIALS=per-user needs CW_MANAGE_CLIENT_ID");
  const baseUrl = (env.CW_MANAGE_URL?.trim() || DEFAULT_BASE_URL).replace(/\/+$/, "");

  return {
    configFor(identity) {
      const own = keys.get(identity.user.toLowerCase());
      if (!own || identity.source === "anonymous") return undefined;
      return { baseUrl, companyId, clientId, publicKey: own.publicKey, privateKey: own.privateKey };
    },
    withoutKeys() {
      return { baseUrl, companyId, clientId, publicKey: "", privateKey: "" };
    },
  };
}
