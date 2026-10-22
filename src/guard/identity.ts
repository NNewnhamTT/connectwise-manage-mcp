/**
 * Who is calling the MCP server.
 *
 * An identity has a name for the audit log and, optionally, an access level
 * that overrides the server default (see policy.ts). It comes from one of:
 * - `entra`:        a validated Entra ID token (upn and app roles)
 * - `proxy`:        X-Mcp-User / X-Mcp-Role set by the signing proxy. Trusted only
 *                   when X-Gateway-S2S verified, because only the proxy holds that secret
 * - `static-token`: the shared MCP_BEARER_TOKEN (one name for everybody)
 * - `anonymous`:    no identity available
 *
 * This module is side-effect free.
 */

export type AccessLevel = "read" | "write" | "admin";
export type IdentitySource = "entra" | "proxy" | "static-token" | "anonymous";

export interface Identity {
  user: string;
  /** Overrides MCP_POLICY for this caller. Absent means use the server default. */
  role?: AccessLevel;
  source: IdentitySource;
}

export const ANONYMOUS: Identity = { user: "anonymous", source: "anonymous" };

/** Names go into log lines and headers. Keep them plain. */
const USER_PATTERN = /^[A-Za-z0-9._@+-]{1,100}$/;

export function isValidUserName(value: string): boolean {
  return USER_PATTERN.test(value);
}

export function parseAccessLevel(value: string | undefined): AccessLevel | undefined {
  const v = value?.trim().toLowerCase();
  return v === "read" || v === "write" || v === "admin" ? v : undefined;
}

/**
 * Identity from the proxy's headers. Call this only after X-Gateway-S2S has
 * verified. A missing or malformed user gives undefined. A malformed role is
 * dropped (the caller then gets the server default, never more).
 */
export function identityFromProxyHeaders(
  userHeader: string | undefined,
  roleHeader: string | undefined,
): Identity | undefined {
  const user = userHeader?.trim();
  if (!user || !isValidUserName(user)) return undefined;
  return { user, role: parseAccessLevel(roleHeader), source: "proxy" };
}

/** Entra app roles that raise access. Create them on the app registration. */
export const ENTRA_ROLE_WRITE = "CWM.Write";
export const ENTRA_ROLE_ADMIN = "CWM.Admin";

export function identityFromEntra(upn: string, roles: string[]): Identity {
  const role: AccessLevel | undefined = roles.includes(ENTRA_ROLE_ADMIN)
    ? "admin"
    : roles.includes(ENTRA_ROLE_WRITE)
      ? "write"
      : undefined;
  return { user: upn || "unknown-entra-user", role, source: "entra" };
}
