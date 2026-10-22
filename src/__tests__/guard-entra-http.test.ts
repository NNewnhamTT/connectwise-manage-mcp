/**
 * Identity from Microsoft Entra ID over the real HTTP transport. Token
 * validation is stubbed (no network); everything after it is real: the
 * identity mapping, the CWM.Write / CWM.Admin app roles, the audit line and
 * the access policy.
 */

import { createHmac } from "node:crypto";
import { request as httpRequest } from "node:http";
import type { Server as HttpServer } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthError, type EntraIdentity } from "../auth/types.js";

const validate = vi.hoisted(() => ({
  fn: undefined as undefined | ((token: string) => Promise<EntraIdentity>),
}));

vi.mock("../auth/middleware.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../auth/middleware.js")>();
  return {
    ...actual,
    validateToken: (token: string) => {
      if (!validate.fn) throw new Error("validateToken stub not set");
      return validate.fn(token);
    },
  };
});

import { startHttpTransport } from "../index.js";

const S2S_SECRET = "s2s-do-not-log-7f3a9c-entra-test";
const STATIC_TOKEN = "static-bearer-token-for-cli-0123456789";
const servers: HttpServer[] = [];
let auditLines: string[];
let cwCalls: { method: string }[];

function s2s(): string {
  const t = Math.floor(Date.now() / 1000);
  return `t=${t},v1=${createHmac("sha256", S2S_SECRET).update(`t=${t}`).digest("hex")}`;
}

function post(port: number, headers: Record<string, string>, body: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port,
        method: "POST",
        path: "/mcp",
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.write(JSON.stringify(body));
    req.end();
  });
}

const call = (name: string, args: Record<string, unknown>) => ({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name, arguments: args },
});
const UPDATE = call("cw_update_contact", { id: 99, operations: [{ op: "replace", path: "title", value: "Boss" }] });
const READ = call("cw_get_contact", { id: 99 });

async function listen(): Promise<number> {
  vi.stubEnv("MCP_HTTP_PORT", "0");
  const server = await startHttpTransport();
  servers.push(server);
  const info = server.address();
  if (!info || typeof info === "string") throw new Error("expected a TCP address");
  return info.port;
}

function audits(): Record<string, unknown>[] {
  return auditLines.filter((l) => l.startsWith('{"type":"audit"')).map((l) => JSON.parse(l));
}

function identity(upn: string, roles: string[]): EntraIdentity {
  return { upn, roles, oid: "oid-1" };
}

beforeEach(() => {
  auditLines = [];
  cwCalls = [];
  validate.fn = undefined;
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    auditLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: string, init?: RequestInit) => {
      cwCalls.push({ method: init?.method ?? "GET" });
      return new Response(JSON.stringify({ id: 99 }), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
  vi.stubEnv("CONDUIT_S2S_SECRET", S2S_SECRET);
  vi.stubEnv("AUTH_MODE", "env");
  vi.stubEnv("CW_MANAGE_COMPANY_ID", "acme");
  vi.stubEnv("CW_MANAGE_PUBLIC_KEY", "pub");
  vi.stubEnv("CW_MANAGE_PRIVATE_KEY", "priv");
  vi.stubEnv("CW_MANAGE_CLIENT_ID", "cid");
  vi.stubEnv("CW_MANAGE_URL", "https://cw.example.invalid");
  vi.stubEnv("MCP_OAUTH_ENABLED", "true");
  vi.stubEnv("MCP_SERVER_URL", "https://mcp.example.com");
  vi.stubEnv("AZURE_TENANT_ID", "tenant-id");
  vi.stubEnv("AZURE_CLIENT_ID", "client-id");
  vi.stubEnv("AZURE_AUDIENCE", "api://client-id");
  vi.stubEnv("MCP_BEARER_TOKEN", STATIC_TOKEN);
  vi.stubEnv("MCP_AUDIT", "on");
  vi.stubEnv("MCP_POLICY", "read");
  vi.stubEnv("PII_MODE", "off");
});

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(() => r(undefined)))));
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("Entra identity", () => {
  it("names the caller from the validated token", async () => {
    validate.fn = async () => identity("nick@tektrendz.com", ["CWM.Access"]);
    const port = await listen();
    const res = await post(port, { "x-gateway-s2s": s2s(), authorization: "Bearer fake.jwt.value" }, READ);
    expect(res.status).toBe(200);
    expect(audits()[0]).toMatchObject({
      user: "nick@tektrendz.com",
      role: null,
      source: "entra",
      tool: "cw_get_contact",
      status: "ok",
    });
  });

  it("CWM.Access alone cannot write when the server default is read", async () => {
    validate.fn = async () => identity("nick@tektrendz.com", ["CWM.Access"]);
    const port = await listen();
    const res = await post(port, { "x-gateway-s2s": s2s(), authorization: "Bearer fake.jwt.value" }, UPDATE);
    expect(res.body).toContain("Blocked by access policy");
    expect(cwCalls).toHaveLength(0);
    expect(audits()[0]).toMatchObject({ status: "denied", reason: "policy:read" });
  });

  it("CWM.Write adds write access, CWM.Admin adds delete", async () => {
    validate.fn = async () => identity("nick@tektrendz.com", ["CWM.Access", "CWM.Write"]);
    const port = await listen();
    await post(port, { "x-gateway-s2s": s2s(), authorization: "Bearer fake.jwt.value" }, UPDATE);
    expect(cwCalls.some((c) => c.method === "PATCH")).toBe(true);
    expect(audits()[0]).toMatchObject({ role: "write", source: "entra", status: "ok" });

    cwCalls.length = 0;
    const del = call("cw_delete_time_entry", { id: 1 });
    const blocked = await post(port, { "x-gateway-s2s": s2s(), authorization: "Bearer fake.jwt.value" }, del);
    expect(blocked.body).toContain("Blocked by access policy");
    expect(cwCalls).toHaveLength(0);

    validate.fn = async () => identity("sam@tektrendz.com", ["CWM.Access", "CWM.Admin"]);
    await post(port, { "x-gateway-s2s": s2s(), authorization: "Bearer fake.jwt.value" }, del);
    expect(cwCalls.some((c) => c.method === "DELETE")).toBe(true);
  });

  it("ignores X-Mcp-User and X-Mcp-Role when an Entra token validated", async () => {
    validate.fn = async () => identity("nick@tektrendz.com", ["CWM.Access"]);
    const port = await listen();
    await post(
      port,
      { "x-gateway-s2s": s2s(), authorization: "Bearer fake.jwt.value", "x-mcp-user": "mallory", "x-mcp-role": "admin" },
      UPDATE,
    );
    expect(audits()[0]).toMatchObject({ user: "nick@tektrendz.com", role: null, status: "denied" });
    expect(cwCalls).toHaveLength(0);
  });

  it("logs the shared MCP_BEARER_TOKEN as cli-user", async () => {
    validate.fn = async () => {
      throw new Error("must not be called for the static token");
    };
    const port = await listen();
    await post(port, { "x-gateway-s2s": s2s(), authorization: `Bearer ${STATIC_TOKEN}` }, READ);
    expect(audits()[0]).toMatchObject({ user: "cli-user", source: "static-token", role: null, status: "ok" });
  });

  it("answers 401 with no tool call and no audit line when the token is missing or rejected", async () => {
    validate.fn = async () => {
      throw new AuthError("Token expired", 401);
    };
    const port = await listen();
    const none = await post(port, { "x-gateway-s2s": s2s() }, READ);
    const bad = await post(port, { "x-gateway-s2s": s2s(), authorization: "Bearer fake.jwt.value" }, READ);
    expect(none.status).toBe(401);
    expect(bad.status).toBe(401);
    expect(audits()).toHaveLength(0);
    expect(cwCalls).toHaveLength(0);
  });

  it("does not put the Entra token or the S2S secret in any log line", async () => {
    validate.fn = async () => identity("nick@tektrendz.com", ["CWM.Access"]);
    const port = await listen();
    await post(port, { "x-gateway-s2s": s2s(), authorization: "Bearer fake.jwt.value" }, READ);
    const all = auditLines.join("\n");
    expect(all).not.toContain("fake.jwt.value");
    expect(all).not.toContain(S2S_SECRET);
    expect(all).not.toContain(STATIC_TOKEN);
  });
});
