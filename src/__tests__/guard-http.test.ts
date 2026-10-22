/**
 * Identity over the real HTTP transport. X-Mcp-User / X-Mcp-Role are trusted
 * only when X-Gateway-S2S verified (only the signing proxy holds that secret).
 * A caller cannot name itself or raise its own access without it.
 */

import { createHmac } from "node:crypto";
import { request as httpRequest } from "node:http";
import type { Server as HttpServer } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startHttpTransport } from "../index.js";

const S2S_SECRET = "s2s-do-not-log-7f3a9c-guard-test";

const servers: HttpServer[] = [];
let auditLines: string[];
let cwCalls: { method: string; url: string }[];

function s2s(secret = S2S_SECRET): string {
  const t = Math.floor(Date.now() / 1000);
  return `t=${t},v1=${createHmac("sha256", secret).update(`t=${t}`).digest("hex")}`;
}

function post(port: number, headers: Record<string, string>, body: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port,
        method: "POST",
        path: "/mcp",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          ...headers,
        },
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

beforeEach(() => {
  auditLines = [];
  cwCalls = [];
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    auditLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      cwCalls.push({ method: init?.method ?? "GET", url: input });
      return new Response(JSON.stringify({ id: 99 }), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
  vi.stubEnv("CONDUIT_S2S_SECRET", S2S_SECRET);
  vi.stubEnv("AUTH_MODE", "env");
  vi.stubEnv("MCP_OAUTH_ENABLED", "");
  vi.stubEnv("CW_MANAGE_COMPANY_ID", "acme");
  vi.stubEnv("CW_MANAGE_PUBLIC_KEY", "pub");
  vi.stubEnv("CW_MANAGE_PRIVATE_KEY", "priv");
  vi.stubEnv("CW_MANAGE_CLIENT_ID", "cid");
  vi.stubEnv("CW_MANAGE_URL", "https://cw.example.invalid");
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

describe("identity from the signing proxy", () => {
  it("uses X-Mcp-User and X-Mcp-Role after a valid S2S header", async () => {
    const port = await listen();
    const res = await post(port, { "x-gateway-s2s": s2s(), "x-mcp-user": "alice", "x-mcp-role": "write" }, call("cw_get_contact", { id: 99 }));
    expect(res.status).toBe(200);
    expect(audits()[0]).toMatchObject({ user: "alice", role: "write", source: "proxy", tool: "cw_get_contact", status: "ok" });
  });

  it("logs anonymous when the proxy sends no user", async () => {
    const port = await listen();
    await post(port, { "x-gateway-s2s": s2s() }, call("cw_get_contact", { id: 99 }));
    expect(audits()[0]).toMatchObject({ user: "anonymous", source: "anonymous", role: null });
  });

  it("ignores a malformed user name", async () => {
    const port = await listen();
    await post(port, { "x-gateway-s2s": s2s(), "x-mcp-user": 'bad user"x', "x-mcp-role": "admin" }, call("cw_get_contact", { id: 99 }));
    expect(audits()[0]).toMatchObject({ user: "anonymous", role: null });
  });

  it("rejects the request, and writes no audit line, when S2S is missing or wrong", async () => {
    const port = await listen();
    const none = await post(port, { "x-mcp-user": "mallory", "x-mcp-role": "admin" }, call("cw_get_contact", { id: 99 }));
    const wrong = await post(port, { "x-gateway-s2s": s2s("not-the-secret-0123456789"), "x-mcp-user": "mallory" }, call("cw_get_contact", { id: 99 }));
    expect(none.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(audits()).toHaveLength(0);
    expect(cwCalls).toHaveLength(0);
  });

  it("applies the role: write allowed with role write, denied without it at MCP_POLICY=read", async () => {
    const port = await listen();
    const args = { id: 99, operations: [{ op: "replace", path: "title", value: "Boss" }] };
    await post(port, { "x-gateway-s2s": s2s(), "x-mcp-user": "bob", "x-mcp-role": "write" }, call("cw_update_contact", args));
    expect(cwCalls.some((c) => c.method === "PATCH")).toBe(true);

    cwCalls.length = 0;
    const denied = await post(port, { "x-gateway-s2s": s2s(), "x-mcp-user": "carol" }, call("cw_update_contact", args));
    expect(denied.body).toContain("Blocked by access policy");
    expect(cwCalls).toHaveLength(0);
    const line = audits().find((l) => l.user === "carol")!;
    expect(line).toMatchObject({ status: "denied", reason: "policy:read" });
  });

  it("does not leak the S2S secret or CW keys into audit lines", async () => {
    const port = await listen();
    await post(port, { "x-gateway-s2s": s2s(), "x-mcp-user": "alice" }, call("cw_get_contact", { id: 99 }));
    const all = auditLines.join("\n");
    for (const secret of [S2S_SECRET, "priv", "cid"]) {
      // "pub"/"priv"/"cid" are short, so check the audit JSON values rather than substrings of keys.
      expect(JSON.stringify(audits())).not.toContain(`"${secret}"`);
    }
    expect(all).not.toContain(S2S_SECRET);
  });
});
