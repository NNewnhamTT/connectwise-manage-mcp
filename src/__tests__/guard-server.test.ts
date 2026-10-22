/**
 * End to end: audit log and access policy through a real MCP client, with
 * ConnectWise stubbed at global fetch. PII masking is on for most cases so the
 * guard is checked in the same wrapper order the server uses.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../mcp-server.js";
import { resetSharedStore } from "../pii/index.js";
import type { Identity } from "../guard/identity.js";

const CONFIG = {
  baseUrl: "https://cw.example.com",
  companyId: "acme",
  publicKey: "pub-key-do-not-log",
  privateKey: "priv-key-do-not-log",
  clientId: "cid",
};

const contact = {
  id: 99,
  firstName: "Jane",
  lastName: "Doe",
  company: { id: 7, name: "Acme Corporation" },
  communicationItems: [
    { type: { id: 1, name: "Email" }, value: "jane.doe@acme.com", communicationType: "Email" },
  ],
};

const ALICE: Identity = { user: "alice", source: "proxy" };

let fetchCalls: { url: string; method: string }[];
let respond: (url: URL, method: string) => Response;
let auditLines: string[];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function connect(identity?: Identity): Promise<Client> {
  const server = createMcpServer(CONFIG, { identity });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

function textOf(result: unknown): string {
  const r = result as { content?: { type: string; text?: string }[] };
  return (r.content ?? []).map((c) => c.text ?? "").join("\n");
}

function audits(): Record<string, unknown>[] {
  return auditLines.filter((l) => l.startsWith('{"type":"audit"')).map((l) => JSON.parse(l));
}

beforeEach(() => {
  resetSharedStore();
  fetchCalls = [];
  auditLines = [];
  respond = (url) => (url.pathname.endsWith("/company/contacts/99") ? json(contact) : json([]));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      fetchCalls.push({ url: input, method: init?.method ?? "GET" });
      return respond(new URL(input), init?.method ?? "GET");
    }),
  );
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    auditLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  });
  vi.stubEnv("PII_MODE", "on");
  vi.stubEnv("PII_KEY", "e2e-test-key-not-a-secret");
  vi.stubEnv("MCP_AUDIT", "on");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("audit log", () => {
  it("writes one line per call with user, tool, ids and outcome", async () => {
    const client = await connect(ALICE);
    await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    const [line] = audits();
    expect(audits()).toHaveLength(1);
    expect(line).toMatchObject({
      type: "audit",
      user: "alice",
      role: null,
      source: "proxy",
      tool: "cw_get_contact",
      class: "read",
      args: { id: 99 },
      tokens: [],
      status: "ok",
    });
    expect(typeof line!.requestId).toBe("string");
    expect(typeof line!.ms).toBe("number");
    expect(line!.bytes as number).toBeGreaterThan(0);
  });

  it("logs anonymous when no identity is given", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    expect(audits()[0]).toMatchObject({ user: "anonymous", source: "anonymous" });
  });

  it("keeps real PII, string values, keys and secrets out of the line", async () => {
    const client = await connect(ALICE);
    const first = JSON.parse(textOf(await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } })));
    await client.callTool({
      name: "cw_search_contacts",
      arguments: { conditions: `firstName = "${first.firstName}" OR lastName = "Smith"` },
    });
    const all = auditLines.join("\n");
    for (const secret of ["Jane", "Doe", "jane.doe@acme.com", "Smith", CONFIG.publicKey, CONFIG.privateKey]) {
      expect(all).not.toContain(secret);
    }
    const search = audits().find((l) => l.tool === "cw_search_contacts")!;
    expect(search.args).toEqual({ conditions: { len: expect.any(Number) } });
  });

  it("records PII tokens that Claude sent, not the real values behind them", async () => {
    vi.stubEnv("MCP_POLICY", "write");
    const client = await connect(ALICE);
    const first = JSON.parse(textOf(await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } })));
    respond = () => json(contact);
    await client.callTool({
      name: "cw_update_contact",
      arguments: { id: 99, operations: [{ op: "replace", path: "firstName", value: first.firstName }] },
    });
    const update = audits().find((l) => l.tool === "cw_update_contact")!;
    expect(update.tokens).toEqual([first.firstName]);
    expect(update.status).toBe("ok");
    expect(auditLines.join("\n")).not.toContain("Jane");
  });

  it("logs status error for a ConnectWise failure, without the response body", async () => {
    respond = () => json({ message: "secret detail jane.doe@acme.com" }, 500);
    const client = await connect(ALICE);
    await client.callTool({ name: "cw_get_contact", arguments: { id: 5 } });
    const line = audits()[0]!;
    expect(line.status).toBe("error");
    expect(auditLines.join("\n")).not.toContain("jane.doe@acme.com");
  });

  it("writes nothing when MCP_AUDIT is off", async () => {
    vi.stubEnv("MCP_AUDIT", "off");
    const client = await connect(ALICE);
    await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    expect(audits()).toHaveLength(0);
  });
});

describe("access policy", () => {
  it("lets read tools run and blocks write tools at MCP_POLICY=read", async () => {
    vi.stubEnv("MCP_POLICY", "read");
    const client = await connect(ALICE);
    const ok = (await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } })) as { isError?: boolean };
    expect(ok.isError).toBeFalsy();

    fetchCalls = [];
    const denied = (await client.callTool({
      name: "cw_update_contact",
      arguments: { id: 99, operations: [{ op: "replace", path: "title", value: "Boss" }] },
    })) as { isError?: boolean };
    expect(denied.isError).toBe(true);
    expect(textOf(denied)).toContain("Blocked by access policy");
    expect(fetchCalls).toHaveLength(0);

    const line = audits().find((l) => l.tool === "cw_update_contact")!;
    expect(line).toMatchObject({ status: "denied", reason: "policy:read", class: "write" });
  });

  it("stops a denied call before any PII token is turned back into a real value", async () => {
    vi.stubEnv("MCP_POLICY", "read");
    const client = await connect(ALICE);
    const first = JSON.parse(textOf(await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } })));
    fetchCalls = [];
    const denied = (await client.callTool({
      name: "cw_update_contact",
      arguments: { id: 99, operations: [{ op: "replace", path: "firstName", value: first.firstName }] },
    })) as { isError?: boolean };
    expect(denied.isError).toBe(true);
    expect(textOf(denied)).not.toContain("Jane");
    expect(fetchCalls).toHaveLength(0);
  });

  it("lets a role raise access above the server default", async () => {
    vi.stubEnv("MCP_POLICY", "read");
    const client = await connect({ user: "bob", role: "write", source: "proxy" });
    respond = () => json(contact);
    const res = (await client.callTool({
      name: "cw_update_contact",
      arguments: { id: 99, operations: [{ op: "replace", path: "title", value: "Boss" }] },
    })) as { isError?: boolean };
    expect(res.isError).toBeFalsy();
    expect(fetchCalls.some((c) => c.method === "PATCH")).toBe(true);
  });

  it("blocks delete tools below admin, and allows them for admin", async () => {
    vi.stubEnv("MCP_POLICY", "write");
    const writer = await connect({ user: "bob", role: "write", source: "proxy" });
    const blocked = (await writer.callTool({ name: "cw_delete_time_entry", arguments: { id: 1 } })) as {
      isError?: boolean;
    };
    expect(blocked.isError).toBe(true);
    expect(fetchCalls.some((c) => c.method === "DELETE")).toBe(false);

    const admin = await connect({ user: "carol", role: "admin", source: "proxy" });
    respond = () => new Response(null, { status: 204 });
    await admin.callTool({ name: "cw_delete_time_entry", arguments: { id: 1 } });
    expect(fetchCalls.some((c) => c.method === "DELETE")).toBe(true);
  });

  it("lets a role lower access below the server default", async () => {
    vi.stubEnv("MCP_POLICY", "write");
    const client = await connect({ user: "dave", role: "read", source: "proxy" });
    const res = (await client.callTool({
      name: "cw_create_ticket",
      arguments: { summary: "x" },
    })) as { isError?: boolean };
    expect(res.isError).toBe(true);
  });

  it("enforces a caller's role even when MCP_POLICY is unset", async () => {
    const client = await connect({ user: "erin", role: "read", source: "proxy" });
    const res = (await client.callTool({
      name: "cw_create_ticket",
      arguments: { summary: "x" },
    })) as { isError?: boolean };
    expect(res.isError).toBe(true);
    const ok = (await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } })) as { isError?: boolean };
    expect(ok.isError).toBeFalsy();
  });

  it("does not restrict anything when no policy and no role are set", async () => {
    respond = () => json({ id: 1 });
    const client = await connect(ALICE);
    const res = (await client.callTool({ name: "cw_create_ticket", arguments: { summary: "x" } })) as {
      isError?: boolean;
    };
    expect(res.isError).toBeFalsy();
  });
});

describe("configuration errors", () => {
  it("refuses to build a server with a bad MCP_POLICY or MCP_AUDIT", () => {
    vi.stubEnv("MCP_POLICY", "readonly");
    expect(() => createMcpServer(CONFIG)).toThrow(/MCP_POLICY/);
    vi.stubEnv("MCP_POLICY", "");
    vi.stubEnv("MCP_AUDIT", "yes");
    expect(() => createMcpServer(CONFIG)).toThrow(/MCP_AUDIT/);
  });
});
