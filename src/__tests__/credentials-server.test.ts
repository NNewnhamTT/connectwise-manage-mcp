/**
 * Per-user ConnectWise keys end to end: a real MCP client against
 * createMcpServer, with ConnectWise stubbed at global fetch. Checks which key
 * each call used, the refusal for a person with no key, and that the shared
 * key is never sent.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../mcp-server.js";
import { resetSharedStore } from "../pii/index.js";
import { ANONYMOUS, type Identity } from "../guard/identity.js";

const ALICE: Identity = { user: "alice@tektrendz.com", source: "entra" };
const BOB: Identity = { user: "bob@tektrendz.com", source: "entra" };
const CAROL: Identity = { user: "carol@tektrendz.com", source: "entra" };

const contact = {
  id: 99,
  firstName: "Jane",
  lastName: "Doe",
  company: { id: 7, name: "Acme Corporation" },
};

let fetchCalls: { method: string; url: string; authorization: string; clientId: string }[];
let auditLines: string[];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function connect(identity?: Identity): Promise<Client> {
  const server = createMcpServer(undefined, { identity });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

const textOf = (result: unknown): string =>
  ((result as { content?: { text?: string }[] }).content ?? []).map((c) => c.text ?? "").join("\n");

const decodeAuth = (authorization: string): string =>
  Buffer.from(authorization.replace(/^Basic /, ""), "base64").toString("utf8");

const audits = (): Record<string, unknown>[] =>
  auditLines.filter((l) => l.startsWith('{"type":"audit"')).map((l) => JSON.parse(l));

beforeEach(() => {
  resetSharedStore();
  fetchCalls = [];
  auditLines = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      fetchCalls.push({
        method: init?.method ?? "GET",
        url: input,
        authorization: headers.Authorization ?? "",
        clientId: headers.clientId ?? "",
      });
      return json(contact);
    }),
  );
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    auditLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
  });
  vi.stubEnv("CW_CREDENTIALS", "per-user");
  vi.stubEnv("CW_USER_KEYS", "alice@tektrendz.com=PUBA:PRIVA;bob@tektrendz.com=PUBB:PRIVB");
  vi.stubEnv("CW_MANAGE_COMPANY_ID", "acme");
  vi.stubEnv("CW_MANAGE_CLIENT_ID", "client-guid");
  vi.stubEnv("CW_MANAGE_URL", "https://cw.example.com");
  // The shared key is present in the environment but must never be used.
  vi.stubEnv("CW_MANAGE_PUBLIC_KEY", "shared-pub-must-not-be-sent");
  vi.stubEnv("CW_MANAGE_PRIVATE_KEY", "shared-priv-must-not-be-sent");
  vi.stubEnv("PII_MODE", "on");
  vi.stubEnv("PII_KEY", "e2e-test-key-not-a-secret");
  vi.stubEnv("MCP_AUDIT", "on");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("per-user ConnectWise keys", () => {
  it("sends each person's own key, and the shared client id", async () => {
    const alice = await connect(ALICE);
    const bob = await connect(BOB);
    await alice.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    await bob.callTool({ name: "cw_get_contact", arguments: { id: 99 } });

    expect(decodeAuth(fetchCalls[0]!.authorization)).toBe("acme+PUBA:PRIVA");
    expect(decodeAuth(fetchCalls[1]!.authorization)).toBe("acme+PUBB:PRIVB");
    expect(fetchCalls.every((c) => c.clientId === "client-guid")).toBe(true);
    expect(fetchCalls.every((c) => c.url.startsWith("https://cw.example.com/"))).toBe(true);
  });

  it("never sends the shared key", async () => {
    const alice = await connect(ALICE);
    await alice.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    const sent = fetchCalls.map((c) => decodeAuth(c.authorization)).join("\n");
    expect(sent).not.toContain("shared-pub");
    expect(sent).not.toContain("shared-priv");
  });

  it("matches the signed-in name without regard to case", async () => {
    const alice = await connect({ user: "Alice@TekTrendz.com", source: "entra" });
    await alice.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    expect(decodeAuth(fetchCalls[0]!.authorization)).toBe("acme+PUBA:PRIVA");
  });

  it("records the credential mode in the audit line, and never a key", async () => {
    const alice = await connect(ALICE);
    await alice.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    expect(audits()[0]).toMatchObject({ user: "alice@tektrendz.com", credential: "per-user", status: "ok" });
    const all = auditLines.join("\n");
    for (const secret of ["PUBA", "PRIVA", "PUBB", "PRIVB", "shared-pub", "shared-priv"]) {
      expect(all).not.toContain(secret);
    }
  });

  it("gives each person their own PII token namespace", async () => {
    vi.stubEnv("MCP_POLICY", "write");
    const alice = await connect(ALICE);
    const bob = await connect(BOB);
    const first = JSON.parse(textOf(await alice.callTool({ name: "cw_get_contact", arguments: { id: 99 } })));
    fetchCalls = [];
    const res = (await bob.callTool({
      name: "cw_update_contact",
      arguments: { id: 99, operations: [{ op: "replace", path: "firstName", value: first.firstName }] },
    })) as { isError?: boolean };
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain("Unknown or expired PII token");
    expect(fetchCalls).toHaveLength(0);
  });
});

describe("a person with no key on file", () => {
  it("is refused on every tool, reads included, and nothing reaches ConnectWise", async () => {
    const carol = await connect(CAROL);
    const read = (await carol.callTool({ name: "cw_get_contact", arguments: { id: 99 } })) as { isError?: boolean };
    const write = (await carol.callTool({
      name: "cw_create_ticket",
      arguments: { summary: "x" },
    })) as { isError?: boolean };
    expect(read.isError).toBe(true);
    expect(write.isError).toBe(true);
    expect(textOf(read)).toContain("No ConnectWise key is on file");
    expect(textOf(read)).toContain("carol@tektrendz.com");
    expect(fetchCalls).toHaveLength(0);
  });

  it("is logged as denied with the reason no-cw-key", async () => {
    const carol = await connect(CAROL);
    await carol.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    expect(audits()[0]).toMatchObject({
      user: "carol@tektrendz.com",
      status: "denied",
      reason: "no-cw-key",
      credential: "per-user",
    });
  });

  it("is refused even when the access policy would allow the tool", async () => {
    vi.stubEnv("MCP_POLICY", "admin");
    const carol = await connect(CAROL);
    const res = (await carol.callTool({ name: "cw_get_contact", arguments: { id: 99 } })) as { isError?: boolean };
    expect(res.isError).toBe(true);
    expect(fetchCalls).toHaveLength(0);
  });

  it("is refused when the caller is anonymous", async () => {
    const anon = await connect(ANONYMOUS);
    const res = (await anon.callTool({ name: "cw_get_contact", arguments: { id: 99 } })) as { isError?: boolean };
    expect(res.isError).toBe(true);
    expect(fetchCalls).toHaveLength(0);
  });

  it("is refused even with auditing and policy off", async () => {
    vi.stubEnv("MCP_AUDIT", "off");
    const carol = await connect(CAROL);
    const res = (await carol.callTool({ name: "cw_get_contact", arguments: { id: 99 } })) as { isError?: boolean };
    expect(res.isError).toBe(true);
    expect(fetchCalls).toHaveLength(0);
  });

  it("still lists the tools", async () => {
    const carol = await connect(CAROL);
    expect((await carol.listTools()).tools.length).toBeGreaterThanOrEqual(84);
  });
});

describe("configuration", () => {
  it("refuses to build a server with a bad mode or bad entries", () => {
    vi.stubEnv("CW_CREDENTIALS", "peruser");
    expect(() => createMcpServer(undefined, { identity: ALICE })).toThrow(/CW_CREDENTIALS/);
    vi.stubEnv("CW_CREDENTIALS", "per-user");
    vi.stubEnv("CW_USER_KEYS", "alice@tektrendz.com=PUBA");
    expect(() => createMcpServer(undefined, { identity: ALICE })).toThrow(/CW_USER_KEYS/);
  });

  it("refuses to combine per-user mode with keys supplied by the client (gateway mode)", () => {
    expect(() =>
      createMcpServer(
        { baseUrl: "https://x", companyId: "c", publicKey: "p", privateKey: "k", clientId: "i" },
        { identity: ALICE },
      ),
    ).toThrow(/per-user/);
  });

  it("uses the shared key when CW_CREDENTIALS is shared (the default)", async () => {
    vi.stubEnv("CW_CREDENTIALS", "shared");
    const alice = await connect(ALICE);
    await alice.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    expect(decodeAuth(fetchCalls[0]!.authorization)).toBe("acme+shared-pub-must-not-be-sent:shared-priv-must-not-be-sent");
    expect(audits()[0]).toMatchObject({ credential: "shared" });
  });
});
