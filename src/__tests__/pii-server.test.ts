/**
 * End to end: a real MCP client talks to createMcpServer over an in-memory
 * transport, with ConnectWise stubbed at global fetch. Checks that Claude's
 * side never sees real PII and that tokens turn back into real values on the
 * way to ConnectWise.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../mcp-server.js";
import { resetSharedStore } from "../pii/index.js";

const CONFIG = {
  baseUrl: "https://cw.example.com",
  companyId: "acme",
  publicKey: "pub",
  privateKey: "priv",
  clientId: "cid",
};

const contact = {
  id: 99,
  firstName: "Jane",
  lastName: "Doe",
  company: { id: 7, identifier: "AcmeCo", name: "Acme Corporation" },
  communicationItems: [
    { type: { id: 1, name: "Email" }, value: "jane.doe@acme.com", communicationType: "Email" },
    { type: { id: 2, name: "Direct" }, value: "555-123-4567", communicationType: "Phone" },
  ],
};

const ticket = {
  id: 4821,
  summary: "Printer down",
  company: { id: 7, identifier: "AcmeCo", name: "Acme Corporation" },
  contact: { id: 99, name: "Jane Doe" },
  contactEmailAddress: "jane.doe@acme.com",
  owner: { id: 3, identifier: "jsmith", name: "John Smith" },
};

const PII = ["Jane", "Doe", "jane.doe@acme.com", "555-123-4567", "jsmith", "John Smith"];

let fetchCalls: { url: string; method: string; body?: string }[];
let respond: (url: URL, method: string) => Response;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function connect(): Promise<Client> {
  const server = createMcpServer(CONFIG);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

function textOf(result: unknown): string {
  const r = result as { content?: { type: string; text?: string }[] };
  return (r.content ?? []).map((c) => c.text ?? "").join("\n");
}

beforeEach(() => {
  resetSharedStore();
  fetchCalls = [];
  respond = (url) => {
    if (url.pathname.endsWith("/company/contacts/99")) return json(contact);
    if (url.pathname.endsWith("/service/tickets/4821")) return json(ticket);
    return json([]);
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string, init?: RequestInit) => {
      const url = new URL(input);
      fetchCalls.push({ url: input, method: init?.method ?? "GET", body: init?.body as string | undefined });
      return respond(url, init?.method ?? "GET");
    }),
  );
  vi.stubEnv("PII_MODE", "on");
  vi.stubEnv("PII_KEY", "e2e-test-key-not-a-secret");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("PII masking end to end", () => {
  it("masks a contact before Claude sees it", async () => {
    const client = await connect();
    const result = await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } });
    const text = textOf(result);
    for (const p of PII) expect(text).not.toContain(p);
    const parsed = JSON.parse(text);
    expect(parsed.id).toBe(99);
    expect(parsed.company.name).toBe("Acme Corporation");
    expect(parsed.firstName).toMatch(/^<PERSON_[0-9a-f]{10}>$/);
  });

  it("turns a token in a write back into the real value before calling ConnectWise", async () => {
    const client = await connect();
    const first = JSON.parse(textOf(await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } })));
    const emailToken = first.communicationItems[0].value as string;
    const nameToken = first.firstName as string;
    fetchCalls = [];
    respond = () => json(contact);

    const result = await client.callTool({
      name: "cw_update_contact",
      arguments: {
        id: 99,
        operations: [{ op: "replace", path: "firstName", value: nameToken }],
      },
    });
    const patch = fetchCalls.find((c) => c.method === "PATCH");
    expect(patch?.body).toContain('"value":"Jane"');
    expect(patch?.body).not.toContain("<PERSON_");
    // The echoed response is masked again.
    for (const p of PII) expect(textOf(result)).not.toContain(p);
    expect(emailToken).toMatch(/^<EMAIL_/);
  });

  it("turns a token in a search condition back into the real value", async () => {
    const client = await connect();
    const first = JSON.parse(textOf(await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } })));
    fetchCalls = [];
    await client.callTool({
      name: "cw_search_contacts",
      arguments: { conditions: `firstName = "${first.firstName}"` },
    });
    const search = fetchCalls.find((c) => c.url.includes("/company/contacts?"));
    expect(decodeURIComponent((search?.url ?? "").replace(/\+/g, " "))).toContain('firstName = "Jane"');
  });

  it("rejects an unknown token without calling ConnectWise", async () => {
    const client = await connect();
    const result = (await client.callTool({
      name: "cw_search_contacts",
      arguments: { conditions: 'firstName = "<PERSON_0000000000>"' },
    })) as { isError?: boolean };
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain("<PERSON_0000000000>");
    expect(fetchCalls).toHaveLength(0);
  });

  it("masks structuredContent and drops the ticket card", async () => {
    const client = await connect();
    const result = (await client.callTool({ name: "cw_get_ticket", arguments: { id: 4821 } })) as {
      structuredContent?: Record<string, unknown>;
    };
    const all = JSON.stringify(result);
    for (const p of PII) expect(all).not.toContain(p);
    expect(result.structuredContent).toBeDefined();
    expect(result.structuredContent).not.toHaveProperty("_card");
    expect((result.structuredContent as { id: number }).id).toBe(4821);
  });

  it("does not advertise the ticket card UI", async () => {
    const client = await connect();
    const tools = (await client.listTools()).tools;
    expect(tools.find((t) => t.name === "cw_get_ticket")?._meta?.ui).toBeUndefined();
    // With no resources registered the server has no resources capability, so
    // the call is rejected. Either outcome means no ui:// card is served.
    const resources = (await client.listResources().catch(() => ({ resources: [] }))).resources;
    expect(resources.find((r) => r.uri.startsWith("ui://"))).toBeUndefined();
  });

  it("masks PII that appears in an error message", async () => {
    respond = () =>
      json({ code: "InvalidObject", message: "Contact jane.doe@acme.com is invalid" }, 400);
    const client = await connect();
    const result = (await client.callTool({ name: "cw_get_contact", arguments: { id: 5 } })) as {
      isError?: boolean;
    };
    expect(result.isError).toBe(true);
    expect(textOf(result)).not.toContain("jane.doe@acme.com");
  });

  it("refuses to build a server when PII_MODE=on has no key", () => {
    vi.stubEnv("PII_KEY", "");
    expect(() => createMcpServer(CONFIG)).toThrow(/PII_KEY/);
  });

  it("leaves data unchanged when PII_MODE is off", async () => {
    vi.stubEnv("PII_MODE", "off");
    const client = await connect();
    const text = textOf(await client.callTool({ name: "cw_get_contact", arguments: { id: 99 } }));
    expect(text).toContain("jane.doe@acme.com");
  });
});
