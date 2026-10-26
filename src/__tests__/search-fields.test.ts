/**
 * The optional `fields` param on cw_search_* tools. A real MCP client talks to
 * createMcpServer over an in-memory transport, with ConnectWise stubbed at
 * global fetch (same harness as pii-server.test.ts). No live calls.
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

let fetchCalls: string[];
let responseBody: unknown;

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
  responseBody = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      fetchCalls.push(input);
      return new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  vi.stubEnv("PII_MODE", "on");
  vi.stubEnv("PII_KEY", "e2e-test-key-not-a-secret");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("cw_search_* fields param", () => {
  it("sends fields to ConnectWise when provided", async () => {
    const client = await connect();
    await client.callTool({
      name: "cw_search_tickets",
      arguments: { conditions: "id = 1", fields: "id,summary,status/name" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets"))!);
    expect(url.searchParams.get("fields")).toBe("id,summary,status/name");
    expect(url.searchParams.get("pageSize")).toBe("25");
  });

  it("sends no fields param when omitted", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_search_tickets", arguments: { conditions: "id = 1" } });
    const raw = fetchCalls.find((u) => u.includes("/service/tickets"))!;
    expect(raw).not.toContain("fields");
    expect(new URL(raw).searchParams.has("fields")).toBe(false);
  });

  it("passes fields through on another search tool (companies)", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_search_companies", arguments: { fields: "id,name" } });
    const url = new URL(fetchCalls.find((u) => u.includes("/company/companies"))!);
    expect(url.searchParams.get("fields")).toBe("id,name");
  });

  it("still masks a person name in a field-limited response", async () => {
    responseBody = [{ id: 4821, summary: "Printer down", contact: { name: "Jane Doe" } }];
    const client = await connect();
    const result = await client.callTool({
      name: "cw_search_tickets",
      arguments: { fields: "id,summary,contact/name" },
    });
    const text = textOf(result);
    expect(text).not.toContain("Jane");
    expect(text).not.toContain("Doe");
    const parsed = JSON.parse(text);
    expect(parsed[0].id).toBe(4821);
    expect(parsed[0].summary).toBe("Printer down");
  });

  it("advertises fields on cw_search_tickets and the retry hint", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "cw_search_tickets")!;
    expect(Object.keys(tool.inputSchema.properties ?? {})).toContain("fields");
    expect(tool.description).toContain("retry with `fields` and a smaller `pageSize`");
  });
});
