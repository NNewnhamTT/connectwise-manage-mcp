/**
 * cw_get_ticket_count: a count-only read tool for GET /service/tickets/count.
 * Same harness as search-fields.test.ts: in-memory MCP client, ConnectWise stubbed
 * at global fetch. No live calls.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../mcp-server.js";
import { resetSharedStore } from "../pii/index.js";
import { classifyTool, isAllowed } from "../guard/policy.js";

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
  responseBody = { count: 42 };
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

describe("cw_get_ticket_count", () => {
  it("calls /service/tickets/count with the conditions and returns the count", async () => {
    const client = await connect();
    const result = await client.callTool({
      name: "cw_get_ticket_count",
      arguments: { conditions: "closedFlag = false" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/count"))!);
    expect(url.searchParams.get("conditions")).toBe("closedFlag = false");
    expect(url.searchParams.has("page")).toBe(false);
    expect(url.searchParams.has("pageSize")).toBe(false);
    expect(JSON.parse(textOf(result))).toEqual({ count: 42 });
  });

  it("sends no conditions param when omitted", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_get_ticket_count", arguments: {} });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/count"))!);
    expect(url.searchParams.has("conditions")).toBe(false);
  });

  it("is a read-level tool, allowed at the read access level", () => {
    expect(classifyTool("cw_get_ticket_count")).toBe("read");
    expect(isAllowed("read", "cw_get_ticket_count")).toBe(true);
    expect(classifyTool("cw_get_ticket_notes_count")).toBe("read");
    expect(isAllowed("read", "cw_get_ticket_notes_count")).toBe(true);
  });

  it("cw_get_ticket_notes_count calls /allNotes/count with conditions", async () => {
    const client = await connect();
    const result = await client.callTool({
      name: "cw_get_ticket_notes_count",
      arguments: { id: 555744, conditions: "bundledFlag=false" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/555744/allNotes/count"))!);
    expect(url.searchParams.get("conditions")).toBe("bundledFlag=false");
    expect(JSON.parse(textOf(result))).toEqual({ count: 42 });
  });

  it("cw_get_ticket_notes_count reports a 404 as an error and makes no second request", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string) => {
        fetchCalls.push(input);
        if (input.includes("/allNotes/count")) {
          return new Response(JSON.stringify({ code: "NotFound", message: "not found" }), {
            status: 404,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ count: 2 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    const client = await connect();
    const result = await client.callTool({ name: "cw_get_ticket_notes_count", arguments: { id: 100 } });
    expect((result as { isError?: boolean }).isError).toBe(true);
    expect(fetchCalls.some((u) => u.includes("/notes/count") && !u.includes("/allNotes/"))).toBe(false);
  });

  it("cw_get_ticket_configurations_count calls /configurations/count with conditions", async () => {
    responseBody = { count: 4 };
    const client = await connect();
    const result = await client.callTool({
      name: "cw_get_ticket_configurations_count",
      arguments: { id: 555744, conditions: "id>0" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/555744/configurations/count"))!);
    expect(url.searchParams.get("conditions")).toBe("id>0");
    expect(url.searchParams.has("page")).toBe(false);
    expect(JSON.parse(textOf(result))).toEqual({ count: 4 });
    expect(classifyTool("cw_get_ticket_configurations_count")).toBe("read");
  });

  it("is listed with a description that points 'how many' questions at it", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "cw_get_ticket_count")!;
    expect(tool).toBeDefined();
    expect(Object.keys(tool.inputSchema.properties ?? {})).toEqual(["conditions"]);
    expect(tool.description).toContain("how many");
  });
});
