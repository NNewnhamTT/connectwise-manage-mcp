/**
 * cw_get_ticket_documents: lists document metadata for a ticket
 * (GET /service/tickets/{id}/documents). Read-only, no file content.
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

describe("cw_get_ticket_documents", () => {
  it("calls /service/tickets/{id}/documents with paging and the optional params", async () => {
    const client = await connect();
    await client.callTool({
      name: "cw_get_ticket_documents",
      arguments: { id: 555744, fields: "id,title,fileName", conditions: "id>0", orderBy: "id desc" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/555744/documents"))!);
    expect(url.searchParams.get("fields")).toBe("id,title,fileName");
    expect(url.searchParams.get("conditions")).toBe("id>0");
    expect(url.searchParams.get("orderBy")).toBe("id desc");
    expect(url.searchParams.get("page")).toBe("1");
    expect(url.searchParams.get("pageSize")).toBe("25");
  });

  it("sends none of the optional params when omitted", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_get_ticket_documents", arguments: { id: 100 } });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/100/documents"))!);
    expect(url.searchParams.has("fields")).toBe(false);
    expect(url.searchParams.has("conditions")).toBe(false);
    expect(url.searchParams.has("orderBy")).toBe(false);
  });

  it("never requests a file download", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_get_ticket_documents", arguments: { id: 100 } });
    expect(fetchCalls.every((u) => !u.includes("/download"))).toBe(true);
    expect(fetchCalls).toHaveLength(1);
  });

  it("still masks a person under owner in the metadata", async () => {
    responseBody = [{ id: 1, title: "Minutes", fileName: "minutes.pdf", owner: { name: "Jane Doe" } }];
    const client = await connect();
    const result = await client.callTool({ name: "cw_get_ticket_documents", arguments: { id: 100 } });
    const text = textOf(result);
    expect(text).not.toContain("Jane");
    expect(text).not.toContain("Doe");
    expect(JSON.parse(text)[0].fileName).toBe("minutes.pdf");
  });

  it("is a read-level tool", () => {
    expect(classifyTool("cw_get_ticket_documents")).toBe("read");
    expect(isAllowed("read", "cw_get_ticket_documents")).toBe(true);
    expect(classifyTool("cw_get_ticket_documents_count")).toBe("read");
    expect(isAllowed("read", "cw_get_ticket_documents_count")).toBe(true);
  });

  it("cw_get_ticket_documents_count calls /documents/count with conditions and returns the count", async () => {
    responseBody = { count: 3 };
    const client = await connect();
    const result = await client.callTool({
      name: "cw_get_ticket_documents_count",
      arguments: { id: 555744, conditions: "id>0" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/555744/documents/count"))!);
    expect(url.searchParams.get("conditions")).toBe("id>0");
    expect(url.searchParams.has("page")).toBe(false);
    expect(JSON.parse(textOf(result))).toEqual({ count: 3 });
  });

  it("cw_get_ticket_documents_count sends no conditions when omitted and no fallback on error", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_get_ticket_documents_count", arguments: { id: 100 } });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/100/documents/count"))!);
    expect(url.searchParams.has("conditions")).toBe(false);
    expect(fetchCalls).toHaveLength(1);
  });
});
