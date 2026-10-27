/**
 * Optional `fields`, `conditions` and `orderBy` on the notes read tools
 * (cw_get_ticket_notes, cw_get_project_ticket_notes, cw_search_opportunity_notes).
 * Same harness as search-fields.test.ts: in-memory MCP client, ConnectWise stubbed
 * at global fetch. No live calls.
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
let failAllNotes: boolean;

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
  failAllNotes = false;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      fetchCalls.push(input);
      if (failAllNotes && input.includes("/allNotes")) {
        return new Response(JSON.stringify({ code: "NotFound", message: "not found" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }
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

describe("notes tools: fields, conditions, orderBy", () => {
  it("cw_get_ticket_notes sends fields, conditions and orderBy to /allNotes", async () => {
    const client = await connect();
    await client.callTool({
      name: "cw_get_ticket_notes",
      arguments: {
        id: 100,
        fields: "id,text,member/identifier",
        conditions: "bundledFlag=false",
        orderBy: "id desc",
      },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/100/allNotes"))!);
    expect(url.searchParams.get("fields")).toBe("id,text,member/identifier");
    expect(url.searchParams.get("conditions")).toBe("bundledFlag=false");
    expect(url.searchParams.get("orderBy")).toBe("id desc");
    expect(url.searchParams.get("pageSize")).toBe("25");
  });

  it("cw_get_ticket_notes sends none of the new params when omitted", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_get_ticket_notes", arguments: { id: 100 } });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/tickets/100/allNotes"))!);
    expect(url.searchParams.has("fields")).toBe(false);
    expect(url.searchParams.has("conditions")).toBe(false);
    expect(url.searchParams.has("orderBy")).toBe(false);
    expect(url.searchParams.get("page")).toBe("1");
  });

  it("cw_get_ticket_notes passes the same params to the /notes fallback", async () => {
    failAllNotes = true;
    const client = await connect();
    await client.callTool({
      name: "cw_get_ticket_notes",
      arguments: { id: 100, fields: "id,text", conditions: "internalAnalysisFlag=false" },
    });
    const url = new URL(
      fetchCalls.find((u) => u.includes("/service/tickets/100/notes") && !u.includes("allNotes"))!,
    );
    expect(url.searchParams.get("fields")).toBe("id,text");
    expect(url.searchParams.get("conditions")).toBe("internalAnalysisFlag=false");
  });

  it("cw_get_project_ticket_notes sends fields, conditions and orderBy", async () => {
    const client = await connect();
    await client.callTool({
      name: "cw_get_project_ticket_notes",
      arguments: { id: 50, fields: "id,text", conditions: "resolutionFlag=false", orderBy: "id" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/project/tickets/50/allNotes"))!);
    expect(url.searchParams.get("fields")).toBe("id,text");
    expect(url.searchParams.get("conditions")).toBe("resolutionFlag=false");
    expect(url.searchParams.get("orderBy")).toBe("id");
  });

  it("cw_search_opportunity_notes sends conditions and orderBy", async () => {
    const client = await connect();
    await client.callTool({
      name: "cw_search_opportunity_notes",
      arguments: { opportunityId: 7, fields: "id,text", conditions: "id>0", orderBy: "id desc" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/sales/opportunities/7/notes"))!);
    expect(url.searchParams.get("fields")).toBe("id,text");
    expect(url.searchParams.get("conditions")).toBe("id>0");
    expect(url.searchParams.get("orderBy")).toBe("id desc");
  });

  it("still masks contact name and phone numbers in a field-limited notes response", async () => {
    // Known limit (not changed here): a bare first name typed inside free-text `text`
    // is not masked, only emails, phones and IPs there. So this test does not assert that.
    responseBody = [
      { id: 1, text: "Call back on 479-555-0142", contact: { name: "Jane Doe" } },
    ];
    const client = await connect();
    const result = await client.callTool({
      name: "cw_get_ticket_notes",
      arguments: { id: 100, fields: "id,text,contact/name" },
    });
    const text = textOf(result);
    expect(text).not.toContain("479-555-0142");
    expect(text).not.toContain("Jane");
    expect(text).not.toContain("Doe");
    expect(JSON.parse(text)[0].id).toBe(1);
  });

  it("advertises fields, conditions and orderBy and the retry hint", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "cw_get_ticket_notes")!;
    const props = Object.keys(tool.inputSchema.properties ?? {});
    expect(props).toEqual(expect.arrayContaining(["fields", "conditions", "orderBy"]));
    expect(tool.description).toContain("retry with `fields`");
  });
});
