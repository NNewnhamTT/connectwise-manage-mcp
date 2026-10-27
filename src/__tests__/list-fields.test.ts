/**
 * The optional `fields` param on cw_list_boards, cw_list_statuses and
 * cw_list_priorities (src/tools/service.ts). Same harness as search-fields.test.ts:
 * in-memory MCP client, ConnectWise stubbed at global fetch. No live calls.
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

async function connect(): Promise<Client> {
  const server = createMcpServer(CONFIG);
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

beforeEach(() => {
  resetSharedStore();
  fetchCalls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string) => {
      fetchCalls.push(input);
      return new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
  vi.stubEnv("PII_MODE", "on");
  vi.stubEnv("PII_KEY", "e2e-test-key-not-a-secret");
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

describe("list tools: fields", () => {
  it("cw_list_boards sends fields and conditions", async () => {
    const client = await connect();
    await client.callTool({
      name: "cw_list_boards",
      arguments: { fields: "id,name,inactiveFlag", conditions: "inactiveFlag=false", pageSize: 100 },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/boards"))!);
    expect(url.searchParams.get("fields")).toBe("id,name,inactiveFlag");
    expect(url.searchParams.get("conditions")).toBe("inactiveFlag=false");
    expect(url.searchParams.get("pageSize")).toBe("100");
  });

  it("cw_list_boards sends no fields param when omitted", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_list_boards", arguments: {} });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/boards"))!);
    expect(url.searchParams.has("fields")).toBe(false);
  });

  it("cw_list_statuses sends fields for the board's statuses", async () => {
    const client = await connect();
    await client.callTool({
      name: "cw_list_statuses",
      arguments: { boardId: 30, fields: "id,name,emailTemplate/id", conditions: "inactive=false" },
    });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/boards/30/statuses"))!);
    expect(url.searchParams.get("fields")).toBe("id,name,emailTemplate/id");
    expect(url.searchParams.get("conditions")).toBe("inactive=false");
  });

  it("cw_list_priorities sends fields", async () => {
    const client = await connect();
    await client.callTool({ name: "cw_list_priorities", arguments: { fields: "id,name" } });
    const url = new URL(fetchCalls.find((u) => u.includes("/service/priorities"))!);
    expect(url.searchParams.get("fields")).toBe("id,name");
  });

  it("advertises fields and the retry hint on cw_list_boards and cw_list_statuses", async () => {
    const client = await connect();
    const { tools } = await client.listTools();
    for (const name of ["cw_list_boards", "cw_list_statuses", "cw_list_priorities"]) {
      const tool = tools.find((t) => t.name === name)!;
      expect(Object.keys(tool.inputSchema.properties ?? {})).toContain("fields");
    }
    expect(tools.find((t) => t.name === "cw_list_boards")!.description).toContain("Retry with `fields`");
    expect(tools.find((t) => t.name === "cw_list_statuses")!.description).toContain("emailTemplate");
  });
});
