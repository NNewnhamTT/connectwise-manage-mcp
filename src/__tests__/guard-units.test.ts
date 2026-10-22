import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../mcp-server.js";
import {
  identityFromEntra,
  identityFromProxyHeaders,
  isValidUserName,
  parseAccessLevel,
} from "../guard/identity.js";
import { classifyTool, isAllowed, requiredLevel } from "../guard/policy.js";
import { collectTokens, formatAuditLine, summarizeArgs } from "../guard/audit.js";
import { loadGuardConfig } from "../guard/wrap-guard.js";

describe("identity", () => {
  it("accepts plain user names and rejects log-unsafe ones", () => {
    for (const ok of ["alice", "a.b-c_d", "nick@tektrendz.com", "x+y"]) expect(isValidUserName(ok)).toBe(true);
    for (const bad of ["", "a b", 'a"b', "a\nb", "a/b", "x".repeat(101), "<script>"]) {
      expect(isValidUserName(bad)).toBe(false);
    }
  });

  it("parses access levels case-insensitively and rejects unknown ones", () => {
    expect(parseAccessLevel(" Write ")).toBe("write");
    expect(parseAccessLevel("ADMIN")).toBe("admin");
    expect(parseAccessLevel("root")).toBeUndefined();
    expect(parseAccessLevel(undefined)).toBeUndefined();
  });

  it("builds an identity from proxy headers", () => {
    expect(identityFromProxyHeaders("alice", "write")).toEqual({ user: "alice", role: "write", source: "proxy" });
    expect(identityFromProxyHeaders("alice", undefined)).toEqual({ user: "alice", role: undefined, source: "proxy" });
  });

  it("gives no identity for a missing or bad user, and drops a bad role", () => {
    expect(identityFromProxyHeaders(undefined, "admin")).toBeUndefined();
    expect(identityFromProxyHeaders("bad user", "admin")).toBeUndefined();
    // An unknown role never raises access: it falls back to the server default.
    expect(identityFromProxyHeaders("alice", "superuser")?.role).toBeUndefined();
  });

  it("maps Entra app roles to an access level", () => {
    expect(identityFromEntra("a@b.com", ["CWM.Access"]).role).toBeUndefined();
    expect(identityFromEntra("a@b.com", ["CWM.Access", "CWM.Write"]).role).toBe("write");
    expect(identityFromEntra("a@b.com", ["CWM.Write", "CWM.Admin"]).role).toBe("admin");
    expect(identityFromEntra("a@b.com", []).source).toBe("entra");
  });
});

describe("policy", () => {
  it("classifies by name and treats unknown names as write", () => {
    expect(classifyTool("cw_get_ticket")).toBe("read");
    expect(classifyTool("cw_search_tickets")).toBe("read");
    expect(classifyTool("cw_list_communication_types")).toBe("read");
    expect(classifyTool("cw_test_connection")).toBe("read");
    expect(classifyTool("cw_delete_time_entry")).toBe("destructive");
    expect(classifyTool("cw_update_ticket")).toBe("write");
    expect(classifyTool("cw_close_adjustment")).toBe("write");
    expect(classifyTool("cw_some_new_upstream_tool")).toBe("write");
    // A name that only contains a read verb later on is not read.
    expect(classifyTool("cw_update_get_thing")).toBe("write");
    expect(classifyTool("get_ticket")).toBe("write");
  });

  it("orders levels read < write < admin", () => {
    expect(requiredLevel("read")).toBe("read");
    expect(requiredLevel("write")).toBe("write");
    expect(requiredLevel("destructive")).toBe("admin");
    expect(isAllowed("read", "cw_get_ticket")).toBe(true);
    expect(isAllowed("read", "cw_update_ticket")).toBe(false);
    expect(isAllowed("write", "cw_update_ticket")).toBe(true);
    expect(isAllowed("write", "cw_delete_time_entry")).toBe(false);
    expect(isAllowed("admin", "cw_delete_time_entry")).toBe(true);
  });

  it("classifies every real tool, with exactly one destructive tool and the known write tools", async () => {
    const server = createMcpServer({
      baseUrl: "https://cw.example.com",
      companyId: "acme",
      publicKey: "pub",
      privateKey: "priv",
      clientId: "cid",
    });
    const [a, b] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "t", version: "0" });
    await Promise.all([server.connect(a), client.connect(b)]);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names.length).toBeGreaterThanOrEqual(84);

    const byClass = (c: string) => names.filter((n) => classifyTool(n) === c).sort();
    expect(byClass("destructive")).toEqual(["cw_delete_time_entry"]);
    // Guard against a write tool slipping into the read class by name.
    expect(byClass("write")).toEqual(
      expect.arrayContaining([
        "cw_add_ticket_note",
        "cw_create_contact",
        "cw_create_ticket",
        "cw_create_time_entry",
        "cw_update_contact",
        "cw_update_ticket",
        "cw_update_company",
        "cw_update_invoice",
      ]),
    );
    expect(byClass("read").every((n) => /^cw_(get|search|list)_|^cw_test_connection$/.test(n))).toBe(true);
    expect(byClass("read").length + byClass("write").length + byClass("destructive").length).toBe(names.length);
  });
});

describe("audit helpers", () => {
  it("keeps numbers and booleans but only the length of strings", () => {
    expect(
      summarizeArgs({ id: 5, flag: true, none: null, conditions: 'firstName = "Jane"', ops: [1, 2], o: { a: 1 } }),
    ).toEqual({ id: 5, flag: true, none: null, conditions: { len: 18 }, ops: { array: 2 }, o: "object" });
  });

  it("returns an empty summary for non-object args", () => {
    expect(summarizeArgs(undefined)).toEqual({});
    expect(summarizeArgs("x")).toEqual({});
    expect(summarizeArgs([1])).toEqual({});
  });

  it("collects each PII token once, from nested strings", () => {
    const t = "<PERSON_aaaaaaaaaa>";
    const e = "<EMAIL_bbbbbbbbbb>";
    expect(collectTokens({ q: `a ${t} b ${t}`, ops: [{ value: e }, { value: "plain" }], n: 3 })).toEqual([t, e]);
    expect(collectTokens("nothing here")).toEqual([]);
  });

  it("formats one JSON line with the expected fields and no string values", () => {
    const line = formatAuditLine({
      ts: "2026-10-22T00:00:00.000Z",
      requestId: "r1",
      identity: { user: "alice", role: "write", source: "proxy" },
      tool: "cw_get_ticket",
      toolClass: "read",
      args: summarizeArgs({ id: 7 }),
      tokens: [],
      status: "ok",
      ms: 12,
      bytes: 345,
    });
    expect(line.includes("\n")).toBe(false);
    expect(JSON.parse(line)).toEqual({
      type: "audit",
      ts: "2026-10-22T00:00:00.000Z",
      requestId: "r1",
      user: "alice",
      role: "write",
      source: "proxy",
      tool: "cw_get_ticket",
      class: "read",
      args: { id: 7 },
      tokens: [],
      status: "ok",
      ms: 12,
      bytes: 345,
    });
  });
});

describe("loadGuardConfig", () => {
  it("is undefined when both controls are off", () => {
    expect(loadGuardConfig({})).toBeUndefined();
    expect(loadGuardConfig({ MCP_AUDIT: "off" })).toBeUndefined();
  });

  it("reads audit and policy", () => {
    expect(loadGuardConfig({ MCP_AUDIT: "on" })).toEqual({ audit: true, defaultLevel: undefined });
    expect(loadGuardConfig({ MCP_POLICY: "READ" })).toEqual({ audit: false, defaultLevel: "read" });
    expect(loadGuardConfig({ MCP_AUDIT: "on", MCP_POLICY: "write" })).toEqual({ audit: true, defaultLevel: "write" });
  });

  it("throws on a bad value so a typo cannot switch a control off", () => {
    expect(() => loadGuardConfig({ MCP_AUDIT: "true" })).toThrow(/MCP_AUDIT/);
    expect(() => loadGuardConfig({ MCP_POLICY: "readonly" })).toThrow(/MCP_POLICY/);
    expect(() => loadGuardConfig({ MCP_POLICY: "none" })).toThrow(/MCP_POLICY/);
  });
});
