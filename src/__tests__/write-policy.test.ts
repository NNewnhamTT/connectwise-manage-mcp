/**
 * Write policy: a default-deny allow-list for write tools, with per-tool argument
 * rules (src/guard/write-policy.ts). Unit tests for the file format and the
 * decision, then end to end through a real MCP client with ConnectWise stubbed at
 * global fetch. No live calls.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../mcp-server.js";
import { resetSharedStore } from "../pii/index.js";
import type { Identity } from "../guard/identity.js";
import { summarizeArgs } from "../guard/audit.js";
import { loadGuardConfig } from "../guard/wrap-guard.js";
import { checkWrite, parseWritePolicy, loadWritePolicyFile } from "../guard/write-policy.js";

const POLICY = {
  version: 1,
  exemptUsers: ["breakglass"],
  tools: {
    cw_add_ticket_note: {
      require: { internalAnalysisFlag: true, processNotifications: false },
      denyTrue: [
        "detailDescriptionFlag",
        "resolutionFlag",
        "customerUpdatedFlag",
        "emailContactFlag",
        "emailResourceFlag",
        "emailCcFlag",
      ],
      denyArgs: ["emailCc"],
    },
    cw_update_ticket: {
      patch: {
        allowPaths: ["summary", "priority/id", "status/id"],
        allowValues: { "status/id": [12, 14] },
      },
    },
    cw_create_ticket: {
      requireArgs: ["boardId"],
      allowValues: { boardId: [3], statusId: [12] },
    },
  },
};

describe("parseWritePolicy", () => {
  it("accepts a valid policy", () => {
    const p = parseWritePolicy(POLICY);
    expect(p.exemptUsers).toEqual(["breakglass"]);
    expect(Object.keys(p.tools)).toEqual(["cw_add_ticket_note", "cw_update_ticket", "cw_create_ticket"]);
    expect(p.tools.cw_update_ticket!.patch!.allowOps).toEqual(["replace"]);
  });

  it.each([
    ["not an object", [], /JSON object/],
    ["wrong version", { version: 2, tools: {} }, /"version" must be 1/],
    ["missing tools", { version: 1 }, /"tools" must be an object/],
    ["unknown top-level key", { version: 1, tools: {}, extra: 1 }, /unknown key "extra"/],
    ["a comment that is not text", { version: 1, comment: 5, tools: {} }, /"comment" must be a string/],
    ["unknown rule key", { version: 1, tools: { cw_create_ticket: { allow: [] } } }, /unknown key "allow"/],
    ["a read tool", { version: 1, tools: { cw_get_ticket: {} } }, /is a read tool/],
    [
      "a patch value path that is not allowed",
      { version: 1, tools: { cw_update_ticket: { patch: { allowPaths: ["summary"], allowValues: { "status/id": [1] } } } } },
      /not in allowPaths/,
    ],
    ["an empty value list", { version: 1, tools: { cw_create_ticket: { allowValues: { boardId: [] } } } }, /non-empty list/],
    ["a bad op", { version: 1, tools: { cw_update_ticket: { patch: { allowOps: ["delete"] } } } }, /allowOps/],
  ])("rejects %s", (_name, raw, message) => {
    expect(() => parseWritePolicy(raw)).toThrow(message);
  });
});

describe("checkWrite", () => {
  const policy = parseWritePolicy(POLICY);

  it("refuses a write tool that is not listed", () => {
    const d = checkWrite(policy, "cw_create_contact", { firstName: "x" }, "alice");
    expect(d).toMatchObject({ allowed: false, reason: "rule:cw_create_contact:not-listed" });
  });

  it("lets an exempt user skip the policy", () => {
    expect(checkWrite(policy, "cw_create_contact", {}, "breakglass")).toMatchObject({ allowed: true });
  });

  it("adds required values that are missing and reports them", () => {
    const d = checkWrite(policy, "cw_add_ticket_note", { id: 1, text: "hi" }, "alice");
    expect(d).toMatchObject({ allowed: true, injected: ["internalAnalysisFlag", "processNotifications"] });
    expect((d as { args: Record<string, unknown> }).args).toEqual({
      id: 1,
      text: "hi",
      internalAnalysisFlag: true,
      processNotifications: false,
    });
  });

  it("never adds customerUpdatedFlag, and refuses it when true", () => {
    const ok = checkWrite(policy, "cw_add_ticket_note", { id: 1, text: "hi" }, "alice") as {
      args: Record<string, unknown>;
    };
    expect("customerUpdatedFlag" in ok.args).toBe(false);
    expect(checkWrite(policy, "cw_add_ticket_note", { id: 1, text: "hi", customerUpdatedFlag: true }, "alice")).toMatchObject({
      allowed: false,
      reason: "rule:cw_add_ticket_note:deny-true:customerUpdatedFlag",
    });
    // false is not refused and not rewritten.
    expect(checkWrite(policy, "cw_add_ticket_note", { id: 1, text: "hi", customerUpdatedFlag: false }, "alice")).toMatchObject({
      allowed: true,
    });
  });

  it("refuses a value that conflicts with a required one", () => {
    expect(checkWrite(policy, "cw_add_ticket_note", { id: 1, text: "hi", internalAnalysisFlag: false }, "alice")).toMatchObject({
      allowed: false,
      reason: "rule:cw_add_ticket_note:require:internalAnalysisFlag",
    });
    expect(checkWrite(policy, "cw_add_ticket_note", { id: 1, text: "hi", processNotifications: true }, "alice")).toMatchObject({
      allowed: false,
    });
  });

  it("refuses emailCc when set", () => {
    expect(checkWrite(policy, "cw_add_ticket_note", { id: 1, text: "hi", emailCc: "a@b.com" }, "alice")).toMatchObject({
      allowed: false,
      reason: "rule:cw_add_ticket_note:deny-arg:emailCc",
    });
  });

  it("allows only listed patch paths and values", () => {
    const patch = (operations: unknown[]) => checkWrite(policy, "cw_update_ticket", { id: 1, operations }, "alice");
    expect(patch([{ op: "replace", path: "summary", value: "x" }])).toMatchObject({ allowed: true });
    expect(patch([{ op: "replace", path: "/priority/id", value: 2 }])).toMatchObject({ allowed: true });
    expect(patch([{ op: "replace", path: "status/id", value: 12 }])).toMatchObject({ allowed: true });
    expect(patch([{ op: "replace", path: "status/id", value: 99 }])).toMatchObject({
      allowed: false,
      reason: "rule:cw_update_ticket:patch-value:status/id",
    });
    expect(patch([{ op: "replace", path: "status/id", value: "12" }])).toMatchObject({ allowed: false });
    expect(patch([{ op: "remove", path: "status/id" }])).toMatchObject({ allowed: false });
    expect(patch([{ op: "replace", path: "automaticEmailContactFlag", value: true }])).toMatchObject({
      allowed: false,
      reason: "rule:cw_update_ticket:patch-path:automaticEmailContactFlag",
    });
    // Paths are exact and case-sensitive: near misses are refused, not guessed at.
    expect(patch([{ op: "replace", path: "Status/ID", value: 12 }])).toMatchObject({ allowed: false });
    expect(patch([{ op: "replace", path: "status/id/x", value: 12 }])).toMatchObject({ allowed: false });
    // One bad operation refuses the whole call.
    expect(
      patch([
        { op: "replace", path: "summary", value: "x" },
        { op: "replace", path: "board/id", value: 1 },
      ]),
    ).toMatchObject({ allowed: false });
  });

  it("does not echo a hostile patch path into the reason", () => {
    const d = checkWrite(policy, "cw_update_ticket", { id: 1, operations: [{ op: "replace", path: "Jane Doe <x>", value: 1 }] }, "alice");
    expect(d).toMatchObject({ allowed: false, reason: "rule:cw_update_ticket:patch-path:(invalid)" });
    expect(JSON.stringify(d)).not.toContain("Jane");
  });

  it("checks ticket creation by board and status", () => {
    expect(checkWrite(policy, "cw_create_ticket", { summary: "x" }, "alice")).toMatchObject({
      allowed: false,
      reason: "rule:cw_create_ticket:require-arg:boardId",
    });
    expect(checkWrite(policy, "cw_create_ticket", { summary: "x", boardId: 9 }, "alice")).toMatchObject({
      allowed: false,
      reason: "rule:cw_create_ticket:allow-values:boardId",
    });
    expect(checkWrite(policy, "cw_create_ticket", { summary: "x", boardId: 3, statusId: 5 }, "alice")).toMatchObject({
      allowed: false,
      reason: "rule:cw_create_ticket:allow-values:statusId",
    });
    expect(checkWrite(policy, "cw_create_ticket", { summary: "x", boardId: 3, statusId: 12 }, "alice")).toMatchObject({
      allowed: true,
    });
    expect(checkWrite(policy, "cw_create_ticket", { summary: "x", boardId: 3 }, "alice")).toMatchObject({ allowed: true });
  });
});

describe("audit summary of a patch", () => {
  it("lists patch paths, and hides anything that is not a plain field name", () => {
    expect(
      summarizeArgs({
        operations: [
          { op: "replace", path: "status/id", value: 12 },
          { op: "replace", path: "Jane Doe", value: 1 },
        ],
      }),
    ).toEqual({ operations: { array: 2, paths: ["status/id", "(invalid)"] } });
  });

  it("still logs other arrays as a length", () => {
    expect(summarizeArgs({ ops: [1, 2], none: [] })).toEqual({ ops: { array: 2 }, none: { array: 0 } });
  });
});

describe("loading the policy file", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "write-policy-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("reads a valid file", () => {
    const file = join(dir, "policy.json");
    writeFileSync(file, JSON.stringify(POLICY));
    expect(loadWritePolicyFile(file).tools.cw_create_ticket).toBeDefined();
  });

  it("stops on a missing file, bad JSON or an invalid policy, without echoing the content", () => {
    expect(() => loadWritePolicyFile(join(dir, "none.json"))).toThrow(/cannot be read/);
    const bad = join(dir, "bad.json");
    writeFileSync(bad, "{ not json secret-value");
    expect(() => loadWritePolicyFile(bad)).toThrow(/not valid JSON/);
    try {
      loadWritePolicyFile(bad);
    } catch (e) {
      expect(String(e)).not.toContain("secret-value");
    }
    const invalid = join(dir, "invalid.json");
    writeFileSync(invalid, JSON.stringify({ version: 1, tools: { cw_get_ticket: {} } }));
    expect(() => loadWritePolicyFile(invalid)).toThrow(/MCP_WRITE_POLICY_FILE/);
  });

  it("the shipped example file is valid and never injects or forces customerUpdatedFlag", () => {
    const example = loadWritePolicyFile(
      fileURLToPath(new URL("../../deploy/write-policy/write-policy.example.json", import.meta.url)),
    );
    const note = example.tools.cw_add_ticket_note!;
    expect("customerUpdatedFlag" in note.require).toBe(false);
    expect(note.denyTrue).toContain("customerUpdatedFlag");
    expect(example.exemptUsers).toEqual([]);
    // Placeholder ids match nothing real, so the example allows no real board or status.
    expect(example.tools.cw_create_ticket!.allowValues.boardId).toEqual([-1]);
  });

  it("the site policy (write-policy.json) never allows a status change, and creates only on pinned silent statuses", () => {
    for (const name of ["write-policy.json", "write-policy.example.json"]) {
      const p = loadWritePolicyFile(fileURLToPath(new URL(`../../deploy/write-policy/${name}`, import.meta.url)));
      const paths = p.tools.cw_update_ticket!.patch!.allowPaths;
      expect(paths.some((x) => /status/i.test(x))).toBe(false);
      expect(paths).toEqual(["priority/id", "type/id", "subType/id", "item/id"]);
      expect(p.tools.cw_update_ticket!.patch!.allowValues).toEqual({});
      expect(p.tools.cw_create_ticket!.requireArgs).toEqual(expect.arrayContaining(["boardId", "statusId"]));
      expect(p.exemptUsers).toEqual([]);
      const note = p.tools.cw_add_ticket_note!;
      expect("customerUpdatedFlag" in note.require).toBe(false);
      expect(note.denyTrue).toContain("customerUpdatedFlag");
      // Only these write tools are listed; everything else is refused.
      expect(Object.keys(p.tools).sort()).toEqual(["cw_add_ticket_note", "cw_create_ticket", "cw_update_ticket"]);
    }
    const site = loadWritePolicyFile(fileURLToPath(new URL("../../deploy/write-policy/write-policy.json", import.meta.url)));
    expect(site.tools.cw_create_ticket!.allowValues.boardId).toEqual([40]);
    expect(site.tools.cw_create_ticket!.allowValues.statusId).toEqual([674]);
    // Only Administrative is creatable for now. Boards 60 and 72 (default status has an email template) are not.
    expect(site.tools.cw_create_ticket!.allowValues.boardId).not.toContain(60);
    expect(site.tools.cw_create_ticket!.allowValues.boardId).not.toContain(72);
    // End to end through the decision function.
    expect(checkWrite(site, "cw_update_ticket", { id: 1, operations: [{ op: "replace", path: "status/id", value: 548 }] }, "alice")).toMatchObject({
      allowed: false,
      reason: "rule:cw_update_ticket:patch-path:status/id",
    });
    expect(checkWrite(site, "cw_update_ticket", { id: 1, operations: [{ op: "replace", path: "item/id", value: 12 }] }, "alice")).toMatchObject({
      allowed: true,
    });
    expect(checkWrite(site, "cw_create_ticket", { summary: "x", boardId: 40, statusId: 674, itemId: 12 }, "alice")).toMatchObject({
      allowed: true,
    });
    expect(checkWrite(site, "cw_create_ticket", { summary: "x", boardId: 60, statusId: 1081 }, "alice")).toMatchObject({ allowed: false });
    expect(checkWrite(site, "cw_create_ticket", { summary: "x", boardId: 40, statusId: 674 }, "alice")).toMatchObject({ allowed: true });
    expect(checkWrite(site, "cw_create_ticket", { summary: "x", boardId: 30, statusId: 547 }, "alice")).toMatchObject({ allowed: false });
    expect(checkWrite(site, "cw_create_ticket", { summary: "x", boardId: 40 }, "alice")).toMatchObject({ allowed: false });
  });

  it("loadGuardConfig carries the policy, and is off when the variable is unset", () => {
    const file = join(dir, "policy.json");
    writeFileSync(file, JSON.stringify(POLICY));
    expect(loadGuardConfig({ MCP_WRITE_POLICY_FILE: file })?.writePolicy?.exemptUsers).toEqual(["breakglass"]);
    expect(loadGuardConfig({})).toBeUndefined();
    expect(loadGuardConfig({ MCP_POLICY: "write" })?.writePolicy).toBeUndefined();
  });
});

// ---- End to end ----

const CONFIG = {
  baseUrl: "https://cw.example.com",
  companyId: "acme",
  publicKey: "pub-key-do-not-log",
  privateKey: "priv-key-do-not-log",
  clientId: "cid",
};

const ALICE: Identity = { user: "alice", role: "write", source: "proxy" };

let dir: string;
let fetchCalls: { url: string; method: string; body?: unknown }[];
let auditLines: string[];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function connect(identity: Identity = ALICE): Promise<Client> {
  const server = createMcpServer(CONFIG, { identity });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

function writes(): { url: string; method: string; body?: unknown }[] {
  return fetchCalls.filter((c) => c.method !== "GET");
}

function audits(): Record<string, unknown>[] {
  return auditLines.filter((l) => l.startsWith('{"type":"audit"')).map((l) => JSON.parse(l));
}

describe("write policy through the server", () => {
  beforeEach(() => {
    resetSharedStore();
    fetchCalls = [];
    auditLines = [];
    dir = mkdtempSync(join(tmpdir(), "write-policy-e2e-"));
    const file = join(dir, "policy.json");
    writeFileSync(file, JSON.stringify(POLICY));
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string, init?: RequestInit) => {
        fetchCalls.push({
          url: input,
          method: init?.method ?? "GET",
          body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
        });
        return json({ id: 5 });
      }),
    );
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      auditLines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" "));
    });
    vi.stubEnv("PII_MODE", "on");
    vi.stubEnv("PII_KEY", "e2e-test-key-not-a-secret");
    vi.stubEnv("MCP_AUDIT", "on");
    vi.stubEnv("MCP_WRITE_POLICY_FILE", file);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    rmSync(dir, { recursive: true, force: true });
  });

  it("sends a note as internal-only with email off, and never touches customerUpdatedFlag", async () => {
    const client = await connect();
    const res = (await client.callTool({
      name: "cw_add_ticket_note",
      arguments: { id: 100, text: "Checked the UPS alert." },
    })) as { isError?: boolean };
    expect(res.isError).toBeFalsy();
    const [post] = writes();
    expect(post!.url).toContain("/service/tickets/100/notes");
    const body = post!.body as Record<string, unknown>;
    expect(body.internalAnalysisFlag).toBe(true);
    expect(body.processNotifications).toBe(false);
    expect("customerUpdatedFlag" in body).toBe(false);
    expect(body.detailDescriptionFlag).not.toBe(true);
    const line = audits().find((l) => l.tool === "cw_add_ticket_note")!;
    expect(line).toMatchObject({ status: "ok", injected: ["internalAnalysisFlag", "processNotifications"] });
  });

  it("refuses a client-visible or emailing note before anything reaches ConnectWise", async () => {
    const client = await connect();
    for (const args of [
      { id: 100, text: "x", customerUpdatedFlag: true },
      { id: 100, text: "x", detailDescriptionFlag: true },
      { id: 100, text: "x", internalAnalysisFlag: false },
      { id: 100, text: "x", processNotifications: true },
      { id: 100, text: "x", emailContactFlag: true },
    ]) {
      const res = (await client.callTool({ name: "cw_add_ticket_note", arguments: args })) as { isError?: boolean };
      expect(res.isError).toBe(true);
    }
    expect(writes()).toHaveLength(0);
    expect(audits().filter((l) => l.status === "denied")).toHaveLength(5);
  });

  it("applies to an admin too, and to a caller with no role", async () => {
    const admin = await connect({ user: "carol", role: "admin", source: "proxy" });
    const res = (await admin.callTool({ name: "cw_create_contact", arguments: { firstName: "A", lastName: "B", companyId: 1 } })) as {
      isError?: boolean;
    };
    expect(res.isError).toBe(true);
    const noRole = await connect({ user: "dave", source: "proxy" });
    const res2 = (await noRole.callTool({
      name: "cw_update_ticket",
      arguments: { id: 1, operations: [{ op: "replace", path: "automaticEmailContactFlag", value: true }] },
    })) as { isError?: boolean };
    expect(res2.isError).toBe(true);
    expect(writes()).toHaveLength(0);
  });

  it("lets a listed ticket field change through and blocks the email flags", async () => {
    const client = await connect();
    const ok = (await client.callTool({
      name: "cw_update_ticket",
      arguments: { id: 100, operations: [{ op: "replace", path: "status/id", value: 12 }] },
    })) as { isError?: boolean };
    expect(ok.isError).toBeFalsy();
    expect(writes()).toHaveLength(1);
    expect(writes()[0]!.method).toBe("PATCH");

    fetchCalls = [];
    for (const operations of [
      [{ op: "replace", path: "status/id", value: 99 }],
      [{ op: "replace", path: "automaticEmailContactFlag", value: true }],
      [{ op: "replace", path: "board/id", value: 1 }],
    ]) {
      const res = (await client.callTool({ name: "cw_update_ticket", arguments: { id: 100, operations } })) as {
        isError?: boolean;
      };
      expect(res.isError).toBe(true);
    }
    expect(writes()).toHaveLength(0);
    const denied = audits().filter((l) => l.status === "denied");
    expect(denied.map((l) => l.reason)).toEqual([
      "rule:cw_update_ticket:patch-value:status/id",
      "rule:cw_update_ticket:patch-path:automaticEmailContactFlag",
      "rule:cw_update_ticket:patch-path:board/id",
    ]);
    // The audit line shows which paths a patch touched.
    expect(denied[0]!.args).toMatchObject({ operations: { array: 1, paths: ["status/id"] } });
  });

  it("creates a ticket only on a named board and status", async () => {
    const client = await connect();
    const bad = (await client.callTool({ name: "cw_create_ticket", arguments: { summary: "x", boardId: 9 } })) as {
      isError?: boolean;
    };
    expect(bad.isError).toBe(true);
    expect(writes()).toHaveLength(0);
    const ok = (await client.callTool({
      name: "cw_create_ticket",
      arguments: { summary: "x", boardId: 3, statusId: 12 },
    })) as { isError?: boolean };
    expect(ok.isError).toBeFalsy();
    expect(writes()).toHaveLength(1);
  });

  it("sends itemId on ticket creation as item { id }, and omits it when not given", async () => {
    const client = await connect();
    await client.callTool({
      name: "cw_create_ticket",
      arguments: { summary: "x", boardId: 3, statusId: 12, typeId: 4, subTypeId: 5, itemId: 6 },
    });
    await client.callTool({ name: "cw_create_ticket", arguments: { summary: "y", boardId: 3, statusId: 12 } });
    const [withItem, without] = writes().map((w) => w.body as Record<string, unknown>);
    expect(withItem!.item).toEqual({ id: 6 });
    expect(withItem!.type).toEqual({ id: 4 });
    expect(withItem!.subType).toEqual({ id: 5 });
    expect("item" in without!).toBe(false);
  });

  it("refuses write tools that are not listed, and leaves read tools alone", async () => {
    const client = await connect();
    const time = (await client.callTool({
      name: "cw_create_time_entry",
      arguments: { chargeToType: "ServiceTicket", chargeToId: 100, actualHours: 1, memberId: 1 },
    })) as { isError?: boolean };
    expect(time.isError).toBe(true);
    const read = (await client.callTool({ name: "cw_get_ticket", arguments: { id: 100 } })) as { isError?: boolean };
    expect(read.isError).toBeFalsy();
    expect(writes()).toHaveLength(0);
  });

  it("lets an exempt user skip the policy", async () => {
    const client = await connect({ user: "breakglass", role: "write", source: "proxy" });
    const res = (await client.callTool({
      name: "cw_add_ticket_note",
      arguments: { id: 100, text: "x", customerUpdatedFlag: true },
    })) as { isError?: boolean };
    expect(res.isError).toBeFalsy();
    expect((writes()[0]!.body as Record<string, unknown>).customerUpdatedFlag).toBe(true);
  });

  it("still stops at the access level first", async () => {
    const client = await connect({ user: "erin", role: "read", source: "proxy" });
    const res = (await client.callTool({ name: "cw_add_ticket_note", arguments: { id: 100, text: "x" } })) as {
      isError?: boolean;
    };
    expect(res.isError).toBe(true);
    expect(audits().find((l) => l.tool === "cw_add_ticket_note")).toMatchObject({ reason: "policy:read" });
  });

  it("refuses to start with a bad policy file", () => {
    const bad = join(dir, "bad.json");
    writeFileSync(bad, JSON.stringify({ version: 1, tools: { cw_get_ticket: {} } }));
    vi.stubEnv("MCP_WRITE_POLICY_FILE", bad);
    expect(() => createMcpServer(CONFIG)).toThrow(/MCP_WRITE_POLICY_FILE/);
  });
});

describe("without a policy file", () => {
  beforeEach(() => {
    resetSharedStore();
    fetchCalls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string, init?: RequestInit) => {
        fetchCalls.push({ url: input, method: init?.method ?? "GET" });
        return json({ id: 5 });
      }),
    );
    vi.stubEnv("PII_MODE", "on");
    vi.stubEnv("PII_KEY", "e2e-test-key-not-a-secret");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("behaves as before: a writer may run any write tool", async () => {
    const client = await connect();
    const res = (await client.callTool({
      name: "cw_update_ticket",
      arguments: { id: 1, operations: [{ op: "replace", path: "automaticEmailContactFlag", value: true }] },
    })) as { isError?: boolean };
    expect(res.isError).toBeFalsy();
    expect(writes()).toHaveLength(1);
  });
});
