import { describe, it, expect } from "vitest";
import { createTokenizer } from "../pii/tokenizer.js";
import { MemoryTokenStore } from "../pii/store.js";
import {
  maskJson,
  unmaskDeep,
  ANALYZER_UNAVAILABLE,
  type Analyzer,
  type PiiContext,
} from "../pii/mask-json.js";

function makeCtx(analyzer?: Analyzer): PiiContext {
  return {
    tokenizer: createTokenizer("test-key-not-a-secret"),
    store: new MemoryTokenStore(),
    tenant: "acme:pub",
    ttlSeconds: 60,
    analyzer,
    scoreThreshold: 0.4,
  };
}

/** Fake analyzer: flags every occurrence of "Jane Doe" as a PERSON. */
const janeAnalyzer: Analyzer = async (texts) =>
  texts.map((t) => {
    const out = [];
    let i = t.indexOf("Jane Doe");
    while (i !== -1) {
      out.push({ entityType: "PERSON", start: i, end: i + 8, score: 0.85 });
      i = t.indexOf("Jane Doe", i + 1);
    }
    return out;
  });

const ticket = {
  id: 4821,
  summary: "Password reset for Jane Doe",
  initialDescription: "Jane Doe called from 555-123-4567 and email jane.doe@acme.com. Host 10.1.2.3 is slow.",
  company: { id: 7, identifier: "AcmeCo", name: "Acme Corporation", _info: { company_href: "https://na.myconnectwise.net/v4_6_release/apis/3.0/company/companies/7" } },
  contact: { id: 99, name: "Jane Doe", _info: { contact_href: "https://na.myconnectwise.net/x/99" } },
  contactName: "Jane Doe",
  contactEmailAddress: "jane.doe@acme.com",
  contactPhoneNumber: "5551234567",
  owner: { id: 3, identifier: "jsmith", name: "John Smith" },
  status: { id: 1, name: "New" },
  site: { id: 5, name: "Main Office" },
  addressLine1: "1 Main Street",
  resources: "jsmith, bjones",
  customFields: [{ id: 1, caption: "Notes", value: "call Jane Doe back" }],
  _info: { updatedBy: "jsmith", lastUpdated: "2026-10-22T10:00:00Z" },
};

const PII_STRINGS = [
  "Jane Doe",
  "jane.doe@acme.com",
  "5551234567",
  "555-123-4567",
  "10.1.2.3",
  "John Smith",
  "jsmith",
  "bjones",
  "1 Main Street",
];

describe("maskJson", () => {
  it("removes every PII string from a ticket and keeps non-PII fields", async () => {
    const masked = (await maskJson(ticket, makeCtx(janeAnalyzer))) as typeof ticket;
    const text = JSON.stringify(masked);
    for (const pii of PII_STRINGS) expect(text).not.toContain(pii);
    expect(masked.id).toBe(4821);
    expect(masked.company.name).toBe("Acme Corporation");
    expect(masked.company.identifier).toBe("AcmeCo");
    expect(masked.company._info.company_href).toBe(ticket.company._info.company_href);
    expect(masked.status.name).toBe("New");
    expect(masked.site.name).toBe("Main Office");
    expect(masked._info.lastUpdated).toBe("2026-10-22T10:00:00Z");
    expect(masked.contact.id).toBe(99);
  });

  it("uses the same token for the same value in every field", async () => {
    const masked = (await maskJson(ticket, makeCtx(janeAnalyzer))) as typeof ticket;
    expect(masked.contactName).toBe(masked.contact.name);
    expect(masked.summary).toBe(`Password reset for ${masked.contactName}`);
    expect(masked.contactEmailAddress).toMatch(/^<EMAIL_[0-9a-f]{10}>$/);
    expect(masked.contactPhoneNumber).toMatch(/^<PHONE_[0-9a-f]{10}>$/);
    expect(masked.initialDescription).toContain(masked.contactEmailAddress);
  });

  it("still masks regex-detectable PII in free text when no analyzer is set", async () => {
    const masked = (await maskJson(ticket, makeCtx())) as typeof ticket;
    expect(masked.initialDescription).not.toContain("jane.doe@acme.com");
    expect(masked.initialDescription).not.toContain("555-123-4567");
    expect(masked.initialDescription).not.toContain("10.1.2.3");
    // Names in prose need the analyzer.
    expect(masked.summary).toBe("Password reset for Jane Doe");
  });

  it("masks custom field values as free text", async () => {
    const masked = (await maskJson(ticket, makeCtx(janeAnalyzer))) as typeof ticket;
    expect(masked.customFields[0]!.value).not.toContain("Jane Doe");
    expect(masked.customFields[0]!.caption).toBe("Notes");
  });

  it("types communicationItems values by communication type", async () => {
    const contact = {
      id: 1,
      firstName: "Jane",
      lastName: "Doe",
      communicationItems: [
        { type: { id: 1, name: "Email" }, value: "jane@acme.com", communicationType: "Email" },
        { type: { id: 2, name: "Direct" }, value: "555 222 3333", communicationType: "Phone" },
      ],
    };
    const masked = (await maskJson(contact, makeCtx())) as typeof contact;
    expect(masked.communicationItems[0]!.value).toMatch(/^<EMAIL_/);
    expect(masked.communicationItems[1]!.value).toMatch(/^<PHONE_/);
    expect(masked.firstName).toMatch(/^<PERSON_/);
    expect(masked.lastName).toMatch(/^<PERSON_/);
    expect(masked.communicationItems[0]!.type.name).toBe("Email");
  });

  it("masks any camelCase *By member field, such as respondedBy and resplanBy", async () => {
    const record = {
      id: 1,
      respondedBy: "TBible",
      resplanBy: "TBible",
      resolvedBy: "TBible",
      approvedBy: "jsmith",
      status: { id: 1, name: "Standby" },
    };
    const masked = (await maskJson(record, makeCtx())) as typeof record;
    const text = JSON.stringify(masked);
    expect(text).not.toContain("TBible");
    expect(text).not.toContain("jsmith");
    expect(masked.respondedBy).toBe(masked.resplanBy);
    expect(masked.respondedBy).toMatch(/^<PERSON_[0-9a-f]{10}>$/);
    expect(masked.status.name).toBe("Standby");
  });

  it("masks arrays of records", async () => {
    const masked = (await maskJson([ticket, ticket], makeCtx(janeAnalyzer))) as (typeof ticket)[];
    expect(masked).toHaveLength(2);
    expect(masked[0]).toEqual(masked[1]);
  });

  it("is idempotent", async () => {
    const ctx = makeCtx(janeAnalyzer);
    const once = await maskJson(ticket, ctx);
    const twice = await maskJson(once, ctx);
    expect(twice).toEqual(once);
  });

  it("does not mutate its input", async () => {
    const copy = structuredClone(ticket);
    await maskJson(ticket, makeCtx(janeAnalyzer));
    expect(ticket).toEqual(copy);
  });

  it("fails closed on free text when the analyzer throws", async () => {
    const boom: Analyzer = async () => {
      throw new Error("down");
    };
    const masked = (await maskJson(ticket, makeCtx(boom))) as typeof ticket;
    expect(masked.summary).toBe(ANALYZER_UNAVAILABLE);
    expect(masked.initialDescription).toBe(ANALYZER_UNAVAILABLE);
    // Structured field masking still works.
    expect(masked.contactEmailAddress).toMatch(/^<EMAIL_/);
  });

  it("ignores analyzer spans under the score threshold and unknown entity types", async () => {
    const weak: Analyzer = async (texts) =>
      texts.map(() => [
        { entityType: "PERSON", start: 0, end: 8, score: 0.1 },
        { entityType: "LOCATION", start: 9, end: 14, score: 0.99 },
      ]);
    const masked = (await maskJson({ summary: "Password reset" }, makeCtx(weak))) as { summary: string };
    expect(masked.summary).toBe("Password reset");
  });

  it("passes plain strings, numbers and null through", async () => {
    expect(await maskJson(5, makeCtx())).toBe(5);
    expect(await maskJson(null, makeCtx())).toBeNull();
    expect(await maskJson("call 555-123-4567", makeCtx())).toMatch(/^call <PHONE_/);
  });
});

describe("unmaskDeep", () => {
  it("restores real values from tokens in nested args", async () => {
    const ctx = makeCtx(janeAnalyzer);
    const masked = (await maskJson(ticket, ctx)) as typeof ticket;
    const args = {
      id: 1,
      text: `Emailed ${masked.contactEmailAddress}`,
      operations: [{ op: "replace", path: "summary", value: `Reset for ${masked.contactName}` }],
    };
    const { value, unknownTokens } = await unmaskDeep(args, ctx);
    expect(unknownTokens).toEqual([]);
    expect(value).toEqual({
      id: 1,
      text: "Emailed jane.doe@acme.com",
      operations: [{ op: "replace", path: "summary", value: "Reset for Jane Doe" }],
    });
  });

  it("reports tokens it cannot resolve and leaves them in place", async () => {
    const ctx = makeCtx();
    const { value, unknownTokens } = await unmaskDeep({ q: "name=<PERSON_0000000000>" }, ctx);
    expect(unknownTokens).toEqual(["<PERSON_0000000000>"]);
    expect(value).toEqual({ q: "name=<PERSON_0000000000>" });
  });

  it("does not resolve a token stored under another tenant", async () => {
    const a = makeCtx();
    const b = { ...makeCtx(), store: a.store, tenant: "other:pub" };
    const masked = (await maskJson({ contactName: "Jane Doe" }, a)) as { contactName: string };
    const { unknownTokens } = await unmaskDeep({ q: masked.contactName }, b);
    expect(unknownTokens).toEqual([masked.contactName]);
  });

  it("leaves non-token text alone", async () => {
    const { value, unknownTokens } = await unmaskDeep({ q: "status/name != 'Closed' <b>x</b>", n: 3 }, makeCtx());
    expect(unknownTokens).toEqual([]);
    expect(value).toEqual({ q: "status/name != 'Closed' <b>x</b>", n: 3 });
  });
});
