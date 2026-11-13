/**
 * Financial and government identifiers (src/pii/id-rules.ts): card numbers,
 * IBANs, SSNs, tax IDs. Replaced with a fixed marker, never a token.
 * Fixture values are public test numbers or made up.
 */

import { describe, expect, it } from "vitest";
import { createTokenizer } from "../pii/tokenizer.js";
import { MemoryTokenStore } from "../pii/store.js";
import { maskJson, type Analyzer, type PiiContext } from "../pii/mask-json.js";
import { PRESIDIO_ID_ENTITIES, REDACTED_ID, idSpans, isSensitiveIdKey } from "../pii/id-rules.js";
import { DEFAULT_ENTITIES, createPresidioAnalyzer } from "../pii/presidio-client.js";

function makeCtx(analyzer?: Analyzer): PiiContext {
  return {
    tokenizer: createTokenizer("test-key-not-a-secret"),
    store: new MemoryTokenStore(),
    tenant: "t:1",
    ttlSeconds: 60,
    analyzer,
    scoreThreshold: 0.4,
  };
}

const VISA = "4111 1111 1111 1111";
const VISA_DASHED = "4242-4242-4242-4242";
const IBAN_GB = "GB82 WEST 1234 5698 7654 32";
const IBAN_DE = "DE89370400440532013000";

async function mask(value: Record<string, unknown>, ctx = makeCtx()): Promise<Record<string, unknown>> {
  return (await maskJson(value, ctx)) as Record<string, unknown>;
}

describe("local patterns (no Presidio)", () => {
  it.each([
    [`Card on file ${VISA} exp 12/30`, `Card on file ${REDACTED_ID} exp 12/30`],
    [`Card ${VISA_DASHED}.`, `Card ${REDACTED_ID}.`],
    [`pay 5555555555554444 now`, `pay ${REDACTED_ID} now`],
    [`IBAN ${IBAN_GB} for the vendor`, `IBAN ${REDACTED_ID} for the vendor`],
    [`wire to ${IBAN_DE}`, `wire to ${REDACTED_ID}`],
    [`SSN 123-45-6789 on the form`, `SSN ${REDACTED_ID} on the form`],
    [`employee 123-45-6789`, `employee ${REDACTED_ID}`],
    [`Tax ID = 12-3456789`, `Tax ID = ${REDACTED_ID}`],
    [`EIN: 123456789`, `EIN: ${REDACTED_ID}`],
    [`Social Security Number: 123456789`, `Social Security Number: ${REDACTED_ID}`],
    [`<div>TAX ID =&nbsp;12-3456789<br></div>`, `<div>TAX ID =&nbsp;${REDACTED_ID}<br></div>`],
  ])("redacts: %s", async (input, expected) => {
    expect((await mask({ notes: input })).notes).toBe(expected);
  });

  it.each([
    ["a number that fails the Luhn check", "ref 4111 1111 1111 1112 done"],
    ["a short digit run", "ticket 123456789012"],
    ["a dashed SSN with area 000", "id 000-12-3456"],
    ["a dashed SSN with area 666", "id 666-12-3456"],
    ["a dashed SSN with area 9xx", "id 900-12-3456"],
    ["an IBAN-shaped string with a bad checksum", "GB00 WEST 1234 5698 7654 32"],
    ["a bare nine digit number with no label", "serial 123456789"],
    ["a date", "on 2026-11-04"],
  ])("leaves %s alone", async (_label, input) => {
    expect((await mask({ notes: input })).notes).toBe(input);
  });

  it("treats a phone number as a phone, not as an ID", async () => {
    const out = (await mask({ notes: "call 555-123-4567" })).notes as string;
    expect(out).toMatch(/^call <PHONE_[0-9a-f]{10}>$/);
  });

  it("applies to fields that are not free text and uses a marker, not a token", async () => {
    const ctx = makeCtx();
    const out = await mask({ serialNumber: "4111111111111111", notes: `ssn 123-45-6789` }, ctx);
    expect(out.serialNumber).toBe(REDACTED_ID);
    expect(JSON.stringify(out)).not.toMatch(/<[A-Z]+_[0-9a-f]{10}>/);
  });


  it("idSpans returns the digit span only for a labelled tax ID", () => {
    const text = "EIN: 123456789 ok";
    const [span] = idSpans(text);
    expect(text.slice(span.start, span.end)).toBe("123456789");
  });
});

describe("key names", () => {
  it.each([
    "ssn",
    "SSN",
    "socialSecurityNumber",
    "social-security-number",
    "taxId",
    "tax-id",
    "tax_number",
    "taxIdentifier",
    "ein",
    "cardNumber",
    "credit-card",
    "cvv",
    "iban",
    "routingNumber",
    "bankAccount",
    "bankAccountNumber",
    "passportNumber",
    "driversLicense",
  ])("%s is a sensitive ID key", (key) => {
    expect(isSensitiveIdKey(key)).toBe(true);
  });

  it.each([
    "name",
    "accountNumber",
    "taxIdRequired",
    "ssnVerified",
    "cardType",
    "creditCardEnabled",
    "bankAccountStatus",
    "routingPolicy",
    "stein",
    "protein",
    "taxRate",
    "passport",
  ])("%s is not", (key) => {
    expect(isSensitiveIdKey(key)).toBe(false);
  });

  it("replaces the whole value, numbers and objects too, keeps booleans, null and empty", async () => {
    const out = await mask({
      ssn: "123-45-6789",
      cardNumber: 4111111111111111,
      taxId: { value: "12-3456789", country: "US" },
      iban: ["DE89370400440532013000"],
      cvv: "",
      ein: null,
      taxIdRequired: true,
    });
    expect(out.ssn).toBe(REDACTED_ID);
    expect(out.cardNumber).toBe(REDACTED_ID);
    expect(out.taxId).toBe(REDACTED_ID);
    expect(out.iban).toBe(REDACTED_ID);
    expect(out.cvv).toBe("");
    expect(out.ein).toBeNull();
    expect(out.taxIdRequired).toBe(true);
  });
});

describe("Presidio entities", () => {
  it("asks Presidio for the person types and every ID type", async () => {
    let body: { entities: string[] } | undefined;
    const analyze = createPresidioAnalyzer({
      baseUrl: "http://presidio.test:3000",
      fetchImpl: (async (_url: unknown, init?: RequestInit) => {
        body = JSON.parse(String(init?.body)) as { entities: string[] };
        return new Response(JSON.stringify([[]]), { status: 200 });
      }) as typeof fetch,
    });
    await analyze(["hello"]);
    expect(body?.entities).toEqual(DEFAULT_ENTITIES);
    for (const e of ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS", ...PRESIDIO_ID_ENTITIES]) {
      expect(body?.entities).toContain(e);
    }
    expect(PRESIDIO_ID_ENTITIES).toEqual(
      expect.arrayContaining(["CREDIT_CARD", "IBAN_CODE", "US_SSN", "US_ITIN", "US_PASSPORT"]),
    );
  });

  it("turns Presidio ID spans into the marker and drops low-score spans", async () => {
    const text = "Pat gave passport X1234567 and a second one Y7654321";
    const first = text.indexOf("X1234567");
    const second = text.indexOf("Y7654321");
    const analyzer: Analyzer = async () => [
      [
        { entityType: "US_PASSPORT", start: first, end: first + 8, score: 0.85 },
        { entityType: "US_PASSPORT", start: second, end: second + 8, score: 0.1 },
        { entityType: "PERSON", start: 0, end: 3, score: 0.9 },
      ],
    ];
    const out = await mask({ notes: text }, makeCtx(analyzer));
    expect(out.notes).toMatch(/^<PERSON_[0-9a-f]{10}> gave passport \[REDACTED: sensitive ID\] and a second one Y7654321$/);
  });

  it("ignores Presidio entity types we did not ask for", async () => {
    const analyzer: Analyzer = async () => [[{ entityType: "LOCATION", start: 0, end: 5, score: 0.99 }]];
    expect((await mask({ notes: "Paris is nice" }, makeCtx(analyzer))).notes).toBe("Paris is nice");
  });
});
