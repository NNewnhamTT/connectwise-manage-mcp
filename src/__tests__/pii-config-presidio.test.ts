import { describe, it, expect, vi } from "vitest";
import { loadPiiConfig } from "../pii/config.js";
import { createPresidioAnalyzer } from "../pii/presidio-client.js";

describe("loadPiiConfig", () => {
  it("is off by default and when set to off", () => {
    expect(loadPiiConfig({})).toBeUndefined();
    expect(loadPiiConfig({ PII_MODE: "off", PII_KEY: "x" })).toBeUndefined();
  });

  it("reads settings with defaults", () => {
    const c = loadPiiConfig({ PII_MODE: "ON", PII_KEY: "0123456789abcdef" });
    expect(c).toEqual({
      key: "0123456789abcdef",
      presidioUrl: undefined,
      presidioTimeoutMs: 5000,
      ttlSeconds: 86400,
      scoreThreshold: 0.4,
    });
  });

  it("rejects an unknown mode so a typo cannot disable masking", () => {
    expect(() => loadPiiConfig({ PII_MODE: "true", PII_KEY: "0123456789abcdef" })).toThrow(/PII_MODE/);
  });

  it("requires a long enough key when on, and does not echo it", () => {
    expect(() => loadPiiConfig({ PII_MODE: "on" })).toThrow(/PII_KEY/);
    try {
      loadPiiConfig({ PII_MODE: "on", PII_KEY: "shortkey" });
    } catch (e) {
      expect((e as Error).message).not.toContain("shortkey");
    }
  });

  it("validates the analyzer url and numbers", () => {
    const base = { PII_MODE: "on", PII_KEY: "0123456789abcdef" };
    expect(() => loadPiiConfig({ ...base, PII_PRESIDIO_URL: "presidio:3000" })).toThrow(/PII_PRESIDIO_URL/);
    expect(() => loadPiiConfig({ ...base, PII_TTL_SECONDS: "-1" })).toThrow(/PII_TTL_SECONDS/);
    expect(() => loadPiiConfig({ ...base, PII_SCORE_THRESHOLD: "abc" })).toThrow(/PII_SCORE_THRESHOLD/);
  });
});

describe("createPresidioAnalyzer", () => {
  const spans = [[{ entity_type: "PERSON", start: 0, end: 4, score: 0.9, analysis_explanation: null }], []];

  it("posts all texts in one request and maps the result", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(spans), { status: 200 }));
    const analyze = createPresidioAnalyzer({ baseUrl: "http://presidio:3000/", fetchImpl });
    const out = await analyze(["Jane called", "nothing here"]);
    expect(out).toEqual([[{ entityType: "PERSON", start: 0, end: 4, score: 0.9 }], []]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://presidio:3000/analyze");
    const body = JSON.parse(init.body as string);
    expect(body.text).toEqual(["Jane called", "nothing here"]);
    expect(body.language).toBe("en");
    expect(body.entities).toContain("PERSON");
  });

  it("makes no request for an empty list", async () => {
    const fetchImpl = vi.fn();
    const analyze = createPresidioAnalyzer({ baseUrl: "http://p", fetchImpl });
    expect(await analyze([])).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("throws on a non-2xx status without leaking the body", async () => {
    const fetchImpl = vi.fn(async () => new Response("secret Jane Doe", { status: 500 }));
    const analyze = createPresidioAnalyzer({ baseUrl: "http://p", fetchImpl });
    await expect(analyze(["x"])).rejects.toThrow("HTTP 500");
    await expect(analyze(["x"])).rejects.not.toThrow(/Jane/);
  });

  it("throws when the result count does not match", async () => {
    const fetchImpl = vi.fn(async () => new Response("[[]]", { status: 200 }));
    const analyze = createPresidioAnalyzer({ baseUrl: "http://p", fetchImpl });
    await expect(analyze(["a", "b"])).rejects.toThrow(/unexpected result shape/);
  });
});
