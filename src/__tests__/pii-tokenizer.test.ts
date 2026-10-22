import { describe, it, expect } from "vitest";
import { createTokenizer, TOKEN_PATTERN } from "../pii/tokenizer.js";
import { MemoryTokenStore } from "../pii/store.js";

const KEY = "test-key-not-a-secret";

describe("tokenizer", () => {
  it("returns the same token for the same value and type", () => {
    const t = createTokenizer(KEY);
    expect(t.token("PERSON", "Jane Doe")).toBe(t.token("PERSON", "Jane Doe"));
  });

  it("is stable across tokenizer instances with the same key", () => {
    expect(createTokenizer(KEY).token("EMAIL", "a@b.com")).toBe(
      createTokenizer(KEY).token("EMAIL", "a@b.com"),
    );
  });

  it("differs by value, by type and by key", () => {
    const t = createTokenizer(KEY);
    expect(t.token("PERSON", "Jane Doe")).not.toBe(t.token("PERSON", "John Doe"));
    expect(t.token("PERSON", "x")).not.toBe(t.token("EMAIL", "x"));
    expect(createTokenizer("another-test-key-0000").token("PERSON", "Jane Doe")).not.toBe(
      t.token("PERSON", "Jane Doe"),
    );
  });

  it("emits a token that matches TOKEN_PATTERN and hides the value", () => {
    const token = createTokenizer(KEY).token("PERSON", "Jane Doe");
    expect(token).toMatch(/^<PERSON_[0-9a-f]{10}>$/);
    expect(token).not.toContain("Jane");
    expect(`say ${token} hi`.match(TOKEN_PATTERN)).toEqual([token]);
  });

  it("rejects an empty or short key", () => {
    expect(() => createTokenizer("")).toThrow();
    expect(() => createTokenizer("short")).toThrow();
  });
});

describe("MemoryTokenStore", () => {
  it("stores and returns a value per tenant", async () => {
    const s = new MemoryTokenStore();
    await s.put("t1", "<PERSON_aaaaaaaaaa>", "Jane Doe", 60);
    expect(await s.get("t1", "<PERSON_aaaaaaaaaa>")).toBe("Jane Doe");
    expect(await s.get("t2", "<PERSON_aaaaaaaaaa>")).toBeUndefined();
  });

  it("expires entries after the ttl", async () => {
    let now = 1_000;
    const s = new MemoryTokenStore({ now: () => now });
    await s.put("t1", "<PERSON_aaaaaaaaaa>", "Jane Doe", 10);
    now += 9_999;
    expect(await s.get("t1", "<PERSON_aaaaaaaaaa>")).toBe("Jane Doe");
    now += 2;
    expect(await s.get("t1", "<PERSON_aaaaaaaaaa>")).toBeUndefined();
  });

  it("refreshes the ttl when the same token is put again", async () => {
    let now = 0;
    const s = new MemoryTokenStore({ now: () => now });
    await s.put("t1", "<PERSON_aaaaaaaaaa>", "Jane Doe", 10);
    now += 8_000;
    await s.put("t1", "<PERSON_aaaaaaaaaa>", "Jane Doe", 10);
    now += 8_000;
    expect(await s.get("t1", "<PERSON_aaaaaaaaaa>")).toBe("Jane Doe");
  });

  it("refuses to overwrite a token with a different value", async () => {
    const s = new MemoryTokenStore();
    await s.put("t1", "<PERSON_aaaaaaaaaa>", "Jane Doe", 60);
    await expect(s.put("t1", "<PERSON_aaaaaaaaaa>", "John Doe", 60)).rejects.toThrow(/collision/i);
    expect(await s.get("t1", "<PERSON_aaaaaaaaaa>")).toBe("Jane Doe");
  });

  it("evicts the oldest entry when over the size cap", async () => {
    const s = new MemoryTokenStore({ maxEntries: 2 });
    await s.put("t", "<PERSON_0000000001>", "a", 60);
    await s.put("t", "<PERSON_0000000002>", "b", 60);
    await s.put("t", "<PERSON_0000000003>", "c", 60);
    expect(await s.get("t", "<PERSON_0000000001>")).toBeUndefined();
    expect(await s.get("t", "<PERSON_0000000003>")).toBe("c");
  });
});
