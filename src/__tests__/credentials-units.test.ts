import { describe, it, expect } from "vitest";
import { loadCredentialSource } from "../guard/credentials.js";
import { ANONYMOUS, type Identity } from "../guard/identity.js";

const BASE = {
  CW_MANAGE_COMPANY_ID: "acme",
  CW_MANAGE_CLIENT_ID: "client-guid",
  CW_MANAGE_URL: "https://cw.example.com/",
};
const ALICE: Identity = { user: "alice@tektrendz.com", source: "entra" };

describe("loadCredentialSource: mode", () => {
  it("is off by default and when set to shared", () => {
    expect(loadCredentialSource({})).toBeUndefined();
    expect(loadCredentialSource({ ...BASE, CW_CREDENTIALS: "shared" })).toBeUndefined();
    expect(loadCredentialSource({ ...BASE, CW_CREDENTIALS: " SHARED " })).toBeUndefined();
  });

  it("rejects an unknown mode so a typo cannot fall back to the shared key", () => {
    expect(() => loadCredentialSource({ ...BASE, CW_CREDENTIALS: "peruser" })).toThrow(/CW_CREDENTIALS/);
    expect(() => loadCredentialSource({ ...BASE, CW_CREDENTIALS: "true" })).toThrow(/CW_CREDENTIALS/);
  });

  it("requires keys, a company id and a client id in per-user mode", () => {
    const keys = { CW_CREDENTIALS: "per-user", CW_USER_KEYS: "alice@tektrendz.com=PUB:PRIV" };
    expect(() => loadCredentialSource({ ...BASE, CW_CREDENTIALS: "per-user" })).toThrow(/CW_USER_KEYS/);
    expect(() => loadCredentialSource({ ...BASE, CW_CREDENTIALS: "per-user", CW_USER_KEYS: "  " })).toThrow(/CW_USER_KEYS/);
    expect(() => loadCredentialSource({ ...keys, CW_MANAGE_CLIENT_ID: "x" })).toThrow(/CW_MANAGE_COMPANY_ID/);
    expect(() => loadCredentialSource({ ...keys, CW_MANAGE_COMPANY_ID: "x" })).toThrow(/CW_MANAGE_CLIENT_ID/);
  });
});

describe("loadCredentialSource: per-user keys", () => {
  const env = {
    ...BASE,
    CW_CREDENTIALS: "per-user",
    CW_USER_KEYS: "alice@tektrendz.com=PUBA:PRIVA;bob@tektrendz.com=PUBB:PRIVB",
    // The shared keys must never be used in this mode.
    CW_MANAGE_PUBLIC_KEY: "shared-pub",
    CW_MANAGE_PRIVATE_KEY: "shared-priv",
  };

  it("returns the config for the caller's own key, with the shared company, client id and url", () => {
    const source = loadCredentialSource(env)!;
    expect(source.configFor(ALICE)).toEqual({
      baseUrl: "https://cw.example.com",
      companyId: "acme",
      publicKey: "PUBA",
      privateKey: "PRIVA",
      clientId: "client-guid",
    });
    expect(source.configFor({ user: "bob@tektrendz.com", source: "proxy" })?.publicKey).toBe("PUBB");
  });

  it("never returns the shared keys", () => {
    const source = loadCredentialSource(env)!;
    const all = JSON.stringify([source.configFor(ALICE), source.withoutKeys()]);
    expect(all).not.toContain("shared-pub");
    expect(all).not.toContain("shared-priv");
  });

  it("matches the name without regard to case", () => {
    const source = loadCredentialSource(env)!;
    expect(source.configFor({ user: "Alice@TekTrendz.com", source: "entra" })?.publicKey).toBe("PUBA");
  });

  it("has no config for an unknown person or an anonymous caller", () => {
    const source = loadCredentialSource(env)!;
    expect(source.configFor({ user: "carol@tektrendz.com", source: "entra" })).toBeUndefined();
    expect(source.configFor(ANONYMOUS)).toBeUndefined();
    expect(source.configFor({ user: "cli-user", source: "static-token" })).toBeUndefined();
  });

  it("accepts newlines as well as semicolons, and the default cloud url", () => {
    const source = loadCredentialSource({
      CW_MANAGE_COMPANY_ID: "acme",
      CW_MANAGE_CLIENT_ID: "cid",
      CW_CREDENTIALS: "per-user",
      CW_USER_KEYS: "alice=PUBA:PRIVA\nbob=PUBB:PRIVB\n",
    })!;
    expect(source.configFor({ user: "bob", source: "proxy" })?.privateKey).toBe("PRIVB");
    expect(source.withoutKeys().baseUrl).toBe("https://api-na.myconnectwise.net");
  });

  it("gives a keyless config for a server that refuses every call", () => {
    const keyless = loadCredentialSource(env)!.withoutKeys();
    expect(keyless).toMatchObject({ companyId: "acme", clientId: "client-guid", publicKey: "", privateKey: "" });
  });
});

describe("loadCredentialSource: bad entries", () => {
  const withKeys = (keys: string) => ({ ...BASE, CW_CREDENTIALS: "per-user", CW_USER_KEYS: keys });

  it.each([
    ["no equals sign", "alicePUBA:PRIVA"],
    ["no colon in the key pair", "alice=PUBAPRIVA"],
    ["empty public key", "alice=:PRIVA"],
    ["empty private key", "alice=PUBA:"],
    ["extra colon", "alice=PUBA:PRIV:A"],
    ["space in a key", "alice=PU BA:PRIVA"],
    ["bad name", "al ice=PUBA:PRIVA"],
    ["empty name", "=PUBA:PRIVA"],
    ["duplicate name, any case", "alice=PUBA:PRIVA;ALICE=PUBB:PRIVB"],
  ])("throws for %s, without echoing the keys", (_label, entry) => {
    let message = "";
    try {
      loadCredentialSource(withKeys(entry));
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/CW_USER_KEYS/);
    for (const secret of ["PUBA", "PRIVA", "PUBB", "PRIVB"]) expect(message).not.toContain(secret);
  });
});
