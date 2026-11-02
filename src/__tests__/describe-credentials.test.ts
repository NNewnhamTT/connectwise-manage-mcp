import { describe, expect, it } from "vitest";
import { describeCredentialSetup } from "../guard/credentials.js";

// The startup summary must help diagnose a CW failure without ever exposing a key, the company ID or the client ID.
// All values below are made-up test strings.
const PUB = "pubkeyTESTVALUE12345";
const PRIV = "privkeyTESTVALUE67890";
const COMPANY = "testcompanyid";
const CLIENT = "00000000-1111-2222-3333-444444444444";

describe("describeCredentialSetup", () => {
  it("shared mode: reports presence and lengths, never a value", () => {
    const out = describeCredentialSetup({
      CW_MANAGE_PUBLIC_KEY: PUB,
      CW_MANAGE_PRIVATE_KEY: PRIV,
      CW_MANAGE_COMPANY_ID: COMPANY,
      CW_MANAGE_CLIENT_ID: CLIENT,
      CW_MANAGE_URL: "https://api-na.myconnectwise.net/",
    });
    for (const secret of [PUB, PRIV, COMPANY, CLIENT]) expect(out).not.toContain(secret);
    expect(out).toContain("mode shared");
    expect(out).toContain("https://api-na.myconnectwise.net");
    expect(out).toContain(`public present (length ${PUB.length})`);
    expect(out).toContain(`client id present (length ${CLIENT.length})`);
    expect(out).not.toContain("UNRESOLVED");
  });

  it("per-user mode: lists entry names only, never a key", () => {
    const out = describeCredentialSetup({
      CW_CREDENTIALS: "per-user",
      CW_USER_KEYS: `Test.User@example.com=${PUB}:${PRIV};other@example.com=${PUB}2:${PRIV}2`,
      CW_MANAGE_COMPANY_ID: COMPANY,
      CW_MANAGE_CLIENT_ID: CLIENT,
    });
    expect(out).toContain("mode per-user");
    expect(out).toContain("2 entries [test.user@example.com, other@example.com]");
    expect(out).toContain("shared key pair unused");
    expect(out).toContain("(default)");
    for (const secret of [PUB, PRIV, COMPANY, CLIENT]) expect(out).not.toContain(secret);
  });

  it("per-user mode: a bad entry is reported by position, without the key", () => {
    const out = describeCredentialSetup({
      CW_CREDENTIALS: "per-user",
      CW_USER_KEYS: `user@example.com=${PUB}`,
    });
    expect(out).toContain("does not parse");
    expect(out).toContain("entry 1 is invalid");
    expect(out).not.toContain(PUB);
  });

  it("flags an unresolved Key Vault reference by field name, without echoing it", () => {
    const ref = "@Microsoft.KeyVault(SecretUri=https://vault.example/secrets/x/)";
    const out = describeCredentialSetup({
      CW_CREDENTIALS: "per-user",
      CW_USER_KEYS: ref,
      CW_MANAGE_COMPANY_ID: ref,
      CW_MANAGE_CLIENT_ID: CLIENT,
    });
    expect(out).toContain("UNRESOLVED KEY VAULT REFERENCE in: CW_MANAGE_COMPANY_ID, CW_USER_KEYS");
    expect(out).not.toContain("vault.example");
  });

  it("reports MISSING settings and a bad mode", () => {
    expect(describeCredentialSetup({})).toContain("company id MISSING");
    expect(describeCredentialSetup({ CW_CREDENTIALS: "peruser" })).toContain("CW_CREDENTIALS is not 'shared' or 'per-user'");
  });
});
