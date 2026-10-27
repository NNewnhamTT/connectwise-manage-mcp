/**
 * The OAuth proxy sends Entra the GUID form of the API scope.
 *
 * The MCP server and its OAuth client are one app registration, so Entra treats
 * every token request as a token for itself. It accepts that only when the
 * resource is written as the GUID app id. The api://<clientId> form fails with
 * AADSTS90009. These tests pin the scope the proxy sends on /authorize and
 * /token (code exchange and refresh) and the grant type in the rejection log.
 */

import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { entraScope, handleAuthorize, handleToken, safeGrantType } from "../auth/routes.js";
import type { EntraConfig } from "../auth/types.js";

const CLIENT_ID = "ab7d8f34-2d25-4390-9f8e-5487ecfb889e";
const config = { tenantId: "tenant-guid", clientId: CLIENT_ID } as EntraConfig;
const EXPECTED_SCOPE = `${CLIENT_ID}/access_as_user openid profile email offline_access`;

function fakeResponse() {
  const captured: { status?: number; headers?: Record<string, unknown>; body?: string } = {};
  const res = {
    writeHead(status: number, headers?: Record<string, unknown>) {
      captured.status = status;
      captured.headers = headers;
      return res;
    },
    end(body?: string) {
      captured.body = body;
    },
  } as unknown as ServerResponse;
  return { res, captured };
}

function formRequest(body: string): IncomingMessage {
  const req = new EventEmitter() as unknown as IncomingMessage;
  queueMicrotask(() => {
    (req as unknown as EventEmitter).emit("data", Buffer.from(body));
    (req as unknown as EventEmitter).emit("end");
  });
  return req;
}

describe("entraScope", () => {
  it("uses the GUID app id, never the api:// form", () => {
    expect(entraScope(config)).toBe(EXPECTED_SCOPE);
    expect(entraScope(config)).not.toContain("api://");
  });

  it("still asks for a refresh token", () => {
    expect(entraScope(config).split(" ")).toContain("offline_access");
  });
});

describe("handleAuthorize scope", () => {
  it("sends the GUID scope to Entra whatever scope the client asked for", () => {
    const { res, captured } = fakeResponse();
    const req = {
      url: `/authorize?response_type=code&scope=${encodeURIComponent(`api://${CLIENT_ID}/access_as_user`)}&state=s`,
      headers: { host: "mcp.example" },
    } as unknown as IncomingMessage;

    handleAuthorize(req, res, config);

    expect(captured.status).toBe(302);
    const location = new URL(String(captured.headers?.Location));
    expect(location.searchParams.get("scope")).toBe(EXPECTED_SCOPE);
    expect(location.searchParams.get("client_id")).toBe(CLIENT_ID);
  });
});

describe("handleToken scope", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ access_token: "x" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function sentParams(): URLSearchParams {
    return new URLSearchParams(String(fetchMock.mock.calls[0][1].body));
  }

  it("replaces a scope on a refresh request with the GUID scope", async () => {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "r",
      scope: `api://${CLIENT_ID}/access_as_user offline_access`,
    }).toString();

    await handleToken(formRequest(body), fakeResponse().res, config);

    expect(sentParams().get("scope")).toBe(EXPECTED_SCOPE);
    expect(sentParams().get("client_id")).toBe(CLIENT_ID);
  });

  it("adds no scope when the client sent none, so Entra reuses the original grant", async () => {
    const body = new URLSearchParams({ grant_type: "authorization_code", code: "c" }).toString();

    await handleToken(formRequest(body), fakeResponse().res, config);

    expect(sentParams().has("scope")).toBe(false);
  });

  it("drops the resource parameter", async () => {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: "r",
      resource: "https://mcp.example/mcp",
    }).toString();

    await handleToken(formRequest(body), fakeResponse().res, config);

    expect(sentParams().has("resource")).toBe(false);
  });
});

describe("rejection log grant type", () => {
  it.each([
    ["authorization_code", "authorization_code"],
    ["refresh_token", "refresh_token"],
    ["client_credentials", "other"],
    ["SECRET-VALUE", "other"],
    [null, "other"],
  ])("logs %s as %s", (input, expected) => {
    expect(safeGrantType(input)).toBe(expected);
  });

  it("logs a refresh rejection with the grant, status and error code only", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ error: "invalid_resource", error_description: "AADSTS90009 trace SECRET-TRACE" }),
          { status: 400 },
        ),
      ),
    );
    const { res, captured } = fakeResponse();

    await handleToken(formRequest("grant_type=refresh_token&refresh_token=SECRET-REFRESH"), res, config);

    expect(captured.status).toBe(400);
    expect(errorLog).toHaveBeenCalledTimes(1);
    const line = String(errorLog.mock.calls[0][0]);
    expect(JSON.parse(line)).toEqual({
      event: "token_exchange_rejected",
      grant: "refresh_token",
      status: 400,
      error: "invalid_resource",
    });
    expect(line).not.toContain("SECRET");
    expect(line).not.toContain("AADSTS90009");
    errorLog.mockRestore();
    vi.unstubAllGlobals();
  });
});
