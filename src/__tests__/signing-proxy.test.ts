/**
 * The signing proxy (deploy/signing-proxy/proxy.mjs) run as a real process in
 * front of a stub upstream. Checks per-user tokens, the identity headers it
 * sets, spoof stripping, and startup refusals.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createServer, request as httpRequest, type IncomingHttpHeaders, type Server } from "node:http";
import { createServer as createNetServer } from "node:net";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { verifyS2sHeader } from "../s2s-verify.js";

const PROXY = fileURLToPath(new URL("../../deploy/signing-proxy/proxy.mjs", import.meta.url));
const S2S = "proxy-test-s2s-secret-0123456789";
const ALICE = "alice-token-0123456789abcdef0123456789abcdef";
const BOB = "bobby-token-0123456789abcdef0123456789abcdef";

const children: ChildProcess[] = [];
const servers: Server[] = [];

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createNetServer();
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as { port: number }).port;
      s.close(() => resolve(port));
    });
    s.on("error", reject);
  });
}

interface Upstream {
  port: number;
  seen: { method: string; path: string; headers: IncomingHttpHeaders }[];
}

type UpstreamReply = (req: { method: string; path: string }) => { status: number; headers?: Record<string, string> };

async function startUpstream(reply?: UpstreamReply): Promise<Upstream> {
  const port = await freePort();
  const seen: Upstream["seen"] = [];
  const server = createServer((req, res) => {
    const entry = { method: req.method ?? "", path: req.url ?? "", headers: req.headers };
    seen.push(entry);
    req.resume();
    req.on("end", () => {
      const r = reply?.(entry) ?? { status: 200 };
      res.writeHead(r.status, { "Content-Type": "application/json", ...r.headers });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((r) => server.listen(port, "127.0.0.1", () => r()));
  servers.push(server);
  return { port, seen };
}

interface Proxy {
  port: number;
  stderr: () => string;
}

async function startProxy(env: Record<string, string>, upstreamPort: number): Promise<Proxy> {
  const port = await freePort();
  const child = spawn(process.execPath, [PROXY], {
    env: { PATH: process.env.PATH ?? "", UPSTREAM_URL: `http://127.0.0.1:${upstreamPort}`, PORT: String(port), ...env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  children.push(child);
  let err = "";
  child.stderr!.on("data", (d) => (err += d));
  const deadline = Date.now() + 8000;
  while (!err.includes("listening")) {
    if (Date.now() > deadline) throw new Error(`proxy did not start: ${err}`);
    await new Promise((r) => setTimeout(r, 25));
  }
  return { port, stderr: () => err };
}

/** Start the proxy expecting it to refuse. Returns its exit code and stderr. */
function startExpectingExit(env: Record<string, string>): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [PROXY], {
      env: { PATH: process.env.PATH ?? "", PORT: "0", ...env },
      stdio: ["ignore", "ignore", "pipe"],
    });
    children.push(child);
    let err = "";
    child.stderr!.on("data", (d) => (err += d));
    child.on("exit", (code) => resolve({ code, stderr: err }));
  });
}

function send(
  port: number,
  opts: { method?: string; path?: string; headers?: Record<string, string> },
): Promise<{ status: number; body: string; headers: IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { hostname: "127.0.0.1", port, method: opts.method ?? "POST", path: opts.path ?? "/mcp", headers: opts.headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8"), headers: res.headers }),
        );
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    // Real clients send a body only with POST. A GET with a body is not a case to test.
    if ((opts.method ?? "POST") === "POST") req.end("{}");
    else req.end();
  });
}

const bearer = (t: string) => ({ authorization: `Bearer ${t}`, "content-type": "application/json" });

afterEach(async () => {
  for (const c of children.splice(0)) c.kill();
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(() => r(undefined)))));
});

describe("per-user tokens", () => {
  it("forwards with the caller's name, role and a valid S2S header, without the bearer token", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE}:write;bob:${BOB}` }, up.port);

    expect((await send(proxy.port, { headers: bearer(ALICE) })).status).toBe(200);
    expect((await send(proxy.port, { headers: bearer(BOB) })).status).toBe(200);

    const [a, b] = up.seen;
    expect(a!.path).toBe("/mcp");
    expect(a!.headers["x-mcp-user"]).toBe("alice");
    expect(a!.headers["x-mcp-role"]).toBe("write");
    expect(verifyS2sHeader(a!.headers["x-gateway-s2s"] as string, S2S)).toBe(true);
    expect(a!.headers.authorization).toBeUndefined();
    expect(b!.headers["x-mcp-user"]).toBe("bob");
    expect(b!.headers["x-mcp-role"]).toBeUndefined();
  });

  it("replaces any identity headers the client sends", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE}:read;bob:${BOB}` }, up.port);

    await send(proxy.port, { headers: { ...bearer(ALICE), "x-mcp-user": "root", "x-mcp-role": "admin", "X-MCP-Extra": "1" } });
    await send(proxy.port, { headers: { ...bearer(BOB), "x-mcp-role": "admin", "x-gateway-s2s": "t=1,v1=00" } });

    const [a, b] = up.seen;
    expect(a!.headers["x-mcp-user"]).toBe("alice");
    expect(a!.headers["x-mcp-role"]).toBe("read");
    expect(a!.headers["x-mcp-extra"]).toBeUndefined();
    expect(b!.headers["x-mcp-user"]).toBe("bob");
    expect(b!.headers["x-mcp-role"]).toBeUndefined();
    expect(verifyS2sHeader(b!.headers["x-gateway-s2s"] as string, S2S)).toBe(true);
  });

  it("rejects a missing, unknown or malformed token without calling the server", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE}` }, up.port);

    expect((await send(proxy.port, { headers: { "content-type": "application/json" } })).status).toBe(401);
    expect((await send(proxy.port, { headers: bearer("nope") })).status).toBe(401);
    expect((await send(proxy.port, { headers: bearer(ALICE + "x") })).status).toBe(401);
    expect((await send(proxy.port, { headers: { authorization: ALICE } })).status).toBe(401);
    expect(up.seen).toHaveLength(0);
  });

  it("only forwards POST /mcp and GET /health", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE}` }, up.port);

    expect((await send(proxy.port, { method: "GET", headers: bearer(ALICE) })).status).toBe(405);
    expect((await send(proxy.port, { path: "/other", headers: bearer(ALICE) })).status).toBe(404);
    expect((await send(proxy.port, { method: "GET", path: "/health" })).status).toBe(200);
    expect(up.seen.map((s) => s.path)).toEqual(["/health"]);
    // /health carries no caller identity.
    expect(up.seen[0]!.headers["x-mcp-user"]).toBeUndefined();
  });

  it("keeps tokens out of its log and logs the user name", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE}` }, up.port);
    await send(proxy.port, { headers: bearer(ALICE) });
    await send(proxy.port, { headers: bearer("wrong-token-0123456789abcdef0123456789") });
    // The finish event can land just after the response.
    await new Promise((r) => setTimeout(r, 100));
    const log = proxy.stderr();
    expect(log).toContain("POST /mcp 200 user=alice");
    expect(log).toContain("POST /mcp 401");
    expect(log).not.toContain(ALICE);
    expect(log).not.toContain(S2S);
    expect(log).not.toContain("wrong-token");
  });

  it("still accepts the older single PROXY_BEARER_TOKEN as user shared-token", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_BEARER_TOKEN: ALICE }, up.port);
    expect((await send(proxy.port, { headers: bearer(ALICE) })).status).toBe(200);
    expect(up.seen[0]!.headers["x-mcp-user"]).toBe("shared-token");
    expect(up.seen[0]!.headers["x-mcp-role"]).toBeUndefined();
    expect(proxy.stderr()).toContain("PROXY_BEARER_TOKEN is one token for everybody");
  });
});

describe("entra mode (PROXY_AUTH=entra)", () => {
  const JWT = "eyJhbGciOiJSUzI1NiJ9.fake-payload.fake-signature";

  it("starts with no users, and warns when user tokens are also set", async () => {
    const up = await startUpstream();
    const proxy = await startProxy(
      { CONDUIT_S2S_SECRET: S2S, PROXY_AUTH: "entra", PROXY_USERS: `alice:${ALICE}` },
      up.port,
    );
    expect(proxy.stderr()).toContain("auth entra");
    expect(proxy.stderr()).toContain("ignored when PROXY_AUTH=entra");
    expect(proxy.stderr()).not.toContain(ALICE);
  });

  it("passes the Authorization header through and adds the S2S header, with no identity headers", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_AUTH: "entra" }, up.port);

    const res = await send(proxy.port, {
      headers: {
        authorization: `Bearer ${JWT}`,
        "content-type": "application/json",
        "x-mcp-user": "root",
        "x-mcp-role": "admin",
      },
    });
    expect(res.status).toBe(200);
    const [seen] = up.seen;
    expect(seen!.path).toBe("/mcp");
    expect(seen!.headers.authorization).toBe(`Bearer ${JWT}`);
    expect(verifyS2sHeader(seen!.headers["x-gateway-s2s"] as string, S2S)).toBe(true);
    expect(seen!.headers["x-mcp-user"]).toBeUndefined();
    expect(seen!.headers["x-mcp-role"]).toBeUndefined();
  });

  it("forwards a request with no token so the server can answer 401 with its own WWW-Authenticate", async () => {
    const challenge = "Bearer resource_metadata=https://mcp.example.com/.well-known/oauth-protected-resource";
    const up = await startUpstream(() => ({ status: 401, headers: { "WWW-Authenticate": challenge } }));
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_AUTH: "entra" }, up.port);

    const res = await send(proxy.port, { headers: { "content-type": "application/json" } });
    expect(res.status).toBe(401);
    expect(res.headers["www-authenticate"]).toBe(challenge);
    expect(up.seen).toHaveLength(1);
  });

  it("forwards the five OAuth routes with their query string, without needing a token", async () => {
    const up = await startUpstream((r) =>
      r.path.startsWith("/authorize")
        ? { status: 302, headers: { Location: "https://login.microsoftonline.com/x/oauth2/v2.0/authorize?a=1" } }
        : { status: 200 },
    );
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_AUTH: "entra" }, up.port);

    expect((await send(proxy.port, { method: "GET", path: "/.well-known/oauth-protected-resource" })).status).toBe(200);
    expect((await send(proxy.port, { method: "GET", path: "/.well-known/oauth-authorization-server" })).status).toBe(200);
    expect(
      (await send(proxy.port, { method: "POST", path: "/register", headers: { "content-type": "application/json" } }))
        .status,
    ).toBe(200);
    expect(
      (
        await send(proxy.port, {
          method: "POST",
          path: "/token",
          headers: { "content-type": "application/x-www-form-urlencoded" },
        })
      ).status,
    ).toBe(200);
    const authz = await send(proxy.port, {
      method: "GET",
      path: "/authorize?response_type=code&client_id=abc&code_challenge=xyz&redirect_uri=http%3A%2F%2Flocalhost%3A1234%2Fcallback",
    });
    expect(authz.status).toBe(302);
    expect(authz.headers.location).toContain("login.microsoftonline.com");

    expect(up.seen.map((s) => `${s.method} ${s.path.split("?")[0]}`)).toEqual([
      "GET /.well-known/oauth-protected-resource",
      "GET /.well-known/oauth-authorization-server",
      "POST /register",
      "POST /token",
      "GET /authorize",
    ]);
    expect(up.seen[4]!.path).toContain("code_challenge=xyz&redirect_uri=http%3A%2F%2Flocalhost%3A1234%2Fcallback");
  });

  it("does not forward other paths or wrong methods on the OAuth routes", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_AUTH: "entra" }, up.port);

    expect((await send(proxy.port, { method: "GET", path: "/token" })).status).toBe(404);
    expect((await send(proxy.port, { method: "POST", path: "/authorize" })).status).toBe(404);
    expect((await send(proxy.port, { method: "GET", path: "/admin" })).status).toBe(404);
    expect((await send(proxy.port, { method: "GET", path: "/mcp" })).status).toBe(405);
    expect(up.seen).toHaveLength(0);
  });

  it("keeps the OAuth routes closed in tokens mode", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE}` }, up.port);
    expect((await send(proxy.port, { method: "GET", path: "/.well-known/oauth-protected-resource" })).status).toBe(404);
    expect((await send(proxy.port, { method: "POST", path: "/token" })).status).toBe(404);
    expect(up.seen).toHaveLength(0);
  });

  it("does not log tokens or query strings", async () => {
    const up = await startUpstream();
    const proxy = await startProxy({ CONDUIT_S2S_SECRET: S2S, PROXY_AUTH: "entra" }, up.port);
    await send(proxy.port, { headers: { authorization: `Bearer ${JWT}`, "content-type": "application/json" } });
    await send(proxy.port, { method: "GET", path: "/authorize?code_challenge=secret-challenge-value" });
    await new Promise((r) => setTimeout(r, 100));
    const log = proxy.stderr();
    expect(log).toContain("POST /mcp 200");
    expect(log).toContain("GET /authorize 200");
    expect(log).not.toContain(JWT);
    expect(log).not.toContain("secret-challenge-value");
  });

  it("refuses an unknown PROXY_AUTH value", async () => {
    const { code, stderr } = await startExpectingExit({ CONDUIT_S2S_SECRET: S2S, PROXY_AUTH: "oauth" });
    expect(code).toBe(1);
    expect(stderr).toMatch(/PROXY_AUTH/);
  });
});

describe("startup refusals", () => {
  const cases: [string, Record<string, string>, RegExp][] = [
    ["no S2S secret", { PROXY_USERS: `alice:${ALICE}` }, /CONDUIT_S2S_SECRET/],
    ["no users at all", { CONDUIT_S2S_SECRET: S2S }, /PROXY_USERS/],
    ["short token", { CONDUIT_S2S_SECRET: S2S, PROXY_USERS: "alice:short" }, /32 or more/],
    ["unknown role", { CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE}:root` }, /unknown role/],
    ["bad name", { CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `al ice:${ALICE}` }, /invalid name/],
    ["missing token", { CONDUIT_S2S_SECRET: S2S, PROXY_USERS: "alice" }, /name:token/],
    ["duplicate name", { CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE};alice:${BOB}` }, /unique/],
    ["duplicate token", { CONDUIT_S2S_SECRET: S2S, PROXY_USERS: `alice:${ALICE};bob:${ALICE}` }, /share one token/],
    ["short legacy token", { CONDUIT_S2S_SECRET: S2S, PROXY_BEARER_TOKEN: "short" }, /PROXY_BEARER_TOKEN/],
  ];

  it.each(cases)("refuses to start: %s", async (_name, env, message) => {
    const { code, stderr } = await startExpectingExit(env);
    expect(code).toBe(1);
    expect(stderr).toMatch(message);
    expect(stderr).not.toContain(ALICE);
    expect(stderr).not.toContain(BOB);
  });
});
