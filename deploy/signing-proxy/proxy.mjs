// Signing proxy for the ConnectWise Manage MCP server.
//
// The server's /mcp route rejects any request without a valid X-Gateway-S2S
// header (t=<unix seconds>,v1=<hex hmac-sha256 of "t=<unix seconds>">). Claude
// clients cannot send that header. This proxy takes a per-user bearer token
// from the client, checks it, adds the signed header plus the caller's name
// and access level, and forwards the request.
//
// Settings (environment):
//   CONDUIT_S2S_SECRET   Same value the MCP server has. Required.
//   PROXY_USERS          One entry per person: name:token[:role], separated by
//                        ";" or newlines. token: 32+ characters, no ":" or
//                        spaces. role: read | write | admin (optional; without
//                        one the server's MCP_POLICY default applies).
//                        Example: alice:<token>:write;bob:<token>
//   PROXY_BEARER_TOKEN   Older single shared token (32+ characters). Still
//                        accepted, logged as user "shared-token". Not per-user.
//   PROXY_AUTH           tokens (default) or entra. In entra mode people sign in
//                        with Microsoft Entra ID (the server validates the token and
//                        names the user from it). The proxy then does no sign-in of
//                        its own: PROXY_USERS and PROXY_BEARER_TOKEN are ignored, the
//                        client's Authorization header is passed through, and the
//                        server's OAuth routes (/.well-known/oauth-protected-resource,
//                        /.well-known/oauth-authorization-server, /register,
//                        /authorize, /token) are forwarded too.
//   UPSTREAM_URL         Default http://connectwise-manage-mcp:8080
//   PORT                 Default 8081
//
// In tokens mode clients send `Authorization: Bearer <their token>`. The proxy sets
// X-Mcp-User and X-Mcp-Role itself and removes any X-Mcp-* header the client
// sent, so a caller cannot name itself or raise its own access. The server
// trusts those two headers only because the S2S header verified.
//
// In both modes the proxy removes every X-Mcp-* header the client sent. In entra
// mode it sets none, so the only identity is the one the server validates.
//
// Only POST /mcp (tokens mode: with a known token) and GET /health are forwarded,
// plus the five OAuth routes in entra mode. Tokens,
// request bodies and responses are never logged. The log shows method, path,
// status and user name. No dependencies: runs on the node image as-is.

import { createServer, request as httpRequest } from "node:http";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const secret = (process.env.CONDUIT_S2S_SECRET ?? "").trim();
const upstream = new URL(process.env.UPSTREAM_URL || "http://connectwise-manage-mcp:8080");
const port = Number.parseInt(process.env.PORT || "8081", 10);

const NAME_RE = /^[A-Za-z0-9._@+-]{1,100}$/;
const ROLES = new Set(["read", "write", "admin"]);

function fail(message) {
  console.error(`Refusing to start: ${message}`);
  process.exit(1);
}

function parseUsers() {
  const users = [];
  const entries = (process.env.PROXY_USERS ?? "")
    .split(/[;\n\r]+/)
    .map((e) => e.trim())
    .filter(Boolean);
  entries.forEach((entry, i) => {
    // Never echo an entry: it contains a token.
    const parts = entry.split(":");
    if (parts.length < 2 || parts.length > 3) fail(`PROXY_USERS entry ${i + 1} must be name:token[:role].`);
    const [name, token, role] = parts.map((p) => p.trim());
    if (!NAME_RE.test(name)) fail(`PROXY_USERS entry ${i + 1} has an invalid name.`);
    if (token.length < 32) fail(`PROXY_USERS entry ${i + 1} (${name}) needs a token of 32 or more characters.`);
    if (role !== undefined && role !== "" && !ROLES.has(role)) {
      fail(`PROXY_USERS entry ${i + 1} (${name}) has an unknown role. Use read, write or admin.`);
    }
    users.push({ name, token, role: role || undefined });
  });

  const legacy = (process.env.PROXY_BEARER_TOKEN ?? "").trim();
  if (legacy) {
    if (legacy.length < 32) fail("PROXY_BEARER_TOKEN must be at least 32 characters.");
    users.push({ name: "shared-token", token: legacy, role: undefined });
    console.error("warning: PROXY_BEARER_TOKEN is one token for everybody. Use PROXY_USERS for per-user names in the audit log.");
  }

  const names = new Set();
  const digests = new Set();
  for (const u of users) {
    u.digest = createHash("sha256").update(u.token).digest();
    delete u.token;
    const key = u.digest.toString("hex");
    if (names.has(u.name)) fail(`PROXY_USERS names must be unique (duplicate: ${u.name}).`);
    if (digests.has(key)) fail(`Two users share one token (${u.name}). Every token must be unique.`);
    names.add(u.name);
    digests.add(key);
  }
  return users;
}

if (!secret) fail("CONDUIT_S2S_SECRET is empty.");
const authMode = (process.env.PROXY_AUTH ?? "tokens").trim().toLowerCase();
if (authMode !== "tokens" && authMode !== "entra") fail("PROXY_AUTH must be 'tokens' or 'entra'.");
const entra = authMode === "entra";

let users = [];
if (entra) {
  if ((process.env.PROXY_USERS ?? "").trim() || (process.env.PROXY_BEARER_TOKEN ?? "").trim()) {
    console.error("warning: PROXY_USERS and PROXY_BEARER_TOKEN are ignored when PROXY_AUTH=entra.");
  }
} else {
  users = parseUsers();
  if (users.length === 0) fail("set PROXY_USERS (name:token[:role];...) or PROXY_BEARER_TOKEN.");
}

/** The user whose token matches, or null. Compares every user, no early exit. */
function userForHeader(header) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return null;
  const presented = createHash("sha256").update(header.slice(7)).digest();
  let match = null;
  for (const u of users) {
    if (timingSafeEqual(presented, u.digest)) match = u;
  }
  return match;
}

function s2sHeader() {
  const t = Math.floor(Date.now() / 1000);
  const v1 = createHmac("sha256", secret).update(`t=${t}`).digest("hex");
  return `t=${t},v1=${v1}`;
}

function reply(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

/** The server's OAuth routes. Forwarded without sign-in in entra mode. */
const OAUTH_ROUTES = new Set([
  "GET /.well-known/oauth-protected-resource",
  "GET /.well-known/oauth-authorization-server",
  "POST /register",
  "GET /authorize",
  "POST /token",
]);

const HOP_BY_HOP = new Set(["connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization"]);

// path may include a query string (the OAuth routes need it). keepAuth passes
// the client's Authorization header on (entra mode: the server validates it).
function forward(req, res, path, user, keepAuth = false) {
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || lower === "host" || lower === "x-gateway-s2s") continue;
    if (lower === "authorization" && !keepAuth) continue;
    if (lower.startsWith("x-mcp-")) continue; // identity is ours to set, never the client's
    headers[name] = value;
  }
  headers["x-gateway-s2s"] = s2sHeader();
  if (user) {
    headers["x-mcp-user"] = user.name;
    if (user.role) headers["x-mcp-role"] = user.role;
  }

  const up = httpRequest(
    {
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port || 80,
      method: req.method,
      path,
      headers,
      timeout: 120_000,
    },
    (upRes) => {
      res.writeHead(upRes.statusCode ?? 502, upRes.headers);
      upRes.pipe(res);
    },
  );
  up.on("timeout", () => up.destroy(new Error("upstream timeout")));
  up.on("error", () => {
    if (!res.headersSent) reply(res, 502, { error: "bad_gateway" });
    else res.destroy();
  });
  req.pipe(up);
}

createServer((req, res) => {
  const path = (req.url || "").split("?")[0];
  let who = "";
  res.on("finish", () => {
    console.error(`${req.method} ${path} ${res.statusCode}${who}`);
  });

  if (req.method === "GET" && path === "/health") {
    forward(req, res, "/health", null);
    return;
  }
  if (entra && OAUTH_ROUTES.has(`${req.method} ${path}`)) {
    forward(req, res, req.url, null, true);
    return;
  }
  // Early answers below never read the request body. Drain it so the client
  // gets the status line instead of a reset connection.
  if (path !== "/mcp") {
    req.resume();
    reply(res, 404, { error: "not_found" });
    return;
  }
  if (entra) {
    // The server checks the Entra token and answers 401 with its own
    // WWW-Authenticate header, which the client needs to start sign-in.
    if (req.method !== "POST") {
      req.resume();
      reply(res, 405, { error: "method_not_allowed" });
      return;
    }
    forward(req, res, "/mcp", null, true);
    return;
  }
  const user = userForHeader(req.headers.authorization);
  if (!user) {
    req.resume();
    res.writeHead(401, { "Content-Type": "application/json", "WWW-Authenticate": "Bearer" });
    res.end(JSON.stringify({ error: "unauthorized" }));
    return;
  }
  who = ` user=${user.name}`;
  if (req.method !== "POST") {
    req.resume();
    reply(res, 405, { error: "method_not_allowed" });
    return;
  }
  forward(req, res, "/mcp", user);
}).listen(port, "0.0.0.0", () => {
  console.error(`signing proxy listening on :${port}, upstream ${upstream.origin}, ${entra ? "auth entra" : `${users.length} user(s)`}`);
});
