// Signing proxy for the ConnectWise Manage MCP server.
//
// The server's /mcp route rejects any request without a valid X-Gateway-S2S
// header (t=<unix seconds>,v1=<hex hmac-sha256 of "t=<unix seconds>">). Claude
// clients cannot send that header. This proxy takes a plain bearer token from
// the client, checks it, adds the signed header and forwards the request.
//
// Settings (environment):
//   CONDUIT_S2S_SECRET   Same value the MCP server has. Required.
//   PROXY_BEARER_TOKEN   Token clients send as `Authorization: Bearer <token>`.
//                        Required, 32 or more characters.
//   UPSTREAM_URL         Default http://connectwise-manage-mcp:8080
//   PORT                 Default 8081
//
// Only POST /mcp (with the bearer token) and GET /health are forwarded.
// Nothing about a request body or a token is logged.
// No dependencies: runs on the node image as-is.

import { createServer, request as httpRequest } from "node:http";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const secret = (process.env.CONDUIT_S2S_SECRET ?? "").trim();
const token = (process.env.PROXY_BEARER_TOKEN ?? "").trim();
const upstream = new URL(process.env.UPSTREAM_URL || "http://connectwise-manage-mcp:8080");
const port = Number.parseInt(process.env.PORT || "8081", 10);

if (!secret) {
  console.error("Refusing to start: CONDUIT_S2S_SECRET is empty.");
  process.exit(1);
}
if (token.length < 32) {
  console.error("Refusing to start: PROXY_BEARER_TOKEN must be at least 32 characters.");
  process.exit(1);
}

const tokenDigest = createHash("sha256").update(token).digest();

function bearerOk(header) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const presented = createHash("sha256").update(header.slice(7)).digest();
  return timingSafeEqual(presented, tokenDigest);
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

const HOP_BY_HOP = new Set(["connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization"]);

function forward(req, res, path) {
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || lower === "authorization" || lower === "host" || lower === "x-gateway-s2s") continue;
    headers[name] = value;
  }
  headers["x-gateway-s2s"] = s2sHeader();

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
  let status = 0;
  res.on("finish", () => {
    status = res.statusCode;
    console.error(`${req.method} ${path} ${status}`);
  });

  if (req.method === "GET" && path === "/health") {
    forward(req, res, "/health");
    return;
  }
  if (path !== "/mcp") {
    reply(res, 404, { error: "not_found" });
    return;
  }
  if (!bearerOk(req.headers.authorization)) {
    res.writeHead(401, { "Content-Type": "application/json", "WWW-Authenticate": "Bearer" });
    res.end(JSON.stringify({ error: "unauthorized" }));
    return;
  }
  if (req.method !== "POST") {
    reply(res, 405, { error: "method_not_allowed" });
    return;
  }
  forward(req, res, "/mcp");
}).listen(port, "0.0.0.0", () => {
  console.error(`signing proxy listening on :${port}, upstream ${upstream.origin}`);
});
