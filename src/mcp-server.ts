/**
 * Shared MCP server factory for ConnectWise Manage.
 *
 * This module is **side-effect free** (importing it never starts a transport),
 * so it can be reused by every entrypoint:
 * - `index.ts`  — stdio + Node HTTP transport
 * - `worker.ts` — Cloudflare Workers (Web Standard) transport
 *
 * Credentials are resolved per request, in order:
 * 1. An explicit `CwManageConfig` override (gateway mode / Workers headers).
 * 2. `getConfig()` reading from `process.env` (env mode).
 *
 * `tools/list` and `initialize` work without credentials; when no config is
 * available, only a single diagnostic `cw_test_connection` tool is registered,
 * so credential-requiring calls fail with a clear, graceful message.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { getConfig, CwManageClient, type CwManageConfig } from "./api-client.js";
import { registerCardResources } from "./resources.js";
import { loadPiiConfig, createPiiContext, withPii } from "./pii/index.js";
import { loadGuardConfig, withGuard } from "./guard/wrap-guard.js";
import { loadCredentialSource } from "./guard/credentials.js";
import { ANONYMOUS, type Identity } from "./guard/identity.js";
import { registerTicketTools } from "./tools/tickets.js";
import { registerCompanyTools } from "./tools/companies.js";
import { registerContactTools } from "./tools/contacts.js";
import { registerProjectTools } from "./tools/projects.js";
import { registerTimeEntryTools } from "./tools/time-entries.js";
import { registerScheduleTools } from "./tools/schedule.js";
import { registerMemberTools } from "./tools/members.js";
import { registerConfigurationTools } from "./tools/configurations.js";
import { registerServiceTools } from "./tools/service.js";
import { registerActivityTools } from "./tools/activities.js";
import { registerCatalogTools } from "./tools/catalog.js";
import { registerProcurementTools } from "./tools/procurement.js";
import { registerHealthTools } from "./tools/health.js";
import { registerAgreementTools } from "./tools/agreements.js";
import { registerOpportunityTools } from "./tools/opportunities.js";
import { registerFinanceProcurementTools } from "./tools/finance-procurement.js";

export type { CwManageConfig };

/**
 * Build a validated CwManageConfig from raw values.
 * Returns `{ config }` on success or `{ error }` when required fields are
 * missing. Shared by every transport (Node HTTP headers, Workers headers).
 */
export function buildConfig(
  companyId: string | undefined,
  publicKey: string | undefined,
  privateKey: string | undefined,
  clientId: string | undefined,
  baseUrl?: string,
): { config?: CwManageConfig; error?: string } {
  if (!companyId || !publicKey || !privateKey || !clientId) {
    return {
      error:
        "Missing credentials: X-CW-Company-Id, X-CW-Public-Key, X-CW-Private-Key, X-CW-Client-Id (or CW_MANAGE_* environment variables)",
    };
  }

  const resolvedBaseUrl = (
    baseUrl || "https://api-na.myconnectwise.net"
  ).replace(/\/+$/, "");

  return {
    config: {
      baseUrl: resolvedBaseUrl,
      companyId,
      publicKey,
      privateKey,
      clientId,
    },
  };
}

/**
 * Resolve per-request gateway credentials from a header accessor.
 *
 * Works with any transport: pass a getter that returns a (lowercased) header
 * value. Returns `{ config }` on success, or `{ error }` when required headers
 * are missing.
 */
export function resolveGatewayConfig(
  getHeader: (lowerName: string) => string | undefined,
): { config?: CwManageConfig; error?: string } {
  const result = buildConfig(
    getHeader("x-cw-company-id"),
    getHeader("x-cw-public-key"),
    getHeader("x-cw-private-key"),
    getHeader("x-cw-client-id"),
    getHeader("x-cw-url"),
  );
  // The caller picks this URL, so the client checks it before every request.
  if (result.config && getHeader("x-cw-url")) {
    result.config.untrustedBaseUrl = true;
  }
  return result;
}

/**
 * Create a fresh MCP server instance with all handlers registered.
 * Called once for stdio, or per-request for HTTP / Workers transports.
 *
 * @param configOverride - Optional config (gateway mode / Workers headers).
 *   When provided, the client is built from it instead of reading process.env.
 */
export function createMcpServer(
  configOverride?: CwManageConfig,
  options: { identity?: Identity } = {},
): McpServer {
  const server = new McpServer(
    {
      name: "connectwise-manage-mcp",
      version: "1.4.0",
    },
    {
      capabilities: {
        extensions: {
          "io.modelcontextprotocol/ui": {},
        },
      },
    }
  );

  // Throws on a bad PII_* setting, so a misconfigured server fails closed
  // instead of serving unmasked data.
  const piiConfig = loadPiiConfig();
  // Same rule for MCP_AUDIT / MCP_POLICY: a bad value stops the server.
  const guardConfig = loadGuardConfig();
  // CW_CREDENTIALS=per-user: each person's own CW key. A bad value stops the
  // server, so a typo cannot fall back to the shared key.
  const credentialSource = loadCredentialSource();
  if (credentialSource && configOverride) {
    // Gateway mode takes the key from the client. That cannot mix with keys held here.
    throw new Error("CW_CREDENTIALS=per-user cannot be combined with credentials supplied by the client (AUTH_MODE=gateway)");
  }
  const identity = options.identity ?? ANONYMOUS;

  // MCP Apps (SEP-1865): the ui:// ticket card is static embedded HTML, so it
  // is served with or without credentials (hosts may prefetch it). It is
  // skipped when PII masking is on: the card would show real values.
  if (!piiConfig) registerCardResources(server);

  let config = configOverride ?? getConfig();
  let blocked: { reason: string; message: string } | undefined;
  if (credentialSource) {
    // Never the shared key. A person with no key on file gets a server that refuses every call.
    config = credentialSource.configFor(identity) ?? null;
    if (!config) {
      config = credentialSource.withoutKeys();
      blocked = {
        reason: "no-cw-key",
        message:
          `No ConnectWise key is on file for "${identity.user}". Ask an administrator to add one. ` +
          "Nothing was sent to ConnectWise.",
      };
    }
  }

  if (!config) {
    // Register a single diagnostic tool so the client gets a clear error
    server.tool(
      "cw_test_connection",
      "Test the connection to ConnectWise Manage.",
      {},
      async () => ({
        content: [
          {
            type: "text",
            text: [
              "Error: Missing ConnectWise Manage credentials.",
              "",
              "Required environment variables:",
              "  CW_MANAGE_COMPANY_ID        - Your ConnectWise company identifier",
              "  CW_MANAGE_PUBLIC_KEY        - API member public key",
              "  CW_MANAGE_PRIVATE_KEY       - API member private key",
              "  CW_MANAGE_CLIENT_ID         - Client ID from ConnectWise Developer Portal",
              "",
              "Optional:",
              "  CW_MANAGE_URL               - API base URL",
              "    Cloud:       https://api-na.myconnectwise.net (default)",
              "                 https://api-eu.myconnectwise.net",
              "                 https://api-au.myconnectwise.net",
              "    Self-hosted: https://cwm.yourcompany.com",
              "  CW_MANAGE_REJECT_UNAUTHORIZED - Set to 'false' for self-signed certs",
            ].join("\n"),
          },
        ],
        isError: true,
      }),
    );
    return server;
  }

  const client = new CwManageClient(config);

  // Both wrappers must run before any tool is registered: they wrap
  // server.tool/registerTool. The one applied first ends up outermost, so the
  // guard goes first. It then sees Claude's arguments with PII tokens (never
  // real values), a denied call stops before any unmasking, and the audit line
  // is written after masking.
  if (guardConfig || blocked) {
    withGuard(server, {
      identity,
      config: guardConfig ?? { audit: false },
      credentials: credentialSource ? "per-user" : "shared",
      blocked,
    });
  }
  if (piiConfig) {
    withPii(server, createPiiContext(piiConfig, `${config.companyId}:${config.publicKey}`));
  }

  registerTicketTools(server, client);
  registerCompanyTools(server, client);
  registerContactTools(server, client);
  registerProjectTools(server, client);
  registerTimeEntryTools(server, client);
  registerScheduleTools(server, client);
  registerMemberTools(server, client);
  registerConfigurationTools(server, client);
  registerServiceTools(server, client);
  registerActivityTools(server, client);
  registerCatalogTools(server, client);
  registerProcurementTools(server, client);
  registerHealthTools(server, client);
  registerAgreementTools(server, client);
  registerOpportunityTools(server, client);
  registerFinanceProcurementTools(server, client);

  return server;
}
