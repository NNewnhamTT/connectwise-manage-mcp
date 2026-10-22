/**
 * Add PII masking to every tool of an McpServer without editing the tools.
 *
 * `withPii` replaces `server.tool` and `server.registerTool` on the instance.
 * Each handler registered afterwards runs as:
 *
 *   args -> unmask tokens -> original handler -> mask result
 *
 * Call it before any tool is registered. It is the one chokepoint for all
 * tools, so a tool added later is covered with no change.
 *
 * Masked output: every text block, `structuredContent`, and the message of a
 * thrown error. The ticket card payload (`_card`) is removed because the card
 * would show real values to the host.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { maskJson, unmaskDeep, type PiiContext } from "./mask-json.js";

type Handler = (...args: unknown[]) => unknown;

interface ToolResult {
  content?: { type: string; text?: string }[];
  structuredContent?: unknown;
  [key: string]: unknown;
}

function looksLikeJson(text: string): boolean {
  const t = text.trimStart();
  return t.startsWith("{") || t.startsWith("[");
}

async function maskText(text: string, ctx: PiiContext): Promise<string> {
  if (looksLikeJson(text)) {
    try {
      return JSON.stringify(await maskJson(JSON.parse(text), ctx), null, 2);
    } catch {
      // Not valid JSON after all: treat it as plain text below.
    }
  }
  return (await maskJson(text, ctx)) as string;
}

async function maskResult(result: unknown, ctx: PiiContext): Promise<unknown> {
  if (result === null || typeof result !== "object") return result;
  const r = result as ToolResult;
  const out: ToolResult = { ...r };

  if (Array.isArray(r.content)) {
    out.content = await Promise.all(
      r.content.map(async (block) =>
        block.type === "text" && typeof block.text === "string"
          ? { ...block, text: await maskText(block.text, ctx) }
          : block,
      ),
    );
  }
  if (r.structuredContent !== undefined) {
    const { _card: _dropped, ...rest } = (r.structuredContent ?? {}) as Record<string, unknown>;
    out.structuredContent = await maskJson(rest, ctx);
  }
  return out;
}

function wrapHandler(handler: Handler, hasArgs: boolean, ctx: PiiContext): Handler {
  return async (...a: unknown[]) => {
    if (hasArgs) {
      const { value, unknownTokens } = await unmaskDeep(a[0], ctx);
      if (unknownTokens.length > 0) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text:
                `Unknown or expired PII token(s): ${unknownTokens.join(", ")}. ` +
                "Fetch the record again to get current tokens. The call was not sent to ConnectWise.",
            },
          ],
        };
      }
      a[0] = value;
    }
    let result: unknown;
    try {
      result = await handler(...a);
    } catch (err) {
      // An error message can echo field values. Mask it before the SDK returns it.
      const message = err instanceof Error ? err.message : String(err);
      // No `cause`: the original error carries the unmasked message.
      // eslint-disable-next-line preserve-caught-error
      throw new Error(await maskText(message, ctx));
    }
    return maskResult(result, ctx);
  };
}

/** Remove the MCP Apps card link: the card cannot show masked data. */
function stripCardMeta(config: Record<string, unknown>): Record<string, unknown> {
  const meta = config._meta as Record<string, unknown> | undefined;
  if (!meta) return config;
  const { ui: _ui, "ui/resourceUri": _uri, ...rest } = meta;
  const out = { ...config };
  if (Object.keys(rest).length > 0) out._meta = rest;
  else delete out._meta;
  return out;
}

export function withPii(server: McpServer, ctx: PiiContext): void {
  const originalTool = server.tool.bind(server) as unknown as (...a: unknown[]) => unknown;
  const originalRegister = server.registerTool.bind(server) as unknown as (...a: unknown[]) => unknown;

  (server as unknown as { tool: unknown }).tool = (...args: unknown[]) => {
    const last = args.length - 1;
    // tool(name, [description], [schema], [annotations], cb): a middle object is a schema.
    const hasArgs = args.slice(1, last).some((v) => v !== null && typeof v === "object");
    args[last] = wrapHandler(args[last] as Handler, hasArgs, ctx);
    return originalTool(...args);
  };

  (server as unknown as { registerTool: unknown }).registerTool = (
    name: string,
    config: Record<string, unknown>,
    cb: Handler,
  ) => originalRegister(name, stripCardMeta(config), wrapHandler(cb, config.inputSchema !== undefined, ctx));
}
