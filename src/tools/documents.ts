import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CwManageClient } from "../api-client.js";

/** Decoded size cap. Keeps the base64 tool argument within a sane message size. */
export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;

const BASE64 = /^[A-Za-z0-9+/\r\n]*={0,2}$/;

export function decodeBase64(contentBase64: string): Buffer {
  const trimmed = contentBase64.trim();
  if (!trimmed || !BASE64.test(trimmed)) {
    throw new Error("contentBase64 is not valid base64.");
  }
  const bytes = Buffer.from(trimmed, "base64");
  if (bytes.length === 0) throw new Error("contentBase64 decoded to an empty file.");
  if (bytes.length > MAX_UPLOAD_BYTES) {
    throw new Error(`File is ${bytes.length} bytes; the limit is ${MAX_UPLOAD_BYTES} bytes.`);
  }
  return bytes;
}

/** Strip path parts and control characters from a caller-supplied file name. */
export function safeFileName(name: string): string {
  const leaf = name.split(/[\\/]/).pop() ?? "";
  const cleaned = leaf.replace(/[\x00-\x1f"]/g, "").trim();
  if (!cleaned) throw new Error("fileName is empty after removing path and control characters.");
  return cleaned.slice(0, 200);
}

export function registerDocumentTools(server: McpServer, client: CwManageClient) {
  server.tool(
    "cw_upload_document",
    "Upload a file (document/attachment) to a ConnectWise Manage record: a service ticket, a company, or an activity. Creates one new document; never changes or deletes existing ones. Content is passed as base64 (max 5 MB decoded). recordType 'Activity' is UNVERIFIED against the CW API: if it is rejected, report the error.",
    {
      recordType: z
        .enum(["Ticket", "Company", "Activity"])
        .describe("Record type the document attaches to. 'Activity' is unverified."),
      recordId: z.number().describe("ID of the ticket, company or activity"),
      title: z.string().min(1).describe("Document title"),
      fileName: z.string().min(1).describe("File name including extension (e.g. 'report.pdf')"),
      contentBase64: z.string().describe("File content, base64-encoded"),
      privateFlag: z.boolean().optional().describe("Mark the document private (default: ConnectWise's own default)"),
      readOnlyFlag: z.boolean().optional().describe("Mark the document read-only (default: ConnectWise's own default)"),
    },
    async ({ recordType, recordId, title, fileName, contentBase64, privateFlag, readOnlyFlag }) => {
      const bytes = decodeBase64(contentBase64);
      const name = safeFileName(fileName);

      // Part names per the CW Swagger POST /system/documents request body (pasted by
      // Nickolas, 2026-11-13): file, recordId, recordType, title, url, privateFlag,
      // readOnlyFlay, isAvatar. The Swagger spells the read-only part "readOnlyFlay"
      // (likely a typo in CW's docs; the Document model uses readOnlyFlag).
      // UNVERIFIED: which spelling the API honors, so both are sent when set.
      // Flags are sent only when the caller sets them, so CW defaults apply otherwise.
      const form = new FormData();
      form.append("recordType", recordType);
      form.append("recordId", String(recordId));
      form.append("title", title);
      if (privateFlag !== undefined) form.append("privateFlag", String(privateFlag));
      if (readOnlyFlag !== undefined) {
        form.append("readOnlyFlay", String(readOnlyFlag));
        form.append("readOnlyFlag", String(readOnlyFlag));
      }
      form.append("file", new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" }), name);

      const result = await client.postForm("/system/documents", form);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
