import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CwManageClient } from "../api-client.js";
import { fieldsSchema } from "./fields-param.js";

export function registerServiceTools(server: McpServer, client: CwManageClient) {
  server.tool(
    "cw_list_boards",
    "List service boards in ConnectWise Manage. Each board is a large object (about 3 KB), so a full list can be too big to read. Retry with `fields` (e.g. 'id,name,inactiveFlag,projectFlag') and 'conditions' (e.g. 'inactiveFlag=false') to get a short list.",
    {
      conditions: z.string().optional().describe("ConnectWise conditions query string"),
      page: z.number().optional().describe("Page number (default: 1)"),
      pageSize: z.number().optional().describe("Results per page (default: 25, max: 1000)"),
      fields: fieldsSchema,
    },
    async ({ conditions, page, pageSize, fields }) => {
      const result = await client.get("/service/boards", {
        conditions,
        page: page ?? 1,
        pageSize: pageSize ?? 25,
        fields,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "cw_list_priorities",
    "List ticket priorities in ConnectWise Manage.",
    {
      conditions: z.string().optional().describe("ConnectWise conditions query string"),
      page: z.number().optional().describe("Page number (default: 1)"),
      pageSize: z.number().optional().describe("Results per page (default: 25, max: 1000)"),
      fields: fieldsSchema,
    },
    async ({ conditions, page, pageSize, fields }) => {
      const result = await client.get("/service/priorities", {
        conditions,
        page: page ?? 1,
        pageSize: pageSize ?? 25,
        fields,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "cw_list_statuses",
    "List ticket statuses for a specific service board in ConnectWise Manage. Each status is about 1 KB. Retry with `fields` (e.g. 'id,name,inactive,closedStatus,defaultFlag,emailTemplate/id,emailTemplate/identifier') to get a short list. A status with an emailTemplate sends that email when a ticket moves to it.",
    {
      boardId: z.number().describe("Service board ID"),
      conditions: z.string().optional().describe("ConnectWise conditions query string"),
      page: z.number().optional().describe("Page number (default: 1)"),
      pageSize: z.number().optional().describe("Results per page (default: 25, max: 1000)"),
      fields: fieldsSchema,
    },
    async ({ boardId, conditions, page, pageSize, fields }) => {
      const result = await client.get(`/service/boards/${boardId}/statuses`, {
        conditions,
        page: page ?? 1,
        pageSize: pageSize ?? 25,
        fields,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
