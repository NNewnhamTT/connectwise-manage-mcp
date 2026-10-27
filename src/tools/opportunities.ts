import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CwManageClient } from "../api-client.js";
import { fieldsSchema } from "./fields-param.js";

export function registerOpportunityTools(server: McpServer, client: CwManageClient) {
  server.tool(
    "cw_search_opportunities",
    "Search sales opportunities in ConnectWise Manage. Use 'conditions' for CW query syntax (e.g. \"status/name = '1. Open'\", \"closedFlag = false\").",
    {
      conditions: z.string().optional().describe("ConnectWise conditions query string"),
      page: z.number().optional().describe("Page number (default: 1)"),
      pageSize: z.number().optional().describe("Results per page (default: 25, max: 1000)"),
      orderBy: z.string().optional().describe("Field to order by (e.g. 'id desc')"),
      fields: fieldsSchema,
    },
    async ({ conditions, page, pageSize, orderBy, fields }) => {
      const result = await client.get("/sales/opportunities", {
        conditions,
        page: page ?? 1,
        pageSize: pageSize ?? 25,
        orderBy,
        fields,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "cw_get_opportunity",
    "Get a specific sales opportunity by ID.",
    {
      id: z.number().describe("Opportunity ID"),
    },
    async ({ id }) => {
      const result = await client.get(`/sales/opportunities/${id}`);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "cw_search_opportunity_forecasts",
    "Search opportunity forecasts/revenue items for a specific opportunity.",
    {
      opportunityId: z.number().describe("Opportunity ID"),
      page: z.number().optional().describe("Page number (default: 1)"),
      pageSize: z.number().optional().describe("Results per page (default: 25, max: 1000)"),
      fields: fieldsSchema,
    },
    async ({ opportunityId, page, pageSize, fields }) => {
      const result = await client.get(`/sales/opportunities/${opportunityId}/forecast`, {
        page: page ?? 1,
        pageSize: pageSize ?? 25,
        fields,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "cw_search_opportunity_notes",
    "Get notes on a specific sales opportunity.",
    {
      opportunityId: z.number().describe("Opportunity ID"),
      page: z.number().optional().describe("Page number (default: 1)"),
      pageSize: z.number().optional().describe("Results per page (default: 25, max: 1000)"),
      conditions: z.string().optional().describe("Optional. ConnectWise conditions query string on note fields."),
      orderBy: z.string().optional().describe("Optional. Field to order by (e.g. 'id desc')"),
      fields: fieldsSchema,
    },
    async ({ opportunityId, page, pageSize, conditions, orderBy, fields }) => {
      const result = await client.get(`/sales/opportunities/${opportunityId}/notes`, {
        page: page ?? 1,
        pageSize: pageSize ?? 25,
        conditions,
        orderBy,
        fields,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "cw_search_sales_stages",
    "List sales pipeline stages in ConnectWise Manage.",
    {
      conditions: z.string().optional().describe("ConnectWise conditions query string"),
      page: z.number().optional().describe("Page number (default: 1)"),
      pageSize: z.number().optional().describe("Results per page (default: 25, max: 1000)"),
      fields: fieldsSchema,
    },
    async ({ conditions, page, pageSize, fields }) => {
      const result = await client.get("/sales/stages", {
        conditions,
        page: page ?? 1,
        pageSize: pageSize ?? 25,
        fields,
      });
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );
}
