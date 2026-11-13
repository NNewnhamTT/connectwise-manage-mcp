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
    "cw_create_opportunity",
    "Create a sales opportunity in ConnectWise Manage. ConnectWise requires name, primary sales rep, company and contact. Look up ids first (cw_search_companies, cw_search_contacts, cw_search_members, cw_search_sales_stages). Creates one record; does not change existing ones.",
    {
      name: z.string().describe("Opportunity name"),
      companyId: z.number().describe("Company ID"),
      contactId: z.number().describe("Contact ID"),
      primarySalesRepId: z.number().describe("Primary sales rep member ID"),
      expectedCloseDate: z.string().optional().describe("Expected close date, ISO 8601 (e.g. '2026-12-31T00:00:00Z')"),
      secondarySalesRepId: z.number().optional().describe("Secondary sales rep member ID"),
      typeId: z.number().optional().describe("Opportunity type ID"),
      stageId: z.number().optional().describe("Sales stage ID (see cw_search_sales_stages)"),
      statusId: z.number().optional().describe("Opportunity status ID"),
      priorityId: z.number().optional().describe("Opportunity priority ID"),
      probabilityId: z.number().optional().describe("Opportunity probability ID"),
      ratingId: z.number().optional().describe("Opportunity rating ID"),
      campaignId: z.number().optional().describe("Campaign ID"),
      siteId: z.number().optional().describe("Company site ID"),
      source: z.string().optional().describe("Lead source"),
      notes: z.string().optional().describe("Opportunity notes"),
      customerPO: z.string().optional().describe("Customer PO"),
      locationId: z.number().optional().describe("Location ID (plain number)"),
      businessUnitId: z.number().optional().describe("Business unit ID (plain number)"),
    },
    async ({
      name,
      companyId,
      contactId,
      primarySalesRepId,
      expectedCloseDate,
      secondarySalesRepId,
      typeId,
      stageId,
      statusId,
      priorityId,
      probabilityId,
      ratingId,
      campaignId,
      siteId,
      source,
      notes,
      customerPO,
      locationId,
      businessUnitId,
    }) => {
      // Required fields (name, primarySalesRep, company, contact) and field shapes
      // per the Opportunity POST schema pasted by Nickolas from the CW Swagger, 2026-11-13.
      const body: Record<string, unknown> = {
        name,
        company: { id: companyId },
        contact: { id: contactId },
        primarySalesRep: { id: primarySalesRepId },
      };
      if (expectedCloseDate) body.expectedCloseDate = expectedCloseDate;
      if (secondarySalesRepId !== undefined) body.secondarySalesRep = { id: secondarySalesRepId };
      if (typeId !== undefined) body.type = { id: typeId };
      if (stageId !== undefined) body.stage = { id: stageId };
      if (statusId !== undefined) body.status = { id: statusId };
      if (priorityId !== undefined) body.priority = { id: priorityId };
      if (probabilityId !== undefined) body.probability = { id: probabilityId };
      if (ratingId !== undefined) body.rating = { id: ratingId };
      if (campaignId !== undefined) body.campaign = { id: campaignId };
      if (siteId !== undefined) body.site = { id: siteId };
      if (source) body.source = source;
      if (notes) body.notes = notes;
      if (customerPO) body.customerPO = customerPO;
      if (locationId !== undefined) body.locationId = locationId;
      if (businessUnitId !== undefined) body.businessUnitId = businessUnitId;

      const result = await client.post("/sales/opportunities", body);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    },
  );

  server.tool(
    "cw_update_opportunity",
    "Update an existing sales opportunity using JSON Patch operations (e.g. path 'stage/id', 'expectedCloseDate', 'notes', 'status/id', 'primarySalesRep/id').",
    {
      id: z.number().describe("Opportunity ID"),
      operations: z
        .array(
          z.object({
            op: z.enum(["replace", "add", "remove"]).describe("Patch operation"),
            path: z.string().describe("JSON path (e.g. 'name', 'stage/id', 'expectedCloseDate')"),
            value: z.unknown().optional().describe("New value (required for replace/add)"),
          }),
        )
        .min(1)
        .describe("Array of JSON Patch operations"),
    },
    async ({ id, operations }) => {
      const result = await client.patch(`/sales/opportunities/${id}`, operations);
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
