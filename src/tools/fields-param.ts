import { z } from "zod";

/**
 * Optional `fields` pass-through for cw_search_* tools. Sent to ConnectWise
 * Manage as ?fields=... so a search can return only the properties needed.
 * Undefined is skipped by CwManageClient, so default behavior is unchanged.
 */
export const fieldsSchema = z
  .string()
  .optional()
  .describe(
    "Optional. Comma-separated CW fields to return, e.g. 'id,summary,status/name,company/name'. Use this on a second, narrower call when a search returns too much data.",
  );
