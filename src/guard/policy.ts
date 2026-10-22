/**
 * Tool access policy.
 *
 * Every tool is read, write or destructive. A caller has an access level:
 * read lets read tools run, write adds write tools, admin adds destructive
 * tools. A tool counts as read only when its name says so (`cw_get_`,
 * `cw_search_`, `cw_list_`, plus the diagnostic `cw_test_connection`).
 * Anything else is write, so a tool added upstream later is blocked at the
 * read level until someone classifies it on purpose.
 *
 * This module is side-effect free.
 */

import type { AccessLevel } from "./identity.js";

export type ToolClass = "read" | "write" | "destructive";

const READ_TOOL = /^cw_(get|search|list)_/;
const DESTRUCTIVE_TOOL = /^cw_delete_/;

export function classifyTool(name: string): ToolClass {
  if (name === "cw_test_connection" || READ_TOOL.test(name)) return "read";
  if (DESTRUCTIVE_TOOL.test(name)) return "destructive";
  return "write";
}

const RANK: Record<AccessLevel, number> = { read: 0, write: 1, admin: 2 };

export function requiredLevel(toolClass: ToolClass): AccessLevel {
  return toolClass === "read" ? "read" : toolClass === "write" ? "write" : "admin";
}

export function isAllowed(level: AccessLevel, tool: string): boolean {
  return RANK[level] >= RANK[requiredLevel(classifyTool(tool))];
}
