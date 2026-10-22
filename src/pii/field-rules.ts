/**
 * Which ConnectWise Manage JSON fields hold person PII.
 *
 * Scope (set by Nickolas 2026-10-22): person PII only. That is names, email
 * addresses, phone numbers, street address lines, IP and MAC addresses.
 * Company names, config names, ids, dates and statuses stay readable so Claude
 * can still reason about the data.
 *
 * Three modes for a string value:
 * - `field`: the whole value is PII. Replace it with one token.
 * - `free`:  free text (notes, descriptions). Scan for PII spans.
 * - `other`: anything else. Only the cheap pattern scan runs.
 *
 * This module is side-effect free.
 */

import type { EntityType } from "./tokenizer.js";

export type FieldMode =
  | { mode: "field"; type: EntityType }
  | { mode: "free" }
  | { mode: "other" };

/** An object under one of these keys is a person: mask its name fields. */
const PERSON_PARENT_KEYS = new Set([
  "contact",
  "owner",
  "member",
  "resource",
  "defaultContact",
  "assignedBy",
  "assignedTo",
  "salesRep",
  "salesPerson",
  "enteredBy",
  "updatedBy",
  "closedBy",
  "createdBy",
  "resolvedBy",
  "approver",
  "technician",
  "dispatcher",
]);

/** Name keys inside a person object. `identifier` is the member username. */
const PERSON_OBJECT_NAME_KEYS = new Set(["name", "identifier", "firstName", "lastName", "memberName"]);

/** String-valued keys that always hold a person name, wherever they sit. */
const PERSON_STRING_KEYS = new Set([
  "firstname",
  "lastname",
  "middlename",
  "fullname",
  "nickname",
  "preferredname",
  "contactname",
  "membername",
  "ownername",
  "salesrepname",
  "enteredby",
  "updatedby",
  "createdby",
  "closedby",
  "lastupdatedby",
  "assignedby",
  "resolvedby",
  "resources",
  "who",
]);

const FREE_TEXT_KEYS = new Set([
  "summary",
  "initialdescription",
  "initialinternalanalysis",
  "initialresolution",
  "text",
  "notes",
  "internalnotes",
  "detaildescription",
  "description",
  "resolution",
  "internalanalysis",
  "detail",
  "message",
  "comment",
  "comments",
  "body",
  "subject",
]);

const EMAIL_KEY = /e-?mail/i;
const PHONE_KEY = /(phone|fax|mobile)/i;
const STREET_KEY = /addressline\d?$/i;
/** Keys with these endings are flags, ids or labels, never the value itself. */
const NON_VALUE_KEY = /(flag|template|subject|type|id|name)$/i;

function communicationItemType(parent: Record<string, unknown> | undefined, value: string): EntityType {
  const label = [
    parent?.communicationType,
    (parent?.type as { name?: unknown } | undefined)?.name,
  ]
    .filter((v): v is string => typeof v === "string")
    .join(" ");
  if (EMAIL_KEY.test(label)) return "EMAIL";
  if (/(phone|fax|cell|mobile|direct)/i.test(label)) return "PHONE";
  return value.includes("@") ? "EMAIL" : "PHONE";
}

/**
 * Classify one string value.
 * @param key        the property name holding the value
 * @param parentKey  the property name that holds the parent object (arrays are transparent)
 * @param parent     the object that owns `key`
 */
export function classify(
  key: string,
  parentKey: string | undefined,
  parent: Record<string, unknown> | undefined,
  value: string,
): FieldMode {
  const lower = key.toLowerCase();

  if (parentKey === "communicationItems" && key === "value") {
    return { mode: "field", type: communicationItemType(parent, value) };
  }
  if (parentKey === "customFields" && key === "value") return { mode: "free" };

  if (parentKey && PERSON_PARENT_KEYS.has(parentKey) && PERSON_OBJECT_NAME_KEYS.has(key)) {
    return { mode: "field", type: "PERSON" };
  }
  if (PERSON_STRING_KEYS.has(lower)) return { mode: "field", type: "PERSON" };

  if (lower === "ipaddress" || lower === "ipv4address" || lower === "ipv6address") {
    return { mode: "field", type: "IP" };
  }
  if (lower === "macaddress") return { mode: "field", type: "MAC" };
  if (STREET_KEY.test(key)) return { mode: "field", type: "ADDRESS" };

  if (!NON_VALUE_KEY.test(key)) {
    if (EMAIL_KEY.test(key)) return { mode: "field", type: "EMAIL" };
    if (PHONE_KEY.test(key)) return { mode: "field", type: "PHONE" };
  }

  if (FREE_TEXT_KEYS.has(lower)) return { mode: "free" };
  return { mode: "other" };
}

/** Keys whose string value is a URL. The pattern scan skips these. */
export function isUrlKey(key: string): boolean {
  return /(url|href)$/i.test(key);
}
