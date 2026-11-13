/**
 * Financial and government identifiers that must never reach a model: card
 * numbers, IBANs, SSNs, tax IDs, bank account and routing numbers, passport and
 * driver licence numbers. Added 2026-11-04.
 *
 * Same file in the CW and IT Glue forks. Keep the two copies identical.
 *
 * Like secrets, these are replaced with a fixed marker, not a reversible token.
 * Nobody needs the value back, and a marker keeps real SSNs and card numbers out
 * of the in-memory token store.
 *
 * Three layers:
 *   1. Presidio entity types (PRESIDIO_ID_ENTITIES), free-text strings only.
 *      Names are from the Presidio supported-entities page (checked 2026-11-04).
 *   2. Local patterns (`idSpans`), every string, no Presidio needed: dashed SSN,
 *      labelled tax IDs, card numbers that pass the Luhn check, IBANs that pass
 *      the mod-97 check.
 *   3. Key names (`isSensitiveIdKey`): the whole value under `ssn`, `taxId`,
 *      `cardNumber`, `iban`, `routingNumber`, ... is replaced.
 *
 * Over-masking is accepted. A bare 9-digit number with no label or dashes is not
 * caught locally (Presidio may catch it in free text).
 *
 * This module is side-effect free.
 */

export const REDACTED_ID = "[REDACTED: sensitive ID]";

/**
 * Presidio entity types whose spans become REDACTED_ID. DATE_TIME, LOCATION,
 * NRP, URL and UUID are left out on purpose: too noisy for IT documentation.
 * US_PROVIDER_TAX_ID (healthcare provider tax ID) is left out: it is a newer
 * recognizer that the pinned 2.2.364 image may not have (UNVERIFIED), and the
 * labelled tax ID pattern in `idSpans` covers a business EIN.
 */
export const PRESIDIO_ID_ENTITIES: readonly string[] = [
  "CREDIT_CARD",
  "IBAN_CODE",
  "US_SSN",
  "US_ITIN",
  "US_PASSPORT",
  "US_DRIVER_LICENSE",
  "US_BANK_NUMBER",
  "CRYPTO",
  "MEDICAL_LICENSE",
];

export interface IdSpan {
  start: number;
  end: number;
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

function ibanValid(raw: string): boolean {
  const iban = raw.replace(/\s+/g, "").toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const value = code >= 65 && code <= 90 ? String(code - 55) : ch;
    for (const digit of value) remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
  }
  return remainder === 1;
}

/** Dashed SSN. Area 000, 666 and 9xx, group 00 and serial 0000 are not valid SSNs. */
const SSN_DASHED = /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g;

/** "SSN: 123-45-6789", "Tax ID = 12-3456789", "EIN 123456789". The label stays readable. */
const LABELLED_ID =
  /\b(?:ssn|social[ _-]?security(?:[ _-]?(?:number|no\.?|#))?|tax[ _-]?id(?:[ _-]?(?:number|no\.?|#))?|ein|fein|itin|tin)\b[\s"'*\]]{0,3}[:=#]?(?:[ \t]|&nbsp;|&#160;)*(\d{3}-?\d{2}-?\d{4}|\d{2}-?\d{7})(?!\d)/gi;

/** 13 to 19 digits with optional single spaces or dashes between them. */
const CARD_CANDIDATE = /(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])/g;

const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g;

/** Spans of sensitive IDs found by the local patterns. */
export function idSpans(text: string): IdSpan[] {
  const spans: IdSpan[] = [];

  for (const m of text.matchAll(SSN_DASHED)) {
    spans.push({ start: m.index, end: m.index + m[0].length });
  }
  for (const m of text.matchAll(LABELLED_ID)) {
    // The captured number ends the match.
    spans.push({ start: m.index + m[0].length - m[1].length, end: m.index + m[0].length });
  }
  for (const m of text.matchAll(CARD_CANDIDATE)) {
    const digits = m[0].replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) {
      spans.push({ start: m.index, end: m.index + m[0].length });
    }
  }
  for (const m of text.matchAll(IBAN_CANDIDATE)) {
    if (ibanValid(m[0])) spans.push({ start: m.index, end: m.index + m[0].length });
  }
  return spans;
}

/** One word in a key name that marks the value as a sensitive ID. */
const ID_WORDS = new Set(["ssn", "cvv", "cvc", "iban", "ein", "fein", "itin"]);

/** Two words in a row ("tax id", "card number") that mark the value as a sensitive ID. */
const ID_WORD_PAIRS: readonly (readonly [string, string])[] = [
  ["social", "security"],
  ["tax", "id"],
  ["tax", "identifier"],
  ["tax", "number"],
  ["card", "number"],
  ["credit", "card"],
  ["debit", "card"],
  ["routing", "number"],
  ["bank", "account"],
  ["passport", "number"],
  ["driver", "license"],
  ["drivers", "license"],
  ["driver", "licence"],
  ["drivers", "licence"],
];

/** A last word that says the key holds a flag, date or label about the ID, not the ID. */
const NON_VALUE_LAST_WORDS = new Set([
  "at",
  "on",
  "date",
  "time",
  "count",
  "status",
  "enabled",
  "required",
  "policy",
  "type",
  "flag",
  "verified",
  "expires",
  "expiry",
]);

function keyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((w) => w !== "")
    .map((w) => w.toLowerCase());
}

/** True when the key name says its value is a financial or government ID. */
export function isSensitiveIdKey(key: string): boolean {
  const words = keyWords(key);
  if (words.length === 0) return false;
  if (NON_VALUE_LAST_WORDS.has(words[words.length - 1])) return false;
  if (words.some((w) => ID_WORDS.has(w))) return true;
  return ID_WORD_PAIRS.some(([a, b]) => words.some((w, i) => w === a && words[i + 1] === b));
}
