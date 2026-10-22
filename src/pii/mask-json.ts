/**
 * Mask person PII in a JSON value, and restore it in tool arguments.
 *
 * `maskJson` walks a ConnectWise response. Known PII fields (field-rules.ts)
 * become one token each. Free-text fields are scanned for spans: a built-in
 * pattern scan (email, phone, IPv4, MAC) plus an optional analyzer such as
 * Presidio, called once per response with every free-text string.
 *
 * The analyzer sees the original text, never a token. If it throws, every
 * free-text string in the response is replaced with ANALYZER_UNAVAILABLE.
 * Failing closed is the rule: PII must not leak because a sidecar is down.
 *
 * `unmaskDeep` is the reverse step for tool arguments.
 */

import { classify, isUrlKey } from "./field-rules.js";
import { TOKEN_PATTERN, type EntityType, type Tokenizer } from "./tokenizer.js";
import type { TokenStore } from "./store.js";

export const ANALYZER_UNAVAILABLE = "[REDACTED: PII analyzer unavailable]";

export interface AnalyzerSpan {
  entityType: string;
  start: number;
  end: number;
  score: number;
}

/** Takes N texts, returns N span lists. Presidio's /analyze fits this shape. */
export type Analyzer = (texts: string[]) => Promise<AnalyzerSpan[][]>;

export interface PiiContext {
  tokenizer: Tokenizer;
  store: TokenStore;
  tenant: string;
  ttlSeconds: number;
  analyzer?: Analyzer;
  scoreThreshold: number;
}

const WHOLE_TOKEN = /^<[A-Z]+_[0-9a-f]{10}>$/;

const PRESIDIO_TYPES: Record<string, EntityType> = {
  PERSON: "PERSON",
  EMAIL_ADDRESS: "EMAIL",
  PHONE_NUMBER: "PHONE",
  IP_ADDRESS: "IP",
};

interface Span {
  start: number;
  end: number;
  type: EntityType;
}

const PATTERNS: { type: EntityType; re: RegExp }[] = [
  { type: "EMAIL", re: /[A-Z0-9._%+-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)*\.[A-Z]{2,}/gi },
  { type: "MAC", re: /\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi },
  {
    type: "IP",
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  },
  // Separators are required so ticket numbers and serials do not match.
  { type: "PHONE", re: /(?<![\w-])(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\w-])/g },
];

function patternSpans(text: string): Span[] {
  const spans: Span[] = [];
  for (const { type, re } of PATTERNS) {
    for (const m of text.matchAll(re)) {
      spans.push({ start: m.index, end: m.index + m[0].length, type });
    }
  }
  return spans;
}

/** Keep earlier spans on overlap (pattern spans are listed first, so they win). */
function resolveOverlaps(spans: Span[]): Span[] {
  const kept: Span[] = [];
  for (const s of spans) {
    if (s.end <= s.start) continue;
    if (kept.some((k) => s.start < k.end && k.start < s.end)) continue;
    kept.push(s);
  }
  return kept.sort((a, b) => a.start - b.start);
}

interface Pending {
  text: string;
  spans: Span[];
  free: boolean;
  assign: (value: string) => void;
}

export async function maskJson(root: unknown, ctx: PiiContext): Promise<unknown> {
  const pending: Pending[] = [];
  const toStore: [string, string][] = [];

  const tokenFor = (type: EntityType, value: string): string => {
    const token = ctx.tokenizer.token(type, value);
    toStore.push([token, value]);
    return token;
  };

  // Walk and copy. Strings that need the second pass go on `pending`.
  const walk = (
    node: unknown,
    key: string | undefined,
    parentKey: string | undefined,
    parent: Record<string, unknown> | undefined,
    assign: (v: unknown) => void,
  ): void => {
    if (typeof node === "string") {
      if (key === undefined) {
        // A bare string at the root or inside an array of strings: scan it.
        pending.push({ text: node, spans: patternSpans(node), free: true, assign });
        return;
      }
      if (node.trim() === "" || WHOLE_TOKEN.test(node)) {
        assign(node);
        return;
      }
      const c = classify(key, parentKey, parent, node);
      if (c.mode === "field") {
        assign(tokenFor(c.type, node));
      } else if (isUrlKey(key)) {
        assign(node);
      } else {
        pending.push({
          text: node,
          spans: patternSpans(node),
          free: c.mode === "free",
          assign,
        });
      }
      return;
    }
    if (Array.isArray(node)) {
      const out: unknown[] = new Array(node.length);
      assign(out);
      node.forEach((item, i) => {
        // Array elements keep the key of the array, so `contact: [..]` still works.
        if (typeof item === "string") {
          walkArrayString(item, key, parentKey, parent, (v) => (out[i] = v));
        } else {
          walk(item, key, parentKey, parent, (v) => (out[i] = v));
        }
      });
      return;
    }
    if (node !== null && typeof node === "object") {
      const src = node as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      assign(out);
      for (const [k, v] of Object.entries(src)) {
        walk(v, k, key, src, (val) => (out[k] = val));
      }
      return;
    }
    assign(node);
  };

  // A string inside an array classifies by the array's own key.
  const walkArrayString = (
    item: string,
    arrayKey: string | undefined,
    arrayParentKey: string | undefined,
    arrayParent: Record<string, unknown> | undefined,
    assign: (v: unknown) => void,
  ): void => {
    if (arrayKey === undefined) {
      walk(item, undefined, undefined, undefined, assign);
    } else {
      walk(item, arrayKey, arrayParentKey, arrayParent, assign);
    }
  };

  let result: unknown;
  walk(root, undefined, undefined, undefined, (v) => (result = v));

  // Second pass: one analyzer call for every free-text string.
  const freeTexts = pending.filter((p) => p.free);
  let analyzed: AnalyzerSpan[][] | undefined;
  let analyzerFailed = false;
  if (ctx.analyzer && freeTexts.length > 0) {
    try {
      analyzed = await ctx.analyzer(freeTexts.map((p) => p.text));
      if (analyzed.length !== freeTexts.length) throw new Error("analyzer result size mismatch");
    } catch {
      analyzerFailed = true;
    }
  }

  let freeIndex = 0;
  for (const p of pending) {
    if (p.free && analyzerFailed) {
      p.assign(ANALYZER_UNAVAILABLE);
      continue;
    }
    const spans = [...p.spans];
    if (p.free && analyzed) {
      for (const s of analyzed[freeIndex++] ?? []) {
        const type = PRESIDIO_TYPES[s.entityType];
        if (type && s.score >= ctx.scoreThreshold) spans.push({ start: s.start, end: s.end, type });
      }
    }
    const kept = resolveOverlaps(spans);
    let out = "";
    let cursor = 0;
    for (const s of kept) {
      out += p.text.slice(cursor, s.start) + tokenFor(s.type, p.text.slice(s.start, s.end));
      cursor = s.end;
    }
    p.assign(out + p.text.slice(cursor));
  }

  await Promise.all(toStore.map(([token, value]) => ctx.store.put(ctx.tenant, token, value, ctx.ttlSeconds)));
  return result;
}

export interface UnmaskResult {
  value: unknown;
  /** Tokens that were not in the store (expired, other tenant, or invented). */
  unknownTokens: string[];
}

/** Replace every token in every string of `root` with its real value. */
export async function unmaskDeep(root: unknown, ctx: PiiContext): Promise<UnmaskResult> {
  const unknown = new Set<string>();
  const cache = new Map<string, string | undefined>();

  const lookup = async (token: string): Promise<string | undefined> => {
    if (!cache.has(token)) cache.set(token, await ctx.store.get(ctx.tenant, token));
    return cache.get(token);
  };

  const walk = async (node: unknown): Promise<unknown> => {
    if (typeof node === "string") {
      const tokens = [...new Set(node.match(TOKEN_PATTERN) ?? [])];
      if (tokens.length === 0) return node;
      let out = node;
      for (const t of tokens) {
        const real = await lookup(t);
        if (real === undefined) unknown.add(t);
        else out = out.split(t).join(real);
      }
      return out;
    }
    if (Array.isArray(node)) return Promise.all(node.map(walk));
    if (node !== null && typeof node === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) out[k] = await walk(v);
      return out;
    }
    return node;
  };

  const value = await walk(root);
  return { value, unknownTokens: [...unknown] };
}
