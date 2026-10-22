/**
 * Client for the Presidio Analyzer REST service (the presidio-analyzer image).
 *
 * One POST to `/analyze` carries every free-text string of a response. The
 * service has no authentication. Run it on a private network only.
 */

import type { Analyzer } from "./mask-json.js";

export interface PresidioOptions {
  /** Base URL of the analyzer, for example `http://presidio-analyzer:3000`. */
  baseUrl: string;
  timeoutMs?: number;
  language?: string;
  entities?: string[];
  fetchImpl?: typeof fetch;
}

export const DEFAULT_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS"];

interface RawSpan {
  entity_type: string;
  start: number;
  end: number;
  score: number;
}

function isSpan(v: unknown): v is RawSpan {
  if (v === null || typeof v !== "object") return false;
  const s = v as Record<string, unknown>;
  return (
    typeof s.entity_type === "string" &&
    typeof s.start === "number" &&
    typeof s.end === "number" &&
    typeof s.score === "number"
  );
}

export function createPresidioAnalyzer(options: PresidioOptions): Analyzer {
  const url = `${options.baseUrl.replace(/\/+$/, "")}/analyze`;
  const doFetch = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 5000;

  return async (texts) => {
    if (texts.length === 0) return [];
    const res = await doFetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: texts,
        language: options.language ?? "en",
        entities: options.entities ?? DEFAULT_ENTITIES,
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    // Never put the response body in the error: it can echo the analyzed text.
    if (!res.ok) throw new Error(`Presidio analyzer returned HTTP ${res.status}`);
    const body: unknown = await res.json();
    if (!Array.isArray(body) || body.length !== texts.length) {
      throw new Error("Presidio analyzer returned an unexpected result shape");
    }
    return body.map((list) => {
      if (!Array.isArray(list)) throw new Error("Presidio analyzer returned an unexpected result shape");
      return list.filter(isSpan).map((s) => ({
        entityType: s.entity_type,
        start: s.start,
        end: s.end,
        score: s.score,
      }));
    });
  };
}
