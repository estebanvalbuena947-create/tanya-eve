import { createDecipheriv } from "node:crypto";
import { defineTool } from "eve/tools";
import { z } from "zod";

/**
 * Searches Handoff meeting transcripts for a keyword and returns snippets around
 * each match. Read-only. Two sources, merged and de-duplicated, same as the
 * Railway Slack bot (handoff-tanya-slack-bot/src/search.ts):
 *  - recall_transcripts: Tanya/Recall meetings, `transcript` encrypted at rest
 *    (AES-256-GCM, v1:iv:tag:cipher). The most recent rows are decrypted here
 *    and matched in memory, because an encrypted column cannot be filtered in SQL.
 *  - meeting_transcripts: plain text, Fireflies history; filtered with ilike.
 * Needs SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY and PII_ENCRYPTION_KEY. Without
 * PII_ENCRYPTION_KEY it still searches meeting_transcripts and says Recall was skipped.
 */

const SNIPPET_PAD = 400;
/** Recall rows scanned per search, newest first (the Slack bot scans up to 100). */
const RECALL_SCAN = 100;

type TranscriptRow = {
  id: string;
  title: string | null;
  occurred_at: string | null;
  transcript: string | null;
};

type Match = {
  title: string;
  occurred_at: string | null;
  snippet: string;
  source: "recall" | "meeting";
};

function snippetAround(text: string, query: string): string {
  const idx = text.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return text.slice(0, SNIPPET_PAD * 2);
  const start = Math.max(0, idx - SNIPPET_PAD);
  const end = Math.min(text.length, idx + query.length + SNIPPET_PAD);
  return (start > 0 ? "\u2026" : "") + text.slice(start, end).trim() + (end < text.length ? "\u2026" : "");
}

/** Same decryption as the Slack bot's pii.ts. Returns plain text unchanged. */
function openPiiText(stored: string | null, key: Buffer): string {
  if (!stored) return "";
  if (!stored.startsWith("v1:")) return stored;
  const parts = stored.split(":");
  if (parts.length !== 4) return stored;
  const [, ivB64, tagB64, cipherB64] = parts;
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(cipherB64, "base64")), decipher.final()]).toString("utf8");
}

function readPiiKey(): Buffer | null {
  const b64 = process.env.PII_ENCRYPTION_KEY?.trim();
  if (!b64) return null;
  const key = Buffer.from(b64, "base64");
  return key.length === 32 ? key : null;
}

/** Same identity as the Slack bot's meetingKey(): normalized title + UTC day. */
function meetingKey(m: Pick<Match, "title" | "occurred_at">): string {
  const title = (m.title || "").toLowerCase().replace(/\s+/g, " ").trim();
  let day = "";
  if (m.occurred_at) {
    const d = new Date(m.occurred_at);
    day = Number.isNaN(d.getTime()) ? m.occurred_at : d.toISOString().slice(0, 10);
  }
  return `${title}|${day}`;
}

async function fetchRows(url: string, key: string, table: string, params: URLSearchParams) {
  const res = await fetch(`${url}/rest/v1/${table}?${params}`, {
    headers: { apikey: key, Authorization: `Bearer ${key}` },
  });
  if (!res.ok) throw new Error(`${table} search failed (${res.status})`);
  return (await res.json()) as TranscriptRow[];
}

export default defineTool({
  description:
    "Search the team's meeting transcripts for a keyword or short phrase. Returns matching meetings (title, date) with a snippet around the match. Use short keywords, and call it again with other keywords if needed.",
  inputSchema: z.object({
    query: z.string().min(2).describe("Keyword or short phrase to search for, e.g. 'onboarding'"),
    limit: z.number().int().min(1).max(10).default(5).describe("Max meetings to return"),
  }),
  async execute({ query, limit }) {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) {
      return { error: "SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not configured" };
    }

    // PostgREST ilike filter; escape the wildcard characters the user might type.
    const safe = query.replace(/[%*,()]/g, " ").trim();
    const needle = safe.toLowerCase();
    const piiKey = readPiiKey();
    const warnings: string[] = [];

    const meetingSearch = fetchRows(
      url,
      key,
      "meeting_transcripts",
      new URLSearchParams({
        select: "id,title,occurred_at,transcript",
        deleted_at: "is.null",
        transcript: `ilike.*${safe}*`,
        order: "occurred_at.desc.nullslast",
        limit: String(limit),
      })
    );

    // Only the encrypted `transcript` column is read; transcript_json is never selected.
    const recallSearch = piiKey
      ? fetchRows(
          url,
          key,
          "recall_transcripts",
          new URLSearchParams({
            select: "id,title,occurred_at,transcript",
            deleted_at: "is.null",
            order: "occurred_at.desc.nullslast",
            limit: String(RECALL_SCAN),
          })
        )
      : Promise.resolve([] as TranscriptRow[]);
    if (!piiKey) warnings.push("PII_ENCRYPTION_KEY is missing or invalid, so Recall meetings were not searched");

    const [meetingResult, recallResult] = await Promise.allSettled([meetingSearch, recallSearch]);
    if (meetingResult.status === "rejected" && recallResult.status === "rejected") {
      return { error: "Search failed in both transcript tables" };
    }

    const recall: Match[] = [];
    if (recallResult.status === "fulfilled") {
      let failed = 0;
      for (const row of recallResult.value) {
        let text = "";
        try {
          text = openPiiText(row.transcript, piiKey as Buffer);
        } catch {
          failed += 1;
          continue;
        }
        if (!text.toLowerCase().includes(needle)) continue;
        recall.push({
          title: row.title ?? "(untitled)",
          occurred_at: row.occurred_at,
          snippet: snippetAround(text, safe),
          source: "recall",
        });
      }
      if (failed > 0) warnings.push(`${failed} Recall transcripts could not be decrypted`);
    } else {
      warnings.push("Recall search failed; showing Fireflies history only");
    }

    const meeting: Match[] =
      meetingResult.status === "fulfilled"
        ? meetingResult.value.map((row) => ({
            title: row.title ?? "(untitled)",
            occurred_at: row.occurred_at,
            snippet: snippetAround(row.transcript ?? "", safe),
            source: "meeting" as const,
          }))
        : [];
    if (meetingResult.status === "rejected") warnings.push("Fireflies history search failed; showing Recall only");

    const seen = new Set<string>();
    const merged = [...recall, ...meeting].filter((m) => {
      const k = meetingKey(m);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    merged.sort((a, b) => (b.occurred_at ? Date.parse(b.occurred_at) : 0) - (a.occurred_at ? Date.parse(a.occurred_at) : 0));

    return {
      query: safe,
      matches: merged.slice(0, limit).map((m) => ({
        title: m.title,
        date: m.occurred_at?.slice(0, 10) ?? "unknown date",
        source: m.source === "recall" ? "Recall" : "Fireflies",
        snippet: m.snippet,
      })),
      ...(warnings.length > 0 ? { warnings } : {}),
    };
  },
});
