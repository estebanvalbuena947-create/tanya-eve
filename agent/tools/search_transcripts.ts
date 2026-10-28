import { createDecipheriv } from "node:crypto";
import { defineTool } from "eve/tools";
import { z } from "zod";
import {
  canSeeFirefliesMeeting,
  canSeeRecallMeeting,
  identityOf,
  slackUserIdFromPrincipal,
  toAccessLevel,
  type Attendee,
  type Requester,
} from "../lib/transcript-access";

/**
 * Searches Handoff meeting transcripts for a keyword and returns snippets around
 * each match. Read-only. Two sources, merged and de-duplicated, same as the
 * Railway Slack bot (handoff-tanya-slack-bot/src/search.ts):
 *  - recall_transcripts: Tanya/Recall meetings, `transcript` encrypted at rest
 *    (AES-256-GCM, v1:iv:tag:cipher). The most recent rows are decrypted here
 *    and matched in memory, because an encrypted column cannot be filtered in SQL.
 *  - meeting_transcripts: plain text, Fireflies history; filtered with ilike.
 *
 * Access control (agent/lib/transcript-access.ts): the person asking comes from
 * the session (eve's Slack channel: `slack:<team>:<user>`), never from the model.
 * They are looked up in `accounts` by `slackId` (email + transcript_access).
 * Meetings they may not see are dropped before decrypting or quoting anything.
 * Local testing only (not on Vercel): TANYA_DEV_SLACK_ID stands in for the caller.
 *
 * Needs SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY and PII_ENCRYPTION_KEY. Without
 * PII_ENCRYPTION_KEY it still searches meeting_transcripts and says Recall was skipped.
 */

const SNIPPET_PAD = 400;
/** Recall rows scanned per search, newest first (the Slack bot scans up to 100). */
const RECALL_SCAN = 100;
/** Fireflies rows fetched before access filtering (some may be hidden). */
const FIREFLIES_FETCH_FACTOR = 4;

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

async function fetchRows<T>(url: string, key: string, table: string, params: URLSearchParams): Promise<T[]> {
  const res = await fetch(`${url}/rest/v1/${table}?${params}`, {
    headers: { apikey: key, Authorization: `Bearer ${key}` },
  });
  if (!res.ok) throw new Error(`${table} read failed (${res.status})`);
  return (await res.json()) as T[];
}

/** The caller's Slack id: from the session, or TANYA_DEV_SLACK_ID when running locally. */
function callerSlackId(principalId: string | undefined): string | null {
  const fromSession = slackUserIdFromPrincipal(principalId);
  if (fromSession) return fromSession;
  const dev = process.env.TANYA_DEV_SLACK_ID?.trim();
  return dev && !process.env.VERCEL ? dev : null;
}

async function loadRequester(url: string, key: string, slackId: string): Promise<Requester | null> {
  const rows = await fetchRows<{ email: string | null; transcript_access: string | null }>(
    url,
    key,
    "accounts",
    new URLSearchParams({ select: "email,transcript_access", slackId: `eq.${slackId}`, limit: "1" })
  );
  const row = rows[0];
  if (!row) return null;
  const identity = identityOf(row.email);
  return {
    level: toAccessLevel(row.transcript_access),
    identities: new Set(identity ? [identity] : []),
  };
}

function inList(ids: string[]): string {
  return `in.(${ids.join(",")})`;
}

export default defineTool({
  description:
    "Search the team's meeting transcripts for a keyword or short phrase. Returns matching meetings (title, date) with a snippet around the match. Only returns meetings the person asking is allowed to see. Use short keywords, and call it again with other keywords if needed.",
  inputSchema: z.object({
    query: z.string().min(2).describe("Keyword or short phrase to search for, e.g. 'onboarding'"),
    limit: z.number().int().min(1).max(10).default(5).describe("Max meetings to return"),
  }),
  async execute({ query, limit }, ctx) {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!url || !key) {
      return { error: "SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not configured" };
    }

    // Who is asking comes from the verified session, never from the model's input.
    const slackId = callerSlackId(ctx?.session?.auth?.current?.principalId);
    let requester: Requester | null = null;
    if (slackId) {
      try {
        requester = await loadRequester(url, key, slackId);
      } catch {
        return { error: "Could not check transcript access. Try again in a moment." };
      }
    }
    if (!requester) {
      return {
        error:
          "You are not set up for transcript access yet. Ask an admin to add your Slack account to Alma's team list (accounts).",
      };
    }

    // PostgREST ilike filter; escape the wildcard characters the user might type.
    const safe = query.replace(/[%*,()]/g, " ").trim();
    const needle = safe.toLowerCase();
    const piiKey = readPiiKey();
    const warnings: string[] = [];
    let hidden = 0;

    const meetingSearch = fetchRows<TranscriptRow>(
      url,
      key,
      "meeting_transcripts",
      new URLSearchParams({
        select: "id,title,occurred_at,transcript",
        deleted_at: "is.null",
        transcript: `ilike.*${safe}*`,
        order: "occurred_at.desc.nullslast",
        limit: String(requester.level === "all" ? limit : limit * FIREFLIES_FETCH_FACTOR),
      })
    );

    // Only the encrypted `transcript` column is read; transcript_json is never selected.
    const recallSearch = piiKey
      ? fetchRows<TranscriptRow>(
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
    if (recallResult.status === "fulfilled" && recallResult.value.length > 0) {
      let rows = recallResult.value;
      if (requester.level !== "all") {
        const attendees = await fetchRows<Attendee & { transcript_id: string }>(
          url,
          key,
          "recall_transcript_attendees",
          new URLSearchParams({
            select: "transcript_id,email,contact_id,talent_id",
            transcript_id: inList(rows.map((r) => r.id)),
          })
        ).catch(() => null);
        if (!attendees) {
          warnings.push("Could not check Recall attendees, so Recall meetings were hidden");
          rows = [];
        } else {
          const byMeeting = new Map<string, Attendee[]>();
          for (const a of attendees) byMeeting.set(a.transcript_id, [...(byMeeting.get(a.transcript_id) ?? []), a]);
          rows = rows.filter((r) => canSeeRecallMeeting(requester, byMeeting.get(r.id) ?? []));
        }
      }
      let failed = 0;
      for (const row of rows) {
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
    } else if (recallResult.status === "rejected") {
      warnings.push("Recall search failed; showing Fireflies history only");
    }

    let meetingRows = meetingResult.status === "fulfilled" ? meetingResult.value : [];
    if (requester.level !== "all" && meetingRows.length > 0) {
      const links = await fetchRows<{ transcript_id: string }>(
        url,
        key,
        "meeting_transcript_participants",
        new URLSearchParams({ select: "transcript_id", transcript_id: inList(meetingRows.map((r) => r.id)) })
      ).catch(() => null);
      const before = meetingRows.length;
      if (!links) {
        warnings.push("Could not check Fireflies participants, so Fireflies meetings were hidden");
        meetingRows = [];
      } else {
        const external = new Map<string, number>();
        for (const l of links) external.set(l.transcript_id, (external.get(l.transcript_id) ?? 0) + 1);
        meetingRows = meetingRows.filter((r) => canSeeFirefliesMeeting(requester, external.get(r.id) ?? 0));
      }
      hidden += before - meetingRows.length;
    }
    const meeting: Match[] = meetingRows.map((row) => ({
      title: row.title ?? "(untitled)",
      occurred_at: row.occurred_at,
      snippet: snippetAround(row.transcript ?? "", safe),
      source: "meeting" as const,
    }));
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
      access: requester.level === "all" ? "all meetings" : "client/talent meetings and internal meetings you attended",
      matches: merged.slice(0, limit).map((m) => ({
        title: m.title,
        date: m.occurred_at?.slice(0, 10) ?? "unknown date",
        source: m.source === "recall" ? "Recall" : "Fireflies",
        snippet: m.snippet,
      })),
      ...(hidden > 0 ? { note: "Some matching meetings are not visible to you. Do not mention or describe them." } : {}),
      ...(warnings.length > 0 ? { warnings } : {}),
    };
  },
});
