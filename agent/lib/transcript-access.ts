/**
 * Who can see which meeting through Tanya (pure, no I/O).
 *
 * Agreed with Jazmin and Jake: admins see every meeting. Everyone else sees
 * meetings with clients or talent, plus internal meetings they attended.
 * Fireflies history only lists external contacts (not who from Handoff was
 * there), so its internal meetings are admin-only. When in doubt, hide.
 */

export const INTERNAL_DOMAINS = ["yourhandoff.com", "talenthandoff.com"];

export type AccessLevel = "all" | "standard";

export type Requester = { level: AccessLevel; identities: ReadonlySet<string> };

export type Attendee = {
  email: string | null;
  contact_id: string | null;
  talent_id: string | null;
};

/** eve's Slack channel identifies people as `slack:<team>:<user>`. Returns the user id. */
export function slackUserIdFromPrincipal(principalId: string | undefined | null): string | null {
  const match = /^slack:[^:]+:([A-Z0-9]+)$/.exec(principalId ?? "");
  return match ? match[1] : null;
}

function isInternalEmail(email: string): boolean {
  const domain = email.split("@")[1] ?? "";
  return INTERNAL_DOMAINS.includes(domain);
}

/**
 * Stable identity for matching attendees. Handoff staff emails match on the part
 * before the @ (the domain moved from yourhandoff.com to talenthandoff.com).
 */
export function identityOf(email: string | null | undefined): string | null {
  const e = email?.trim().toLowerCase();
  if (!e || !e.includes("@")) return null;
  return isInternalEmail(e) ? `handoff:${e.split("@")[0]}` : e;
}

export function toAccessLevel(value: unknown): AccessLevel {
  return value === "all" ? "all" : "standard";
}

/** A Recall meeting is external if anyone is a client contact, a talent, or outside Handoff. */
export function isExternalMeeting(attendees: readonly Attendee[]): boolean {
  return attendees.some((a) => {
    if (a.contact_id || a.talent_id) return true;
    const e = a.email?.trim().toLowerCase();
    return Boolean(e && e.includes("@") && !isInternalEmail(e));
  });
}

export function canSeeRecallMeeting(requester: Requester | null, attendees: readonly Attendee[]): boolean {
  if (!requester) return false;
  if (requester.level === "all") return true;
  if (isExternalMeeting(attendees)) return true;
  return attendees.some((a) => {
    const id = identityOf(a.email);
    return id !== null && requester.identities.has(id);
  });
}

/** Fireflies history: external if it has linked client contacts; otherwise admin-only. */
export function canSeeFirefliesMeeting(requester: Requester | null, externalContacts: number): boolean {
  if (!requester) return false;
  return requester.level === "all" || externalContacts > 0;
}
