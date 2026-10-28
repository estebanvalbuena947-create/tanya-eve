// Run with: node --test tests/transcript-access.test.ts  (Node 24 strips the types)
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canSeeFirefliesMeeting,
  canSeeRecallMeeting,
  identityOf,
  slackUserIdFromPrincipal,
  type Requester,
} from "../agent/lib/transcript-access.ts";

const ana: Requester = { level: "standard", identities: new Set([identityOf("ana@yourhandoff.com")!]) };
const admin: Requester = { level: "all", identities: new Set() };
const internalOnly = [
  { email: "jake@talenthandoff.com", contact_id: null, talent_id: null },
  { email: "jazmin@yourhandoff.com", contact_id: null, talent_id: null },
];

test("reads the Slack user id from eve's principal", () => {
  assert.equal(slackUserIdFromPrincipal("slack:T012:U0ABC"), "U0ABC");
  assert.equal(slackUserIdFromPrincipal("local-dev"), null);
  assert.equal(slackUserIdFromPrincipal(undefined), null);
});

test("admins see everything", () => {
  assert.equal(canSeeRecallMeeting(admin, internalOnly), true);
  assert.equal(canSeeRecallMeeting(admin, []), true);
  assert.equal(canSeeFirefliesMeeting(admin, 0), true);
});

test("everyone sees meetings with clients or talent", () => {
  assert.equal(canSeeRecallMeeting(ana, [...internalOnly, { email: "mark@client.com", contact_id: null, talent_id: null }]), true);
  assert.equal(canSeeRecallMeeting(ana, [...internalOnly, { email: null, contact_id: null, talent_id: "t-1" }]), true);
  assert.equal(canSeeFirefliesMeeting(ana, 2), true);
});

test("internal meetings only for people who were there, across both staff domains", () => {
  assert.equal(canSeeRecallMeeting(ana, internalOnly), false);
  assert.equal(canSeeRecallMeeting(ana, [...internalOnly, { email: "Ana@TalentHandoff.com", contact_id: null, talent_id: null }]), true);
});

test("unknown people and unknown attendance see nothing", () => {
  assert.equal(canSeeRecallMeeting(null, [{ email: "mark@client.com", contact_id: null, talent_id: null }]), false);
  assert.equal(canSeeRecallMeeting(ana, []), false);
  assert.equal(canSeeFirefliesMeeting(ana, 0), false);
  assert.equal(canSeeFirefliesMeeting(null, 3), false);
});
