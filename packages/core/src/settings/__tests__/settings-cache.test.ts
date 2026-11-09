/**
 * The settings cache lifetimes are a BILLING control, so they are tested like
 * one.
 *
 * Neon bills compute by time awake and suspends after five minutes of silence.
 * A setting read on a request that carries no session is therefore not merely a
 * query, it is a wake-up: it resets that idle timer. At a five-second lifetime,
 * four such keys were enough to hold the database awake permanently.
 *
 * What makes this worth a test rather than a comment is that getting it wrong
 * fails SILENTLY in both directions. A key missing from the long list keeps the
 * short lifetime and the bill simply does not move. A key wrongly added to it
 * delays an operator's emergency action, and nothing anywhere reports that
 * either. Neither shows up as a failure; both show up weeks later.
 */
import { describe, expect, it } from "vitest";
import { cacheTtlFor, longCachedSettingKeys } from "../service";
import { FEATURE_FLAGS, SYSTEM_SETTINGS } from "../registry";

const SHORT_MS = 5_000;
const LONG_MS = 5 * 60_000;

describe("which keys get the longer cache lifetime", () => {
  /*
   * Each of these is read while serving a request that has no session: a
   * signup-page render, a marketing-page render, or the rate limiter consulting
   * its overrides. Those are precisely the requests a scanner generates, and
   * they are the only reads that cost compute time.
   */
  it.each(["signup_enabled", "early_access_open", "support_form_enabled", "rate_limit_overrides"])(
    "caches %s for minutes, because a scanner can trigger the read",
    (key) => {
      expect(cacheTtlFor(key)).toBe(LONG_MS);
    },
  );

  /*
   * The important half of the change, and the reason the classification is not
   * simply "highRisk or not".
   *
   * `session_epoch` IS the emergency "log everyone out" switch, and it is as
   * high-risk as anything in the registry — but it is read only on requests
   * that already carry a session, and loading that session queries Postgres
   * regardless. The compute is awake either way, so a longer lifetime here
   * would buy exactly zero compute time while delaying an incident response.
   */
  it.each(["session_epoch", "session_policy"])(
    "keeps %s on the short lifetime, so emergency logout is unaffected",
    (key) => {
      expect(cacheTtlFor(key)).toBe(SHORT_MS);
    },
  );

  /*
   * Same reasoning, applied to the authenticated and admin-only controls. These
   * are reached only by a signed-in principal, whose session lookup has already
   * woken the database.
   */
  it.each([
    "code_redemption_enabled",
    "promotional_grants_enabled",
    "generation_enabled",
    "payments_enabled",
    "announcement",
  ])("keeps %s on the short lifetime, because its readers are authenticated", (key) => {
    expect(cacheTtlFor(key)).toBe(SHORT_MS);
  });

  it("falls back to the short lifetime for a key it does not know", () => {
    // The safe direction: an unrecognised key propagates fast and costs a
    // query, rather than being quietly pinned for five minutes.
    expect(cacheTtlFor("not_a_real_setting")).toBe(SHORT_MS);
  });
});

describe("the long-cache list is wired to something real", () => {
  it("names only keys that exist in the registry", () => {
    /*
     * The silent-failure guard. `cacheTtlFor` matches on a string, so a typo
     * ("signup_enable") would not throw, would not fail a type check, and would
     * leave that flag on the five-second lifetime. The bill would stay exactly
     * where it was and nothing would say why.
     */
    const declared = new Set<string>([
      ...Object.keys(FEATURE_FLAGS),
      ...Object.keys(SYSTEM_SETTINGS),
    ]);
    const unknown = longCachedSettingKeys.filter((key) => !declared.has(key));
    expect(unknown).toEqual([]);
  });

  it("is not empty, which would mean the change had been reverted by accident", () => {
    expect(longCachedSettingKeys.length).toBeGreaterThan(0);
  });
});
