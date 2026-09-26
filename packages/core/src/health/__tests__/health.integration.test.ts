/**
 * The alert is only worth what the check behind it is worth.
 *
 * This decides whether an email gets sent at four in the morning, which makes
 * both directions expensive. A check that misses a stopped backup is the reason
 * you discover the gap on the day you need the archive. A check that fires on a
 * healthy night teaches its recipient to filter the address, and then the real
 * one arrives somewhere nobody looks.
 *
 * So: nothing wrong must produce NOTHING, and each individual fault must be
 * detected on its own, without help from any of the others.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { sql } from "drizzle-orm";
import { checkHealth, worstSeverity } from "../index";
import { BACKUP_JOB, recordJobRun, RESTORE_TEST_JOB, RETENTION_JOB } from "../../retention";
import { connectTestDb, createTestUser, type TestDb } from "../../../../../tests/helpers/db";

let test: TestDb;

beforeAll(() => {
  test = connectTestDb();
});

afterAll(async () => {
  await test.close();
});

/** Every scheduled job fresh, so a test can break exactly one thing. */
async function allJobsHealthy() {
  for (const job of [BACKUP_JOB, RETENTION_JOB, RESTORE_TEST_JOB]) {
    await recordJobRun(test.db, {
      job,
      startedAt: new Date(),
      finishedAt: new Date(),
      status: "ok",
      durationMs: 10,
    });
  }
}

beforeEach(async () => {
  await test.truncate();
  await allJobsHealthy();
});

const codes = async () => (await checkHealth(test.db)).problems.map((p) => p.code);

describe("a healthy platform", () => {
  it("reports no problems at all", async () => {
    expect(await codes()).toEqual([]);
  });

  it("still reports the figures it looked at", async () => {
    const report = await checkHealth(test.db);
    expect(Object.keys(report.context)).toEqual(
      expect.arrayContaining([
        BACKUP_JOB,
        RETENTION_JOB,
        RESTORE_TEST_JOB,
        "ledger_drift",
        "errors_24h",
        "critical_security_events_24h",
        "email_24h",
      ]),
    );
  });

  it("has no severity to escalate", async () => {
    expect(worstSeverity([])).toBeNull();
  });
});

describe("each fault is caught on its own", () => {
  it("notices a backup that has stopped, and calls it critical", async () => {
    await test.db.execute(
      sql`UPDATE job_runs SET finished_at = now() - interval '40 hours' WHERE job = ${BACKUP_JOB}`,
    );
    const report = await checkHealth(test.db);
    expect(report.problems).toEqual([
      expect.objectContaining({ code: `job.${BACKUP_JOB}`, severity: "critical" }),
    ]);
  });

  // A week-long window: a failure of assurance, not of the thing assured.
  it("notices a stale restore test as a warning, not a critical", async () => {
    await test.db.execute(
      sql`UPDATE job_runs SET finished_at = now() - interval '10 days' WHERE job = ${RESTORE_TEST_JOB}`,
    );
    const report = await checkHealth(test.db);
    expect(report.problems).toEqual([
      expect.objectContaining({ code: `job.${RESTORE_TEST_JOB}`, severity: "warning" }),
    ]);
  });

  it("notices a wallet that disagrees with the ledger", async () => {
    const userId = await seedUser();
    await test.db.execute(
      sql`INSERT INTO credit_wallets (id, user_id, balance) VALUES ('wal_health_test', ${userId}, 500)`,
    );
    expect(await codes()).toContain("credits.drift");
  });

  it("notices server errors", async () => {
    await test.db.execute(sql`
      INSERT INTO request_metrics (id, day, hour, route_group, requests, status_5xx)
      VALUES ('rqm_health_test', current_date, 1, '/api', 5, 3)
    `);
    expect(await codes()).toContain("requests.5xx");
  });

  it("notices critical security events", async () => {
    await test.db.execute(sql`
      INSERT INTO security_events (id, type, severity, created_at)
      VALUES ('sev_health_test', 'admin_2fa_failed', 'critical', now())
    `);
    expect(await codes()).toContain("security.critical");
  });

  // Verification mail IS the signup flow, so a provider problem reads to users
  // as "the product is broken" while every dashboard stays green.
  it("notices email that is failing to deliver", async () => {
    await test.db.execute(sql`
      INSERT INTO email_events (id, to_email, template, subject, status, created_at)
      VALUES ('eml_health_test', 'someone@example.test', 'verify_email', 'Confirm', 'bounced', now())
    `);
    expect(await codes()).toContain("email.failed");
  });
});

describe("the two ceilings that stop signup without an error", () => {
  /*
   * Every signup sends a verification email. When the provider's quota runs out
   * the account is still created, the mail never leaves, and the person waits
   * on the "check your email" page indefinitely — a failure with no error
   * attached to it anywhere.
   *
   * WHICH quota is the part this got wrong in production, so it is pinned here.
   * The alert watched a rolling 24 hours against a hardcoded 100 and called it
   * "daily". 100 is the provider's FREE-plan ceiling; it survived the upgrade
   * to a paid plan, where there is no daily limit at all and only the month
   * binds. So a perfectly healthy account with 49,000 messages left in its
   * allowance was told, at 131 sent, that new accounts would never hear from
   * us. An alert that is wrong in that direction is worse than none: the next
   * one gets ignored, and mail failing during a launch is precisely when it
   * must not be.
   */
  const PAID = { emailDailyQuota: 0, emailMonthlyQuota: 50_000 };
  const FREE = { emailDailyQuota: 100, emailMonthlyQuota: 3_000 };

  it("warns before the monthly email quota runs out", async () => {
    await sendMail(85);
    const report = await checkHealth(test.db, { emailDailyQuota: 0, emailMonthlyQuota: 100 });
    expect(report.problems).toContainEqual(
      expect.objectContaining({ code: "email.quota", severity: "warning" }),
    );
  });

  it("calls an exhausted monthly quota critical", async () => {
    await sendMail(100);
    const report = await checkHealth(test.db, { emailDailyQuota: 0, emailMonthlyQuota: 100 });
    expect(report.problems).toContainEqual(
      expect.objectContaining({ code: "email.quota", severity: "critical" }),
    );
  });

  it("says nothing at ordinary volume", async () => {
    await sendMail(10);
    const report = await checkHealth(test.db, PAID);
    expect(report.problems.map((p) => p.code)).not.toContain("email.quota");
  });

  it("does not invent a daily crisis on a plan with no daily limit", async () => {
    /*
     * The exact production incident, reproduced: 131 messages in a day on the
     * paid plan. Nothing is wrong, and nothing may be reported.
     */
    await sendMail(131);
    const report = await checkHealth(test.db, PAID);
    const reported = report.problems.map((p) => p.code);
    expect(reported).not.toContain("email.quota");
    expect(reported).not.toContain("email.quota.daily");
    expect(report.context.email_quota).toContain("of 50000");
  });

  it("still watches the daily ceiling on a plan that has one", async () => {
    /*
     * The free plan's limit is real, so removing the daily check outright would
     * trade one blind spot for another. It is watched when it exists.
     */
    await sendMail(131);
    const report = await checkHealth(test.db, FREE);
    expect(report.problems).toContainEqual(
      expect.objectContaining({ code: "email.quota.daily", severity: "critical" }),
    );
  });

  it("counts the month as the provider bills it, not as a rolling window", async () => {
    /*
     * The provider resets on a UTC calendar boundary. A rolling window drags
     * the previous period's sends into this one and reports a ceiling that is
     * never the ceiling the provider is applying.
     */
    await sendMail(40);
    await test.db.execute(sql`
      UPDATE email_events SET created_at = date_trunc('month', now() AT TIME ZONE 'UTC')
                                           - interval '2 days'
    `);
    const report = await checkHealth(test.db, { emailDailyQuota: 0, emailMonthlyQuota: 50 });
    expect(
      report.problems.map((p) => p.code),
      "last month's mail is not this month's spend",
    ).not.toContain("email.quota");
  });

  // A full campaign tells every new arrival their code is "invalid or
  // unavailable" — indistinguishable from a typo, which is what they will
  // assume, and they retry until the rate limiter stops them.
  it("warns before a campaign fills up", async () => {
    await campaign({ used: 400, cap: 500 });
    const report = await checkHealth(test.db);
    expect(report.problems).toContainEqual(
      expect.objectContaining({ code: "campaign.capacity", severity: "warning" }),
    );
  });

  it("calls a full campaign critical", async () => {
    await campaign({ used: 500, cap: 500 });
    const report = await checkHealth(test.db);
    expect(report.problems).toContainEqual(
      expect.objectContaining({ code: "campaign.capacity", severity: "critical" }),
    );
  });

  it("says nothing about a campaign with room left", async () => {
    await campaign({ used: 12, cap: 500 });
    expect(await codes()).not.toContain("campaign.capacity");
  });

  // Unlimited is a deliberate configuration, not an oversight to warn about.
  it("says nothing about an uncapped campaign", async () => {
    await campaign({ used: 9999, cap: null });
    expect(await codes()).not.toContain("campaign.capacity");
  });

  it("ignores a campaign that is not enabled", async () => {
    await campaign({ used: 500, cap: 500, status: "paused" });
    expect(await codes()).not.toContain("campaign.capacity");
  });
});

describe("what it deliberately ignores", () => {
  it("does not flag a 5xx from last week", async () => {
    await test.db.execute(sql`
      INSERT INTO request_metrics (id, day, hour, route_group, requests, status_5xx, updated_at)
      VALUES ('rqm_old', current_date - 7, 1, '/api', 5, 3, now() - interval '7 days')
    `);
    expect(await codes()).not.toContain("requests.5xx");
  });

  it("does not flag delivered email", async () => {
    await test.db.execute(sql`
      INSERT INTO email_events (id, to_email, template, subject, status, created_at)
      VALUES ('eml_ok', 'someone@example.test', 'verify_email', 'Confirm', 'delivered', now())
    `);
    expect(await codes()).not.toContain("email.failed");
  });
});

describe("severity", () => {
  it("lets one critical outrank any number of warnings", () => {
    expect(
      worstSeverity([
        { severity: "warning", code: "a", summary: "", detail: "" },
        { severity: "critical", code: "b", summary: "", detail: "" },
        { severity: "warning", code: "c", summary: "", detail: "" },
      ]),
    ).toBe("critical");
  });
});

/** `n` delivered messages inside the quota window. */
async function sendMail(n: number) {
  for (let i = 0; i < n; i++) {
    await test.db.execute(sql`
      INSERT INTO email_events (id, to_email, template, subject, status, created_at)
      VALUES (${`eml_q_${i}`}, 'someone@example.test', 'verify_email', 'Confirm', 'delivered', now())
    `);
  }
}

async function campaign(spec: { used: number; cap: number | null; status?: string }) {
  await test.db.execute(sql`
    INSERT INTO access_code_campaigns
      (id, name, code_fingerprint, code_masked, code_last4, credit_amount,
       redemption_count, max_total_redemptions, status)
    VALUES (${`cmp_${Math.random().toString(36).slice(2, 10)}`}, 'Early access — launch',
            ${`fp_${Math.random().toString(36).slice(2, 10)}`}, 'INKL••••ARLY', 'ARLY', 25,
            ${spec.used}, ${spec.cap}, ${spec.status ?? "enabled"}::campaign_status)
  `);
}

async function seedUser(): Promise<string> {
  return (await createTestUser(test.db)).id;
}

describe("backups that are paused on purpose", () => {
  /*
   * A paused job and a broken one are indistinguishable from the database: both
   * are simply overdue. Alerting on a pause every morning is how an alert stops
   * being read, and the one that matters then arrives in a folder nobody opens.
   */
  it("does not raise a problem for an overdue backup while backups are paused", async () => {
    await test.db.execute(
      sql`UPDATE job_runs SET finished_at = now() - interval '40 hours' WHERE job = ${BACKUP_JOB}`,
    );
    const report = await checkHealth(test.db, { backupsExpected: false });
    expect(report.problems.map((p) => p.code)).toEqual([]);
  });

  // Silent is not the same as invisible: a pause left in place by accident has
  // to be findable, so it is still reported as context.
  it("still says so, so a forgotten pause is visible", async () => {
    const report = await checkHealth(test.db, { backupsExpected: false });
    expect(report.context[BACKUP_JOB]).toContain("PAUSED");
    expect(report.context[RESTORE_TEST_JOB]).toContain("PAUSED");
  });

  // Retention is a Cloudflare cron and keeps running regardless, so pausing
  // the GitHub backups must not silence it.
  it("still alerts on the retention sweep, which is not paused", async () => {
    await test.db.execute(
      sql`UPDATE job_runs SET finished_at = now() - interval '40 hours' WHERE job = ${RETENTION_JOB}`,
    );
    const report = await checkHealth(test.db, { backupsExpected: false });
    expect(report.problems.map((p) => p.code)).toEqual([`job.${RETENTION_JOB}`]);
  });

  it("goes back to alerting the moment backups are expected again", async () => {
    await test.db.execute(
      sql`UPDATE job_runs SET finished_at = now() - interval '40 hours' WHERE job = ${BACKUP_JOB}`,
    );
    const report = await checkHealth(test.db, { backupsExpected: true });
    expect(report.problems.map((p) => p.code)).toEqual([`job.${BACKUP_JOB}`]);
  });
});
