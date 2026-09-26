/**
 * What "production is fine" means, written once.
 *
 * Two things ask this question and they watch each other. The Worker's nightly
 * cron asks it and emails the owner; a scheduled GitHub job asks it and emails
 * the owner. Neither can report its own death — a cron that stops firing cannot
 * tell you it has stopped — so each one's freshness is a check the OTHER
 * performs. That mutual arrangement only works if both are measuring the same
 * thing, which is why this lives in core rather than in either caller.
 *
 * Everything here is read-only.
 */
import { sql } from "drizzle-orm";
import type { Database } from "@inkloom/db/client";
import {
  BACKUP_JOB,
  jobHealth,
  JOB_MAX_AGE_HOURS,
  RESTORE_TEST_JOB,
  RETENTION_JOB,
} from "../retention";

export type Severity = "critical" | "warning";

export interface HealthProblem {
  severity: Severity;
  /** Stable identifier, so an alert can be recognised as "the same one again". */
  code: string;
  summary: string;
  detail: string;
}

export interface HealthReport {
  checkedAt: Date;
  problems: HealthProblem[];
  /** Figures worth seeing even when nothing is wrong. */
  context: Record<string, string>;
}

/**
 * A scheduled job that has not run inside its window.
 *
 * `critical` for backups: an environment whose backups stopped is one bad
 * afternoon from losing everything, and the gap is invisible until the day it
 * matters. `warning` for the restore test, which is a week-long window and a
 * failure of assurance rather than of the thing being assured.
 */
const JOB_SEVERITY: Record<string, Severity> = {
  [BACKUP_JOB]: "critical",
  [RETENTION_JOB]: "warning",
  [RESTORE_TEST_JOB]: "warning",
};

export interface HealthOptions {
  /**
   * Whether backups are expected to be running at all.
   *
   * False while the schedules are deliberately paused. A paused job and a
   * broken one look identical from here — both are simply overdue — and
   * reporting the paused one as a problem every morning is how an alert
   * becomes something people filter. It is still REPORTED, as context, so a
   * pause nobody meant to leave in place is visible rather than silent.
   */
  backupsExpected?: boolean;
  /**
   * The mail provider's daily send limit, or 0 when the plan has none.
   *
   * Passed in rather than read from the environment: inside a Worker,
   * `process.env` does not carry the deployment's `vars`, so a value configured
   * there would have been ignored while appearing to be set.
   */
  emailDailyQuota?: number;
  /** The mail provider's monthly send limit, or 0 to not watch it. */
  emailMonthlyQuota?: number;
}

export async function checkHealth(
  db: Database,
  options: HealthOptions = {},
): Promise<HealthReport> {
  const problems: HealthProblem[] = [];
  const context: Record<string, string> = {};

  const backupsExpected = options.backupsExpected ?? true;
  const paused = new Set(backupsExpected ? [] : [BACKUP_JOB, RESTORE_TEST_JOB]);

  for (const job of [BACKUP_JOB, RETENTION_JOB, RESTORE_TEST_JOB]) {
    const health = await jobHealth(db, job, JOB_MAX_AGE_HOURS[job]);
    const age =
      health.ageHours === null ? "never run" : `${health.ageHours}h ago, ${health.lastStatus}`;
    context[job] = paused.has(job) ? `${age} (PAUSED)` : age;

    if (!health.healthy && !paused.has(job)) {
      problems.push({
        severity: JOB_SEVERITY[job] ?? "warning",
        code: `job.${job}`,
        summary: `The ${job.replace(/_/g, " ")} job is overdue`,
        detail:
          health.ageHours === null
            ? "It has never run."
            : `Last ran ${health.ageHours}h ago with status "${health.lastStatus}". ` +
              `The window is ${JOB_MAX_AGE_HOURS[job]}h.`,
      });
    }
  }

  /*
   * The ledger is the accounting record and a wallet is a cache of it. Drift
   * means one of them is lying, and there is no safe amount of that.
   */
  const drift = await db.execute<{ n: string }>(sql`
    SELECT COUNT(*)::text AS n FROM credit_wallets w
     WHERE w.balance <> COALESCE(
       (SELECT SUM(amount) FROM credit_ledger l WHERE l.user_id = w.user_id), 0)
  `);
  const drifted = drift.rows[0]?.n ?? "0";
  context.ledger_drift = drifted;
  if (Number(drifted) > 0) {
    problems.push({
      severity: "critical",
      code: "credits.drift",
      summary: "A wallet disagrees with the credit ledger",
      detail: `${drifted} wallet(s) drifted. Run \`pnpm credits:reconcile\` to see which.`,
    });
  }

  const errors = await db.execute<{ n: string }>(sql`
    SELECT COALESCE(SUM(status_5xx), 0)::text AS n FROM request_metrics
     WHERE updated_at > now() - interval '24 hours'
  `);
  const fiveXx = errors.rows[0]?.n ?? "0";
  context.errors_24h = fiveXx;
  if (Number(fiveXx) > 0) {
    problems.push({
      severity: "warning",
      code: "requests.5xx",
      summary: "The application returned server errors",
      detail: `${fiveXx} 5xx response(s) in the last 24 hours.`,
    });
  }

  const critical = await db.execute<{ n: string; newest: string | null }>(sql`
    SELECT COUNT(*)::text AS n, MAX(created_at)::text AS newest
      FROM security_events
     WHERE severity = 'critical' AND created_at > now() - interval '24 hours'
  `);
  const criticalCount = critical.rows[0]?.n ?? "0";
  const criticalNewest = critical.rows[0]?.newest ?? "unknown";
  context.critical_security_events_24h = criticalCount;
  if (Number(criticalCount) > 0) {
    problems.push({
      severity: "critical",
      code: "security.critical",
      summary: "Critical security events were recorded",
      detail: `${criticalCount} in the last 24 hours, newest at ${criticalNewest}.`,
    });
  }

  /*
   * Email that leaves and does not arrive. Verification mail is the whole
   * signup flow, so a provider problem reads to users as "the product is
   * broken" while every dashboard stays green.
   */
  const mail = await db.execute<{ failed: string; total: string }>(sql`
    SELECT COUNT(*) FILTER (WHERE status IN ('failed','bounced'))::text AS failed,
           COUNT(*)::text AS total
      FROM email_events WHERE created_at > now() - interval '24 hours'
  `);
  const mailFailed = mail.rows[0]?.failed ?? "0";
  const mailTotal = mail.rows[0]?.total ?? "0";
  context.email_24h = `${mailFailed} failed of ${mailTotal}`;
  if (Number(mailFailed) > 0) {
    problems.push({
      severity: "critical",
      code: "email.failed",
      summary: "Email is failing to deliver",
      detail: `${mailFailed} of ${mailTotal} message(s) failed or bounced in the last 24 hours.`,
    });
  }

  /*
   * The provider's send quota, which nothing else in the system can see.
   *
   * Every signup sends a verification email, so the mail quota IS the signup
   * capacity. Exhaust it and signup does not fail loudly — the account is
   * created, the email never arrives, and the person sits on the "check your
   * email" page forever. There is no error anywhere that says so.
   *
   * WHICH quota, though, is the part this got wrong, and it cried wolf for it.
   *
   * It watched a rolling 24-hour window against a hardcoded ceiling of 100 and
   * called that "the daily quota". Three things were wrong with that. The 100
   * belongs to the provider's FREE plan, and survived the upgrade to a paid one
   * because it lived in configuration rather than anywhere near the truth. A
   * paid plan has NO daily limit at all — only a monthly one, which nothing
   * here measured. And even on the free plan the number never matched: the
   * provider counts a UTC calendar day that resets at midnight, not a window
   * sliding backwards from now.
   *
   * So it reported "131 of 100 — critical, new accounts never hear from us" on
   * an account with forty-nine thousand messages left in the month and nothing
   * whatsoever wrong. That is worse than no alert: the next one gets ignored,
   * and mail failing during a launch is exactly when it must not be.
   *
   * Now: the monthly allowance is watched as a UTC calendar month, matching how
   * the provider bills it, and the daily ceiling is watched only when the plan
   * actually has one (0 means it does not).
   */
  const dailyQuota = options.emailDailyQuota ?? 0;
  const monthlyQuota = options.emailMonthlyQuota ?? 0;

  const sent = await db.execute<{ day: string; month: string }>(sql`
    SELECT
      COUNT(*) FILTER (WHERE created_at >= date_trunc('day', now() AT TIME ZONE 'UTC'))::text
        AS day,
      COUNT(*) FILTER (WHERE created_at >= date_trunc('month', now() AT TIME ZONE 'UTC'))::text
        AS month
    FROM email_events
  `);
  const sentToday = Number(sent.rows[0]?.day ?? 0);
  const sentThisMonth = Number(sent.rows[0]?.month ?? 0);

  if (monthlyQuota > 0) {
    context.email_quota = `${sentThisMonth} of ${monthlyQuota} this month (UTC)`;
    if (sentThisMonth >= monthlyQuota * 0.8) {
      problems.push({
        severity: sentThisMonth >= monthlyQuota ? "critical" : "warning",
        code: "email.quota",
        summary:
          sentThisMonth >= monthlyQuota
            ? "The monthly email quota is exhausted"
            : "The monthly email quota is nearly used up",
        detail:
          `${sentThisMonth} of ${monthlyQuota} sent this calendar month. Every signup needs a ` +
          `verification email, so when this runs out new accounts are created and never hear ` +
          `from us — with no error shown to them and none recorded here. This counts only ` +
          `mail THIS application sent; if the provider account is shared, the real figure is ` +
          `higher, and the provider's own dashboard is the authority.`,
      });
    }
  } else {
    context.email_quota = `${sentThisMonth} this month (UTC), no monthly limit configured`;
  }

  if (dailyQuota > 0) {
    context.email_quota_day = `${sentToday} of ${dailyQuota} today (UTC)`;
    if (sentToday >= dailyQuota * 0.8) {
      problems.push({
        severity: sentToday >= dailyQuota ? "critical" : "warning",
        code: "email.quota.daily",
        summary:
          sentToday >= dailyQuota
            ? "The daily email quota is exhausted"
            : "The daily email quota is nearly used up",
        detail:
          `${sentToday} of ${dailyQuota} sent today (UTC, resets at midnight). A daily ceiling ` +
          `means this deployment is on the provider's free plan; upgrading removes it.`,
      });
    }
  }

  /*
   * A campaign that has run out looks exactly like a wrong code.
   *
   * That is deliberate — telling a stranger which codes exist is an invitation
   * to enumerate them — but it means the day a campaign fills up, every new
   * arrival is told their code is "invalid or unavailable", assumes a typo,
   * retries, and trips the redemption rate limiter on their way out. The only
   * way that does not become a silent cliff is to know it is coming.
   */
  const campaigns = await db.execute<{ name: string; used: string; cap: string }>(sql`
    SELECT name,
           redemption_count::text     AS used,
           max_total_redemptions::text AS cap
      FROM access_code_campaigns
     WHERE status = 'enabled' AND max_total_redemptions IS NOT NULL
       AND redemption_count >= max_total_redemptions * 0.8
  `);
  for (const row of campaigns.rows) {
    const full = Number(row.used) >= Number(row.cap);
    problems.push({
      severity: full ? "critical" : "warning",
      code: "campaign.capacity",
      summary: full
        ? `The "${row.name}" campaign is full`
        : `The "${row.name}" campaign is nearly full`,
      detail:
        `${row.used} of ${row.cap} redemptions used. ` +
        (full
          ? "Every further attempt is told the code is invalid or unavailable, which reads as a typo."
          : "Raise the cap or start another campaign before it runs out."),
    });
  }

  return { checkedAt: new Date(), problems, context };
}

/** Critical outranks warning; used to decide how loudly to say it. */
export function worstSeverity(problems: HealthProblem[]): Severity | null {
  if (problems.some((p) => p.severity === "critical")) return "critical";
  return problems.length > 0 ? "warning" : null;
}
