/**
 * Is production all right?
 *
 *   DATABASE_URL="<production>" pnpm health:check
 *   DATABASE_URL="<production>" pnpm health:check --alert
 *
 * Read-only. Prints every figure it looked at, so a healthy run is still worth
 * reading, and exits non-zero when something is wrong.
 *
 * `--alert` emails the owner — ONLY when there is a problem. An alert that
 * arrives every day is an alert nobody opens, and the first thing anyone does
 * with a daily "all fine" message is write a filter for it.
 *
 * This is one half of a pair. It runs from CI on a schedule and watches the
 * Worker, including whether the Worker's own nightly cron is still firing. The
 * Worker's cron watches this, by noticing when the backup job — which only this
 * side can run — goes stale. Neither can report its own death, so each reports
 * the other's.
 */
import { checkHealth, worstSeverity } from "@inkloom/core/health";
import { createDb } from "@inkloom/db/client";
import { ResendTransport, templates } from "@inkloom/email";
import { describeTarget, optional, required } from "./_env";

async function main() {
  const url = required("DATABASE_URL");
  const alert = process.argv.includes("--alert");
  const environment = optional("INKLOOM_ENV", "production");

  const { db, pool } = createDb({ connectionString: url, max: 1 });

  try {
    console.log(`\n  Health of ${environment} — ${describeTarget(url)}\n`);

    const report = await checkHealth(db, {
      emailDailyQuota: Number(optional("EMAIL_DAILY_QUOTA", "0")),
      emailMonthlyQuota: Number(optional("EMAIL_MONTHLY_QUOTA", "50000")),
      backupsExpected: optional("BACKUPS_EXPECTED", "true") === "true",
    });

    for (const [key, value] of Object.entries(report.context)) {
      console.log(`  ..    ${key.padEnd(34)} ${value}`);
    }

    if (report.problems.length === 0) {
      console.log("\n  Healthy. Nothing to report.\n");
      return;
    }

    console.log("");
    for (const problem of report.problems) {
      console.log(`  ${problem.severity.toUpperCase().padEnd(8)} ${problem.summary}`);
      console.log(`           ${problem.detail}`);
    }

    if (alert) {
      const to = required("OWNER_EMAIL");
      const rendered = templates.operationalAlert(
        {
          appUrl: optional("APP_URL", "https://inkloom.art"),
          supportEmail: optional("SUPPORT_EMAIL", "support@inkloom.art"),
        },
        {
          environment,
          problems: report.problems,
          context: report.context,
          source: optional("HEALTH_SOURCE", "the scheduled health check"),
        },
      );

      const result = await new ResendTransport(required("RESEND_API_KEY")).send(
        { ...rendered, to, template: "operational_alert" },
        required("EMAIL_FROM"),
      );

      /*
       * A failed alert must not be mistaken for a healthy system, so it is
       * reported loudly — but it does not replace the exit code, which already
       * reflects the problems themselves.
       */
      console.log(
        result.ok
          ? `\n  Alerted ${to}.`
          : `\n  COULD NOT ALERT ${to}: ${result.error ?? "unknown error"}`,
      );
    }

    console.log("");
    process.exit(worstSeverity(report.problems) === "critical" ? 2 : 1);
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error("Health check failed to run:", error);
  process.exit(1);
});
