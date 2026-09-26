/**
 * The Cloudflare Worker entry.
 *
 * ONE Worker serves both the React application and the API, on one origin.
 * That is the same-origin backend-for-frontend the brief asks for: the session
 * cookie is first-party, there is no CORS anywhere, and the `__Host-` cookie
 * prefix applies.
 *
 *   /api/*   ->  Hono  (@inkloom/api)
 *   /*       ->  React Router SSR
 *
 * CONNECTION LIFETIME
 * -------------------
 * The database client is created PER REQUEST and closed with `waitUntil`.
 *
 * An earlier version cached a `pg` Pool for the life of the isolate, which is
 * the obvious optimisation and is wrong here: a Worker may not carry a socket
 * from one request context into another, so the cached pool intermittently
 * handed out a dead connection and queries failed with "Query read timeout"
 * — rarely under load, reliably after an idle gap, which is the worst kind of
 * bug to ship.
 *
 * Hyperdrive is what makes per-request clients cheap: it keeps the real pool of
 * Postgres connections at Cloudflare's edge, so opening a client here is a
 * local handshake rather than a new round trip to Neon.
 */
import { createRequestHandler, RouterContextProvider } from "react-router";
import { buildServices, createApiApp, resolveConfig } from "@inkloom/api";
import { createDb } from "@inkloom/db/client";
import { createLogger } from "@inkloom/core/logger";
import {
  accessTokenFrom,
  generateNonce,
  isUngatedPath,
  securityHeaders,
  verifyAccessToken,
} from "@inkloom/core/security";
import { recordJobRun, RETENTION_JOB, runRetentionSweep } from "@inkloom/core/retention";
import { checkHealth } from "@inkloom/core/health";
import { templates } from "@inkloom/email";
import {
  captureSelfMeasuredUsage,
  flushIfDue,
  record as recordRequest,
  rollUpDay,
  routeGroupFor,
} from "@inkloom/core/telemetry";
import { nonceContext, servicesContext } from "../app/lib/context";
import { runWithApiDispatch } from "../app/lib/api-dispatch.server";

interface WorkerEnv {
  /** Hyperdrive binding. Presents an ordinary Postgres connection string. */
  HYPERDRIVE?: { connectionString: string };
  DATABASE_URL?: string;
  [key: string]: unknown;
}

const requestHandler = createRequestHandler(
  () => import("virtual:react-router/server-build"),
  import.meta.env.MODE,
);

/**
 * Authenticated areas, which no shared cache may hold.
 *
 * The admin console's real prefix is a deployment secret, so it is added from
 * config at request time rather than listed here — a hardcoded "/admin" would
 * have silently stopped matching the moment a secret path was configured, and
 * the console would have started coming back cacheable.
 */
const PRIVATE_PATHS = ["/app", "/admin"];

/*
 * WHY THE MARKETING PAGES ARE NOT EDGE-CACHED
 * -------------------------------------------
 * They look like the obvious candidate: an anonymous request to `/` issues zero
 * database queries, so holding it at the edge would take the Worker out of the
 * path for exactly the traffic most likely to spike.
 *
 * It would also be a data leak. `routes/marketing/layout.tsx` has a loader that
 * resolves the session and server-renders the visitor's display name into the
 * header, so these pages are NOT identical for every visitor. A shared cache
 * would store one person's name and serve it to everyone who followed.
 *
 * `Vary: Cookie` is the textbook answer and does not help here: Cloudflare only
 * honours custom cache keys on Enterprise, and varying on the whole cookie
 * header would fragment the cache to a near-zero hit rate anyway.
 *
 * Two designs actually work, and both are a product decision rather than a
 * config change:
 *   1. Move the signed-in header state out of the loader and fetch it on the
 *      client after hydration. The document becomes genuinely public and fully
 *      cacheable; the header flickers from signed-out to signed-in.
 *   2. Cache only responses to requests carrying no session cookie, and bypass
 *      the cache entirely when one is present. Needs a Worker-side Cache API
 *      implementation, and signed-in visitors get no edge acceleration.
 *
 * Until one of those is chosen, no `public` caching goes on these routes.
 */

/** Open a per-request database client. See the connection-lifetime note above. */
/**
 * Is this database on a network only we can reach?
 *
 * Decides whether to demand TLS. A managed database — Neon, or anything behind
 * Hyperdrive — is reached across the public internet and must be encrypted. One
 * on the loopback or a private network is a developer's docker container or a
 * CI runner's, where there is no TLS to negotiate and demanding it only breaks
 * the connection.
 *
 * Private ranges are included, not just loopback, because a Worker in local dev
 * cannot open a connection to a loopback address at all: miniflare runs the
 * Worker behind a network policy that permits `public` and `private` addresses
 * and NOT `local`, so 127.0.0.1 is refused before it leaves the runtime. CI
 * therefore points the Worker at the runner's own private address, and that
 * address needs the same "no TLS" answer as loopback.
 *
 * Deliberately conservative: an address that is not demonstrably private gets
 * TLS. Getting this wrong in the other direction would send credentials in
 * clear text across a network we do not control.
 */
export function isPrivateAddress(connectionString: string): boolean {
  let host: string;
  try {
    host = new URL(connectionString).hostname;
  } catch {
    // Unparseable: assume the internet and keep TLS on.
    return false;
  }

  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || host === "[::1]") return true;

  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!v4) return false;

  const [a, b] = [Number(v4[1]), Number(v4[2])];
  return (
    a === 127 || // loopback
    a === 10 || // 10.0.0.0/8
    (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
    (a === 192 && b === 168) || // 192.168.0.0/16
    (a === 169 && b === 254) // link-local
  );
}

function connect(env: WorkerEnv) {
  const connectionString = env.HYPERDRIVE?.connectionString ?? (env.DATABASE_URL as string);
  if (!connectionString) {
    throw new Error("No database connection: bind HYPERDRIVE or set DATABASE_URL.");
  }

  const isLocal = isPrivateAddress(connectionString);

  return createDb({
    connectionString,
    // One connection is enough: a Worker request is single-threaded and the
    // real pooling happens in Hyperdrive.
    max: 1,
    ssl: !isLocal,
  });
}

/**
 * Cloudflare Access, enforced here rather than assumed.
 *
 * An Access policy is attached to a HOSTNAME. Anything that reaches this Worker
 * by another route — a workers.dev subdomain, a preview URL, a hostname added
 * later — arrives with no Access in front of it, and a staging environment that
 * everyone believes is private is then simply public. The failure is silent,
 * which is what makes it worth a check at the origin.
 *
 * Runs BEFORE the database client is opened: a request that is about to be
 * refused should not cost a connection.
 */
async function refuseUnlessAllowedIn(
  request: Request,
  env: WorkerEnv,
  pathname: string,
): Promise<Response | null> {
  const gate = resolveConfig(env as Record<string, unknown>).accessGate;
  if (!gate || isUngatedPath(pathname)) return null;

  const token = accessTokenFrom(request);
  const result = token
    ? await verifyAccessToken(token, gate)
    : ({ ok: false, reason: "no_token" } as const);

  if (result.ok) return null;

  /*
   * 403 with a bare explanation, and deliberately no detail about WHY.
   *
   * The reason is genuinely useful when setting this up and genuinely useful to
   * an attacker afterwards: "wrong_audience" says the gate is misconfigured,
   * "email_not_allowed" confirms both that a valid Access login exists and that
   * this environment is worth attacking. It goes to the log, which only the
   * operator reads, and never into the response.
   */
  // Its own logger: the gate deliberately runs before services are built, so
  // there is no request logger to borrow yet.
  createLogger({ level: "info", context: { env: String(env.INKLOOM_ENV ?? "") } }).warn(
    "access_gate_refused",
    { reason: result.reason, path: pathname },
  );

  return new Response("Not authorised for this environment.", {
    status: 403,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      // Nothing here is ever a shared-cache hit, and a proxy that cached one
      // 403 would lock out the person who IS allowed in.
      vary: "cookie, cf-access-jwt-assertion",
    },
  });
}

/**
 * Send www to the bare domain, once, permanently.
 *
 * `www.inkloom.art` is a CNAME to the apex and it is PROXIED, so Cloudflare
 * accepts the connection and then looks for an origin it does not have —
 * 522, which reads as "the site is down" rather than "that is not the address".
 * Attaching the hostname to this Worker gives it an origin; redirecting here is
 * what stops the same pages being served, and indexed, under two names.
 *
 * 308 rather than 301: a 301 lets an intermediary rewrite a POST into a GET,
 * which would silently turn a submitted form into a blank page.
 */
export function redirectToCanonicalHost(request: Request, env: WorkerEnv): Response | null {
  const appUrl = typeof env.APP_URL === "string" ? env.APP_URL : "";
  if (!appUrl) return null;

  const canonical = new URL(appUrl).hostname;
  const url = new URL(request.url);
  if (url.hostname !== `www.${canonical}`) return null;

  url.hostname = canonical;
  return Response.redirect(url.toString(), 308);
}

export default {
  async fetch(request: Request, env: WorkerEnv, ctx: ExecutionContext): Promise<Response> {
    // Before the Access gate and before the database: a request that is only
    // going to be redirected should cost neither a JWKS fetch nor a connection.
    const canonical = redirectToCanonicalHost(request, env);
    if (canonical) return canonical;

    const refusal = await refuseUnlessAllowedIn(request, env, new URL(request.url).pathname);
    if (refusal) return refusal;

    const { db, pool } = connect(env);

    const services = buildServices({ db, env: env as Record<string, unknown> });
    const url = new URL(request.url);
    const startedAt = Date.now();

    /**
     * Record the request, flush if due, then close the connection — in that
     * order, after the handler has finished.
     *
     * `ctx.waitUntil` extends the isolate's lifetime; it does NOT defer the
     * promise it is given. Passing `pool.end()` directly therefore ended the
     * pool immediately, before a single loader had run, and every request
     * failed with "Cannot use a pool after calling end on the pool".
     *
     * The flush is CHAINED ahead of the close rather than scheduled beside it.
     * Two independent `waitUntil` calls have no ordering guarantee, so the pool
     * could end first and every flush would fail against a dead connection —
     * silently, since a flush must never turn a served request into an error.
     * Telemetry would simply have been empty forever, which is the kind of bug
     * that is only noticed months later when someone asks for a graph.
     */
    /*
     * Background work started by a route, which must finish before the pool does.
     *
     * Handlers defer observational writes — security events, the "you already
     * have an account" notice — with `waitUntil`. Those keep the ISOLATE alive,
     * which is what `waitUntil` is for, but they say nothing about the database
     * CLIENT, and this request owns a client it is about to close.
     *
     * That race was real and it was silent. In production `flushIfDue` almost
     * always has nothing to flush and resolves at once, so `pool.end()` ran
     * within a tick of the response. A deferred single INSERT usually beat it;
     * a deferred SELECT-then-send-then-INSERT never did. The symptom was a
     * duplicate signup that recorded its security event and sent no email —
     * half the side effects landing, with no error anywhere, because both
     * failures were swallowed by design.
     *
     * Collecting them here and closing the pool only once they have all settled
     * is the fix. `waitUntil` is still called on each, so the isolate outlives
     * the response either way.
     */
    const deferred: Array<Promise<unknown>> = [];
    /*
     * Spread from the real one so every field the runtime adds — exports,
     * props, tracing, abort — comes along, and only `waitUntil` is intercepted.
     * Enumerating them by hand would break on the next runtime version.
     */
    const apiCtx: ExecutionContext = {
      ...ctx,
      passThroughOnException: () => ctx.passThroughOnException(),
      waitUntil(promise) {
        // Never let a rejection escape: these are side effects whose failure
        // must not turn a served request into an error.
        const settled = Promise.resolve(promise).catch(() => {});
        deferred.push(settled);
        ctx.waitUntil(settled);
      },
    };

    const finish = (status: number, errorCode?: string | null) => {
      recordRequest(
        {
          routeGroup: routeGroupFor(url.pathname, services.config.ADMIN_PATH),
          status,
          durationMs: Date.now() - startedAt,
          errorCode,
        },
        new Date(),
      );

      ctx.waitUntil(
        Promise.allSettled(deferred)
          // Eager in development only: the dev server re-evaluates modules per
          // request, so nothing would ever accumulate long enough to flush.
          .then(() =>
            flushIfDue(db, services.logger, services.config.INKLOOM_ENV === "development"),
          )
          .catch(() => {})
          .finally(() => pool.end().catch(() => {})),
      );
    };

    // --- API ---------------------------------------------------------------
    // Returns JSON, sets its own headers, and must not receive the document CSP.
    if (url.pathname.startsWith("/api/")) {
      const apiResponse = await createApiApp(services).fetch(request, env, apiCtx);
      /*
       * The typed code from the error envelope, when there is one.
       *
       * A category — RATE_LIMITED, DB_TIMEOUT — never a message. Messages carry
       * addresses, ids and query fragments, and this lands in a table with a
       * longer life and a wider audience than anything that should hold them.
       * Stack traces go to Sentry, which is built for them.
       */
      finish(apiResponse.status, apiResponse.headers.get("x-error-code"));
      return apiResponse;
    }

    /*
     * --- The decoy ---------------------------------------------------------
     *
     * The console is mounted at `ADMIN_PATH` by the route table itself (see
     * app/routes.ts), so the router generates correct links and nothing needs
     * rewriting here. What this does is make the obvious path a dead end: once
     * a secret path is configured, /admin answers exactly as any other missing
     * URL does, with no header, no redirect and no timing tell to distinguish
     * "moved" from "never existed".
     *
     * Obscurity only. Every request that reaches the real path still faces the
     * whole server-side gate — session, role, owner, 2FA, rate limit, audit —
     * and that gate would hold if this path were printed on the home page.
     */
    const adminPath = services.config.ADMIN_PATH;
    if (
      adminPath !== "/admin" &&
      (url.pathname === "/admin" || url.pathname.startsWith("/admin/"))
    ) {
      finish(404);
      return new Response("Not found", {
        status: 404,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
      });
    }

    // --- Documents ---------------------------------------------------------
    // A fresh nonce per response, so the CSP can forbid inline script wholesale
    // while React Router's own hydration script still runs.
    const nonce = generateNonce();

    const context = new RouterContextProvider();
    context.set(servicesContext, services);
    context.set(nonceContext, nonce);

    /*
     * Loaders and actions call the API in-process, not over the network.
     *
     * A Worker cannot fetch its own hostname: the subrequest is not routed back
     * into the Worker but into the asset handler, which returns an empty 404
     * that the caller cannot parse as JSON. Vite's dev server does loop back,
     * so this was invisible locally and broke every data path once deployed.
     *
     * The app is built lazily and memoised for the life of the request, so a
     * document making no API calls builds nothing, and one making five builds
     * it once.
     */
    let apiApp: ReturnType<typeof createApiApp> | undefined;
    const response = await runWithApiDispatch(
      async (apiRequest) => (apiApp ??= createApiApp(services)).fetch(apiRequest, env, apiCtx),
      () => requestHandler(request, context),
    );
    /**
     * Safe here even though SSR streams: React Router resolves every loader
     * before rendering begins, and no route defers data with `Await`, so all
     * database work is complete by the time this resolves.
     */
    finish(response.status);

    const headers = securityHeaders({
      nonce,
      isProduction: services.config.isProduction,
      // The transport, not the environment: staging is HTTPS and must rehearse
      // the same CSP and HSTS production will run.
      isSecureTransport: url.protocol === "https:",
      connectSrc: services.config.SENTRY_DSN ? [originOf(services.config.SENTRY_DSN)] : [],
    });

    for (const [key, value] of Object.entries(headers)) {
      response.headers.set(key, value);
    }

    if ([...PRIVATE_PATHS, adminPath].some((path) => url.pathname.startsWith(path))) {
      response.headers.set("Cache-Control", "no-store, must-revalidate, private");
    } else {
      /*
       * Every other document renders the visitor's signed-in state (see the note
       * above the route lists), so none of them may enter a shared cache. Said
       * explicitly rather than left to a default, because the default is what a
       * CDN in front of this would guess.
       */
      response.headers.set("Cache-Control", "private, no-cache");
    }

    return response;
  },

  /**
   * Cron entry point.
   *
   * Everything the privacy policy promises to delete is deleted here, and
   * nowhere else. Before this existed the periods published at /privacy were
   * enforced by nothing at all: `purgeExpired` was written and never called,
   * and a data export whose payload the policy said was gone after 24 hours was
   * still sitting in the table.
   *
   * The connection is closed in a `finally`, not via `waitUntil`: a scheduled
   * invocation has no response to hang the lifetime off, so the handler must
   * own it from open to close or the pool leaks on every failure.
   */
  async scheduled(event: ScheduledController, env: WorkerEnv, ctx: ExecutionContext) {
    const { db, pool } = connect(env);
    const services = buildServices({ db, env: env as Record<string, unknown> });
    const logger = services.logger.child({ cron: event.cron });
    const startedAt = Date.now();

    try {
      /*
       * Roll up BEFORE sweeping, not after.
       *
       * The sweep deletes expired security and analytics rows, which are the
       * very rows the roll-up counts. Running it first would quietly understate
       * every figure on the boundary day — a bug that produces plausible
       * numbers, which is the worst kind. The two are sequential rather than
       * parallel for the same reason.
       */
      await rollUpDay(db, logger).catch((error: unknown) => {
        logger.error("daily_rollup_failed", { error });
        services.monitoring.captureException(error, { extra: { job: "daily_rollup" } });
      });
      await captureSelfMeasuredUsage(db, logger).catch((error: unknown) => {
        logger.error("usage_capture_failed", { error });
      });

      const result = await runRetentionSweep(db, logger);

      /*
       * A partial failure is reported, not swallowed and not thrown.
       *
       * Throwing would mark the whole invocation failed and lose the steps that
       * did succeed; staying silent would let a step fail every night unnoticed.
       * Sentry gets told, the next run retries it, and nothing is lost either
       * way because every step is idempotent.
       */
      if (result.failed > 0) {
        const failures = result.steps.filter((s) => !s.ok);
        logger.error("retention_sweep_partial", {
          failed: result.failed,
          steps: failures.map((s) => `${s.name}: ${s.error}`),
        });
        services.monitoring.captureMessage(`Retention sweep: ${result.failed} step(s) failed`, {
          extra: { steps: failures.map((s) => ({ step: s.name, error: s.error })) },
        });
      }

      /*
       * Tell somebody, once a day, and only when something is wrong.
       *
       * Everything this application knows about its own health was already
       * recorded — job runs, 5xx counts, ledger drift, failed mail — and all of
       * it sat in tables that only report to a console nobody watches at four
       * in the morning. A failure that is recorded and never delivered is
       * indistinguishable, from the outside, from one that was never detected.
       *
       * This half of the pair watches the things the SCHEDULED SIDE cannot:
       * backups run from CI, so only the application can notice they have
       * stopped. The CI side returns the favour by noticing when this cron
       * stops — nothing can report its own death, so each reports the other's.
       *
       * Never throws. An alerting failure must not mark the nightly job failed
       * and so cause a second, more confusing alert about itself.
       */
      await notifyOwnerOfProblems(db, services, logger).catch((error: unknown) => {
        logger.error("health_alert_failed", { error });
      });
    } catch (error) {
      logger.error("retention_sweep_failed", { error });
      services.monitoring.captureException(error, { extra: { cron: event.cron } });

      /*
       * Record the failure durably before rethrowing.
       *
       * Staleness alone would eventually catch this, but only after the job
       * had been missing for a day — and it could not say WHY. A `failed` row
       * names the error at the moment it happened. Best-effort: if the
       * database is what broke, this insert cannot work either, and staleness
       * is the backstop that does not depend on anything working.
       */
      await recordJobRun(db, {
        job: RETENTION_JOB,
        startedAt: new Date(startedAt),
        finishedAt: new Date(),
        status: "failed",
        durationMs: Date.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      }).catch(() => {});

      throw error;
    } finally {
      ctx.waitUntil(pool.end().catch(() => {}));
    }
  },
} satisfies ExportedHandler<WorkerEnv>;

/**
 * Email the owner when the nightly health check finds something.
 *
 * Silent when healthy, on purpose: a daily "all fine" message trains its
 * recipient to filter the address, and the one that matters arrives in the
 * folder nobody opens.
 */
async function notifyOwnerOfProblems(
  db: ReturnType<typeof connect>["db"],
  services: ReturnType<typeof buildServices>,
  logger: ReturnType<typeof createLogger>,
): Promise<void> {
  const owner = services.config.OWNER_EMAIL;
  if (!owner) {
    logger.info("health_alert_skipped", { reason: "no OWNER_EMAIL configured" });
    return;
  }

  const report = await checkHealth(db, {
    emailDailyQuota: services.config.EMAIL_DAILY_QUOTA,
    emailMonthlyQuota: services.config.EMAIL_MONTHLY_QUOTA,
    backupsExpected: services.config.BACKUPS_EXPECTED,
  });
  if (report.problems.length === 0) {
    logger.info("health_ok", report.context);
    return;
  }

  logger.error("health_problems", {
    count: report.problems.length,
    codes: report.problems.map((p) => p.code),
  });

  const rendered = templates.operationalAlert(
    { appUrl: services.config.APP_URL, supportEmail: services.config.SUPPORT_EMAIL },
    {
      environment: String(services.config.INKLOOM_ENV),
      problems: report.problems,
      context: report.context,
      source: "the nightly job on the application itself",
    },
  );

  // `force`, because this is operational mail to the operator: it is not
  // subject to the notification preferences that govern mail to users.
  await services.mailer.send({
    to: owner,
    template: "operational_alert",
    rendered,
    force: true,
  });
}

function originOf(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}
