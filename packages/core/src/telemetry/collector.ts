/**
 * In-isolate request metrics, flushed as aggregates.
 *
 * THE CONSTRAINT: a request must not write to the database to be measured.
 *
 * A signup already costs 15-17 round trips and a dashboard view 17-29. Adding a
 * telemetry insert to each would make observing the system the most expensive
 * thing it does, and the table would grow fastest exactly when traffic spiked —
 * the worst possible coupling.
 *
 * So this accumulates counters in module scope, which in a Worker means "for as
 * long as this isolate lives", and writes one row per flush interval per
 * isolate. At early-access volume that is a handful of writes an hour, against
 * thousands of requests.
 *
 * WHAT IS DELIBERATELY GIVEN UP
 * -----------------------------
 * An isolate can be discarded at any moment, taking unflushed counters with it.
 * That is accepted: these are operational trends, not an audit trail, and a
 * slightly low request count on a quiet hour changes no decision. Anything that
 * must not be lost — credits, consent, admin actions — is written
 * transactionally by the handler, never through here.
 *
 * WHY A HISTOGRAM AND NOT A PERCENTILE
 * ------------------------------------
 * Percentiles do not merge. Several isolates serve traffic simultaneously and
 * each reports separately; averaging two p95 values yields a number that is not
 * the p95 of anything. Bucket counts add, so the merged histogram is exact and
 * the percentile is computed from it at read time.
 */
import { bucketFor } from "./buckets";

export { bucketFor };

export interface RequestSample {
  routeGroup: string;
  status: number;
  durationMs: number;
  /** A typed category such as "DB_TIMEOUT" — never a raw error message. */
  errorCode?: string | null;
}

interface Slot {
  day: string;
  hour: number;
  routeGroup: string;
  requests: number;
  status2xx: number;
  status3xx: number;
  status4xx: number;
  status429: number;
  status5xx: number;
  durationMsTotal: number;
  durationMsMax: number;
  latencyBuckets: Record<string, number>;
  errorCodes: Record<string, number>;
}

/**
 * Accumulated slots, keyed by day|hour|routeGroup.
 *
 * Module scope on purpose — see the note above `SettingsService`'s cache for
 * the same reasoning. Per-instance state here would be discarded every request
 * and the collector would never accumulate anything at all.
 */
const slots = new Map<string, Slot>();
let lastFlushAt = Date.now();

/**
 * How long an isolate may hold counters before writing them out.
 *
 * THIS INTERVAL IS A BILLING CONTROL, not a freshness preference, and it must
 * stay comfortably above `SCALE_TO_ZERO_IDLE_MS`.
 *
 * Neon suspends a compute after five minutes with no queries, and a suspended
 * compute is free. This flush is the only Postgres write that fires on traffic
 * alone -- it needs no user, no session and no JavaScript, so a scanner probing
 * the site is enough to trigger it. At the previous 60 seconds it therefore
 * reset the five-minute idle timer before it could ever elapse, and the
 * database never slept: ~16 hours a day awake, 110 CU-hours in October 2026,
 * which exhausted the Free plan's 100 and took signups down for ~45 hours.
 *
 * Thirty minutes means the compute is woken roughly twice an hour and sleeps
 * through the rest, at the cost of admin request-metrics graphs lagging by up
 * to half an hour. Telemetry is already lossy by design -- `drain()` clears the
 * counters before the write, and in-memory counters die with the isolate -- so
 * staleness is the cheapest thing here to spend.
 */
const FLUSH_INTERVAL_MS = 30 * 60_000;

/**
 * Neon's scale-to-zero idle window: five minutes of no queries at all.
 *
 * Exported so the test suite can assert the invariant above rather than
 * restating the number, and so the next person to tune the interval sees what
 * it is measured against.
 */
export const SCALE_TO_ZERO_IDLE_MS = 5 * 60_000;

/** Exported for the same reason. */
export const FLUSH_INTERVAL = FLUSH_INTERVAL_MS;
/** A hard ceiling, so a burst flushes on volume rather than waiting for the clock. */
const FLUSH_AT_SLOTS = 64;

function slotKey(day: string, hour: number, routeGroup: string): string {
  return `${day}|${hour}|${routeGroup}`;
}

/**
 * Reduce a path to a coarse group.
 *
 * Never the raw path: `/admin/users/usr_01H…` names a person, and a metrics
 * table has a longer life and a wider audience than anything that should carry
 * that. Who was looked at belongs in the audit trail, which is append-only and
 * access-controlled; this is for "how much, how fast, how often broken".
 */
export function routeGroupFor(pathname: string, adminPath = "/admin"): string {
  if (pathname.startsWith("/api/")) {
    const segment = pathname.split("/")[3] ?? "root";
    return `api.${segment.replace(/[^a-z0-9-]/gi, "") || "root"}`;
  }
  if (pathname === adminPath || pathname.startsWith(`${adminPath}/`)) return "admin";
  if (pathname === "/app" || pathname.startsWith("/app/")) return "app";
  if (pathname.startsWith("/auth/")) return "auth";
  return "marketing";
}

/** Record one request. Pure bookkeeping — never touches the database. */
export function record(sample: RequestSample, now: Date = new Date()): void {
  const day = now.toISOString().slice(0, 10);
  const hour = now.getUTCHours();
  const key = slotKey(day, hour, sample.routeGroup);

  let slot = slots.get(key);
  if (!slot) {
    slot = {
      day,
      hour,
      routeGroup: sample.routeGroup,
      requests: 0,
      status2xx: 0,
      status3xx: 0,
      status4xx: 0,
      status429: 0,
      status5xx: 0,
      durationMsTotal: 0,
      durationMsMax: 0,
      latencyBuckets: {},
      errorCodes: {},
    };
    slots.set(key, slot);
  }

  slot.requests += 1;
  slot.durationMsTotal += Math.round(sample.durationMs);
  slot.durationMsMax = Math.max(slot.durationMsMax, Math.round(sample.durationMs));

  // 429 is counted on its own AND left out of 4xx: "we are refusing people" and
  // "people are sending us nonsense" are different operational situations and
  // folding them together hides a rate-limit storm inside ordinary noise.
  if (sample.status === 429) slot.status429 += 1;
  else if (sample.status >= 500) slot.status5xx += 1;
  else if (sample.status >= 400) slot.status4xx += 1;
  else if (sample.status >= 300) slot.status3xx += 1;
  else slot.status2xx += 1;

  const bucket = bucketFor(sample.durationMs);
  slot.latencyBuckets[bucket] = (slot.latencyBuckets[bucket] ?? 0) + 1;

  if (sample.errorCode) {
    slot.errorCodes[sample.errorCode] = (slot.errorCodes[sample.errorCode] ?? 0) + 1;
  }
}

/**
 * Whether enough time or volume has passed to justify a write.
 *
 * `eager` exists because of a real limitation rather than a preference. This
 * whole design assumes a long-lived isolate: workerd keeps one alive for
 * minutes, so a 60-second interval means a handful of writes an hour against
 * thousands of requests. The Vite dev server does not — it re-evaluates modules
 * per request, so `slots` is empty and `lastFlushAt` is `now` on every single
 * request, and nothing would EVER flush locally.
 *
 * Verified by experiment, not assumed: with the interval temporarily dropped to
 * one second, twelve requests over five seconds still produced zero rows.
 *
 * So development flushes on every request. That is a database write per request,
 * which would be indefensible in production and is nothing at all against the
 * dozen requests a developer makes — and it buys an end-to-end check of the
 * pipeline that would otherwise be impossible to run outside a deployment.
 */
export function shouldFlush(now: number = Date.now(), eager = false): boolean {
  if (slots.size === 0) return false;
  if (eager) return true;
  return now - lastFlushAt >= FLUSH_INTERVAL_MS || slots.size >= FLUSH_AT_SLOTS;
}

/**
 * Hand over everything accumulated so far and reset.
 *
 * Drains BEFORE the caller writes, not after: if the write fails, the counters
 * are already gone. That is the right way round — retrying would need the
 * counters held while another request thread kept adding to them, and
 * double-counting an hour of traffic is a worse outcome than losing a minute of
 * it. Losing telemetry is survivable by design; corrupting it is not.
 */
export function drain(now: number = Date.now()): Slot[] {
  const drained = [...slots.values()];
  slots.clear();
  lastFlushAt = now;
  return drained;
}

/** Test seam: forget everything, including the flush clock. */
export function reset(): void {
  slots.clear();
  lastFlushAt = Date.now();
}

export type { Slot as MetricSlot };
