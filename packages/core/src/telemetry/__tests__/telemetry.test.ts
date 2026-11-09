/**
 * Telemetry collection: the pure half.
 *
 * Bucketing, grouping, percentile arithmetic and the drain contract need no
 * database, so they live in the `unit` project and run on every change. The
 * merge across isolates happens in SQL and is proved in the integration file
 * beside this one — the projects are split because the integration project
 * disables file parallelism, and a database test running in `unit` truncates
 * tables out from under whatever else is running at the same time.
 */
import { beforeEach, describe, expect, it } from "vitest";
import {
  FLUSH_INTERVAL,
  SCALE_TO_ZERO_IDLE_MS,
  bucketFor,
  drain,
  record,
  reset,
  routeGroupFor,
  shouldFlush,
} from "../collector";
import { percentileFrom } from "../flush";

beforeEach(() => {
  reset();
});

describe("route grouping", () => {
  it("never lets an identifier into the metrics table", () => {
    /*
     * The whole point of grouping. A raw path carries ids — who was looked at,
     * whose ledger was opened — and this table outlives and out-scopes anything
     * that should hold that. Those facts belong in the audit trail.
     */
    expect(routeGroupFor("/admin/users/usr_01H8XGJWBWBAQ4")).toBe("admin");
    expect(routeGroupFor("/api/v1/admin/users/usr_01H8XGJ")).toBe("api.admin");
    expect(routeGroupFor("/app/credits")).toBe("app");
    expect(routeGroupFor("/pricing")).toBe("marketing");
    expect(routeGroupFor("/auth/login")).toBe("auth");
  });

  it("follows the console to its secret mount point", () => {
    expect(routeGroupFor("/internal-admin-7f3a/users", "/internal-admin-7f3a")).toBe("admin");
    // ...and does not mistake a lookalike for it.
    expect(routeGroupFor("/internal-admin-7f3a-other", "/internal-admin-7f3a")).toBe("marketing");
  });
});

describe("collecting", () => {
  it("separates 429 from other 4xx", () => {
    // A rate-limit storm and a wave of malformed requests are different
    // situations; folding them together hides the first inside the second.
    record({ routeGroup: "api.auth", status: 429, durationMs: 5 });
    record({ routeGroup: "api.auth", status: 400, durationMs: 5 });
    record({ routeGroup: "api.auth", status: 500, durationMs: 5 });

    const [slot] = drain();
    expect(slot).toBeDefined();
    expect(slot!.status429).toBe(1);
    expect(slot!.status4xx).toBe(1);
    expect(slot!.status5xx).toBe(1);
  });

  it("puts durations in the right buckets", () => {
    expect(bucketFor(3)).toBe("5");
    expect(bucketFor(5)).toBe("5");
    expect(bucketFor(6)).toBe("10");
    expect(bucketFor(99)).toBe("100");
    expect(bucketFor(9_999)).toBe("inf");
  });

  it("writes nothing on its own and holds until a flush is due", () => {
    record({ routeGroup: "marketing", status: 200, durationMs: 12 });
    // Freshly reset, so the interval has not elapsed and one slot is far below
    // the volume ceiling: a single request must not trigger a database write.
    expect(shouldFlush()).toBe(false);
  });
});

describe("the flush interval as a billing control", () => {
  /*
   * This is the regression guard for the outage of 29-30 October 2026.
   *
   * The flush is the only Postgres write that fires on traffic alone: no user,
   * no session, no JavaScript, so an unauthenticated scanner is enough to
   * trigger it. At 60 seconds it reset Neon's five-minute scale-to-zero timer
   * before that timer could ever elapse, so the compute never suspended --
   * ~16 hours a day awake, 110 CU-hours in a month against a 100 CU-hour
   * allowance, and signups down for about 45 hours once it ran out.
   *
   * Any future tuning of the interval has to clear that window, so the
   * invariant is asserted against the window rather than against a number
   * somebody would have to remember the meaning of.
   */
  it("leaves room for the database to actually fall asleep", () => {
    expect(FLUSH_INTERVAL).toBeGreaterThan(SCALE_TO_ZERO_IDLE_MS);
  });

  it("no longer writes at the old sixty-second cadence", () => {
    record({ routeGroup: "marketing", status: 200, durationMs: 12 });
    // A minute in: under the previous interval this was a database write, and
    // the idle timer went back to zero.
    expect(shouldFlush(Date.now() + 60_000 + 1)).toBe(false);
  });

  it("still writes once the interval has elapsed", () => {
    record({ routeGroup: "marketing", status: 200, durationMs: 12 });
    expect(shouldFlush(Date.now() + FLUSH_INTERVAL + 1)).toBe(true);
  });

  it("still flushes early on volume, so a burst is not held for half an hour", () => {
    /*
     * The volume ceiling is the safety valve the longer clock makes more
     * important: counters now live far longer, so an isolate under real load
     * must not accumulate without bound while waiting for the interval.
     */
    for (let i = 0; i < 64; i += 1) {
      record({ routeGroup: `group-${i}`, status: 200, durationMs: 1 });
    }
    expect(shouldFlush()).toBe(true);
  });
});

describe("percentiles from merged buckets", () => {
  it("reports the bound the percentile falls under", () => {
    // 100 requests: 90 under 50ms, 9 under 250ms, 1 beyond everything.
    const buckets = { "50": 90, "250": 9, inf: 1 };
    expect(percentileFrom(buckets, 0.5)).toBe(50);
    expect(percentileFrom(buckets, 0.95)).toBe(250);
  });

  it("does not interpolate, because the data has no such precision", () => {
    // Everything landed in one bucket; the honest answer is that bound, not a
    // fabricated point inside it.
    expect(percentileFrom({ "100": 10 }, 0.5)).toBe(100);
    expect(percentileFrom({ "100": 10 }, 0.99)).toBe(100);
  });

  /*
   * The unit error this guard exists for. A caller passing 50 instead of 0.5
   * used to get -1 back for every percentile, which reads as "catastrophically
   * slow" rather than "you called this wrong".
   */
  it("refuses a percentile expressed as 50 instead of 0.5", () => {
    expect(() => percentileFrom({ "5": 10 }, 50)).toThrow(/fraction between 0 and 1/);
    expect(() => percentileFrom({ "5": 10 }, 95)).toThrow(RangeError);
    expect(() => percentileFrom({ "5": 10 }, 0)).toThrow(RangeError);
    expect(() => percentileFrom({ "5": 10 }, -1)).toThrow(RangeError);
  });

  it("returns -1 when the tail runs past the last bucket", () => {
    expect(percentileFrom({ "5": 1, inf: 99 }, 0.95)).toBe(-1);
  });

  it("answers null for an hour with no traffic", () => {
    expect(percentileFrom({}, 0.5)).toBeNull();
  });
});

describe("flush safety", () => {
  it("drains so a failed write cannot double-count an hour", () => {
    record({ routeGroup: "app", status: 200, durationMs: 10 });
    const first = drain();
    const second = drain();

    expect(first).toHaveLength(1);
    // Losing a minute of telemetry is survivable by design. Counting it twice
    // would quietly corrupt every figure read off it afterwards.
    expect(second, "a second drain must not replay the first").toHaveLength(0);
  });
});
