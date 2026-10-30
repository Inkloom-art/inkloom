/**
 * Redaction and error serialisation.
 *
 * The `cause` assertions exist because of a real outage. Production could not
 * reach Postgres for two days, and every log line said exactly
 * `Failed query: SELECT 1` and nothing else. Drizzle wraps each driver failure
 * as `new Error("Failed query: …", { cause: pgError })`, and the serialiser
 * kept only `name`, `message` and `stack` — so `28P01 password authentication
 * failed`, the one string that named the problem, was dropped on the way out.
 * Diagnosis had to come from outside the system instead.
 */
import { describe, expect, it } from "vitest";
import { redact } from "../logger";

/** The shape Drizzle actually throws: a flat message over a driver cause. */
function drizzleError(cause: unknown): Error {
  return new Error("Failed query: SELECT 1\nparams: ", { cause });
}

/** A `pg` error carries its SQLSTATE on `code`, never in the message. */
function pgError(code: string, message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code, severity: "ERROR" });
}

describe("error serialisation", () => {
  it("keeps the driver cause that names the failure", () => {
    const out = redact({
      error: drizzleError(pgError("28P01", "password authentication failed for user 'x'")),
    }) as { error: { message: string; cause?: { message?: string } } };

    expect(out.error.message).toContain("Failed query");
    expect(out.error.cause?.message).toBe("password authentication failed for user 'x'");
  });

  it("surfaces SQLSTATE under a key the access-code rule does not redact", () => {
    const out = redact({ error: pgError("28P01", "nope") }) as {
      error: { sqlState?: string; code?: string };
    };

    // `code` is a REDACTED_KEY because access codes share the name, so the
    // SQLSTATE has to travel under its own key to survive.
    expect(out.error.sqlState).toBe("28P01");
  });

  it("walks a nested cause chain", () => {
    const out = redact({ error: drizzleError(new Error("outer", { cause: new Error("root") })) }) as {
      error: { cause?: { cause?: { message?: string } } };
    };

    expect(out.error.cause?.cause?.message).toBe("root");
  });

  it("terminates on a cause cycle rather than recursing forever", () => {
    const a = new Error("a");
    const b = new Error("b", { cause: a });
    (a as { cause?: unknown }).cause = b;

    expect(() => redact({ error: a })).not.toThrow();
  });

  it("strips the password from a connection string inside a message", () => {
    const out = redact({
      error: new Error("connect failed: postgresql://neondb_owner:hunter2@ep-x.neon.tech/neondb"),
    }) as { error: { message: string } };

    expect(out.error.message).not.toContain("hunter2");
    expect(out.error.message).toContain("neondb_owner");
    expect(out.error.message).toContain("ep-x.neon.tech");
  });
});

describe("existing redaction still holds", () => {
  it("redacts by key name at depth", () => {
    const out = redact({ outer: { password: "hunter2" } }) as { outer: { password: string } };
    expect(out.outer.password).toBe("[redacted]");
  });

  it("redacts a bearer token by shape", () => {
    const out = redact({ header: "Bearer abc.def.ghi" }) as { header: string };
    expect(out.header).toBe("[redacted]");
  });
});
