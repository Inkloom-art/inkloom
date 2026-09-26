/**
 * Exporting the account list.
 *
 * This endpoint hands over every address the platform holds, in one file, to a
 * laptop the platform has no further control over. That is a legitimate thing
 * for an operator to need — an event's organiser has to be able to reach the
 * people who signed up for it — and it is also the single most sensitive read
 * in the console. So the tests here are about who may do it, what they get,
 * and what is written down afterwards.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { sql } from "drizzle-orm";
import { createTestApp, extractToken, type TestApp } from "../../../../../tests/helpers/app";

let app: TestApp;

beforeAll(() => {
  app = createTestApp();
});
afterAll(async () => {
  await app.close();
});
beforeEach(async () => {
  await app.reset();
});

const PASSWORD = "a-perfectly-fine-passphrase-1";

async function signupAndVerify(email: string, name = "Test Person"): Promise<string[]> {
  await app.json("/v1/auth/signup", {
    method: "POST",
    body: JSON.stringify({ email, password: PASSWORD, name, acceptedTerms: true }),
  });
  const token = extractToken(app.mail.lastTo(email)!.html);
  await app.json("/v1/auth/verify-email", { method: "POST", body: JSON.stringify({ token }) });
  const login = await app.json("/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  return login.cookies;
}

/** Sign in and take a role, the way the other admin suites do. */
async function staffCookies(email: string, role: string): Promise<string[]> {
  const cookies = await signupAndVerify(email);
  await app.db.db.execute(
    sql`UPDATE users SET role = ${role}, two_factor_enabled = true WHERE email = ${email}`,
  );
  return cookies;
}

/** The raw response, because the body here is a file rather than JSON. */
async function exportCsv(cookies: string[], query = ""): Promise<Response> {
  return app.fetch(`/v1/admin/users/export${query}`, { cookies });
}

describe("who may export the account list", () => {
  it("lets a super admin export", async () => {
    const staff = await staffCookies("owner@example.test", "super_admin");
    const response = await exportCsv(staff);
    expect(response.status).toBe(200);
  });

  it("refuses front-line support, who may read accounts but not take them away", async () => {
    /*
     * The distinction the `users.export` permission exists to draw. Looking one
     * person up to answer their ticket is support's job; leaving the building
     * with the whole list is not, and `users.read` alone must not imply it.
     */
    const staff = await staffCookies("support@example.test", "support");
    const response = await exportCsv(staff);
    expect(response.status).toBe(403);
  });

  it("refuses an ordinary signed-in user", async () => {
    const cookies = await signupAndVerify("nobody@example.test");
    const response = await exportCsv(cookies);
    expect(response.status).toBe(403);
  });

  it("refuses an anonymous caller", async () => {
    const response = await exportCsv([]);
    expect(response.status).toBe(401);
  });
});

describe("what comes back", () => {
  it("is a CSV attachment that a browser will save, and never cache", async () => {
    const staff = await staffCookies("owner2@example.test", "super_admin");
    const response = await exportCsv(staff);

    expect(response.headers.get("content-type")).toContain("text/csv");
    expect(response.headers.get("content-disposition")).toMatch(/attachment; filename=".*\.csv"/);
    // Personal data must not sit in a shared cache or at an edge.
    expect(response.headers.get("cache-control")).toContain("no-store");
  });

  it("carries the people who signed up", async () => {
    const staff = await staffCookies("owner3@example.test", "super_admin");
    await signupAndVerify("participant@example.test", "A Participant");

    const csv = await (await exportCsv(staff)).text();
    expect(csv).toContain("participant@example.test");
    expect(csv).toContain("A Participant");
    expect(csv.split("\r\n")[0]).toContain("email");
  });

  it("never carries a secret", async () => {
    /*
     * The columns are chosen, not inherited from the table. A `SELECT *` here
     * would put password hashes and two-factor secrets in a file that gets
     * emailed around.
     */
    const staff = await staffCookies("owner4@example.test", "super_admin");
    await signupAndVerify("participant2@example.test");

    const csv = (await (await exportCsv(staff)).text()).toLowerCase();
    for (const forbidden of ["password", "secret", "token", "hash", "backup_code"]) {
      expect(csv, `the export must not contain "${forbidden}"`).not.toContain(forbidden);
    }
  });

  it("leaves erased accounts out unless they are asked for by name", async () => {
    /*
     * Anonymisation has already been over a tombstone, so exporting one
     * produces a row of scrubbed placeholders that reads like a real
     * participant until somebody tries to mail it.
     */
    const staff = await staffCookies("owner5@example.test", "super_admin");
    await signupAndVerify("gone@example.test");
    await app.db.db.execute(
      sql`UPDATE users SET status = 'deleted', anonymized_at = now()
           WHERE email = 'gone@example.test'`,
    );

    const csv = await (await exportCsv(staff)).text();
    expect(csv).not.toContain("gone@example.test");

    const asked = await (await exportCsv(staff, "?status=deleted")).text();
    expect(asked.split("\r\n").length, "asked for by name, they are included").toBeGreaterThan(1);
  });

  it("honours the same filters as the list above it", async () => {
    const staff = await staffCookies("owner6@example.test", "super_admin");
    await signupAndVerify("findme@example.test", "Findable");
    await signupAndVerify("other@example.test", "Someone Else");

    const csv = await (await exportCsv(staff, "?q=findme")).text();
    expect(csv).toContain("findme@example.test");
    expect(csv).not.toContain("other@example.test");
  });
});

describe("what is written down afterwards", () => {
  it("records who exported, when, and how much — but not the addresses", async () => {
    /*
     * The question asked after a list leaks is who took a copy and how big it
     * was. Copying the personal data into the audit trail to record that
     * personal data was copied is not a safeguard; it is a second copy.
     */
    const staff = await staffCookies("auditor@example.test", "super_admin");
    await signupAndVerify("counted@example.test");

    expect((await exportCsv(staff)).status).toBe(200);

    const events = await app.db.db.execute<{ action: string; metadata: unknown }>(
      sql`SELECT action, metadata FROM audit_events WHERE action = 'users.exported'`,
    );
    expect(events.rows).toHaveLength(1);
    const metadata = events.rows[0]!.metadata as { rows: number };
    expect(metadata.rows).toBeGreaterThan(0);
    expect(JSON.stringify(events.rows[0]!.metadata)).not.toContain("counted@example.test");
  });

  it("records a refused attempt nowhere as a successful one", async () => {
    const staff = await staffCookies("support2@example.test", "support");
    expect((await exportCsv(staff)).status).toBe(403);

    const events = await app.db.db.execute(
      sql`SELECT 1 FROM audit_events WHERE action = 'users.exported'`,
    );
    expect(events.rows).toHaveLength(0);
  });
});
