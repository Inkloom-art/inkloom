/**
 * Downloading the account list from the console.
 *
 * The API is covered in depth by admin-user-export.integration.test.ts — who
 * may do it, what the file contains, what is audited. This covers the one thing
 * that cannot be asserted from the server side: that a browser, given the link
 * an operator actually clicks, ends up with a file on disk. The header carries
 * `content-disposition: attachment`, which is an instruction to the BROWSER, so
 * nothing below the browser can prove it was honoured.
 */
import { expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { settled, signUpAndVerify, STRONG_PASSWORD, uniqueEmail } from "./support";
import { secretFromUri, totp } from "./totp";

test("an operator can download the account list", async ({ page }) => {
  test.setTimeout(120_000);
  const adminPath = process.env.ADMIN_PATH!.replace(/^\/+/, "");
  const email = await signUpAndVerify(page, uniqueEmail("exporter"));

  execFileSync("pnpm", ["bootstrap:superadmin", "--email", email, "--force"], {
    input: `${email}\n`,
    stdio: "pipe",
    env: process.env,
  });
  const enrol = await page.evaluate(async (password) => {
    const r = await fetch("/api/auth/two-factor/enable", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ password, issuer: "Inkloom" }),
    });
    return r.text();
  }, STRONG_PASSWORD);
  const secret = secretFromUri((JSON.parse(enrol) as { totpURI: string }).totpURI);
  await page.evaluate(async (code) => {
    await fetch("/api/auth/two-factor/verify-totp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ code, trustDevice: false }),
    });
  }, totp(secret));

  await page.goto(`/${adminPath}/users`);
  await settled(page);

  // The control is on the page an operator is already looking at.
  const download = page.getByRole("link", { name: /download csv/i });
  await expect(download).toBeVisible();

  const [file] = await Promise.all([page.waitForEvent("download"), download.click()]);
  const path = await file.path();
  const body = readFileSync(path!, "utf8");

  expect(file.suggestedFilename()).toMatch(/\.csv$/);
  expect(body.split("\r\n")[0]).toContain("email");
  expect(body).toContain(email);
});
