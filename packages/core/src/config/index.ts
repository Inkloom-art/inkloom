/**
 * Runtime configuration.
 *
 * Parsed once per isolate from the environment, validated with Zod, and
 * thereafter immutable. A missing or malformed secret fails the boot rather
 * than surfacing as a confusing runtime error halfway through a request — and
 * critically, the production branch REFUSES to start on a development
 * placeholder secret, so a misconfigured deploy cannot serve traffic with a
 * known key.
 */
import { z } from "zod";

/** Values shipped in .env.example that must never reach staging or production. */
const DEV_PLACEHOLDERS = [
  "dev-only-insecure-secret-replace-me-0000000000",
  "dev-only-insecure-pepper-replace-me-000000",
  "dev-only-insecure-ip-pepper-replace-me-00",
];

const secret = (label: string, min = 32) =>
  z
    .string()
    .min(
      min,
      `${label} must be at least ${min} characters (generate with: openssl rand -base64 32)`,
    );

const boolish = z
  .union([z.boolean(), z.string()])
  .transform((v) => (typeof v === "boolean" ? v : v.toLowerCase() === "true" || v === "1"));

export const envSchema = z.object({
  INKLOOM_ENV: z.enum(["development", "test", "staging", "production"]).default("development"),
  APP_URL: z.url().refine((u) => !u.endsWith("/"), "APP_URL must not have a trailing slash"),

  DATABASE_URL: z.string().min(1),

  BETTER_AUTH_SECRET: secret("BETTER_AUTH_SECRET"),
  BETTER_AUTH_URL: z.url().optional(),

  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),

  ACCESS_CODE_PEPPER: secret("ACCESS_CODE_PEPPER", 24),
  IP_HASH_PEPPER: secret("IP_HASH_PEPPER", 24),

  EMAIL_TRANSPORT: z.enum(["mailpit", "resend", "console"]).default("console"),
  MAILPIT_HOST: z.string().default("127.0.0.1"),
  MAILPIT_PORT: z.coerce.number().int().positive().default(1025),
  RESEND_API_KEY: z.string().optional(),
  EMAIL_FROM: z.string().default("Inkloom <no-reply@mail.inkloom.art>"),
  EMAIL_REPLY_TO: z.string().default("support@inkloom.art"),
  SUPPORT_EMAIL: z.string().default("support@inkloom.art"),
  /**
   * Where support submissions are actually delivered.
   *
   * Separate from SUPPORT_EMAIL, which is printed on the contact page and in
   * every email footer. Routing complaints somewhere real should not require
   * publishing that address to the world, so this defaults to the public one
   * and can be pointed at a personal inbox without changing what visitors see.
   */
  SUPPORT_INBOX: z.string().optional(),

  /**
   * Who a non-production environment is permitted to email.
   *
   * Comma-separated; an entry may be a whole address or `@domain`. Empty means
   * nobody, which is the safe end of the range — staging shares production's
   * Resend account and verified sending domain, so an unguarded staging signup
   * mails a real stranger and spends production's reputation doing it.
   *
   * Ignored in production, where the whole point is to email real people.
   */
  EMAIL_ALLOWLIST: z.string().default(""),

  /**
   * Cloudflare Access, when this environment sits behind it.
   *
   * `ACCESS_TEAM_DOMAIN` is the team hostname (e.g.
   * "inkloom.cloudflareaccess.com") and `ACCESS_AUD` the Application Audience
   * tag of the Access application in front of this Worker. Both, or neither:
   * one alone cannot verify anything, and a half-configured gate that quietly
   * lets everything through is worse than no gate, because it looks like one.
   *
   * Unset means ungated, which is correct for local development and for
   * production — a public product is supposed to be public.
   */
  ACCESS_TEAM_DOMAIN: z.string().default(""),
  ACCESS_AUD: z.string().default(""),

  /**
   * Access service tokens allowed through, by Client ID, comma-separated.
   *
   * Anything non-interactive needs one: the post-deploy smoke test drives a
   * real browser at the deployed site and would otherwise meet a login page.
   * Kept apart from the human allowlist because this is a credential held by
   * CI, and the two should be revocable independently.
   */
  ACCESS_SERVICE_TOKENS: z.string().default(""),

  TURNSTILE_SITE_KEY: z.string().default(""),
  TURNSTILE_SECRET_KEY: z.string().default(""),
  TURNSTILE_ENABLED: boolish.default(true),

  /**
   * The mail provider's daily send limit, watched by the nightly health check.
   * Every signup needs a verification email, so this is the signup ceiling —
   * and exhausting it fails silently, with the account created and no message
   * sent. 0 turns the check off.
   */
  /*
   * 0 means "this plan has no daily limit", which is the case on every paid
   * mail plan. The default is 100 because that is the free plan's ceiling, and
   * an unconfigured deployment is likeliest to be on it.
   */
  EMAIL_DAILY_QUOTA: z.coerce.number().int().min(0).default(100),
  /* The monthly allowance; 0 to not watch it. 3,000 is the free plan's. */
  EMAIL_MONTHLY_QUOTA: z.coerce.number().int().min(0).default(3_000),
  /**
   * Whether the nightly backup and the weekly restore drill are expected to be
   * running. False while their schedules are deliberately paused, so a pause is
   * reported as a pause rather than alerted as a failure every morning.
   */
  BACKUPS_EXPECTED: z
    .enum(["true", "false"])
    .default("true")
    .transform((v) => v === "true"),
  SENTRY_DSN: z.string().optional(),
  SENTRY_ENVIRONMENT: z.string().optional(),
  SENTRY_TRACES_SAMPLE_RATE: z.coerce.number().min(0).max(1).default(0.1),
  INKLOOM_RELEASE: z.string().default("dev"),

  /**
   * Where the admin console is mounted.
   *
   * An obscure path raises the cost of casual discovery — a scanner walking
   * /admin, /wp-admin, /administrator finds nothing. It is an obscurity layer
   * and NOTHING MORE. It leaks through Referer headers, browser history, proxy
   * and CDN logs, screenshots and shared links, and it is worth exactly zero
   * against the realistic threat, which is a compromised staff account. Every
   * control that actually matters — session, role, owner check, 2FA, recent
   * auth, rate limit, audit — is enforced server-side on every request and
   * would hold if this path were printed on the home page.
   *
   * Rotatable: change the secret, redeploy, and the old path stops resolving.
   *
   * Must start with "/" and contain one path segment of safe characters, so it
   * cannot be set to something that escapes its own prefix or collides with
   * /api, /app or /auth.
   */
  ADMIN_PATH: z
    .string()
    .default("/admin")
    .refine((v) => /^\/[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/.test(v), {
      message: "ADMIN_PATH must be a single path segment such as /internal-admin-7f3a91",
    })
    .refine((v) => !["/api", "/app", "/auth", "/assets"].includes(v.toLowerCase()), {
      message: "ADMIN_PATH must not collide with a reserved prefix.",
    }),

  /**
   * The one account that owns this installation.
   *
   * A second, independent gate on top of the role check. Roles live in a table
   * an attacker with database access could edit; this lives in the deployment's
   * secrets. Both must agree before the console renders, so neither a stolen
   * session nor a rewritten role row is sufficient alone.
   *
   * Optional: unset means "role check only", which is the correct behaviour for
   * a staging environment where several people legitimately hold staff roles.
   */
  OWNER_EMAIL: z.string().optional(),

  ANALYTICS_ENABLED: boolish.default(true),
  RATE_LIMIT_ENABLED: boolish.default(true),

  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
});

export type Env = z.infer<typeof envSchema>;

export interface AppConfig extends Env {
  readonly isProduction: boolean;
  readonly isStaging: boolean;
  readonly isDevelopment: boolean;
  readonly isTest: boolean;
  /** True only when Google OAuth is fully configured; the UI hides it otherwise. */
  readonly googleOAuthEnabled: boolean;
  /** Origin derived from APP_URL, used for strict origin checks. */
  readonly origin: string;
  /**
   * Set when this environment sits behind Cloudflare Access and the Worker is
   * to verify that for itself, rather than trusting the edge in front of it.
   */
  readonly accessGate: {
    teamDomain: string;
    aud: string;
    allowedEmails: readonly string[];
    allowedServiceTokens: readonly string[];
  } | null;
  /**
   * The addresses a non-production environment may email, already parsed.
   *
   * Empty in production, where it is not consulted; in staging it falls back to
   * OWNER_EMAIL so the common setup — one environment, one person — needs no
   * extra configuration to be safe.
   */
  readonly emailAllowlist: readonly string[];
}

export class ConfigError extends Error {}

export function loadConfig(source: Record<string, unknown>): AppConfig {
  const parsed = envSchema.safeParse(source);

  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n");
    throw new ConfigError(`Invalid environment configuration:\n${issues}`);
  }

  const env = parsed.data;
  const isProduction = env.INKLOOM_ENV === "production";
  const isStaging = env.INKLOOM_ENV === "staging";

  if (isProduction || isStaging) {
    // A deploy that still carries a placeholder secret must not start.
    for (const [key, value] of Object.entries({
      BETTER_AUTH_SECRET: env.BETTER_AUTH_SECRET,
      ACCESS_CODE_PEPPER: env.ACCESS_CODE_PEPPER,
      IP_HASH_PEPPER: env.IP_HASH_PEPPER,
    })) {
      if (DEV_PLACEHOLDERS.includes(value) || value.startsWith("dev-only-")) {
        throw new ConfigError(
          `${key} is still the development placeholder. Set a real secret with ` +
            `\`wrangler secret put ${key}\` before deploying to ${env.INKLOOM_ENV}.`,
        );
      }
    }
    if (!env.APP_URL.startsWith("https://")) {
      throw new ConfigError(`APP_URL must be https:// in ${env.INKLOOM_ENV} (got ${env.APP_URL}).`);
    }
    if (env.EMAIL_TRANSPORT !== "resend") {
      throw new ConfigError(
        `EMAIL_TRANSPORT must be "resend" in ${env.INKLOOM_ENV}; Mailpit is local-only.`,
      );
    }
    if (!env.RESEND_API_KEY) {
      throw new ConfigError(`RESEND_API_KEY is required in ${env.INKLOOM_ENV}.`);
    }
    /*
     * Staging must know who it is allowed to email, and must be told rather
     * than left to guess.
     *
     * It sends through production's Resend account and production's verified
     * domain, so an unguarded staging environment mails real strangers and
     * spends the sending reputation that production depends on — and staging is
     * precisely where fixtures, demos and half-finished flows run. Refusing the
     * boot costs one line of configuration; the alternative costs a domain.
     *
     * OWNER_EMAIL counts, because a staging environment with an owner already
     * names the one person it exists for.
     */
    if (isStaging && !env.EMAIL_ALLOWLIST.trim() && !env.OWNER_EMAIL?.trim()) {
      throw new ConfigError(
        "EMAIL_ALLOWLIST is required in staging so it cannot email the public. " +
          'Set it to the addresses staging may write to (e.g. "you@example.com,@yourdomain.com"), ' +
          "or set OWNER_EMAIL.",
      );
    }
    if (env.TURNSTILE_ENABLED && !env.TURNSTILE_SECRET_KEY) {
      throw new ConfigError(
        `TURNSTILE_SECRET_KEY is required in ${env.INKLOOM_ENV} while Turnstile is enabled.`,
      );
    }
    /*
     * The site key matters as much as the secret, and fails far more quietly.
     *
     * It is public — it ships in the HTML — so it lives in wrangler.jsonc rather
     * than in secrets, and that is exactly what makes it easy to lose: Wrangler
     * REPLACES the top-level `vars` block with `env.<name>.vars` instead of
     * merging, so a key set once at the top silently becomes "" in every
     * deployed environment. The widget then renders with an empty sitekey and
     * issues no token, while the server keeps demanding one, and signup, login,
     * password reset and contact all fail with nothing but "captcha failed" to
     * go on. Refusing to boot turns a day of debugging into one clear line.
     */
    if (env.TURNSTILE_ENABLED && !env.TURNSTILE_SITE_KEY) {
      throw new ConfigError(
        `TURNSTILE_SITE_KEY is required in ${env.INKLOOM_ENV} while Turnstile is enabled. ` +
          `Set it in the "${env.INKLOOM_ENV}" vars block of wrangler.jsonc — note that ` +
          `env vars REPLACE the top-level block rather than merging with it.`,
      );
    }
    if (env.TURNSTILE_SITE_KEY.startsWith("1x000000")) {
      throw new ConfigError(
        `TURNSTILE_SITE_KEY is Cloudflare's always-passing test key. Use a real key in ${env.INKLOOM_ENV}.`,
      );
    }
    // Cloudflare's public test keys always pass; shipping them is the same as
    // having no bot protection at all.
    if (env.TURNSTILE_SECRET_KEY.startsWith("1x000000")) {
      throw new ConfigError(
        `TURNSTILE_SECRET_KEY is Cloudflare's always-passing test key. Use a real key in ${env.INKLOOM_ENV}.`,
      );
    }
  }

  const accessTeam = env.ACCESS_TEAM_DOMAIN.trim();
  const accessAud = env.ACCESS_AUD.trim();
  if (Boolean(accessTeam) !== Boolean(accessAud)) {
    throw new ConfigError(
      "ACCESS_TEAM_DOMAIN and ACCESS_AUD must be set together. One without the other " +
        "cannot verify an Access token, and the Worker would serve every request ungated " +
        "while appearing to be protected.",
    );
  }
  if (accessTeam.includes("://")) {
    throw new ConfigError(
      `ACCESS_TEAM_DOMAIN must be a hostname, not a URL (got "${accessTeam}").`,
    );
  }

  return Object.freeze({
    ...env,
    isProduction,
    isStaging,
    isDevelopment: env.INKLOOM_ENV === "development",
    isTest: env.INKLOOM_ENV === "test",
    googleOAuthEnabled: Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
    origin: new URL(env.APP_URL).origin,
    emailAllowlist: isProduction ? [] : parseAllowlist(env.EMAIL_ALLOWLIST, env.OWNER_EMAIL),
    accessGate: accessTeam
      ? {
          teamDomain: accessTeam,
          aud: accessAud,
          /*
           * The SAME list that decides who may be emailed decides who may get
           * in. Both answer "who is this environment for", and keeping them in
           * one place means a staging environment cannot end up open to someone
           * it is not allowed to write to.
           */
          allowedEmails: parseAllowlist(env.EMAIL_ALLOWLIST, env.OWNER_EMAIL),
          allowedServiceTokens: parseAllowlist(env.ACCESS_SERVICE_TOKENS),
        }
      : null,
  });
}

/** Comma or whitespace separated, lower-cased, de-duplicated. */
function parseAllowlist(raw: string, ownerEmail?: string): readonly string[] {
  const entries = [...raw.split(/[,\s]+/), ownerEmail ?? ""]
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
  return Object.freeze([...new Set(entries)]);
}
