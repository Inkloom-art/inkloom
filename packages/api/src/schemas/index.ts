/**
 * Request and response schemas.
 *
 * These are the contract: the OpenAPI document is generated from them, the
 * server validates against them, and client types are inferred from them, so
 * the three cannot drift.
 *
 * Note what is ABSENT from every input schema: `role`, `balance`, `credits`,
 * `userId`, `status`. Those are decided by the server from the session and the
 * database. A client that sends them has them stripped, not honoured.
 */
import { z } from "zod";

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/** Control characters, which would corrupt logs, headers and email rendering. */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

/**
 * Email.
 *
 * Trimmed and case-folded at the edge so everything downstream — rate limiting,
 * uniqueness, lookups — operates on one canonical form.
 */
export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254)
  .email("Enter a valid email address.");

/**
 * Password: at least 6 characters, with a letter, a number and a symbol.
 *
 * This is a product decision and it is worth being straight about the
 * trade-off, because the previous rule was the opposite one. NIST SP 800-63B
 * advises AGAINST composition rules and for length, on the evidence that
 * "must contain a symbol" pushes people toward predictable shapes like
 * "Passw0rd!" while a longer passphrase resists guessing far better. A
 * six-character password meeting all three rules has a smaller search space
 * than a twelve-character one meeting none.
 *
 * It is implemented as asked because the rules are familiar to users and the
 * owner chose them. What compensates is elsewhere and stays in place: mandatory
 * email verification, progressive login cooldowns, per-account and per-IP rate
 * limits, Turnstile, scrypt hashing, and mandatory 2FA for staff. The maximum
 * is high enough for any passphrase or password-manager output, and nothing
 * here forbids pasting.
 *
 * Each rule gets its own message, so "that password is invalid" is never the
 * whole answer — the person is told exactly what is missing.
 */
export const passwordSchema = z
  .string()
  .min(6, "Use at least 6 characters.")
  .max(200, "That password is too long (200 characters maximum).")
  .refine((v) => /[A-Za-z]/.test(v), "Include at least one letter.")
  .refine((v) => /\d/.test(v), "Include at least one number.")
  .refine(
    (v) => /[^A-Za-z0-9]/.test(v),
    "Include at least one special character, such as ! ? # or -.",
  );

export const displayNameSchema = z
  .string()
  .trim()
  .min(1, "Enter a name.")
  .max(80, "That name is too long.")
  .refine((v) => !CONTROL_CHARS.test(v), "That name contains invalid characters.");

export const publicIdSchema = z
  .string()
  .regex(/^[a-z]{2,5}_[0-9A-HJKMNP-TV-Z]{26}$/, "Not a valid identifier.");

export const turnstileTokenSchema = z.string().max(4096).optional();

/** Server-generated when absent, so a forgetful client still gets safety. */
export const idempotencyKeySchema = z.string().trim().min(8).max(128).optional();

export const cursorSchema = z.iso.datetime().optional();

export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  cursor: cursorSchema,
});

export const reasonSchema = z
  .string()
  .trim()
  .min(4, "Give a short reason — it is recorded in the audit log.")
  .max(500);

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const signupSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  name: displayNameSchema,
  turnstileToken: turnstileTokenSchema,
  /** Explicit, unticked-by-default consent. Required to create an account. */
  acceptedTerms: z.literal(true, { message: "You must accept the terms to create an account." }),
  /** Genuinely optional — marketing consent is separate from the terms. */
  marketingOptIn: z.boolean().default(false),
  utm: z
    .object({
      source: z.string().max(100).optional(),
      medium: z.string().max(100).optional(),
      campaign: z.string().max(100).optional(),
      referrer: z.string().max(500).optional(),
      landingPath: z.string().max(200).optional(),
    })
    .optional(),
});

export const loginSchema = z.object({
  email: emailSchema,
  // NOT `passwordSchema`: a login must accept a password that predates any
  // policy change. Rejecting it here would both reveal the policy to an
  // attacker and lock out legitimate users.
  password: z.string().min(1).max(200),
  turnstileToken: turnstileTokenSchema,
  rememberMe: z.boolean().default(true),
});

export const forgotPasswordSchema = z.object({
  email: emailSchema,
  turnstileToken: turnstileTokenSchema,
});

export const resetPasswordSchema = z.object({
  token: z.string().min(10).max(500),
  password: passwordSchema,
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(200),
  newPassword: passwordSchema,
  /** Default true: changing a password should evict anyone else who had one. */
  revokeOtherSessions: z.boolean().default(true),
});

export const verifyEmailSchema = z.object({ token: z.string().min(10).max(500) });

/**
 * A TOTP code or a backup code.
 *
 * Deliberately loose on shape (6 digits vs a longer backup string) so the same
 * schema serves both endpoints; the library does the real validation, and being
 * stricter here would only tell an attacker which format they got wrong.
 *
 * ALL whitespace is removed, not just the ends. Google Authenticator, 1Password
 * and Authy all display a TOTP code as two groups — `210 661` — so copying it
 * brings a space along, and `.trim()` leaves an inner space exactly where it
 * breaks the comparison. The code is then rejected as wrong while being read
 * out correctly, which is unfalsifiable from the user's side: the digits on
 * screen match the digits in the box. It blocked both enrolment and sign-in.
 *
 * Safe for backup codes too — `3NzQH-QaF1Y` has no spaces to lose.
 */
export const twoFactorSchema = z.object({
  code: z
    .string()
    .max(80)
    .transform((value) => value.replace(/\s+/g, ""))
    .pipe(z.string().min(4, "Enter the code from your app.").max(64)),
  trustDevice: z.boolean().optional(),
});

/**
 * Setting a FIRST password, for an account created through Google.
 *
 * No `currentPassword` field, because there is no current password — that is
 * the whole point. The endpoint refuses if one already exists, so this cannot
 * be used to bypass the change-password flow.
 */
export const setPasswordSchema = z.object({ newPassword: passwordSchema });

/** Turning 2FA on or off both require the password, proven right now. */
export const twoFactorPasswordSchema = z.object({
  currentPassword: z.string().min(1, "Enter your password.").max(200),
});

export const resendVerificationSchema = z.object({ email: emailSchema });

// ---------------------------------------------------------------------------
// Me
// ---------------------------------------------------------------------------

export const updateMeSchema = z
  .object({
    name: displayNameSchema.optional(),
    company: z.string().trim().max(120).optional(),
    timezone: z.string().max(64).optional(),
  })
  // At least one field, so an empty PATCH is a clear client error.
  .refine((v) => Object.values(v).some((x) => x !== undefined), "Nothing to update.");

export const notificationPreferencesSchema = z.object({
  productUpdatesEmail: z.boolean().optional(),
  marketingEmail: z.boolean().optional(),
  creditsEmail: z.boolean().optional(),
  // `securityEmail` is intentionally absent: it cannot be disabled, and a
  // silently stripped unknown key is a clearer contract than a rejected one.
});

// ---------------------------------------------------------------------------
// Access codes
// ---------------------------------------------------------------------------

export const redeemCodeSchema = z.object({
  /** Normalised server-side; hyphens, spaces and case are all accepted. */
  code: z.string().trim().min(1).max(128),
  idempotencyKey: idempotencyKeySchema,
});

// ---------------------------------------------------------------------------
// Support
// ---------------------------------------------------------------------------

export const supportSchema = z.object({
  email: emailSchema,
  name: z.string().trim().max(80).optional(),
  category: z
    .enum(["account", "billing", "access_code", "bug", "feedback", "security", "other"])
    .default("other"),
  subject: z.string().trim().min(3, "Add a short subject.").max(150),
  message: z.string().trim().min(10, "Tell us a little more.").max(5000),
  turnstileToken: turnstileTokenSchema,
  context: z
    .object({ path: z.string().max(200).optional(), userAgent: z.string().max(200).optional() })
    .optional(),
});

// ---------------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------------

/**
 * Allowlisted event names. An arbitrary string would let anyone with the
 * endpoint fill the table with junk and make the funnel unreliable.
 */
export const ANALYTICS_EVENTS = [
  "landing_viewed",
  "primary_cta_clicked",
  "examples_viewed",
  "signup_started",
  "signup_completed",
  "email_verified",
  "login_completed",
  "early_access_viewed",
  "access_code_attempted",
  "access_code_redeemed",
  "dashboard_viewed",
  "credits_viewed",
  "profile_completed",
  "support_submitted",
  "account_export_requested",
] as const;

export const analyticsEventSchema = z.object({
  name: z.enum(ANALYTICS_EVENTS),
  anonymousId: z.string().max(64).optional(),
  path: z.string().max(200).optional(),
  utm: z
    .object({
      source: z.string().max(100).optional(),
      medium: z.string().max(100).optional(),
      campaign: z.string().max(100).optional(),
    })
    .optional(),
  referrer: z.string().max(500).optional(),
  landingPath: z.string().max(200).optional(),
  /**
   * Strictly bounded scalars only. No free-form object, so an email address or
   * an access code cannot be smuggled into analytics.
   */
  properties: z
    .record(z.string().max(40), z.union([z.string().max(120), z.number(), z.boolean()]))
    .refine((p) => Object.keys(p).length <= 10, "Too many properties.")
    .optional(),
});

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

export const adminUserListSchema = paginationSchema.extend({
  q: z.string().trim().max(200).optional(),
  status: z.enum(["active", "suspended", "pending_deletion", "deleted"]).optional(),
  verified: z.enum(["true", "false"]).optional(),
  role: z.enum(["user", "support", "operations", "admin", "super_admin"]).optional(),
  signedUpAfter: z.iso.datetime().optional(),
  signedUpBefore: z.iso.datetime().optional(),
});

/**
 * The export takes the SAME filters as the list and no pagination.
 *
 * Same filters so that what an operator exports is what they were just looking
 * at — an export that silently covers a different population than the screen
 * above it is a trap. No cursor because a paginated export is not an export.
 */
export const adminUserExportSchema = adminUserListSchema
  .omit({ limit: true, cursor: true })
  .extend({
    /** Marks the file, so two exports in a folder can be told apart. */
    label: z.string().trim().max(40).optional(),
  });

export const suspendUserSchema = z.object({
  reason: reasonSchema,
  /** Also kill their sessions. Default true — a suspension should take effect now. */
  revokeSessions: z.boolean().default(true),
});

export const unsuspendUserSchema = z.object({ reason: reasonSchema });

export const createCampaignSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    description: z.string().trim().max(500).optional(),
    /** Omit to have the server generate a cryptographically random code. */
    code: z.string().trim().max(128).optional(),
    creditAmount: z.number().int().positive().max(1_000_000),
    maxTotalRedemptions: z.number().int().positive().max(10_000_000).nullable().optional(),
    maxRedemptionsPerUser: z.number().int().positive().max(100).default(1),
    startsAt: z.iso.datetime().nullable().optional(),
    expiresAt: z.iso.datetime().nullable().optional(),
    allowedEmailDomains: z
      .array(z.string().trim().toLowerCase().max(255))
      .max(50)
      .nullable()
      .optional(),
    targetCohort: z.string().trim().max(100).nullable().optional(),
    reason: reasonSchema,
    idempotencyKey: idempotencyKeySchema,
  })
  .refine((v) => !v.startsAt || !v.expiresAt || Date.parse(v.startsAt) < Date.parse(v.expiresAt), {
    message: "The start time must be before the expiry time.",
    path: ["expiresAt"],
  });

export const updateCampaignSchema = z.object({
  name: z.string().trim().min(2).max(120).optional(),
  description: z.string().trim().max(500).nullable().optional(),
  maxTotalRedemptions: z.number().int().positive().nullable().optional(),
  expiresAt: z.iso.datetime().nullable().optional(),
  targetCohort: z.string().trim().max(100).nullable().optional(),
  // `creditAmount` and `code` are absent by design: changing either after
  // issuance would retroactively alter what an already-distributed code means.
});

export const campaignActionSchema = z.object({ reason: reasonSchema });

export const adjustCreditsSchema = z.object({
  userId: publicIdSchema,
  /** Signed and non-zero: positive grants, negative deducts. */
  amount: z
    .number()
    .int()
    .refine((v) => v !== 0, "Amount cannot be zero.")
    .refine((v) => Math.abs(v) <= 1_000_000, "That adjustment is too large."),
  reason: reasonSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const reverseCreditsSchema = z.object({
  entryId: publicIdSchema,
  reason: reasonSchema,
  idempotencyKey: idempotencyKeySchema,
});

export const updateSettingsSchema = z.object({
  flags: z.record(z.string().max(64), z.boolean()).optional(),
  settings: z.record(z.string().max(64), z.unknown()).optional(),
  reason: reasonSchema,
  /** Typed confirmation, demanded for any high-risk key. */
  confirmation: z.string().max(64).optional(),
});

export const auditQuerySchema = paginationSchema.extend({
  action: z.string().max(100).optional(),
  actorId: publicIdSchema.optional(),
  targetId: z.string().max(64).optional(),
});

export const securityQuerySchema = paginationSchema.extend({
  type: z.string().max(64).optional(),
  severity: z.enum(["info", "warning", "critical"]).optional(),
  userId: publicIdSchema.optional(),
});

export const supportQuerySchema = paginationSchema.extend({
  status: z.enum(["open", "in_progress", "waiting_on_user", "resolved", "closed"]).optional(),
  priority: z.enum(["low", "normal", "high", "urgent"]).optional(),
});

export const ledgerQuerySchema = paginationSchema.extend({
  userId: publicIdSchema.optional(),
  type: z.string().max(40).optional(),
});

export const emergencySchema = z.object({
  action: z.enum(["logout_all_users", "logout_all_admins", "pause_signups", "pause_redemption"]),
  reason: reasonSchema,
  /** Must equal the action name — a deliberate, un-mis-clickable confirmation. */
  confirmation: z.string(),
});

export type SignupInput = z.infer<typeof signupSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RedeemCodeInput = z.infer<typeof redeemCodeSchema>;
export type SupportInput = z.infer<typeof supportSchema>;
export type CreateCampaignInput = z.infer<typeof createCampaignSchema>;
export type AdjustCreditsInput = z.infer<typeof adjustCreditsSchema>;
export type UpdateSettingsInput = z.infer<typeof updateSettingsSchema>;
export type EmergencyInput = z.infer<typeof emergencySchema>;
