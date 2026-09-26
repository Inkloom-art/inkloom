/**
 * Mail dispatch.
 *
 * Every send is recorded in `email_events` — template, recipient, provider id
 * and outcome — so "did the verification email actually go out?" is answerable,
 * and so the email-delivery alert has something to watch. The rendered body and
 * any signed link inside it are deliberately NOT stored.
 *
 * Security email bypasses preferences by design: a user must always learn that
 * their password changed, whatever they have toggled off.
 */
import { eq } from "drizzle-orm";
import type { Database } from "@inkloom/db/client";
import { emailEvent, newId, notificationPreference } from "@inkloom/db";
import type { EmailTransport, RenderedEmail } from "@inkloom/email";
import type { Logger } from "../util/logger";

/** Which preference toggle, if any, gates a template. */
const TEMPLATE_PREFERENCE: Record<string, keyof PreferenceFlags | null> = {
  // Security and account-lifecycle mail is never opt-out.
  verify_email: null,
  password_reset: null,
  password_changed: null,
  new_login: null,
  account_suspended: null,
  account_restored: null,
  data_export_ready: null,
  support_received: null,
  support_submitted: null,
  password_added: null,
  // These respect user preference.
  welcome: "productUpdatesEmail",
  early_access_approved: "productUpdatesEmail",
  code_redeemed: "creditsEmail",
  credits_granted: "creditsEmail",
};

interface PreferenceFlags {
  securityEmail: boolean;
  productUpdatesEmail: boolean;
  marketingEmail: boolean;
  creditsEmail: boolean;
}

export class Mailer {
  constructor(
    private readonly db: Database,
    private readonly transport: EmailTransport,
    private readonly logger: Logger,
    private readonly options: { from: string; replyTo?: string },
  ) {}

  async send(params: {
    to: string;
    template: string;
    rendered: RenderedEmail;
    userId?: string | null;
    requestId?: string;
    /** Skip the preference check. Used for security mail. */
    force?: boolean;
    /**
     * Override the default Reply-To for this one message.
     *
     * Used when the recipient is the support inbox: a reply should reach the
     * person who wrote in, not bounce back to the support alias.
     */
    replyTo?: string;
  }): Promise<{ sent: boolean; reason?: string }> {
    const normalizedTo = params.to.trim().toLowerCase();

    if (!params.force && params.userId) {
      const allowed = await this.isAllowed(params.userId, params.template);
      if (!allowed) {
        this.logger.info("email_suppressed_by_preference", {
          template: params.template,
          userId: params.userId,
        });
        return { sent: false, reason: "preference" };
      }
    }

    const eventId = newId("eml");
    await this.db.insert(emailEvent).values({
      id: eventId,
      userId: params.userId ?? null,
      toEmail: normalizedTo,
      template: params.template,
      subject: params.rendered.subject,
      status: "queued",
      requestId: params.requestId ?? null,
    });

    const result = await this.transport.send(
      {
        to: normalizedTo,
        template: params.template,
        subject: params.rendered.subject,
        html: params.rendered.html,
        text: params.rendered.text,
        replyTo: params.replyTo ?? this.options.replyTo,
        requestId: params.requestId,
      },
      this.options.from,
    );

    await this.db
      .update(emailEvent)
      .set({
        status: result.ok ? "sent" : "failed",
        providerMessageId: result.providerMessageId ?? null,
        error: result.error ?? null,
        updatedAt: new Date(),
      })
      .where(eq(emailEvent.id, eventId));

    /*
     * The provider's own view of the account, recorded where it can be searched.
     *
     * Logged rather than stored: it would otherwise cost a second write on
     * every single message to keep a number that only matters when somebody is
     * asking. It is here because our `email_events` count cannot see a shared
     * provider account — another service sending from the same Resend team
     * spends the same monthly allowance, invisibly from in here.
     */
    if (result.quota?.monthlyUsed !== undefined || result.quota?.dailyUsed !== undefined) {
      this.logger.info("email_provider_quota", {
        transport: this.transport.name,
        monthlyUsed: result.quota.monthlyUsed,
        // Resend sends this to free-plan accounts only, so seeing it at all
        // means the deployment is sending on a plan with a 100/day ceiling.
        dailyUsed: result.quota.dailyUsed,
        freePlan: result.quota.dailyUsed !== undefined,
      });
    }

    if (!result.ok) {
      // Loud, because undelivered verification mail silently blocks signup.
      this.logger.error("email_send_failed", {
        template: params.template,
        transport: this.transport.name,
        error: result.error,
      });
    }

    return { sent: result.ok, reason: result.error };
  }

  private async isAllowed(userId: string, template: string): Promise<boolean> {
    const gate = TEMPLATE_PREFERENCE[template];
    // An unknown template is treated as security-critical, not as opt-out.
    if (gate === null || gate === undefined) return true;

    const prefs = await this.db.query.notificationPreference.findFirst({
      where: eq(notificationPreference.userId, userId),
    });
    if (!prefs) return true;
    return prefs[gate] !== false;
  }
}
