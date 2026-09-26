export interface EmailAddress {
  email: string;
  name?: string;
}

export interface RenderedEmail {
  subject: string;
  html: string;
  /**
   * Plain-text alternative. Mandatory, not optional: a text part improves
   * deliverability, and some clients render nothing else.
   */
  text: string;
}

export interface SendEmailInput extends RenderedEmail {
  to: string;
  /** Template id, recorded on the email_events row for debugging. */
  template: string;
  replyTo?: string;
  /** Correlates the send with the request that triggered it. */
  requestId?: string;
}

export interface SendResult {
  ok: boolean;
  providerMessageId?: string;
  error?: string;
  /**
   * What the PROVIDER says about our usage, when it says anything.
   *
   * Worth capturing because our own count of `email_events` only knows about
   * mail this application sent. The provider account can be shared — another
   * service sending from the same Resend team draws down the same monthly
   * allowance — and from inside here that spending is invisible. These numbers
   * are the account's own, so they are the only ones that can reveal it.
   */
  quota?: ProviderQuota;
}

/** Usage as the mail provider reports it, in whatever units it chooses to. */
export interface ProviderQuota {
  /** Resend sends this to FREE-plan accounts only; its absence implies a paid plan. */
  dailyUsed?: number;
  monthlyUsed?: number;
}

export interface EmailTransport {
  readonly name: string;
  send(input: SendEmailInput, from: string): Promise<SendResult>;
}
