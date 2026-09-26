/**
 * Email transports.
 *
 * All three speak HTTP, deliberately: Cloudflare Workers cannot open an SMTP
 * connection, so a transport that only worked in Node would mean local
 * development exercised a different code path from production. Mailpit exposes
 * an HTTP send API alongside its SMTP listener, which lets local development
 * use the identical call shape as Resend.
 */
import type { EmailTransport, SendEmailInput, SendResult } from "./types";

/**
 * How long an email provider gets before we give up on it.
 *
 * Ten seconds, because sending is on the critical path of signup and password
 * reset: a caller is waiting on a page that has already told them the mail is
 * coming.
 */
const SEND_TIMEOUT_MS = 10_000;

/**
 * `fetch` that cannot hang forever.
 *
 * A provider returning an ERROR was already handled — the mailer records the
 * failure and returns rather than throwing, so a Resend outage degrades to
 * "signup succeeded, mail did not". A provider that simply never answers was
 * not: `await fetch(...)` with no signal blocks until the Worker's own duration
 * limit, so every signup and every reset would hang behind one slow dependency
 * until the isolate was killed. That is the difference between a degraded
 * feature and an outage, and it is the whole reason this exists.
 *
 * The timer is always cleared, including on the error path — a pending timer
 * would keep the isolate alive past the response for no reason.
 */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs = SEND_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/** Turn an aborted request into the same shape every other failure has. */
function describeSendError(error: unknown, provider: string): SendResult {
  const aborted = error instanceof Error && error.name === "AbortError";
  return {
    ok: false,
    error: aborted
      ? `${provider} did not respond within ${SEND_TIMEOUT_MS / 1000}s`
      : error instanceof Error
        ? error.message
        : String(error),
  };
}

/** Development: delivers into Mailpit's web UI at http://localhost:8025 */
export class MailpitTransport implements EmailTransport {
  readonly name = "mailpit";

  constructor(private readonly baseUrl: string) {}

  async send(input: SendEmailInput, from: string): Promise<SendResult> {
    try {
      const response = await fetchWithTimeout(`${this.baseUrl}/api/v1/send`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          From: parseAddress(from),
          To: [{ Email: input.to }],
          Subject: input.subject,
          HTML: input.html,
          Text: input.text,
          /*
           * Was missing entirely, so every message sent locally arrived with no
           * Reply-To. It matters most for the support notification: without it,
           * replying to a complaint goes to the sending address rather than to
           * the person who wrote in.
           */
          ...(input.replyTo ? { ReplyTo: [{ Email: input.replyTo }] } : {}),
        }),
      });

      if (!response.ok) {
        return { ok: false, error: `Mailpit returned ${response.status}` };
      }
      const data = (await response.json()) as { ID?: string };
      return { ok: true, providerMessageId: data.ID };
    } catch (error) {
      return describeSendError(error, "Mailpit");
    }
  }
}

/** A header that should be a number, or nothing if it is absent or isn't one. */
function readCount(value: string | null): number | undefined {
  if (value === null) return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

/** Staging and production. */
export class ResendTransport implements EmailTransport {
  readonly name = "resend";

  constructor(private readonly apiKey: string) {}

  async send(input: SendEmailInput, from: string): Promise<SendResult> {
    /*
     * An address that cannot exist is never handed to the provider.
     *
     * RFC 2606 and RFC 6761 reserve these domains permanently, so no mailbox
     * behind one can ever be registered and every message to one is
     * undeliverable by definition. Sending anyway costs three things that all
     * matter: a slot from the account's monthly allowance, a hard bounce
     * recorded against a domain whose sending reputation is brand new, and — at
     * load-test volume — thousands of both.
     *
     * The router above already did this in DEVELOPMENT. Doing it here means it
     * holds in staging and production too, which is where the quota and the
     * reputation actually exist. A load test can create ten thousand
     * `@example.test` accounts and the provider never hears about any of them.
     *
     * This is not a test hook that could be turned on against real users: the
     * check is on the RECIPIENT, and no real recipient can ever match it.
     */
    if (isUndeliverableTestAddress(input.to)) {
      return { ok: true, providerMessageId: `suppressed_${input.template}` };
    }

    try {
      const response = await fetchWithTimeout("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          // Never logged: the logger redacts any key named `authorization`.
          authorization: `Bearer ${this.apiKey}`,
          "content-type": "application/json",
          // Resend deduplicates on this, so a retried send cannot double-deliver.
          ...(input.requestId ? { "Idempotency-Key": `${input.template}:${input.requestId}` } : {}),
        },
        body: JSON.stringify({
          from,
          to: [input.to],
          subject: input.subject,
          html: input.html,
          text: input.text,
          ...(input.replyTo ? { reply_to: input.replyTo } : {}),
        }),
      });

      const data = (await response.json().catch(() => ({}))) as {
        id?: string;
        message?: string;
        name?: string;
      };

      /*
       * Resend reports usage on every response, and it is the only account-wide
       * view we can get. `x-resend-daily-quota` is sent to FREE accounts only,
       * so its presence is itself the answer to "which plan is this?" — which
       * matters, because the daily limit exists only on the free plan and the
       * paid plans are bounded by the month alone.
       */
      const quota = {
        dailyUsed: readCount(response.headers.get("x-resend-daily-quota")),
        monthlyUsed: readCount(response.headers.get("x-resend-monthly-quota")),
      };

      if (!response.ok) {
        return { ok: false, error: data.message ?? `Resend returned ${response.status}`, quota };
      }
      return { ok: true, providerMessageId: data.id, quota };
    } catch (error) {
      return describeSendError(error, "Resend");
    }
  }
}

/**
 * Tests and offline development. Records what WOULD have been sent, including
 * the URLs inside, so an integration test can assert a verification link was
 * generated without a mail server running.
 */
export class ConsoleTransport implements EmailTransport {
  readonly name = "console";
  readonly sent: Array<SendEmailInput & { from: string }> = [];

  async send(input: SendEmailInput, from: string): Promise<SendResult> {
    this.sent.push({ ...input, from });
    return { ok: true, providerMessageId: `console_${this.sent.length}` };
  }

  /** Most recent message sent to an address, for assertions. */
  lastTo(email: string): (SendEmailInput & { from: string }) | undefined {
    return [...this.sent].reverse().find((m) => m.to.toLowerCase() === email.toLowerCase());
  }

  clear(): void {
    this.sent.length = 0;
  }
}

/**
 * Domains reserved by RFC 2606 and RFC 6761 for testing and documentation.
 *
 * These can never be registered, so no mailbox behind one can ever exist. Any
 * message addressed to one is undeliverable by definition — which is exactly
 * what makes them safe to keep local.
 */
const RESERVED_TLDS = ["test", "example", "invalid", "localhost"];
const RESERVED_DOMAINS = ["example.com", "example.net", "example.org"];

/** True when no real mailbox can possibly exist at this address. */
export function isUndeliverableTestAddress(address: string): boolean {
  const domain = address.trim().toLowerCase().split("@").pop() ?? "";
  if (!domain) return true;
  return (
    RESERVED_TLDS.some((tld) => domain === tld || domain.endsWith(`.${tld}`)) ||
    RESERVED_DOMAINS.some((d) => domain === d || domain.endsWith(`.${d}`))
  );
}

/**
 * A recipient gate for environments that are not meant to email the public.
 *
 * Staging sends through the same Resend account and the same verified domain as
 * production. Nothing about it is a sandbox: a signup there with a real address
 * puts a real message in a real stranger's inbox, signed by the domain whose
 * reputation production depends on. A mistyped fixture, a shared demo link, or
 * anyone who finds the URL and signs up is enough — and the cost lands on the
 * one asset that cannot be rebuilt quickly, which is deliverability.
 *
 * RFC-reserved addresses are already suppressed everywhere, but that only
 * covers addresses that were never real. This covers the opposite case: an
 * address that is real and simply is not ours.
 *
 * FAILS CLOSED. An empty allowlist suppresses every deliverable recipient
 * rather than falling back to sending, because the failure mode of the other
 * choice is the exact incident this exists to prevent. `loadConfig` refuses to
 * boot a staging deploy that configures neither an allowlist nor an owner, so
 * "closed" is a deliberate state rather than an accident.
 */
export class AllowlistTransport implements EmailTransport {
  readonly name: string;
  private readonly entries: string[];

  constructor(
    private readonly inner: EmailTransport,
    entries: readonly string[],
    /** Called when a message is dropped, so the decision is not invisible. */
    private readonly onSuppressed?: (to: string, template: string) => void,
  ) {
    this.name = `allowlist(${inner.name})`;
    this.entries = entries.map((e) => e.trim().toLowerCase()).filter(Boolean);
  }

  async send(input: SendEmailInput, from: string): Promise<SendResult> {
    if (isAllowedRecipient(input.to, this.entries)) return this.inner.send(input, from);

    this.onSuppressed?.(input.to, input.template);
    /*
     * Reported as a SUCCESS, deliberately, and matching how reserved addresses
     * are already handled above. A failure here would be retried, would mark
     * the address as bouncing in `email_events`, and would surface to the user
     * as a broken signup — when nothing is broken and the message was withheld
     * on purpose. The provider id records what actually happened.
     */
    return { ok: true, providerMessageId: `suppressed_not_allowlisted_${input.template}` };
  }
}

/**
 * Entries are matched as whole addresses, or as domains when written `@domain`.
 *
 * Plus-addressing is normalised away, so one real inbox listed once covers
 * `you+signup@`, `you+admin@` and every other throwaway a tester invents. That
 * is the difference between an allowlist people work with and one they turn
 * off.
 */
export function isAllowedRecipient(address: string, entries: readonly string[]): boolean {
  if (entries.length === 0) return false;

  const clean = address.trim().toLowerCase();
  const at = clean.lastIndexOf("@");
  if (at <= 0) return false;

  const domain = clean.slice(at + 1);
  const local = clean.slice(0, at);
  const plus = local.indexOf("+");
  const canonical = `${plus === -1 ? local : local.slice(0, plus)}@${domain}`;

  return entries.some((entry) => {
    if (entry.startsWith("@")) {
      const suffix = entry.slice(1);
      return domain === suffix || domain.endsWith(`.${suffix}`);
    }
    return entry === clean || entry === canonical;
  });
}

/**
 * Development-only routing between a real provider and the local catcher.
 *
 * Wanting real mail in a real inbox during development and wanting a test suite
 * are not in conflict, but a single flat transport makes them look that way.
 * Point everything at Resend and the E2E suite — which creates dozens of
 * `@example.test` accounts per run — gets every one of them rejected, and burns
 * the daily send quota trying. Point everything at Mailpit and no real message
 * ever arrives.
 *
 * So the recipient decides. An RFC-reserved address cannot belong to anyone, so
 * it goes to Mailpit; anything else is a real person and goes to the real
 * provider. There is no allowlist to maintain and no way for a fixture to
 * accidentally email a stranger.
 *
 * Development only. Staging and production always use the real transport
 * directly — see `createTransport`.
 */
export class DevelopmentMailRouter implements EmailTransport {
  readonly name: string;

  constructor(
    private readonly real: EmailTransport,
    private readonly local: EmailTransport,
  ) {
    this.name = `${real.name}+${local.name}`;
  }

  async send(input: SendEmailInput, from: string): Promise<SendResult> {
    if (isUndeliverableTestAddress(input.to)) {
      return this.local.send(input, from);
    }

    const result = await this.real.send(input, from);
    if (result.ok) return result;

    /*
     * The provider refused a real address. In development that is nearly always
     * a configuration answer rather than a dead address — Resend, for one,
     * refuses every recipient except the account owner until a domain is
     * verified, which is the single most likely thing to be wrong on a machine
     * that has just been wired up.
     *
     * Dropping the message there would leave a developer staring at an inbox
     * that never fills, so the message is also delivered locally and can be
     * read in Mailpit. The failure is NOT hidden: the real provider's own words
     * are returned as the error, and `Mailer` writes them to `email_events` and
     * logs them, so the send is still recorded as failed.
     */
    const fallback = await this.local.send(input, from);
    return {
      ok: false,
      providerMessageId: fallback.providerMessageId,
      error: fallback.ok
        ? `${result.error} — a copy was delivered to Mailpit so the flow can still be completed locally.`
        : result.error,
    };
  }
}

function parseAddress(value: string): { Email: string; Name?: string } {
  const match = /^\s*(.*?)\s*<([^>]+)>\s*$/.exec(value);
  if (match) return { Email: match[2]!.trim(), Name: match[1]!.replace(/^"|"$/g, "") };
  return { Email: value.trim() };
}
