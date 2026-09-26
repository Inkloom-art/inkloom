/**
 * Which mail leaves the machine during development.
 *
 * The rule has to be exactly right in both directions. Route a real address to
 * Mailpit and the person never gets their verification link. Route a fixture
 * address to Resend and the E2E suite fails on rejected recipients while
 * spending the daily quota — and, worse, a typo in a fixture could put a real
 * stranger's address on a development send.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { DevelopmentMailRouter, ResendTransport, isUndeliverableTestAddress } from "../transport";
import type { EmailTransport, SendEmailInput, SendResult } from "../types";

class Spy implements EmailTransport {
  readonly received: string[] = [];
  constructor(
    readonly name: string,
    private readonly result: SendResult = { ok: true },
  ) {}
  async send(input: SendEmailInput): Promise<SendResult> {
    this.received.push(input.to);
    return { providerMessageId: `${this.name}_1`, ...this.result };
  }
}

describe("isUndeliverableTestAddress", () => {
  it.each([
    "someone@example.test",
    "e2e-123@example.test",
    "a@sub.example.test",
    "a@example.com",
    "a@example.net",
    "a@example.org",
    "a@anything.invalid",
    "a@host.localhost",
    "a@my.example",
  ])("treats %s as undeliverable", (address) => {
    expect(isUndeliverableTestAddress(address)).toBe(true);
  });

  it.each([
    "ada@gmail.com",
    "someone@inkloom.art",
    "person@company.co.uk",
    // Deliberately adversarial: a real domain that merely CONTAINS a reserved
    // string must not be mistaken for one.
    "a@example.community",
    "a@notexample.com",
    "a@testing.com",
    "a@example.com.co",
  ])("treats %s as a real address", (address) => {
    expect(isUndeliverableTestAddress(address)).toBe(false);
  });

  it("is case and whitespace insensitive", () => {
    expect(isUndeliverableTestAddress("  Someone@EXAMPLE.TeST  ")).toBe(true);
  });

  it("treats a malformed address as undeliverable rather than sending it", () => {
    expect(isUndeliverableTestAddress("")).toBe(true);
    expect(isUndeliverableTestAddress("no-at-sign")).toBe(false);
  });
});

describe("DevelopmentMailRouter", () => {
  const build = () => {
    const real = new Spy("resend");
    const local = new Spy("mailpit");
    return { real, local, router: new DevelopmentMailRouter(real, local) };
  };

  const message = (to: string): SendEmailInput => ({
    to,
    template: "verify_email",
    subject: "Confirm your email address",
    html: "<p>hi</p>",
    text: "hi",
  });

  it("sends a real address to the real provider", async () => {
    const { real, local, router } = build();
    await router.send(message("ada@gmail.com"), "Inkloom <x@y.com>");
    expect(real.received).toEqual(["ada@gmail.com"]);
    expect(local.received).toEqual([]);
  });

  it("keeps a fixture address local", async () => {
    const { real, local, router } = build();
    await router.send(message("e2e-1@example.test"), "Inkloom <x@y.com>");
    expect(local.received).toEqual(["e2e-1@example.test"]);
    expect(real.received).toEqual([]);
  });

  it("reports both transports in its name, so email_events records the truth", () => {
    const { router } = build();
    expect(router.name).toBe("resend+mailpit");
  });

  it("still delivers locally when the provider refuses a real address", async () => {
    // Exactly Resend's 403 before a domain is verified.
    const refusal = "You can only send testing emails to your own email address";
    const real = new Spy("resend", { ok: false, error: refusal });
    const local = new Spy("mailpit");
    const router = new DevelopmentMailRouter(real, local);

    const result = await router.send(message("someone@gmail.com"), "Inkloom <x@y.com>");

    // The developer can still read the message and finish the flow...
    expect(local.received).toEqual(["someone@gmail.com"]);
    // ...but the send is still recorded as a failure, carrying the real reason.
    expect(result.ok).toBe(false);
    expect(result.error).toContain(refusal);
    expect(result.error).toContain("Mailpit");
  });

  it("does not fall back for an address the provider never saw", async () => {
    const real = new Spy("resend");
    const local = new Spy("mailpit");
    const router = new DevelopmentMailRouter(real, local);
    await router.send(message("e2e@example.test"), "Inkloom <x@y.com>");
    expect(real.received).toEqual([]);
    expect(local.received).toEqual(["e2e@example.test"]);
  });

  it("passes the provider result straight through", async () => {
    const { router } = build();
    const result = await router.send(message("ada@gmail.com"), "Inkloom <x@y.com>");
    expect(result).toEqual({ ok: true, providerMessageId: "resend_1" });
  });
});

// ===========================================================================

describe("the real provider never sees an address that cannot exist", () => {
  /*
   * Load testing was the forcing function, but the reason is permanent.
   *
   * A run that creates ten thousand `@example.test` accounts would, without
   * this, make ten thousand Resend calls: exhausting a 100/day quota in the
   * first minute and recording thousands of hard bounces against a sending
   * domain whose reputation is days old. Bounces are the single fastest way to
   * get a new domain treated as a spammer, and that damage outlives the test.
   *
   * The check is on the RECIPIENT, so it cannot be turned against a real user:
   * RFC 2606 and RFC 6761 reserve these domains permanently and no real mailbox
   * can ever be registered behind one.
   */
  const transport = () => new ResendTransport("re_should_never_be_used");

  it.each([
    "bot-0001@example.test",
    "someone@sub.example.test",
    "a@example.com",
    "b@foo.invalid",
    "c@localhost",
  ])("does not call the provider for %s", async (to) => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const result = await transport().send(
      { to, subject: "s", html: "<p>h</p>", text: "h", template: "verify_email" },
      "Inkloom <no-reply@mail.inkloom.art>",
    );

    expect(result.ok).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("still calls the provider for a real address", async () => {
    const fetchSpy = vi.fn(
      async () =>
        new Response(JSON.stringify({ id: "msg_1" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchSpy);

    await transport().send(
      {
        to: "a.real.person@gmail.com",
        subject: "s",
        html: "<p>h</p>",
        text: "h",
        template: "verify_email",
      },
      "Inkloom <no-reply@mail.inkloom.art>",
    );

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });
});

describe("what the provider says about the account", () => {
  /*
   * Our own count of `email_events` only knows about mail THIS application
   * sent. The provider account can be shared, and a second service spending the
   * same monthly allowance is invisible from in here — which is exactly the
   * blind spot that let a stale, hardcoded ceiling go unnoticed until it fired
   * a false critical. These headers are the account's own numbers.
   */
  const original = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = original;
  });

  /** Answer the send call with a given set of headers. */
  function respondWith(headers: Record<string, string>, status = 200) {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ id: "msg_1" }), {
        status,
        headers: { "content-type": "application/json", ...headers },
      })) as typeof fetch;
  }

  const message = {
    /*
     * NOT an example.* or .test address. Those are RFC 2606 reserved, and the
     * transport suppresses them before it ever reaches the provider — so a
     * fixture using one silently tests the suppression path instead of the
     * send path, and every assertion about response headers reads undefined.
     */
    to: "someone@inkloom.art",
    template: "verify_email" as const,
    subject: "Confirm",
    html: "<p>hi</p>",
    text: "hi",
  };

  it("reports the monthly figure the provider returns", async () => {
    respondWith({ "x-resend-monthly-quota": "1234" });
    const result = await new ResendTransport("re_test").send(message, "Inkloom <no-reply@x.test>");
    expect(result.ok).toBe(true);
    expect(result.quota?.monthlyUsed).toBe(1234);
  });

  it("treats a daily figure as the tell that this is a free plan", async () => {
    /*
     * The provider sends the daily header to free accounts ONLY, so its
     * presence answers "which plan is this?" without anyone having to remember
     * to write the answer down in configuration — which is how the wrong answer
     * survived an upgrade and raised a critical over nothing.
     */
    respondWith({ "x-resend-daily-quota": "87", "x-resend-monthly-quota": "900" });
    const result = await new ResendTransport("re_test").send(message, "Inkloom <no-reply@x.test>");
    expect(result.quota?.dailyUsed).toBe(87);
  });

  it("says nothing about a plan when the provider does not", async () => {
    respondWith({});
    const result = await new ResendTransport("re_test").send(message, "Inkloom <no-reply@x.test>");
    expect(result.quota?.dailyUsed).toBeUndefined();
    expect(result.quota?.monthlyUsed).toBeUndefined();
  });

  it("still carries the figures when the send was refused", async () => {
    /*
     * A refusal is when the numbers matter MOST — a 429 for an exhausted quota
     * is the one moment someone needs to know how much of the allowance is
     * gone, and dropping the headers on the error path would lose it.
     */
    respondWith({ "x-resend-monthly-quota": "50000" }, 429);
    const result = await new ResendTransport("re_test").send(message, "Inkloom <no-reply@x.test>");
    expect(result.ok).toBe(false);
    expect(result.quota?.monthlyUsed).toBe(50000);
  });

  it("ignores a header that is not a number", async () => {
    respondWith({ "x-resend-monthly-quota": "unlimited" });
    const result = await new ResendTransport("re_test").send(message, "Inkloom <no-reply@x.test>");
    expect(result.quota?.monthlyUsed).toBeUndefined();
  });
});
