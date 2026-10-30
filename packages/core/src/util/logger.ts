/**
 * Structured JSON logging with hard redaction.
 *
 * The brief lists things that must never be logged: passwords, hashes,
 * cookies, session tokens, reset and verification tokens, access-code
 * plaintext, secrets, Authorization headers. Relying on every call site to
 * remember that will fail eventually, so redaction happens HERE, on the way
 * out, by key name and by value shape. ESLint additionally bans bare
 * `console.*` outside scripts and tests, so this is the only way logs are
 * produced by application code.
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_RANK: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

/** Key names whose values are replaced wholesale, at any nesting depth. */
const REDACTED_KEYS = new Set(
  [
    "password",
    "newpassword",
    "currentpassword",
    "confirmpassword",
    "passwordhash",
    "hash",
    "token",
    "sessiontoken",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "resettoken",
    "verificationtoken",
    "cookie",
    "cookies",
    "setcookie",
    "authorization",
    "auth",
    "secret",
    "clientsecret",
    "apikey",
    "api_key",
    "pepper",
    "code",
    "accesscode",
    "plaintextcode",
    "otp",
    "totp",
    "backupcodes",
    "twofactorsecret",
    "credentials",
    "ssn",
    "creditcard",
    "cardnumber",
    "cvv",
  ].map((k) => k.toLowerCase()),
);

const REDACTED = "[redacted]";

/**
 * Blank the password inside any `scheme://user:password@host` in a string.
 *
 * Driver errors quote the DSN they failed on, so this runs on every string
 * rather than on a chosen key. The user and host survive, because knowing
 * WHICH database refused the connection is the whole value of the line.
 */
function scrubUrlCredentials(value: string): string {
  return value.replace(/\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+):[^\s@/]+@/gi, `$1:${REDACTED}@`);
}

/** Values that look like a secret regardless of the key they arrived under. */
function looksSecret(value: string): boolean {
  // Bearer tokens and cookie headers.
  if (/^Bearer\s+\S+/i.test(value)) return true;
  if (/(^|;\s*)__Host-[\w.-]+=/.test(value)) return true;
  // Long, high-entropy, URL-safe blobs — the shape of a session or reset token.
  if (/^[A-Za-z0-9_-]{40,}$/.test(value)) return true;
  return false;
}

function redactValue(value: unknown, depth: number): unknown {
  if (depth > 6) return "[truncated]";
  if (value == null) return value;

  if (typeof value === "string") {
    if (looksSecret(value)) return REDACTED;
    const scrubbed = scrubUrlCredentials(value);
    return scrubbed.length > 2000 ? `${scrubbed.slice(0, 2000)}…` : scrubbed;
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (value instanceof Date) return value.toISOString();
  if (value instanceof Error) {
    // The message and stack go through the string rules rather than being
    // copied out verbatim: a driver error quotes the DSN it failed on, and
    // that is the one place a live password turns up in an error object.
    const stack = value.stack?.split("\n").slice(0, 12).join("\n");
    const serialised: Record<string, unknown> = {
      name: value.name,
      message: redactValue(value.message, depth + 1),
      // Stacks stay server-side only; they are never returned to a client.
      stack: stack === undefined ? undefined : redactValue(stack, depth + 1),
    };
    // A driver puts the reason on a property, not in the message: Postgres
    // sets `code` to "28P01" while the message says only "password
    // authentication failed". `code` is a REDACTED_KEY because access codes
    // share the name, so the SQLSTATE travels under one of its own.
    const { code } = value as { code?: unknown };
    if (typeof code === "string") serialised.sqlState = code;
    // Drizzle, Better Auth and `fetch` all wrap the original failure in
    // `cause`. Dropping it is how a two-day outage reached these logs as a
    // bare "Failed query" with nothing in it to act on. Recursing through
    // `redactValue` keeps the chain under every rule above, and the depth
    // guard terminates a cause cycle.
    if (value.cause != null) serialised.cause = redactValue(value.cause, depth + 1);
    return serialised;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 100).map((v) => redactValue(v, depth + 1));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      out[key] = REDACTED_KEYS.has(key.toLowerCase()) ? REDACTED : redactValue(v, depth + 1);
    }
    return out;
  }
  return String(value);
}

/** Exported for the logging test suite, which asserts each banned shape. */
export function redact(fields: Record<string, unknown>): Record<string, unknown> {
  return redactValue(fields, 0) as Record<string, unknown>;
}

export interface LoggerContext {
  requestId?: string;
  /** Correlates a chain of work across services; propagated from the edge. */
  traceId?: string;
  userId?: string;
  route?: string;
  method?: string;
  /** The cron expression, on a scheduled invocation. There is no route then. */
  cron?: string;
  env?: string;
  release?: string;
}

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  /** Derive a child logger carrying extra context on every line. */
  child(context: LoggerContext): Logger;
}

export interface LoggerOptions {
  level?: LogLevel;
  context?: LoggerContext;
  /** Overridable so tests can capture output instead of writing to stdout. */
  sink?: (line: string) => void;
}

export function createLogger(options: LoggerOptions = {}): Logger {
  const level = options.level ?? "info";
  const context = options.context ?? {};
  const sink =
    options.sink ??
    ((line: string) => {
      // The single sanctioned console call in the codebase.
      // eslint-disable-next-line no-restricted-syntax
      console.log(line);
    });

  function emit(entry: LogLevel, message: string, fields?: Record<string, unknown>) {
    if (LEVEL_RANK[entry] < LEVEL_RANK[level]) return;
    const line = {
      level: entry,
      time: new Date().toISOString(),
      msg: message,
      ...context,
      ...(fields ? redact(fields) : {}),
    };
    try {
      sink(JSON.stringify(line));
    } catch {
      sink(
        JSON.stringify({
          level: "error",
          time: new Date().toISOString(),
          msg: "log_serialize_failed",
        }),
      );
    }
  }

  return {
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
    child: (extra) => createLogger({ level, context: { ...context, ...extra }, sink }),
  };
}

/** A logger that discards everything. Used in tests that assert on behaviour, not output. */
export const silentLogger: Logger = createLogger({ level: "error", sink: () => {} });
