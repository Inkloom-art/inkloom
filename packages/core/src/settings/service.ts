/**
 * Reads and writes feature flags and system settings.
 *
 * Values are cached per key, for either a few seconds or a few minutes. Which
 * one a key gets is decided by whether reading it wakes a sleeping database,
 * not by how risky the key is -- see `cacheTtlFor` below, which explains why
 * the mass-logout control keeps the short lifetime and the signup flag does
 * not.
 *
 * THE CACHE IS MODULE-LEVEL, NOT PER INSTANCE, and that is the whole point.
 *
 * It used to be an instance field, while `buildServices` — despite a comment
 * saying "once per isolate" — runs inside the Worker's `fetch`, because it
 * takes the per-request database handle. So a fresh SettingsService, and a
 * fresh empty cache, was built and discarded on every request: the cache
 * existed, cost a Map allocation, and never once served a hit across requests.
 * Every request that read a flag, and every rate-limited request reading the
 * override setting, paid a database round trip the design had already decided
 * it should not.
 *
 * Module scope is per isolate, which is the correct lifetime: these are global
 * operator settings, identical for every caller, so there is nothing
 * user-specific to leak between requests that share one. `invalidate()` clears
 * it, which is what keeps a writer seeing their own change and what keeps tests
 * isolated from one another.
 */
import { eq } from "drizzle-orm";
import type { Database, Executor } from "@inkloom/db/client";
import { featureFlag, newId, systemSetting } from "@inkloom/db";
import { fail } from "../util/errors";
import type { Logger } from "../util/logger";
import {
  FEATURE_FLAGS,
  SYSTEM_SETTINGS,
  isFeatureFlagKey,
  isSystemSettingKey,
  type FeatureFlagKey,
  type SystemSettingKey,
} from "./registry";

/**
 * Default cache lifetime. Short, so an operator's change reaches every isolate
 * quickly -- including the emergency controls, which is the point.
 */
const CACHE_TTL_MS = 5_000;

/**
 * Lifetime for the keys whose reads are what WAKE THE DATABASE.
 *
 * The distinction is not how risky a key is, it is whether reading it costs
 * money. Neon bills compute by time awake and sleeps after five minutes of
 * silence, so the only reads worth lengthening are the ones that happen on
 * requests which would otherwise never touch Postgres at all.
 *
 * `session_epoch` and `session_policy` are read on every AUTHENTICATED request
 * -- and those already query the database to load the session, so the compute
 * is awake regardless. Caching them longer would save a query and not one
 * second of compute time, while delaying the emergency "log everyone out"
 * switch. So they deliberately keep the short TTL: that control is exactly as
 * fast as it was before this change.
 */
const PUBLIC_READ_TTL_MS = 5 * 60_000;

/**
 * Keys read while rendering a page or serving a request that carries no
 * session, which is to say: the ones a scanner can trigger. Each of these would
 * otherwise reset Neon's five-minute idle timer every five seconds, forever.
 *
 * The cost of being on this list is propagation delay. Pausing signups, closing
 * early access, closing the support form, or widening a rate-limit bucket takes
 * up to PUBLIC_READ_TTL_MS to reach every isolate instead of CACHE_TTL_MS. The
 * base rate limits still apply throughout, and nothing here can log a user in
 * who should not be.
 */
const LONG_CACHE_KEYS: ReadonlySet<string> = new Set([
  // apps/web/app/routes/auth/signup.tsx, marketing/early-access.tsx,
  // packages/api/src/routes/auth.ts -- all reachable with no session.
  "signup_enabled",
  // apps/web/app/routes/marketing/early-access.tsx
  "early_access_open",
  // apps/web/app/routes/marketing/contact.tsx, packages/api/src/routes/public.ts
  "support_form_enabled",
  // packages/api/src/index.ts -- consulted by the rate limiter on every request.
  "rate_limit_overrides",
]);

/**
 * How long a value for `key` may be served from cache.
 *
 * Exported so the test suite can assert the classification directly. A typo in
 * LONG_CACHE_KEYS would otherwise fail silently -- the key would simply keep
 * the short TTL and the bill would not move, which is the hardest kind of
 * regression to notice.
 */
export function cacheTtlFor(key: string): number {
  return LONG_CACHE_KEYS.has(key) ? PUBLIC_READ_TTL_MS : CACHE_TTL_MS;
}

/** The keys that carry the longer lifetime, for tests and for documentation. */
export const longCachedSettingKeys: readonly string[] = [...LONG_CACHE_KEYS];

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const flagCache = new Map<string, CacheEntry<boolean>>();
const settingCache = new Map<string, CacheEntry<unknown>>();

export class SettingsService {
  constructor(
    private readonly db: Database,
    private readonly logger: Logger,
  ) {}

  /** Drop caches immediately after a write, so the writer sees their own change. */
  invalidate(): void {
    flagCache.clear();
    settingCache.clear();
  }

  async isEnabled(key: FeatureFlagKey): Promise<boolean> {
    const cached = flagCache.get(key);
    if (cached && cached.expiresAt > Date.now()) return cached.value;

    const row = await this.db.query.featureFlag.findFirst({ where: eq(featureFlag.key, key) });
    // Falling back to the declared default means a missing row degrades to the
    // SAFE value — V2 flags default to false, so an unseeded database cannot
    // accidentally expose unbuilt functionality.
    const value = row?.enabled ?? FEATURE_FLAGS[key].default;

    flagCache.set(key, { value, expiresAt: Date.now() + cacheTtlFor(key) });
    return value;
  }

  async allFlags(): Promise<
    Array<{ key: string; enabled: boolean; description: string; highRisk: boolean }>
  > {
    const rows = await this.db.query.featureFlag.findMany();
    const byKey = new Map(rows.map((r) => [r.key, r]));
    return Object.values(FEATURE_FLAGS).map((def) => ({
      key: def.key,
      enabled: byKey.get(def.key)?.enabled ?? def.default,
      description: def.description,
      highRisk: def.highRisk,
    }));
  }

  async setFlag(tx: Executor, key: string, enabled: boolean, updatedBy: string): Promise<void> {
    if (!isFeatureFlagKey(key)) {
      throw fail("VALIDATION_ERROR", { details: { key: "Unknown feature flag" } });
    }
    await tx
      .insert(featureFlag)
      .values({
        id: newId("flag"),
        key,
        enabled,
        description: FEATURE_FLAGS[key].description,
        highRisk: FEATURE_FLAGS[key].highRisk,
        updatedBy,
      })
      .onConflictDoUpdate({
        target: featureFlag.key,
        set: { enabled, updatedBy, updatedAt: new Date() },
      });
    this.invalidate();
  }

  async get<K extends SystemSettingKey>(key: K): Promise<(typeof SYSTEM_SETTINGS)[K]["default"]> {
    const cached = settingCache.get(key);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.value as (typeof SYSTEM_SETTINGS)[K]["default"];
    }

    const row = await this.db.query.systemSetting.findFirst({ where: eq(systemSetting.key, key) });
    const definition = SYSTEM_SETTINGS[key];

    let value = definition.default;
    if (row) {
      const parsed = definition.schema.safeParse(row.value);
      if (parsed.success) {
        value = parsed.data;
      } else {
        // A malformed stored value must not take the site down; fall back to
        // the declared default and make the problem loud.
        this.logger.error("system_setting_invalid", { key, issues: parsed.error.issues });
      }
    }

    settingCache.set(key, { value, expiresAt: Date.now() + cacheTtlFor(key) });
    return value as (typeof SYSTEM_SETTINGS)[K]["default"];
  }

  async set(tx: Executor, key: string, value: unknown, updatedBy: string): Promise<void> {
    if (!isSystemSettingKey(key)) {
      throw fail("VALIDATION_ERROR", { details: { key: "Unknown system setting" } });
    }
    const definition = SYSTEM_SETTINGS[key];
    const parsed = definition.schema.safeParse(value);
    if (!parsed.success) {
      throw fail("VALIDATION_ERROR", {
        details: { key, issues: parsed.error.issues.map((i) => i.message) },
      });
    }

    await tx
      .insert(systemSetting)
      .values({
        id: newId("set"),
        key,
        value: parsed.data as never,
        description: definition.description,
        highRisk: definition.highRisk,
        updatedBy,
      })
      .onConflictDoUpdate({
        target: systemSetting.key,
        set: { value: parsed.data as never, updatedBy, updatedAt: new Date() },
      });
    this.invalidate();
  }

  async allSettings(): Promise<
    Array<{ key: string; value: unknown; description: string; highRisk: boolean }>
  > {
    const rows = await this.db.query.systemSetting.findMany();
    const byKey = new Map(rows.map((r) => [r.key, r]));
    return Object.values(SYSTEM_SETTINGS).map((def) => ({
      key: def.key,
      value: byKey.get(def.key)?.value ?? def.default,
      description: def.description,
      highRisk: def.highRisk,
    }));
  }
}
