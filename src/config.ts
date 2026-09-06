import "dotenv/config";
import { FirewallConfig } from "./types";

function numberEnv(
  name: string,
  fallback: number
): number {
  const value = process.env[name];

  if (!value) {
    return fallback;
  }

  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return parsed;
}

function booleanEnv(
  name: string,
  fallback: boolean
): boolean {
  const value = process.env[name];

  if (!value) {
    return fallback;
  }

  return ["true", "1", "yes", "on"].includes(
    value.toLowerCase()
  );
}

function listEnv(name: string): string[] {
  return (process.env[name] ?? "")
    .split(",")
    .map(value => value.trim())
    .filter(Boolean);
}

export const PORT = numberEnv("PORT", 3000);

export const HOST =
  process.env.HOST || "127.0.0.1";

export const NODE_ENV =
  process.env.NODE_ENV || "development";

export const TRUST_PROXY =
  booleanEnv("TRUST_PROXY", false);

export const ADMIN_TOKEN =
  process.env.ADMIN_TOKEN || "";

export const MAX_EVENTS =
  numberEnv("MAX_EVENTS", 1000);

export const firewallConfig: FirewallConfig = {
  windowMs: numberEnv(
    "WINDOW_MS",
    60_000
  ),

  maxRequestsPerWindow: numberEnv(
    "MAX_REQUESTS_PER_WINDOW",
    60
  ),

  whitelistedIPs: listEnv(
    "WHITELIST_IPS"
  ),

  blacklistedCIDRs: listEnv(
    "BLACKLIST_CIDRS"
  ),

  scoreThresholds: {
    soft: numberEnv(
      "SOFT_THRESHOLD",
      30
    ),

    hard: numberEnv(
      "HARD_THRESHOLD",
      60
    ),

    critical: numberEnv(
      "CRITICAL_THRESHOLD",
      100
    )
  },

  banDurations: {
    soft: numberEnv(
      "SOFT_BAN_MS",
      15 * 60 * 1000
    ),

    hard: numberEnv(
      "HARD_BAN_MS",
      2 * 60 * 60 * 1000
    ),

    critical: numberEnv(
      "CRITICAL_BAN_MS",
      24 * 60 * 60 * 1000
    )
  },

  maxBodySize: numberEnv(
    "MAX_BODY_SIZE",
    1024 * 1024
  ),

  maxViolationsHistory: numberEnv(
    "MAX_VIOLATIONS_HISTORY",
    100
  )
};