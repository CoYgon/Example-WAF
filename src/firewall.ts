import {
  NextFunction,
  Request,
  Response
} from "express";

import crypto from "crypto";

import {
  BanLevel,
  FirewallConfig,
  FirewallStats,
  IPProfile,
  ThreatEvent,
  Violation,
  WAFInspectionResult
} from "./types";

import { SecurityLogger } from "./logger";

function normalizeIPv4(
  ip: string
): string {
  return ip.startsWith("::ffff:")
    ? ip.substring(7)
    : ip;
}

class IPUtils {
static ipToInt(ip: string): number | null {
  const normalized = normalizeIPv4(ip);

  const parts = normalized.split(".");

  if (parts.length !== 4) {
    return null;
  }

  const numbers = parts.map(Number);

  if (
    numbers.some(
      value =>
        !Number.isInteger(value) ||
        value < 0 ||
        value > 255
    )
  ) {
    return null;
  }

  const a = numbers[0];
  const b = numbers[1];
  const c = numbers[2];
  const d = numbers[3];

  if (
    a === undefined ||
    b === undefined ||
    c === undefined ||
    d === undefined
  ) {
    return null;
  }

  return (
    ((a << 24) >>> 0) +
    ((b << 16) >>> 0) +
    ((c << 8) >>> 0) +
    d
  ) >>> 0;
}

  static matchCIDR(
    ip: string,
    cidr: string
  ): boolean {
    const [network, prefixString] =
      cidr.split("/");

    if (!network || !prefixString) {
      return false;
    }

    const prefix = Number(prefixString);

    if (
      !Number.isInteger(prefix) ||
      prefix < 0 ||
      prefix > 32
    ) {
      return false;
    }

    const ipInt = this.ipToInt(ip);
    const networkInt = this.ipToInt(network);

    if (
      ipInt === null ||
      networkInt === null
    ) {
      return false;
    }

    if (prefix === 0) {
      return true;
    }

    const mask =
      (0xffffffff << (32 - prefix)) >>> 0;

    return (
      (ipInt & mask) ===
      (networkInt & mask)
    );
  }
}

class WAFSignatureEngine {
  private static readonly PATTERNS: Array<{
    name: string;
    score: number;
    regex: RegExp;
  }> = [

    {
      name: "SQL_INJECTION",
      score: 50,
      regex:
        /(?:union\s+select|select\s+.+\s+from|insert\s+into|update\s+.+\s+set|delete\s+from|drop\s+(?:table|database)|exec(?:ute)?\s*\(|--|%27|'(?:\s|$))/i
    },

    {
      name: "XSS",
      score: 30,
      regex:
        /(?:<script\b|javascript:|onerror\s*=|onload\s*=|onclick\s*=|<iframe\b|<svg\b|document\.cookie|eval\s*\()/i
    },

    {
      name: "PATH_TRAVERSAL",
      score: 35,
      regex:
        /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)/i
    },

    {
      name: "COMMAND_INJECTION",
      score: 70,
      regex:
        /(?:;\s*(?:cat|ls|whoami|curl|wget|bash|sh|powershell|cmd)\b|\|\s*(?:cat|ls|whoami|curl|wget|bash|sh|powershell|cmd)\b|\$\(|`[^`]+`)/i
    },

    {
      name: "SCANNER",
      score: 20,
      regex:
        /\b(?:nmap|sqlmap|nikto|masscan|zgrab|acunetix|nessus|gobuster|dirbuster)\b/i
    },

    {
      name: "SUSPICIOUS_PATH",
      score: 25,
      regex:
        /(?:\/\.git(?:\/|$)|\/\.env(?:\/|$)|\/wp-admin(?:\/|$)|\/wp-login\.php|\/phpmyadmin(?:\/|$)|\/server-status)/i
    }
  ];

  static inspect(
    req: Request
  ): WAFInspectionResult {
    const chunks: string[] = [];

    chunks.push(
      req.originalUrl || ""
    );

    chunks.push(
      req.get("user-agent") || ""
    );

    if (req.body !== undefined) {
      try {
        chunks.push(
          JSON.stringify(req.body)
        );
      } catch {
        // Ignore unserializable body.
      }
    }

    const raw = chunks.join(" ");

    let decoded = raw;

    try {
      decoded = decodeURIComponent(raw);
    } catch {
      // Keep original string if malformed.
    }

    const combined =
      `${raw} ${decoded}`;

    const violations: string[] = [];
    let addedScore = 0;

    for (const pattern of this.PATTERNS) {
      if (pattern.regex.test(combined)) {
        violations.push(pattern.name);
        addedScore += pattern.score;
      }
    }

    return {
      threatDetected:
        violations.length > 0,

      addedScore,

      violations
    };
  }
}

export class EnterpriseFirewall {
  private readonly profiles =
    new Map<string, IPProfile>();

  private readonly stats: FirewallStats = {
    totalRequests: 0,
    blockedRequests: 0,
    rateLimitedRequests: 0,
    detectedThreats: 0,
    activeBans: 0,
    trackedIPs: 0
  };

  constructor(
    private readonly config: FirewallConfig,
    private readonly logger: SecurityLogger
  ) {
    setInterval(
      () => this.cleanup(),
      60_000
    ).unref();
  }

  private createProfile(): IPProfile {
    const now = Date.now();

    return {
      score: 0,
      requestTimestamps: [],

      banLevel: BanLevel.NONE,
      bannedUntil: 0,

      lastScoreUpdate: now,
      lastSeen: now,

      totalRequests: 0,
      blockedRequests: 0,

      violationsHistory: []
    };
  }

  private getProfile(
    ip: string
  ): IPProfile {
    let profile =
      this.profiles.get(ip);

    if (!profile) {
      profile = this.createProfile();
      this.profiles.set(ip, profile);
    }

    profile.lastSeen =
      Date.now();

    return profile;
  }

  public getPublicProfile(
    ip: string
  ): IPProfile {
    return this.getProfile(ip);
  }

  public extractClientIP(
    req: Request
  ): string {
    return normalizeIPv4(
      req.ip ||
      req.socket.remoteAddress ||
      "unknown"
    );
  }

  private isWhitelisted(
    ip: string
  ): boolean {
    return this.config.whitelistedIPs.includes(ip);
  }

  private isBlacklisted(
    ip: string
  ): boolean {
    return this.config.blacklistedCIDRs.some(
      cidr =>
        IPUtils.matchCIDR(ip, cidr)
    );
  }

  private decayScore(
    profile: IPProfile
  ): void {
    const now = Date.now();

    const elapsed =
      now - profile.lastScoreUpdate;

    const hours =
      Math.floor(
        elapsed / 3_600_000
      );

    if (hours <= 0) {
      return;
    }

    profile.score = Math.max(
      0,
      profile.score - hours * 10
    );

    profile.lastScoreUpdate =
      now;

    if (
      profile.score === 0 &&
      profile.bannedUntil <= now
    ) {
      profile.banLevel =
        BanLevel.NONE;

      profile.bannedUntil = 0;
    }
  }

  private addViolation(
    profile: IPProfile,
    violation: string,
    score: number
  ): void {
    const item: Violation = {
      timestamp: Date.now(),
      violation,
      scoreAdded: score
    };

    profile.violationsHistory.unshift(
      item
    );

    if (
      profile.violationsHistory.length >
      this.config.maxViolationsHistory
    ) {
      profile.violationsHistory.length =
        this.config.maxViolationsHistory;
    }
  }

  private addScore(
    profile: IPProfile,
    score: number
  ): void {
    this.decayScore(profile);

    profile.score = Math.min(
      100,
      profile.score + score
    );

    profile.lastScoreUpdate =
      Date.now();
  }

  private evaluateBanState(
    profile: IPProfile
  ): BanLevel {
    const now = Date.now();

    if (
      profile.bannedUntil > now
    ) {
      return profile.banLevel;
    }

    if (
      profile.banLevel !==
      BanLevel.NONE
    ) {
      profile.banLevel =
        BanLevel.NONE;

      profile.bannedUntil = 0;
    }

    if (
      profile.score >=
      this.config.scoreThresholds.critical
    ) {
      profile.banLevel =
        BanLevel.CRITICAL;

      profile.bannedUntil =
        now +
        this.config.banDurations.critical;

      return BanLevel.CRITICAL;
    }

    if (
      profile.score >=
      this.config.scoreThresholds.hard
    ) {
      profile.banLevel =
        BanLevel.HARD;

      profile.bannedUntil =
        now +
        this.config.banDurations.hard;

      return BanLevel.HARD;
    }

    if (
      profile.score >=
      this.config.scoreThresholds.soft
    ) {
      profile.banLevel =
        BanLevel.SOFT;

      profile.bannedUntil =
        now +
        this.config.banDurations.soft;

      return BanLevel.SOFT;
    }

    return BanLevel.NONE;
  }

  private isCurrentlyBanned(
    profile: IPProfile
  ): boolean {
    return (
      profile.bannedUntil >
      Date.now()
    );
  }

  private createEvent(
    req: Request,
    ip: string,
    type: string,
    scoreAdded: number,
    totalScore: number,
    action: ThreatEvent["action"]
  ): ThreatEvent {
    return {
      id: crypto.randomUUID(),
      timestamp: Date.now(),

      ip,

      type,
      scoreAdded,
      totalScore,

      action,

      path:
        req.originalUrl || req.path,

      method:
        req.method,

      userAgent:
        req.get("user-agent") ||
        "unknown",

      requestId:
        String(
          resLocals(req, "requestId") ||
          "unknown"
        )
    };
  }

  public getMiddleware() {
    return (
      req: Request,
      res: Response,
      next: NextFunction
    ) => {
      const ip =
        this.extractClientIP(req);

      const profile =
        this.getProfile(ip);

      profile.totalRequests++;

      this.stats.totalRequests++;

      if (
        this.isWhitelisted(ip)
      ) {
        return next();
      }

      if (
        this.isBlacklisted(ip)
      ) {
        profile.blockedRequests++;
        this.stats.blockedRequests++;

        profile.banLevel =
          BanLevel.CRITICAL;

        profile.bannedUntil =
          Date.now() +
          this.config.banDurations.critical;

        this.logger.add(
          this.createEvent(
            req,
            ip,
            "BLACKLISTED_IP",
            100,
            100,
            "BLOCKED"
          )
        );

        return res
          .status(403)
          .json({
            error: "Request blocked",
            reason: "IP_BLACKLISTED"
          });
      }

      this.decayScore(profile);

      if (
        this.isCurrentlyBanned(profile)
      ) {
        profile.blockedRequests++;
        this.stats.blockedRequests++;

        this.stats.activeBans =
          this.countActiveBans();

        return res
          .status(429)
          .set(
            "Retry-After",
            String(
              Math.ceil(
                (profile.bannedUntil -
                  Date.now()) /
                1000
              )
            )
          )
          .json({
            error:
              "Request blocked",
            message:
              "Security policy temporarily restricted this client.",
            banLevel:
              BanLevel[
                profile.banLevel
              ],
            threatScore:
              profile.score
          });
      }

      const now =
        Date.now();

      profile.requestTimestamps =
        profile.requestTimestamps.filter(
          timestamp =>
            now - timestamp <
            this.config.windowMs
        );

      profile.requestTimestamps.push(
        now
      );

      if (
        profile.requestTimestamps.length >
        this.config.maxRequestsPerWindow
      ) {
        this.addScore(
          profile,
          15
        );

        profile.blockedRequests++;

        this.stats.blockedRequests++;
        this.stats.rateLimitedRequests++;

        this.logger.add(
          this.createEvent(
            req,
            ip,
            "RATE_LIMIT",
            15,
            profile.score,
            "RATE_LIMITED"
          )
        );

        return res
          .status(429)
          .set(
            "Retry-After",
            String(
              Math.ceil(
                this.config.windowMs /
                1000
              )
            )
          )
          .json({
            error:
              "Too many requests",
            message:
              "Rate limit exceeded.",
            threatScore:
              profile.score
          });
      }

      const inspection =
        WAFSignatureEngine.inspect(req);

      if (
        inspection.threatDetected
      ) {
        this.stats.detectedThreats++;

        const scorePerViolation =
          inspection.violations.length > 0
            ? Math.ceil(
                inspection.addedScore /
                inspection.violations.length
              )
            : inspection.addedScore;

        for (
          const violation of
          inspection.violations
        ) {
          this.addViolation(
            profile,
            violation,
            scorePerViolation
          );
        }

        this.addScore(
          profile,
          inspection.addedScore
        );

        const banLevel =
          this.evaluateBanState(
            profile
          );

        const shouldBlock =
          banLevel !==
            BanLevel.NONE;

        this.logger.add(
          this.createEvent(
            req,
            ip,
            inspection.violations.join(","),
            inspection.addedScore,
            profile.score,
            shouldBlock
              ? "BLOCKED"
              : "DETECTED"
          )
        );

        if (shouldBlock) {
          profile.blockedRequests++;
          this.stats.blockedRequests++;

          return res
            .status(403)
            .json({
              error:
                "Request blocked",
              message:
                "Security policy detected suspicious activity.",
              violations:
                inspection.violations,
              banLevel:
                BanLevel[
                  banLevel
                ],
              threatScore:
                profile.score
            });
        }
      }

      this.stats.activeBans =
        this.countActiveBans();

      next();
    };
  }

  public getStats(): FirewallStats {
    return {
      ...this.stats,
      trackedIPs:
        this.profiles.size,
      activeBans:
        this.countActiveBans()
    };
  }

  private countActiveBans(): number {
    const now =
      Date.now();

    let count = 0;

    for (
      const profile of
      this.profiles.values()
    ) {
      if (
        profile.bannedUntil > now
      ) {
        count++;
      }
    }

    return count;
  }

  public resetProfile(
    ip: string
  ): void {
    this.profiles.delete(ip);
  }

  public resetAll(): void {
    this.profiles.clear();
  }

  private cleanup(): void {
    const now =
      Date.now();

    const expiration =
      30 * 60 * 1000;

    for (
      const [ip, profile] of
      this.profiles
    ) {
      const inactive =
        now - profile.lastSeen >
        expiration;

      const expiredBan =
        profile.bannedUntil <= now;

      if (
        inactive &&
        expiredBan
      ) {
        this.profiles.delete(ip);
      }
    }

    this.stats.activeBans =
      this.countActiveBans();
  }
}

function resLocals(
  req: Request,
  key: string
): unknown {
  return (
    req.res?.locals?.[key]
  );
}