export enum BanLevel {
  NONE = 0,
  SOFT = 1,
  HARD = 2,
  CRITICAL = 3
}

export type ThreatAction =
  | "DETECTED"
  | "BLOCKED"
  | "RATE_LIMITED";

export interface Violation {
  timestamp: number;
  violation: string;
  scoreAdded: number;
}

export interface IPProfile {
  score: number;
  requestTimestamps: number[];

  banLevel: BanLevel;
  bannedUntil: number;

  lastScoreUpdate: number;
  lastSeen: number;

  totalRequests: number;
  blockedRequests: number;

  violationsHistory: Violation[];
}

export interface FirewallConfig {
  windowMs: number;
  maxRequestsPerWindow: number;

  whitelistedIPs: string[];
  blacklistedCIDRs: string[];

  scoreThresholds: {
    soft: number;
    hard: number;
    critical: number;
  };

  banDurations: {
    soft: number;
    hard: number;
    critical: number;
  };

  maxBodySize: number;
  maxViolationsHistory: number;
}

export interface WAFInspectionResult {
  threatDetected: boolean;
  addedScore: number;
  violations: string[];
}

export interface FirewallStats {
  totalRequests: number;
  blockedRequests: number;
  rateLimitedRequests: number;
  detectedThreats: number;
  activeBans: number;
  trackedIPs: number;
}

export interface ThreatEvent {
  id: string;
  timestamp: number;

  ip: string;

  type: string;
  scoreAdded: number;
  totalScore: number;

  action: ThreatAction;

  path: string;
  method: string;

  userAgent: string;

  requestId: string;
}