import {
  ThreatEvent
} from "./types";

export class SecurityLogger {
  private events: ThreatEvent[] = [];

  constructor(
    private readonly maxEvents: number
  ) {}

  add(event: ThreatEvent): void {
    this.events.unshift(event);

    if (this.events.length > this.maxEvents) {
      this.events.length = this.maxEvents;
    }

    const icon =
      event.action === "BLOCKED"
        ? "🔴"
        : event.action === "RATE_LIMITED"
          ? "🟠"
          : "🟡";

    console.log(
      `${icon} [NOVA-WAF] ${event.action}` +
      ` | ${event.ip}` +
      ` | ${event.type}` +
      ` | +${event.scoreAdded}` +
      ` | ${event.method}` +
      ` ${event.path}`
    );
  }

  getEvents(limit = 100): ThreatEvent[] {
    return this.events.slice(
      0,
      Math.max(1, Math.min(limit, this.maxEvents))
    );
  }

  clear(): void {
    this.events = [];
  }

  getStats() {
    return {
      total: this.events.length,

      blocked: this.events.filter(
        event => event.action === "BLOCKED"
      ).length,

      rateLimited: this.events.filter(
        event => event.action === "RATE_LIMITED"
      ).length,

      detected: this.events.filter(
        event => event.action === "DETECTED"
      ).length
    };
  }
}