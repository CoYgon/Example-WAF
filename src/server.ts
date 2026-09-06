import express, {
  NextFunction,
  Request,
  Response
} from "express";

import path from "path";
import crypto from "crypto";
import helmet from "helmet";

import {
  ADMIN_TOKEN,
  firewallConfig,
  HOST,
  MAX_EVENTS,
  NODE_ENV,
  PORT,
  TRUST_PROXY
} from "./config";

import { EnterpriseFirewall } from "./firewall";
import { SecurityLogger } from "./logger";
import { BanLevel } from "./types";

const app = express();

const logger =
  new SecurityLogger(
    MAX_EVENTS
  );

const firewall =
  new EnterpriseFirewall(
    firewallConfig,
    logger
  );

app.set(
  "trust proxy",
  TRUST_PROXY
);

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    const requestId =
      crypto.randomUUID();

    res.locals.requestId =
      requestId;

    res.setHeader(
      "X-Request-ID",
      requestId
    );

    next();
  }
);

app.use(
  express.json({
    limit:
      firewallConfig.maxBodySize
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit:
      firewallConfig.maxBodySize
  })
);

app.use(
  express.static(
    path.join(
      __dirname,
      "..",
      "public"
    )
  )
);

/*
 * Health endpoint.
 * Intentionally before WAF.
 */
app.get(
  "/health",
  (_req, res) => {
    res.json({
      status: "ok",
      service: "NOVA WAF",
      version: "3.0.0",
      environment: NODE_ENV,
      timestamp: new Date().toISOString()
    });
  }
);

/*
 * Dashboard APIs.
 * These remain available so the administrator
 * can inspect a currently blocked client.
 */
app.get(
  "/api/dashboard",
  (_req, res) => {
    res.json({
      success: true,
      stats:
        firewall.getStats(),
      logger:
        logger.getStats(),
      timestamp: Date.now()
    });
  }
);

app.get(
  "/api/events",
  (req, res) => {
    const requested =
      Number(
        req.query.limit || 100
      );

    const limit =
      Number.isFinite(requested)
        ? Math.min(
            Math.max(requested, 1),
            200
          )
        : 100;

    res.json({
      success: true,
      events:
        logger.getEvents(limit)
    });
  }
);

app.get(
  "/api/test-status",
  (req, res) => {
    const ip =
      firewall.extractClientIP(req);

    const profile =
      firewall.getPublicProfile(ip);

    const remaining =
      Math.max(
        0,
        profile.bannedUntil -
        Date.now()
      );

    res.json({
      success: true,

      ip,

      score:
        profile.score,

      banLevel:
        BanLevel[
          profile.banLevel
        ],

      bannedUntil:
        profile.bannedUntil,

      remainingSeconds:
        Math.ceil(
          remaining / 1000
        ),

      requests:
        profile.totalRequests,

      blocked:
        profile.blockedRequests,

      history:
        profile.violationsHistory
    });
  }
);

app.post(
  "/api/test-reset",
  (req, res) => {
    const ip =
      firewall.extractClientIP(req);

    firewall.resetProfile(ip);

    res.json({
      success: true,
      message:
        "Current client profile reset."
    });
  }
);

/*
 * Admin authentication.
 */
function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (!ADMIN_TOKEN) {
    return res
      .status(503)
      .json({
        error:
          "Admin API disabled",
        message:
          "Configure ADMIN_TOKEN in the environment."
      });
  }

  const supplied =
    req.header(
      "X-Admin-Token"
    );

  if (
    !supplied ||
    supplied !== ADMIN_TOKEN
  ) {
    return res
      .status(401)
      .json({
        error:
          "Unauthorized"
      });
  }

  next();
}

app.post(
  "/api/admin/reset-all",
  requireAdmin,
  (_req, res) => {
    firewall.resetAll();
    logger.clear();

    res.json({
      success: true,
      message:
        "All WAF state cleared."
    });
  }
);

/*
 * WAF middleware.
 */
app.use(
  firewall.getMiddleware()
);

/*
 * Protected demo routes.
 */
app.get(
  "/api/public",
  (_req, res) => {
    res.json({
      success: true,
      message:
        "Meşru istek başarılı.",
      timestamp:
        Date.now()
    });
  }
);

app.get(
  "/api/search",
  (req, res) => {
    res.json({
      success: true,
      query:
        req.query
    });
  }
);

app.post(
  "/api/login",
  (req, res) => {
    res.json({
      success: true,
      message:
        "Demo login endpoint.",
      body:
        req.body
    });
  }
);

/*
 * 404.
 */
app.use(
  (
    _req,
    res
  ) => {
    res.status(404).json({
      error:
        "Not Found"
    });
  }
);

/*
 * Error handler.
 */
app.use(
  (
    error: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction
  ) => {
    console.error(
      "[NOVA-WAF] Internal error:",
      error
    );

    if (
      res.headersSent
    ) {
      return;
    }

    res.status(500).json({
      error:
        "Internal Server Error"
    });
  }
);

const server =
  app.listen(
    PORT,
    HOST,
    () => {
      console.log("");
      console.log(
        "========================================"
      );
      console.log(
        "        NOVA WAF V3"
      );
      console.log(
        "        Application Firewall"
      );
      console.log(
        "========================================"
      );
      console.log(
        `Environment : ${NODE_ENV}`
      );
      console.log(
        `Listening   : http://${HOST}:${PORT}`
      );
      console.log(
        `Proxy Trust : ${TRUST_PROXY}`
      );
      console.log(
        "========================================"
      );
      console.log("");
    }
  );

function shutdown(
  signal: string
) {
  console.log(
    `\n[NOVA-WAF] ${signal} received.`
  );

  server.close(() => {
    console.log(
      "[NOVA-WAF] Server stopped."
    );

    process.exit(0);
  });
}

process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM")
);