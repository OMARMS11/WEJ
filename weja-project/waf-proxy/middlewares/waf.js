const crypto = require("crypto");
const CONFIG = require("../config");
const aiClient = require("../services/aiClient");
const behaviouralModel = require("../services/behaviouralModel");
const blacklistService = require("../services/blacklist");
const logService = require("../database/logService");
const ipRequestCounters = {}; // Track precise packet counts

// ==========================================
// TRAINING MODE (dataset capture / bypass)
// ==========================================
// Enable with:  WAF_TRAINING_MODE=1 WAF_TRAINING_SECRET=<secret> node server.js
// A request is "training" if it carries header  x-waf-training: <secret>
// (use a browser extension like ModHeader), OR its IP is in WAF_TRAINING_IPS
// (comma-separated, e.g. "127.0.0.1,::1,::ffff:127.0.0.1" for natural browsing
// with no extension). Training requests are never blocked or blacklisted, but
// they still flow through the AI engine so traffic_history keeps building.
// The whole gate is inert unless BOTH env vars are set — remove them for demos.
const TRAINING_MODE = process.env.WAF_TRAINING_MODE === "1";
const TRAINING_SECRET = process.env.WAF_TRAINING_SECRET || "";
const TRAINING_IPS = (process.env.WAF_TRAINING_IPS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function isTrainingRequest(req, clientIp) {
  if (!TRAINING_MODE || !TRAINING_SECRET) return false;
  if (TRAINING_IPS.includes(clientIp)) return true;
  const header = req.headers["x-waf-training"];
  return Boolean(header && safeEqual(header, TRAINING_SECRET));
}

const wafMiddleware = async (req, res, next) => {
  // 1. Static Assets Opt-out (Keep this to protect asset performance)
  if (
    req.method === "GET" &&
    (req.path.startsWith("/static") ||
      req.path.endsWith(".js") ||
      req.path.endsWith(".css") ||
      req.path.endsWith(".png") ||
      req.path.endsWith(".jpg") ||
      req.path.endsWith(".svg") ||
      req.path.endsWith(".ico") ||
      req.headers.upgrade === "websocket")
  ) {
    return next();
  }

  const startTime = Date.now();
  const clientIp = req.ip || req.connection.remoteAddress || "unknown";
  const requestId = `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

  // === POST-RESPONSE TELEMETRY (The Feedback Loop) ===
  res.on('finish', () => {
    const responseTime = Date.now() - startTime;
    const statusCode = res.statusCode;
    const responseSize = res.get('Content-Length') || 0;

    aiClient.post('/behavioural/telemetry', {
      ip: clientIp,
      requestId: requestId,
      statusCode: statusCode,
      responseTime: responseTime,
      responseSize: responseSize,
      path: req.path
    }).catch(err => { });
  });

  const training = isTrainingRequest(req, clientIp);

  // 2. Blacklist Inspection Gate
  if (training && blacklistService.isBlacklisted(clientIp)) {
    // Self-heal: a stale edge ban must not trap the training IP.
    // (blacklistService.ipBlacklist is the Map already used above in this file.)
    blacklistService.ipBlacklist.delete(clientIp);
    console.log(`🎓 [TRAINING] Cleared edge blacklist entry for ${clientIp}`);
  }
  if (!training && blacklistService.isBlacklisted(clientIp)) {
    const entry = blacklistService.ipBlacklist.get(clientIp);
    console.log(`🚫 BLOCK (BLACKLISTED IP): ${clientIp} - ${entry.reason}`);

    await logService
      .saveLog({
        method: req.method,
        path: req.path,
        query: req.query,
        body: req.body,
        headers: { "user-agent": req.headers["user-agent"] },
        sourceIp: clientIp,
        userAgent: req.headers["user-agent"] || "",
        blocked: true,
        attackType: "BLACKLISTED",
        confidence: 1.0,
        responseTime: Date.now() - startTime,
        geo: req.geoData,
      })
      .catch(() => { });

    // Render the Blacklist page with additional details
    return res.status(403).render("blacklist", {
      error: "Request Blocked",
      reason:
        "IP Address is blacklisted due to persistent behavioral anomalies.",
      blacklistReason: entry.reason,
      remainingTime:
        Math.ceil(
          (CONFIG.BLACKLIST_DURATION - (Date.now() - entry.blockedAt)) / 1000,
        ) + "s",
    });
  }

  // Increment total packets seen from this IP
  if (!ipRequestCounters[clientIp]) {
    ipRequestCounters[clientIp] = 0;
  }
  ipRequestCounters[clientIp] += 1;

  // 3. Compile Metric Metadata for the AI Request Packet
  const requestData = {
    method: req.method,
    path: req.path,
    query: req.query || {},
    body: req.body || {},
    headers: {
      "user-agent": req.headers["user-agent"] || "",
      "content-type": req.headers["content-type"] || "",
      host: req.headers.host || "",
    },
    ip: clientIp, // Explicitly forward the client IP for sequence windows tracking
    totalPackets: ipRequestCounters[clientIp],
  };

  // Flatten parameters for the Tier 1 text fallback signature analysis string
  const payloadObj = {
    ...requestData.query,
    ...requestData.body,
    path: requestData.path,
  };
  const payloadString = JSON.stringify(payloadObj);

  try {
    // HARDENED EXECUTION: Force Tier 2 behavioral checking for EVERY request flow.
    // No short-circuits on query lengths or GET limits
    console.log(
      `SENDING TO URL: ${aiClient.defaults.baseURL}/behavioural/analyze`,
    );

    const response = await aiClient.post("/behavioural/analyze", {
      ip: clientIp,
      payload: payloadString,
      method: req.method,
      path: req.path,
      headers: requestData.headers,
      totalPackets: requestData.totalPackets,
      requestId: requestId,
      trainingMode: training,
      trainingSecret: training ? TRAINING_SECRET : undefined
    });

    const analysis = response.data;
    const responseTime = Date.now() - startTime;

    // Handle Behavioral Drop Trigger
    if (analysis.blocked && training) {
      console.log(
        `🎓 [TRAINING] Behavioral verdict would block ${clientIp} (${analysis.type}, conf ${analysis.confidence}) — not enforcing.`,
      );
    }
    if (analysis.blocked && !training) {
      blacklistService.trackAttack(clientIp, analysis.type);
      console.log(
        `🚫 WAF BLOCK: ${req.method} ${req.path} -> Motive: ${analysis.type} (Conf: ${analysis.confidence})`,
      );

      return res.status(403).render("blocked", {
        error: "Request Blocked",
        reason:
          "Potential security threat or abnormal request pattern detected.",
        attackType: analysis.type,
        confidence: analysis.confidence,
        requestId: Date.now().toString(),
      });
    }

    try {
      const hybridResponse = await aiClient.post("/analyze", {
        ip: clientIp,
        payload: payloadString,
        method: req.method,
        path: req.path,
        headers: requestData.headers,
        totalPackets: requestData.totalPackets,
        behavioral_result: analysis,
        requestId: requestId,
        trainingMode: training,
        trainingSecret: training ? TRAINING_SECRET : undefined
      });

      const hybridAnalysis = hybridResponse.data;
      // Log the structural evaluation to database records
      logService
        .saveLog({
          method: req.method,
          path: req.path,
          query: req.query,
          body: req.body,
          headers: requestData.headers,
          sourceIp: clientIp,
          userAgent: req.headers["user-agent"] || "",
          blocked: hybridAnalysis.blocked,
          attackType: hybridAnalysis.type,
          confidence: hybridAnalysis.confidence,
          rule_confidence: hybridAnalysis.rule_confidence,
          ml_confidence: hybridAnalysis.ml_confidence,
          decision: hybridAnalysis.decision,
          responseTime: responseTime,
          geo: req.geoData,
        })
        .catch(() => { });

      if (hybridAnalysis.blocked && training) {
        console.log(
          `🎓 [TRAINING] Hybrid verdict would block ${clientIp} (${hybridAnalysis.type}) — not enforcing.`,
        );
      }
      if (hybridAnalysis.blocked && !training) {
        blacklistService.trackAttack(clientIp, hybridAnalysis.type);
        console.log(
          `🚫 Hybrid WAF BLOCK: ${req.method} ${req.path} -> Motive: ${hybridAnalysis.type} (Conf: ${hybridAnalysis.confidence})`,
        );
        return res.status(403).render("blocked", {
          error: "Request Blocked",
          reason:
            "Potential payload threat detected after behavioral inspection.",
          attackType: hybridAnalysis.type,
          confidence: hybridAnalysis.confidence,
          decision: hybridAnalysis.decision,
          requestId: Date.now().toString(),
        });
      }
    } catch (hybridError) {
      console.warn(
        `⚠️ Hybrid analysis failed after safe behavior check: ${hybridError.message}`,
      );
    }

    next();
  } catch (error) {
    // FAILOVER LAYER: If Tier 2 route drops or breaks, instantly fall back to standard Tier 1 payload metrics
    console.error("AXIOS ROUTING FAILED:", error.message, error.code);
    console.warn(
      `⚠️ Tier 2 Router issue (${error.message}). Invoking Tier 1 Fallback Pipeline...`,
    );

    try {
      const fallbackResponse = await aiClient.post("/analyze", {
        ip: clientIp,
        payload: payloadString,
        method: req.method,
        path: req.path,
        headers: requestData.headers,
        totalPackets: requestData.totalPackets,
        requestId: requestId,
        trainingMode: training,
        trainingSecret: training ? TRAINING_SECRET : undefined
      });

      const fallbackAnalysis = fallbackResponse.data;
      const responseTime = Date.now() - startTime;

      logService
        .saveLog({
          method: req.method,
          path: req.path,
          query: req.query,
          body: req.body,
          headers: requestData.headers,
          sourceIp: clientIp,
          userAgent: req.headers["user-agent"] || "",
          blocked: fallbackAnalysis.blocked,
          attackType: fallbackAnalysis.type,
          confidence: fallbackAnalysis.confidence,
          responseTime: responseTime,
          geo: req.geoData,
        })
        .catch(() => { });

      if (fallbackAnalysis.blocked && training) {
        console.log(
          `🎓 [TRAINING] Fallback verdict would block ${clientIp} (${fallbackAnalysis.type}) — not enforcing.`,
        );
      }
      if (fallbackAnalysis.blocked && !training) {
        blacklistService.trackAttack(clientIp, fallbackAnalysis.type);
        console.log(
          `🚫 Fallback WAF BLOCK: ${req.method} ${req.path} -> Motive: ${fallbackAnalysis.type}`,
        );
        return res.status(403).render("blocked", {
          error: "Request Blocked",
          reason:
            "Potential signature payload threat flagged by backup engine.",
          attackType: fallbackAnalysis.type,
          confidence: fallbackAnalysis.confidence,
          decision: fallbackAnalysis.decision,
        });
      }

      next();
    } catch (fallbackError) {
      console.error(
        "Severe WAF Failure: Both Core and Fallback engines are unreachable.",
        fallbackError.message,
      );

      next();
    }
  }
};

module.exports = wafMiddleware;
