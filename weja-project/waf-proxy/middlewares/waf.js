const CONFIG = require('../config');
const aiClient = require('../services/aiClient');
const blacklistService = require('../services/blacklist');
const logService = require('../database/logService');

// ============ WAF MIDDLEWARE ============
const wafMiddleware = async (req, res, next) => {
    // Skip static assets & websocket upgrades
    if (
        req.method === 'GET' &&
        (
            req.path.startsWith('/static') ||//needs revision
            req.path.endsWith('.js') ||
            req.path.endsWith('.css') ||
            req.path.endsWith('.png') ||
            req.path.endsWith('.jpg') ||
            req.path.endsWith('.svg') ||
            req.path.endsWith('.ico') ||
            req.headers.upgrade === 'websocket'
        )
    ) {
        return next();
    }

    const startTime = Date.now();
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';

    // CHECK BLACKLIST FIRST
    if (blacklistService.isBlacklisted(clientIp)) {
        const entry = blacklistService.ipBlacklist.get(clientIp);
        console.log(`🚫 BLACKLISTED IP: ${clientIp} - ${entry.reason}`);

        // Log the blocked request
        await logService.saveLog({
            method: req.method,
            path: req.path,
            query: req.query,
            body: req.body,
            headers: { 'user-agent': req.headers['user-agent'] },
            sourceIp: clientIp,
            userAgent: req.headers['user-agent'] || '',
            blocked: true,
            attackType: 'BLACKLISTED',
            confidence: 1.0,
            responseTime: Date.now() - startTime,
            geo: req.geoData
        }).catch(() => { });

        return res.status(403).json({
            error: 'Request Blocked',
            reason: 'IP Address is blacklisted',
            blacklistReason: entry.reason,
            remainingTime: Math.ceil((CONFIG.BLACKLIST_DURATION - (Date.now() - entry.blockedAt)) / 1000) + 's'
        });
    }

    // Extract request data for analysis
    const requestData = {
        method: req.method,
        path: req.path,
        query: req.query,
        body: req.body,
        headers: {
            'user-agent': req.headers['user-agent'],
            'content-type': req.headers['content-type'],
            'host': req.headers['host']
        }
    };

    // Build payload object for AI analysis (query params + body + path)
    const payloadObj = {
        ...requestData.query,
        ...(requestData.body || {}),
        path: requestData.path
    };

    // Skip inspection if there's nothing meaningful to analyze
    // For GET requests: only inspect if there are query parameters
    // For other methods: always inspect (body content is relevant)
    const hasQueryParams = Object.keys(req.query || {}).length > 0;
    if (req.method === 'GET' && !hasQueryParams) {
        return next();
    }

    const payload = JSON.stringify(payloadObj);

    if (Object.keys(payloadObj).length <= 1) {
        // Only "path" key exists, nothing user-supplied to analyze
        return next();
    }
    try {
        // Send to AI Engine for analysis
        const aiResponse = await aiClient.post('/analyze', {
            payload,
            method: req.method,
            path: req.path,
            headers: requestData.headers
        });


        const analysis = aiResponse.data;
        const responseTime = Date.now() - startTime;

        // Log the request
        //made the logging non blocking to the request
        logService.saveLog({
            method: req.method,
            path: req.path,
            query: req.query,
            body: req.body,
            headers: requestData.headers,
            sourceIp: clientIp,
            userAgent: req.headers['user-agent'] || '',
            blocked: analysis.blocked,
            attackType: analysis.type,
            confidence: analysis.confidence,
            responseTime: responseTime,
            geo: req.geoData
        }).catch(() => { });

        // Block malicious requests
        if (analysis.blocked) {
            // Track attack for auto-blacklisting
            blacklistService.trackAttack(clientIp, analysis.type);

            console.log(`🚫 BLOCKED: ${req.method} ${req.path} - ${analysis.type} (${analysis.confidence})`);
            return res.status(403).json({
                error: 'Request Blocked',
                reason: 'Potential security threat detected',
                attackType: analysis.type,
                confidence: analysis.confidence,
                requestId: Date.now().toString() //the date is genrated on the fly not from the db to save time
            });
        }

        // Allow safe requests
        console.log(`✅ ALLOWED: ${req.method} ${req.path}`);
        next();

    } catch (error) {
        console.error('🔥 WAF Analysis Error:', error.message);

        // Log the error but allow the request (fail-open for MVP)
        await logService.saveLog({
            method: req.method,
            path: req.path,
            query: req.query,
            body: req.body,
            headers: requestData.headers,
            sourceIp: clientIp,
            userAgent: req.headers['user-agent'] || '',
            blocked: false,
            attackType: 'ERROR',
            confidence: 0,
            responseTime: Date.now() - startTime,
            geo: req.geoData
        }).catch(() => { });

        next();
    }
};

module.exports = wafMiddleware;
