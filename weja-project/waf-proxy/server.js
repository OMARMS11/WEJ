/**
 * WEJÀ WAF Gateway Server
 * Reverse proxy with AI-powered attack detection.
 * Supports in-memory logging when MongoDB is unavailable.
 */

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const mongoose = require('mongoose');
const Log = require('./models/Log');

const app = express();

// ============ CONFIGURATION ============
const CONFIG = {
    PORT: 3000,
    AI_ENGINE_URL: 'http://localhost:5000',
    TARGET_URL: 'http://localhost:4000',
    MONGODB_URI: 'mongodb://localhost:27017/weja_waf'
};

// ============ IN-MEMORY FALLBACK ============
let inMemoryLogs = [];
let useInMemory = false;
const MAX_MEMORY_LOGS = 1000;

// ============ IP BLACKLIST SYSTEM ============
const ipBlacklist = new Map(); // IP -> { blockedAt, reason, autoBlocked }
const ipAttackCount = new Map(); // IP -> count of blocked requests
const BLACKLIST_THRESHOLD = 3; // Auto-blacklist after 3 blocked requests
const BLACKLIST_DURATION = 60 * 60 * 1000; // 1 hour blacklist duration

// Simulated geolocation data for demo purposes
const SIMULATED_GEOLOCATIONS = {
    '127.0.0.1': { country: 'Local', city: 'Localhost', lat: 0, lon: 0 },
    '::1': { country: 'Local', city: 'Localhost', lat: 0, lon: 0 },
    '192.168.': { country: 'Private Network', city: 'LAN', lat: 0, lon: 0 },
    '10.': { country: 'Private Network', city: 'LAN', lat: 0, lon: 0 },
    'default': [
        { country: 'United States', city: 'New York', lat: 40.7128, lon: -74.0060 },
        { country: 'Russia', city: 'Moscow', lat: 55.7558, lon: 37.6173 },
        { country: 'China', city: 'Beijing', lat: 39.9042, lon: 116.4074 },
        { country: 'Germany', city: 'Berlin', lat: 52.5200, lon: 13.4050 },
        { country: 'Brazil', city: 'São Paulo', lat: -23.5505, lon: -46.6333 },
        { country: 'India', city: 'Mumbai', lat: 19.0760, lon: 72.8777 },
        { country: 'Nigeria', city: 'Lagos', lat: 6.5244, lon: 3.3792 },
        { country: 'Australia', city: 'Sydney', lat: -33.8688, lon: 151.2093 }
    ]
};

// Get simulated geolocation for an IP
function getGeoLocation(ip) {
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
        return SIMULATED_GEOLOCATIONS['127.0.0.1'];
    }
    if (ip.startsWith('192.168.') || ip.startsWith('::ffff:192.168.')) {
        return SIMULATED_GEOLOCATIONS['192.168.'];
    }
    if (ip.startsWith('10.') || ip.startsWith('::ffff:10.')) {
        return SIMULATED_GEOLOCATIONS['10.'];
    }
    // Return random location for other IPs (consistent per IP using hash)
    const hash = ip.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
    const locations = SIMULATED_GEOLOCATIONS['default'];
    return locations[hash % locations.length];
}

// Check if IP is blacklisted
function isBlacklisted(ip) {
    const entry = ipBlacklist.get(ip);
    if (!entry) return false;

    // Check if blacklist has expired
    if (Date.now() - entry.blockedAt > BLACKLIST_DURATION) {
        ipBlacklist.delete(ip);
        return false;
    }
    return true;
}

// Add IP to blacklist
function addToBlacklist(ip, reason, autoBlocked = false) {
    ipBlacklist.set(ip, {
        blockedAt: Date.now(),
        reason: reason,
        autoBlocked: autoBlocked,
        geo: getGeoLocation(ip)
    });
    console.log(`🚫 IP ${ip} added to blacklist: ${reason}`);
}

// Track attack attempts and auto-blacklist
function trackAttack(ip, attackType) {
    const count = (ipAttackCount.get(ip) || 0) + 1;
    ipAttackCount.set(ip, count);

    if (count >= BLACKLIST_THRESHOLD && !isBlacklisted(ip)) {
        addToBlacklist(ip, `Auto-blocked after ${count} attacks (${attackType})`, true);
    }
}

// ============ MIDDLEWARE ============
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============ DATABASE CONNECTION ============
mongoose.connect(CONFIG.MONGODB_URI, {
    serverSelectionTimeoutMS: 3000,
    connectTimeoutMS: 3000
})
    .then(() => {
        console.log('📦 Connected to MongoDB');
        useInMemory = false;
    })
    .catch(err => {
        console.warn('⚠️  MongoDB unavailable, using in-memory storage');
        console.warn('   To enable MongoDB: brew services start mongodb-community');
        useInMemory = true;
    });

// Helper function to save log
async function saveLog(logData) {
    if (useInMemory || mongoose.connection.readyState !== 1) {
        const memLog = {
            _id: Date.now().toString(36) + Math.random().toString(36).substr(2),
            ...logData,
            timestamp: new Date(),
            createdAt: new Date(),
            updatedAt: new Date()
        };
        inMemoryLogs.unshift(memLog);
        if (inMemoryLogs.length > MAX_MEMORY_LOGS) {
            inMemoryLogs.pop();
        }
        return memLog;
    } else {
        const logEntry = new Log(logData);
        await logEntry.save();
        return logEntry;
    }
}


// ============ WAF MIDDLEWARE ============
const wafMiddleware = async (req, res, next) => {
    const startTime = Date.now();
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';

    // CHECK BLACKLIST FIRST
    if (isBlacklisted(clientIp)) {
        const entry = ipBlacklist.get(clientIp);
        console.log(`🚫 BLACKLISTED IP: ${clientIp} - ${entry.reason}`);

        // Log the blocked request
        await saveLog({
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
            responseTime: Date.now() - startTime
        }).catch(() => { });

        return res.status(403).json({
            error: 'Request Blocked',
            reason: 'IP Address is blacklisted',
            blacklistReason: entry.reason,
            remainingTime: Math.ceil((BLACKLIST_DURATION - (Date.now() - entry.blockedAt)) / 1000) + 's'
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

    // Combine all inputs into payload for AI analysis
    const payload = JSON.stringify({
        ...requestData.query,
        ...requestData.body,
        path: requestData.path
    });

    try {
        // Send to AI Engine for analysis
        const aiResponse = await axios.post(`${CONFIG.AI_ENGINE_URL}/analyze`, {
            payload: payload,
            method: req.method,
            path: req.path,
            headers: requestData.headers
        }, { timeout: 5000 });

        const analysis = aiResponse.data;
        const responseTime = Date.now() - startTime;

        // Log the request
        const logEntry = await saveLog({
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
            responseTime: responseTime
        });

        // Block malicious requests
        if (analysis.blocked) {
            // Track attack for auto-blacklisting
            trackAttack(clientIp, analysis.type);

            console.log(`🚫 BLOCKED: ${req.method} ${req.path} - ${analysis.type} (${analysis.confidence})`);
            return res.status(403).json({
                error: 'Request Blocked',
                reason: 'Potential security threat detected',
                attackType: analysis.type,
                confidence: analysis.confidence,
                requestId: logEntry._id
            });
        }

        // Allow safe requests
        console.log(`✅ ALLOWED: ${req.method} ${req.path}`);
        next();

    } catch (error) {
        console.error('🔥 WAF Analysis Error:', error.message);

        // Log the error but allow the request (fail-open for MVP)
        await saveLog({
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
            responseTime: Date.now() - startTime
        }).catch(() => { });

        next();
    }
};


// ============ API ROUTES (Dashboard) ============

// Get all logs (paginated)
app.get('/api/logs', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;

        let logs, total;

        if (useInMemory || mongoose.connection.readyState !== 1) {
            total = inMemoryLogs.length;
            logs = inMemoryLogs.slice(skip, skip + limit);
        } else {
            logs = await Log.find()
                .sort({ timestamp: -1 })
                .skip(skip)
                .limit(limit);
            total = await Log.countDocuments();
        }

        res.json({
            logs,
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit)
            },
            storage: useInMemory ? 'memory' : 'mongodb'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get attack statistics
app.get('/api/stats', async (req, res) => {
    try {
        let totalRequests, blockedRequests, attackTypes, hourlyTraffic;

        if (useInMemory || mongoose.connection.readyState !== 1) {
            totalRequests = inMemoryLogs.length;
            blockedRequests = inMemoryLogs.filter(l => l.blocked).length;

            // Attack type breakdown
            const typeMap = {};
            inMemoryLogs.filter(l => l.blocked).forEach(l => {
                typeMap[l.attackType] = (typeMap[l.attackType] || 0) + 1;
            });
            attackTypes = Object.entries(typeMap)
                .map(([type, count]) => ({ type, count }))
                .sort((a, b) => b.count - a.count);

            hourlyTraffic = [];
        } else {
            totalRequests = await Log.countDocuments();
            blockedRequests = await Log.countDocuments({ blocked: true });

            const attackTypesAgg = await Log.aggregate([
                { $match: { blocked: true } },
                { $group: { _id: '$attackType', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ]);
            attackTypes = attackTypesAgg.map(t => ({ type: t._id, count: t.count }));

            hourlyTraffic = await Log.aggregate([
                {
                    $match: {
                        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
                    }
                },
                {
                    $group: {
                        _id: {
                            hour: { $hour: '$timestamp' },
                            blocked: '$blocked'
                        },
                        count: { $sum: 1 }
                    }
                },
                { $sort: { '_id.hour': 1 } }
            ]);
        }

        const allowedRequests = totalRequests - blockedRequests;

        res.json({
            summary: {
                total: totalRequests,
                blocked: blockedRequests,
                allowed: allowedRequests,
                blockRate: totalRequests > 0 ? ((blockedRequests / totalRequests) * 100).toFixed(2) : 0
            },
            attackTypes,
            hourlyTraffic,
            storage: useInMemory ? 'memory' : 'mongodb'
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check
app.get('/api/health', async (req, res) => {
    try {
        // Check AI Engine
        const aiHealth = await axios.get(`${CONFIG.AI_ENGINE_URL}/health`, { timeout: 2000 })
            .then(() => 'healthy')
            .catch(() => 'unhealthy');

        // Check MongoDB
        const dbHealth = mongoose.connection.readyState === 1 ? 'healthy' : 'unavailable (using memory)';

        res.json({
            waf: 'healthy',
            aiEngine: aiHealth,
            database: dbHealth,
            storage: useInMemory ? 'memory' : 'mongodb',
            target: CONFIG.TARGET_URL,
            blacklistedIPs: ipBlacklist.size
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============ BLACKLIST API ROUTES ============

// Get all blacklisted IPs
app.get('/api/blacklist', (req, res) => {
    const blacklist = [];
    ipBlacklist.forEach((entry, ip) => {
        // Check if still valid
        if (Date.now() - entry.blockedAt <= BLACKLIST_DURATION) {
            blacklist.push({
                ip: ip,
                blockedAt: new Date(entry.blockedAt).toISOString(),
                reason: entry.reason,
                autoBlocked: entry.autoBlocked,
                geo: entry.geo,
                remainingSeconds: Math.ceil((BLACKLIST_DURATION - (Date.now() - entry.blockedAt)) / 1000)
            });
        }
    });

    res.json({
        count: blacklist.length,
        blacklist: blacklist.sort((a, b) => b.blockedAt - a.blockedAt)
    });
});

// Add IP to blacklist manually
app.post('/api/blacklist', (req, res) => {
    const { ip, reason } = req.body;

    if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
    }

    if (isBlacklisted(ip)) {
        return res.status(409).json({ error: 'IP is already blacklisted' });
    }

    addToBlacklist(ip, reason || 'Manually added', false);

    res.json({
        success: true,
        message: `IP ${ip} added to blacklist`,
        expiresIn: BLACKLIST_DURATION / 1000 + ' seconds'
    });
});

// Remove IP from blacklist
app.delete('/api/blacklist/:ip', (req, res) => {
    const ip = req.params.ip;

    if (!ipBlacklist.has(ip)) {
        return res.status(404).json({ error: 'IP not found in blacklist' });
    }

    ipBlacklist.delete(ip);
    ipAttackCount.delete(ip);
    console.log(`✅ IP ${ip} removed from blacklist`);

    res.json({
        success: true,
        message: `IP ${ip} removed from blacklist`
    });
});

// Get top attackers (for Attacker Map)
app.get('/api/top-attackers', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        let topAttackers;

        if (useInMemory || mongoose.connection.readyState !== 1) {
            // Aggregate from in-memory logs
            const ipMap = {};
            inMemoryLogs.filter(l => l.blocked).forEach(log => {
                const ip = log.sourceIp;
                if (!ipMap[ip]) {
                    ipMap[ip] = {
                        ip: ip,
                        attackCount: 0,
                        lastAttack: log.timestamp,
                        attackTypes: {},
                        geo: getGeoLocation(ip),
                        isBlacklisted: isBlacklisted(ip)
                    };
                }
                ipMap[ip].attackCount++;
                ipMap[ip].attackTypes[log.attackType] = (ipMap[ip].attackTypes[log.attackType] || 0) + 1;
                if (new Date(log.timestamp) > new Date(ipMap[ip].lastAttack)) {
                    ipMap[ip].lastAttack = log.timestamp;
                }
            });

            topAttackers = Object.values(ipMap)
                .map(attacker => ({
                    ...attacker,
                    attackTypes: Object.entries(attacker.attackTypes)
                        .map(([type, count]) => ({ type, count }))
                        .sort((a, b) => b.count - a.count)
                }))
                .sort((a, b) => b.attackCount - a.attackCount)
                .slice(0, limit);
        } else {
            // Aggregate from MongoDB
            const attackersAgg = await Log.aggregate([
                { $match: { blocked: true } },
                {
                    $group: {
                        _id: '$sourceIp',
                        attackCount: { $sum: 1 },
                        lastAttack: { $max: '$timestamp' },
                        attackTypes: { $push: '$attackType' }
                    }
                },
                { $sort: { attackCount: -1 } },
                { $limit: limit }
            ]);

            topAttackers = attackersAgg.map(a => {
                const typeCounts = {};
                a.attackTypes.forEach(t => { typeCounts[t] = (typeCounts[t] || 0) + 1; });

                return {
                    ip: a._id,
                    attackCount: a.attackCount,
                    lastAttack: a.lastAttack,
                    attackTypes: Object.entries(typeCounts)
                        .map(([type, count]) => ({ type, count }))
                        .sort((a, b) => b.count - a.count),
                    geo: getGeoLocation(a._id),
                    isBlacklisted: isBlacklisted(a._id)
                };
            });
        }

        res.json({
            count: topAttackers.length,
            attackers: topAttackers
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// ============ PROXY ROUTES ============
// Apply WAF middleware and proxy to target
app.use('/proxy', wafMiddleware, async (req, res) => {
    try {
        const targetUrl = `${CONFIG.TARGET_URL}${req.path}`;

        const response = await axios({
            method: req.method,
            url: targetUrl,
            params: req.query,
            data: req.body,
            headers: {
                'Content-Type': req.headers['content-type'] || 'application/json'
            },
            timeout: 10000
        });

        res.status(response.status).json(response.data);

    } catch (error) {
        if (error.response) {
            res.status(error.response.status).json(error.response.data);
        } else {
            res.status(502).json({
                error: 'Bad Gateway',
                message: 'Unable to reach target server'
            });
        }
    }
});

// ============ START SERVER ============
app.listen(CONFIG.PORT, () => {
    console.log(`🛡️  WEJÀ WAF Gateway running on http://localhost:${CONFIG.PORT}`);
    console.log(`📡 AI Engine: ${CONFIG.AI_ENGINE_URL}`);
    console.log(`🎯 Target: ${CONFIG.TARGET_URL}`);
    console.log(`📊 Dashboard API: http://localhost:${CONFIG.PORT}/api`);
});
