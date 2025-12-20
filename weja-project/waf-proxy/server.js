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
            sourceIp: req.ip || req.connection.remoteAddress || 'unknown',
            userAgent: req.headers['user-agent'] || '',
            blocked: analysis.blocked,
            attackType: analysis.type,
            confidence: analysis.confidence,
            responseTime: responseTime
        });

        // Block malicious requests
        if (analysis.blocked) {
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
            sourceIp: req.ip || req.connection.remoteAddress || 'unknown',
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
            target: CONFIG.TARGET_URL
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
