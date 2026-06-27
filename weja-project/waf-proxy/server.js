/**
 * WEJÀ WAF Gateway Server
 * Refactored modular architecture
 */

const express = require('express');
const cors = require('cors');
const CONFIG = require('./config');
const { connectDB } = require('./database/connection');
const geoService = require('./services/geolocation');
const geoFilter = require('./middlewares/geoFilter');
const wafMiddleware = require('./middlewares/waf');
const proxyMiddleware = require('./middlewares/proxy');
const { rateLimiter } = require('./middlewares/rateLimiter');
const apiRoutes = require('./routes/api');

const app = express();
app.set('trust proxy', true);
//configure view engine for blocked page
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// ============ MIDDLEWARE ============
app.use(cors());
app.use(express.json({ limit: '10kb' })); // Limit body size to 10kb to prevent payload-based DoS
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ============ DATABASE ============
connectDB();

// ============ RATE LIMITER ============
app.use(rateLimiter);

// ============ API ROUTES ============
app.use('/api', apiRoutes);

// ============ GEO-FILTER ============
// Placed BEFORE WAF to block geo-denied IPs without AI Engine round-trip
app.use(geoFilter);

// ============ WAF & PROXY ============
// Apply WAF to all other requests
app.use(wafMiddleware);

// Proxy everything else to target
app.use(proxyMiddleware);

// ============ START SERVER ============
async function startServer() {
    // Initialise geolocation service (never crashes — enters degraded mode on failure)
    try {
        await geoService.init();
        geoService.startUpdateScheduler();
    } catch (err) {
        console.warn('⚠️  Geolocation init failed (non-fatal):', err.message);
    }

    app.listen(CONFIG.PORT, () => {
        console.log(`🛡️  WEJÀ WAF Gateway running on http://localhost:${CONFIG.PORT}`);
        console.log(`📡 AI Engine: ${CONFIG.AI_ENGINE_URL}`);
        console.log(`🎯 Target: ${CONFIG.TARGET_URL}`);
        console.log(`📊 Dashboard API: http://localhost:${CONFIG.PORT}/api`);
    });
}

startServer();
