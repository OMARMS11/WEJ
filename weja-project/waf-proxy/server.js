/**
 * WEJÀ WAF Gateway Server
 * Refactored modular architecture
 */

const express = require('express');
const cors = require('cors');
const CONFIG = require('./config');
const { connectDB } = require('./database/connection');
const wafMiddleware = require('./middlewares/waf');
const proxyMiddleware = require('./middlewares/proxy');
const rateLimiter = require('./middlewares/rateLimiter');
const apiRoutes = require('./routes/api');

const app = express();

// ============ MIDDLEWARE ============
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============ DATABASE ============
connectDB();

// ============ API ROUTES ============
app.use('/api', apiRoutes);

// ============ RATE LIMITER ============
app.use(rateLimiter);

// ============ WAF & PROXY ============
// Apply WAF to all other requests
app.use(wafMiddleware);

// Proxy everything else to target
app.use(proxyMiddleware);

// ============ START SERVER ============
app.listen(CONFIG.PORT, () => {
    console.log(`🛡️  WEJÀ WAF Gateway running on http://localhost:${CONFIG.PORT}`);
    console.log(`📡 AI Engine: ${CONFIG.AI_ENGINE_URL}`);
    console.log(`🎯 Target: ${CONFIG.TARGET_URL}`);
    console.log(`📊 Dashboard API: http://localhost:${CONFIG.PORT}/api`);
});
