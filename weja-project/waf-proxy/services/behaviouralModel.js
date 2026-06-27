const aiClient = require('./aiClient');
const CONFIG = require('../config');

/**
 * Behavioural model service wrapper for waf-proxy.
 * - If `CONFIG.BEHAVIOURAL_MODEL_ENABLED` is false, forwards to generic `/analyze`.
 * - Otherwise, tries `/behavioural/analyze` on the AI engine, falls back to `/analyze`.
 * - On any error, returns a safe non-blocking result.
 */

// async function analyze({ payload, method, path, headers }) {
//     // Feature flag: if disabled, use generic analyze endpoint
//     if (!CONFIG.BEHAVIOURAL_MODEL_ENABLED) {
//         try {
//             const res = await aiClient.post('/analyze', { payload, method, path, headers });
//             return res.data;
//         } catch (err) {
//             console.warn('behaviouralModel: fallback generic analyze failed:', err.message);
//             return { blocked: false, type: null, confidence: 0 };
//         }
//     }

//     // Try dedicated behavioural endpoint first
//     try {
//         const res = await aiClient.post('/behavioural/analyze', { payload, method, path, headers });
//         return res.data;
//     } catch (err) {
//         console.warn('behaviouralModel: behavioural endpoint failed, falling back to generic analyze:', err.message);
//         try {
//             const res2 = await aiClient.post('/analyze', { payload, method, path, headers });
//             return res2.data;
//         } catch (err2) {
//             console.error('behaviouralModel: both behavioural and generic analysis failed:', err2.message);
//             return { blocked: false, type: null, confidence: 0 };
//         }
//     }
// }

async function analyze({ payload, method, path, headers }) {
    // === FORCE PRINT EVERY SINGLE REQUEST ===
    console.log(`\n[GATEWAY TRAFFIC] Incoming check for path: ${path} | method: ${method}`);

    try {
        console.log("➡️ Sending request to AI Engine (/behavioural/analyze)...");
        const res = await aiClient.post('/behavioural/analyze', { payload, method, path, headers });
        console.log("✅ AI Engine Responded Successfully!");
        return res.data;
    } catch (err) {
        console.log(`⚠️ Primary endpoint failed (${err.message}). Trying fallback (/analyze)...`);
        try {
            const res2 = await aiClient.post('/analyze', { payload, method, path, headers });
            console.log("✅ Fallback AI Engine Responded Successfully!");
            return res2.data;
        } catch (err2) {
            console.log(`BOTH ENDPOINTS CRASHED! Error: ${err2.message}`);
            return { blocked: false, type: null, confidence: 0 };
        }
    }
}

module.exports = { analyze };
