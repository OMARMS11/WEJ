/**
 * WEJÀ Geo-Filter Middleware
 *
 * Resolves client IP → geolocation, then optionally blocks based on
 * country allow/deny lists. Runs BEFORE the WAF middleware to avoid
 * unnecessary AI Engine round-trips for geo-blocked IPs.
 *
 * SAFETY GUARANTEES:
 *  - Entire function body wrapped in try/catch — never blocks the pipeline on error.
 *  - Never calls next(err) — errors are logged and swallowed.
 *  - Private/loopback IPs always pass through regardless of filter mode.
 *  - Low-accuracy lookups (>500km radius) are never used for blocking.
 */

const geoService = require('../services/geolocation');
const logService = require('../database/logService');

const geoFilter = async (req, res, next) => {
    try {
        const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
        const startTime = Date.now();

        // Resolve geolocation — always returns a valid object
        const geoData = geoService.getGeoLocation(clientIp);

        // Attach to request for downstream consumers
        req.geoData = geoData;

        // Check if country is blocked
        const blockResult = geoService.isCountryBlocked(clientIp);

        if (blockResult.blocked) {
            console.log(`🌍 GEO-BLOCKED: ${clientIp} — ${blockResult.reason}`);

            // Log the geo-blocked request (non-blocking)
            logService.saveLog({
                method: req.method,
                path: req.path,
                query: req.query,
                body: req.body,
                headers: { 'user-agent': req.headers['user-agent'] },
                sourceIp: clientIp,
                userAgent: req.headers['user-agent'] || '',
                blocked: true,
                attackType: 'GEO_BLOCKED',
                confidence: 1.0,
                responseTime: Date.now() - startTime,
                geo: {
                    country: geoData.country,
                    countryCode: geoData.countryCode,
                    city: geoData.city,
                    lat: geoData.lat,
                    lon: geoData.lon
                }
            }).catch(() => { });

            return res.status(403).json({
                error: 'Request Blocked',
                reason: 'Geographic restriction',
                detail: blockResult.reason,
                countryCode: blockResult.countryCode
            });
        }

        // Not blocked — continue through pipeline
        next();
    } catch (err) {
        // FAIL-SAFE: log error, set geoData to null, continue pipeline
        console.error('🔥 GeoFilter error:', err.message);
        req.geoData = null;
        next();
    }
};

module.exports = geoFilter;
