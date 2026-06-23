/**
 * WEJÀ Geolocation Service — Real IP Geolocation via MaxMind GeoLite2
 *
 * Replaces simulated geo data with binary MMDB lookups (~3-5μs per query).
 * Supports graceful degradation: if the database is missing or corrupt,
 * the WAF continues to function with "Unknown" geo data.
 *
 * Exports are backwards-compatible with the original simulated service:
 *   { country, city, lat, lon } — existing callers need no changes.
 */

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const maxmind = require('maxmind');
const CONFIG = require('../config');

// ============ STATE ============

let activeReader = null;   // maxmind.Reader instance (or null if degraded)
let degraded = true;       // true when no valid database is loaded
let dbFileHash = null;     // SHA-256 of the currently loaded .mmdb
let lastUpdateCheck = null;
let updateInterval = null;

// ============ PRIVATE IP DETECTION ============

const PRIVATE_RANGES = [
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^::1$/,
    /^::ffff:127\./,
    /^::ffff:10\./,
    /^::ffff:172\.(1[6-9]|2\d|3[01])\./,
    /^::ffff:192\.168\./,
    /^fe80:/i,
    /^fd[0-9a-f]{2}:/i
];

function isPrivateIp(ip) {
    if (!ip) return true;
    return PRIVATE_RANGES.some(re => re.test(ip));
}

/**
 * Normalise an IP address: strip IPv6-mapped-IPv4 prefix.
 * e.g. "::ffff:1.2.3.4" → "1.2.3.4"
 */
function normalizeIp(ip) {
    if (!ip) return ip;
    const match = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    return match ? match[1] : ip;
}

// ============ UNKNOWN / PRIVATE FALLBACK SHAPES ============

function unknownGeo() {
    return {
        country: 'Unknown',
        countryCode: 'XX',
        city: 'Unknown',
        lat: 0,
        lon: 0,
        subdivision: null,
        postalCode: null,
        timezone: null,
        accuracyRadius: null,
        isPrivate: false,
        isUnknown: true,
        isDegraded: degraded
    };
}

function privateGeo() {
    return {
        country: 'Private Network',
        countryCode: 'XX',
        city: 'LAN',
        lat: 0,
        lon: 0,
        subdivision: null,
        postalCode: null,
        timezone: null,
        accuracyRadius: null,
        isPrivate: true,
        isUnknown: false,
        isDegraded: false
    };
}

// ============ CORE LOOKUP ============

/**
 * Resolve an IP address to geolocation data.
 * Always returns a valid object — never null, never throws.
 *
 * Return shape (backwards-compatible + new fields):
 * {
 *   country, countryCode, city, lat, lon,
 *   subdivision, postalCode, timezone, accuracyRadius,
 *   isPrivate, isUnknown, isDegraded
 * }
 */
function getGeoLocation(ip) {
    try {
        const cleanIp = normalizeIp(ip);

        // Private / loopback IPs — no DB lookup needed
        if (isPrivateIp(cleanIp)) {
            return privateGeo();
        }

        // Degraded mode — no valid database loaded
        if (degraded || !activeReader) {
            return unknownGeo();
        }

        const result = activeReader.get(cleanIp);

        if (!result) {
            return unknownGeo();
        }

        return {
            country: result.country?.names?.en || 'Unknown',
            countryCode: result.country?.iso_code || 'XX',
            city: result.city?.names?.en || 'Unknown',
            lat: result.location?.latitude || 0,
            lon: result.location?.longitude || 0,
            subdivision: result.subdivisions?.[0]?.names?.en || null,
            postalCode: result.postal?.code || null,
            timezone: result.location?.time_zone || null,
            accuracyRadius: result.location?.accuracy_radius || null,
            isPrivate: false,
            isUnknown: false,
            isDegraded: false
        };
    } catch (err) {
        console.error(`⚠️  Geo lookup error for IP ${ip}:`, err.message);
        return unknownGeo();
    }
}

// ============ COUNTRY BLOCKING ============

/**
 * Check if an IP's country is blocked according to current filter config.
 * Returns { blocked: boolean, countryCode: string, reason: string }
 */
function isCountryBlocked(ip) {
    try {
        if (CONFIG.GEO_FILTER_MODE === 'disabled') {
            return { blocked: false, countryCode: null, reason: null };
        }

        const geo = getGeoLocation(ip);

        // Private IPs always pass through
        if (geo.isPrivate) {
            return { blocked: false, countryCode: 'XX', reason: null };
        }

        // Unknown geo (degraded or lookup failure) — never block
        if (geo.isUnknown || geo.isDegraded) {
            return { blocked: false, countryCode: 'XX', reason: null };
        }

        // Low-accuracy lookups — never used for blocking
        if (geo.accuracyRadius && geo.accuracyRadius > CONFIG.GEO_LOW_ACCURACY_THRESHOLD_KM) {
            return { blocked: false, countryCode: geo.countryCode, reason: null };
        }

        const code = geo.countryCode.toUpperCase();

        if (CONFIG.GEO_FILTER_MODE === 'deny') {
            const blockedList = (CONFIG.GEO_BLOCKED_COUNTRIES || []).map(c => c.toUpperCase());
            if (blockedList.includes(code)) {
                return {
                    blocked: true,
                    countryCode: code,
                    reason: `Country ${code} (${geo.country}) is in deny list`
                };
            }
        }

        if (CONFIG.GEO_FILTER_MODE === 'allow-only') {
            const allowedList = (CONFIG.GEO_ALLOWED_COUNTRIES || []).map(c => c.toUpperCase());
            if (!allowedList.includes(code)) {
                return {
                    blocked: true,
                    countryCode: code,
                    reason: `Country ${code} (${geo.country}) is not in allow list`
                };
            }
        }

        return { blocked: false, countryCode: code, reason: null };
    } catch (err) {
        console.error('⚠️  Country block check error:', err.message);
        return { blocked: false, countryCode: null, reason: null };
    }
}

// ============ DATABASE LOADING ============

/**
 * Compute SHA-256 hash of a file.
 */
async function fileHash(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('data', chunk => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
    });
}

/**
 * Initialise the geolocation service.
 * Loads the MMDB database from the configured path.
 * If the file is missing or corrupt, enters degraded mode gracefully.
 *
 * NEVER throws — the WAF must start even if geo is broken.
 */
async function init() {
    try {
        const dbPath = path.resolve(CONFIG.GEOLITE2_DB_PATH);

        if (!fs.existsSync(dbPath)) {
            console.warn(`⚠️  GeoLite2 database not found at ${dbPath}`);
            console.warn('   Geolocation will operate in degraded mode (all lookups return "Unknown")');
            console.warn('   To enable: place GeoLite2-City.mmdb in waf-proxy/data/');
            degraded = true;
            return false;
        }

        const reader = await maxmind.open(dbPath);

        // Smoke test: verify the reader works
        const test = reader.get('8.8.8.8');
        if (!test || !test.country) {
            console.warn('⚠️  GeoLite2 database loaded but smoke test failed (8.8.8.8 returned no country)');
            console.warn('   The database file may be corrupt. Entering degraded mode.');
            degraded = true;
            return false;
        }

        activeReader = reader;
        degraded = false;
        dbFileHash = await fileHash(dbPath);
        lastUpdateCheck = new Date();

        console.log(`🌍 GeoLite2 database loaded successfully from ${dbPath}`);
        console.log(`   Database hash: ${dbFileHash.substring(0, 12)}...`);
        console.log(`   Smoke test: 8.8.8.8 → ${test.country?.names?.en || 'Unknown'}`);

        return true;
    } catch (err) {
        console.warn(`⚠️  GeoLite2 database error: ${err.message}`);
        console.warn('   Geolocation will operate in degraded mode');
        degraded = true;
        return false;
    }
}

/**
 * Hot-swap the database with a new file.
 * Loads new database into a separate reader, validates it,
 * then atomically swaps the pointer. Old reader is GC'd.
 *
 * NEVER throws — on failure, old reader stays active.
 */
async function reloadDatabase() {
    try {
        const dbPath = path.resolve(CONFIG.GEOLITE2_DB_PATH);
        lastUpdateCheck = new Date();

        if (!fs.existsSync(dbPath)) {
            console.warn('⚠️  Geo reload: database file not found. Keeping current state.');
            return false;
        }

        // Check if file has changed
        const newHash = await fileHash(dbPath);
        if (newHash === dbFileHash) {
            // File hasn't changed — skip reload
            return false;
        }

        // Load new reader
        const newReader = await maxmind.open(dbPath);

        // Smoke test the new reader
        const test = newReader.get('8.8.8.8');
        if (!test || !test.country) {
            console.warn('⚠️  Geo reload: new database failed smoke test. Keeping current database.');
            return false;
        }

        // Atomic pointer swap (safe in single-threaded V8 event loop)
        const oldReader = activeReader;
        activeReader = newReader;
        degraded = false;
        dbFileHash = newHash;

        console.log(`🌍 GeoLite2 database hot-swapped successfully`);
        console.log(`   New hash: ${newHash.substring(0, 12)}...`);

        // Old reader will be GC'd once no in-flight request references it
        return true;
    } catch (err) {
        console.error('⚠️  Geo reload error:', err.message);
        return false;
    }
}

// ============ UPDATE SCHEDULER ============

/**
 * Start periodic update checks.
 * Checks for a new .mmdb file at the configured interval.
 */
function startUpdateScheduler() {
    if (updateInterval) {
        clearInterval(updateInterval);
    }

    const intervalMs = CONFIG.GEO_UPDATE_CHECK_INTERVAL_MS || 86400000; // 24h default

    updateInterval = setInterval(async () => {
        try {
            await reloadDatabase();
        } catch (err) {
            console.error('⚠️  Geo update scheduler error:', err.message);
        }
    }, intervalMs);

    // Don't block process exit
    if (updateInterval.unref) {
        updateInterval.unref();
    }

    console.log(`🔄 Geo update scheduler started (checking every ${Math.round(intervalMs / 3600000)}h)`);
}

/**
 * Stop the update scheduler.
 */
function stopUpdateScheduler() {
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
}

// ============ STATUS ============

/**
 * Get current service status (for health endpoint).
 */
function getStatus() {
    return {
        status: degraded ? 'degraded' : 'healthy',
        databaseLoaded: !degraded,
        databaseHash: dbFileHash ? dbFileHash.substring(0, 12) + '...' : null,
        lastUpdateCheck: lastUpdateCheck ? lastUpdateCheck.toISOString() : null,
        filterMode: CONFIG.GEO_FILTER_MODE || 'disabled',
        blockedCountries: CONFIG.GEO_BLOCKED_COUNTRIES || [],
        allowedCountries: CONFIG.GEO_ALLOWED_COUNTRIES || []
    };
}

// ============ RUNTIME CONFIG UPDATE ============

/**
 * Update geo-filter config at runtime (without restart).
 * Only updates filter-related settings, not the database path.
 */
function updateFilterConfig({ mode, blockedCountries, allowedCountries }) {
    if (mode !== undefined) {
        const validModes = ['disabled', 'deny', 'allow-only'];
        if (validModes.includes(mode)) {
            CONFIG.GEO_FILTER_MODE = mode;
        }
    }
    if (blockedCountries !== undefined && Array.isArray(blockedCountries)) {
        CONFIG.GEO_BLOCKED_COUNTRIES = blockedCountries;
    }
    if (allowedCountries !== undefined && Array.isArray(allowedCountries)) {
        CONFIG.GEO_ALLOWED_COUNTRIES = allowedCountries;
    }

    console.log(`🌍 Geo filter config updated: mode=${CONFIG.GEO_FILTER_MODE}`);
    return getStatus();
}

// ============ EXPORTS ============

module.exports = {
    init,
    getGeoLocation,
    isCountryBlocked,
    reloadDatabase,
    startUpdateScheduler,
    stopUpdateScheduler,
    getStatus,
    updateFilterConfig
};
