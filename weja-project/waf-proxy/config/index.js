const path = require('path');

// ============ CONFIGURATION ============
const CONFIG = {
    PORT: process.env.PORT || 3000,
    AI_ENGINE_URL: process.env.AI_ENGINE_URL || 'http://localhost:5005',
    TARGET_URL: process.env.TARGET_URL || 'http://localhost:4000',
    MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/weja_waf',

    // Blacklist configuration
    BLACKLIST_THRESHOLD: 3, // Auto-blacklist after 3 blocked requests
    BLACKLIST_DURATION: 60 * 60 * 1000, // 1 hour blacklist duration

    // Logging configuration
    MAX_MEMORY_LOGS: 1000,

    // ============ GEOLOCATION CONFIGURATION ============

    // Path to the GeoLite2 City MMDB database file
    GEOLITE2_DB_PATH: process.env.GEOLITE2_DB_PATH
        || path.join(__dirname, '..', 'data', 'GeoLite2-City.mmdb'),

    // Geo-filter mode: 'disabled' | 'deny' | 'allow-only'
    //   disabled  — enrichment only, no blocking (safe default)
    //   deny      — block countries in GEO_BLOCKED_COUNTRIES list
    //   allow-only — only allow countries in GEO_ALLOWED_COUNTRIES list
    GEO_FILTER_MODE: process.env.GEO_FILTER_MODE || 'disabled',

    // Country codes to block (ISO 3166-1 alpha-2) — only used when mode is 'deny'
    GEO_BLOCKED_COUNTRIES: process.env.GEO_BLOCKED_COUNTRIES
        ? process.env.GEO_BLOCKED_COUNTRIES.split(',').map(c => c.trim().toUpperCase())
        : [],

    // Country codes to allow (ISO 3166-1 alpha-2) — only used when mode is 'allow-only'
    GEO_ALLOWED_COUNTRIES: process.env.GEO_ALLOWED_COUNTRIES
        ? process.env.GEO_ALLOWED_COUNTRIES.split(',').map(c => c.trim().toUpperCase())
        : [],

    // How often to check for database updates (milliseconds)
    GEO_UPDATE_CHECK_INTERVAL_MS: parseInt(process.env.GEO_UPDATE_CHECK_INTERVAL_MS) || 86400000, // 24 hours

    // Lookups with accuracy radius above this threshold (km) are never used for blocking
    GEO_LOW_ACCURACY_THRESHOLD_KM: parseInt(process.env.GEO_LOW_ACCURACY_THRESHOLD_KM) || 500
};

module.exports = CONFIG;
