/**
 * WEJÀ Geo Controller
 * API handlers for geolocation diagnostic and configuration endpoints.
 */

const geoService = require('../services/geolocation');

// GET /api/geo/lookup/:ip — On-demand IP lookup (diagnostic tool)
const lookupIp = (req, res) => {
    try {
        const ip = req.params.ip;

        if (!ip) {
            return res.status(400).json({ error: 'IP address is required' });
        }

        const geo = geoService.getGeoLocation(ip);

        res.json({
            ip: ip,
            geo: geo
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// GET /api/geo/status — Current database info
const getStatus = (req, res) => {
    try {
        const status = geoService.getStatus();
        res.json(status);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// GET /api/geo/config — Current filter configuration
const getConfig = (req, res) => {
    try {
        const status = geoService.getStatus();
        res.json({
            filterMode: status.filterMode,
            blockedCountries: status.blockedCountries,
            allowedCountries: status.allowedCountries
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// POST /api/geo/config — Update filter rules at runtime (no restart needed)
const updateConfig = (req, res) => {
    try {
        const { mode, blockedCountries, allowedCountries } = req.body;

        // Validate mode if provided
        if (mode !== undefined) {
            const validModes = ['disabled', 'deny', 'allow-only'];
            if (!validModes.includes(mode)) {
                return res.status(400).json({
                    error: `Invalid mode. Must be one of: ${validModes.join(', ')}`
                });
            }
        }

        // Validate country lists if provided
        if (blockedCountries !== undefined && !Array.isArray(blockedCountries)) {
            return res.status(400).json({ error: 'blockedCountries must be an array' });
        }
        if (allowedCountries !== undefined && !Array.isArray(allowedCountries)) {
            return res.status(400).json({ error: 'allowedCountries must be an array' });
        }

        const updated = geoService.updateFilterConfig({
            mode,
            blockedCountries,
            allowedCountries
        });

        res.json({
            success: true,
            message: 'Geo filter configuration updated',
            config: updated
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// POST /api/geo/reload — Trigger manual database reload
const reloadDatabase = async (req, res) => {
    try {
        const reloaded = await geoService.reloadDatabase();

        if (reloaded) {
            res.json({
                success: true,
                message: 'Database reloaded successfully',
                status: geoService.getStatus()
            });
        } else {
            res.json({
                success: false,
                message: 'Database unchanged or reload failed',
                status: geoService.getStatus()
            });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

module.exports = {
    lookupIp,
    getStatus,
    getConfig,
    updateConfig,
    reloadDatabase
};
