const express = require('express');
const router = express.Router();

const logsController = require('../controllers/logsController');
const healthController = require('../controllers/healthController');
const blacklistController = require('../controllers/blacklistController');
const attackersController = require('../controllers/attackersController');
const { updateRateLimit, getRateLimit } = require('../middlewares/rateLimiter');

// Logs Routes
router.get('/logs', logsController.getLogs);
router.get('/stats', logsController.getStats);

// Health Check
router.get('/health', healthController.getHealth);

// Blacklist Routes
router.get('/blacklist', blacklistController.getBlacklist);
router.post('/blacklist', blacklistController.addBlacklist);
router.delete('/blacklist/:ip', blacklistController.removeBlacklist);

// Top Attackers
router.get('/top-attackers', attackersController.getTopAttackers);

// Get current rate limit settings
router.get('/rate-limit', (req, res) => {

    res.json(getRateLimit());

});

// Update rate limit settings
router.post('/rate-limit', (req, res) => {

    const { windowMs, maxRequests } = req.body;

    if (!windowMs || !maxRequests) {

        return res.status(400).json({

            error: 'windowMs and maxRequests are required'

        });

    }

    updateRateLimit(windowMs, maxRequests);

    res.json({

        message: 'Rate limit updated successfully',

        config: getRateLimit()

    });

});

module.exports = router;
