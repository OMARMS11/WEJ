const express = require('express');
const router = express.Router();

const logsController = require('../controllers/logsController');
const healthController = require('../controllers/healthController');
const blacklistController = require('../controllers/blacklistController');
const attackersController = require('../controllers/attackersController');
const geoRoutes = require('./geo');

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

// Geolocation Routes
router.use('/geo', geoRoutes);

module.exports = router;
