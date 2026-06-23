/**
 * WEJÀ Geo API Routes
 * All geo management endpoints under /api/geo/
 */

const express = require('express');
const router = express.Router();
const geoController = require('../controllers/geoController');

// Diagnostic: lookup any IP
router.get('/lookup/:ip', geoController.lookupIp);

// Database status
router.get('/status', geoController.getStatus);

// Filter configuration (get/update)
router.get('/config', geoController.getConfig);
router.post('/config', geoController.updateConfig);

// Manual database reload
router.post('/reload', geoController.reloadDatabase);

module.exports = router;
