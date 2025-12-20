/**
 * WEJÀ WAF Log Model
 * MongoDB schema for storing attack logs and request metadata.
 */

const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    },
    method: {
        type: String,
        required: true,
        enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    },
    path: {
        type: String,
        required: true
    },
    query: {
        type: Object,
        default: {}
    },
    body: {
        type: Object,
        default: {}
    },
    headers: {
        type: Object,
        default: {}
    },
    sourceIp: {
        type: String,
        required: true
    },
    userAgent: {
        type: String,
        default: ''
    },
    blocked: {
        type: Boolean,
        required: true,
        index: true
    },
    attackType: {
        type: String,
        required: true,
        index: true
    },
    confidence: {
        type: Number,
        required: true,
        min: 0,
        max: 1
    },
    responseStatus: {
        type: Number,
        default: null
    },
    responseTime: {
        type: Number,  // in milliseconds
        default: null
    }
}, {
    timestamps: true
});

// Index for common queries
LogSchema.index({ timestamp: -1 });
LogSchema.index({ blocked: 1, timestamp: -1 });
LogSchema.index({ attackType: 1, timestamp: -1 });

module.exports = mongoose.model('Log', LogSchema);
