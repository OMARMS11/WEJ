const axios = require('axios');
const http = require('http');
const https = require('https');
const CONFIG = require('../config');

const aiClient = axios.create({
    baseURL: CONFIG.AI_ENGINE_URL,
    //modified from 1500 to 10000 to test tier2
    timeout: 10000,
    httpAgent: new http.Agent({ keepAlive: true }),
    httpsAgent: new https.Agent({ keepAlive: true })
});

module.exports = aiClient;
