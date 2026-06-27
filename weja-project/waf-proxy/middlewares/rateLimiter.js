const requests = new Map();

const rateLimitConfig = {
    windowMs: 60 * 1000,
    maxRequests: 50
};

// Memory cleanup: Clear inactive IPs every 5 minutes to prevent Map unbounded growth
setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamps] of requests.entries()) {
        const active = timestamps.filter(t => now - t < rateLimitConfig.windowMs);
        if (active.length === 0) {
            requests.delete(ip);
        } else {
            requests.set(ip, active);
        }
    }
}, 5 * 60 * 1000);

const rateLimiter = (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();

    if (!requests.has(ip)) {
        requests.set(ip, []);
    }

    let timestamps = requests.get(ip);

    // Remove old requests outside the time window
    timestamps = timestamps.filter(
        timestamp => now - timestamp < rateLimitConfig.windowMs
    );

    // Check if limit exceeded
    if (timestamps.length >= rateLimitConfig.maxRequests) {
        return res.status(429).json({
            error: 'Too many requests'
        });
    }

    // Add current request
    timestamps.push(now);
    requests.set(ip, timestamps);

    next();
};

// Update config dynamically
const updateRateLimit = (windowMs, maxRequests) => {
    rateLimitConfig.windowMs = windowMs;
    rateLimitConfig.maxRequests = maxRequests;
    requests.clear();
};

// Get current config
const getRateLimit = () => {
    return rateLimitConfig;
};

module.exports = {
    rateLimiter,
    updateRateLimit,
    getRateLimit
};