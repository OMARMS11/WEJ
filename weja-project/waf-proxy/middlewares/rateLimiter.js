const requests = new Map();

const WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS = 50;

module.exports = (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();

    if (!requests.has(ip)) {
        requests.set(ip, []);
    }

    let timestamps = requests.get(ip);

    // remove expired timestamps
    timestamps = timestamps.filter(
        timestamp => now - timestamp < WINDOW_MS
    );

    if (timestamps.length >= MAX_REQUESTS) {
        return res.status(429).json({
            error: 'Too many requests'
        });
    }

    timestamps.push(now);
    requests.set(ip, timestamps);

    next();
};