# WEJAÀ - AI-Powered Web Application Firewall

A microservices-based WAF MVP that combines a two-layer defense model:

- **Tier 1**: fast payload inspection using rule-based signatures and a Logistic Regression model.
- **Tier 2**: behavioral anomaly detection for suspicious request sequences, fuzzing, and DDoS-style traffic.

## 🏗️ Architecture

```

                    ┌──────────────────┐
                    │ React Dashboard  │
                    └────────┬─────────┘
                             |
                             v
                  ┌────────────────────┐
                  │ WAF Gateway        │
                  │ Express.js         │
                  └────────┬───────────┘
                           |
                ┌──────────┼──────────┐
                │          │          │
                ▼          ▼          ▼
        ┌────────────┐ ┌──────────┐ ┌────────────┐
        │Blacklist   │ │MongoDB   │ │GeoIP       │
        │Manager     │ │Logs      │ │Service     │
        └────────────┘ └──────────┘ └────────────┘
                           |
                           ▼
               ┌───────────────────────┐
               │ AI Engine Service     │
               │ (Flask/Python)        │
               └──────────┬────────────┘
                          |
                 ┌────────┴─────────┐
                 ▼                  ▼
         ┌───────────────┐  ┌───────────────┐
         │ Tier 2        │  │ Tier 1        │
         │ Behavioral AI │  │ Hybrid AI     │
         │               │  │               │
         │ DDoS          │  │ Rule Engine   │
         │ Fuzzing       │  │ Logistic Reg. │
         │ Pattern       │  │ Fusion Logic  │
         └───────────────┘  └───────────────┘

```

### Detection Flow

1. **Tier 1** inspects incoming payloads for known attack patterns and suspicious semantics.
2. **Tier 2** evaluates request behavior over time to detect anomalies such as web fuzzing, DDoS-like bursts, and port scan behavior.
3. The gateway uses both layers to decide whether to allow, block, or flag traffic.

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- Python 3.8+
- MongoDB running on localhost:27017

### Installation

```bash
# Install all dependencies
cd weja-project

# AI Engine
cd ai-engine
python3 -m venv venv
source venv/Scripts/activate  #if didn't work try venv/bin/activate
pip install -r requirements.txt

# WAF Gateway
cd ../waf-proxy
npm install

# Dummy Target
cd ../dummy-target
npm install

# Dashboard
cd ../client-dashboard
npm install
```

### Running

**Option 1: Use the startup script**

```bash
chmod +x start.sh
./start.sh
```

**Option 2: Run services individually**

Terminal 1 - AI Engine:

```bash
cd ai-engine && source venv/bin/activate && python app.py
```

Terminal 2 - Target:

```bash
cd dummy-target && npm start
```

Terminal 3 - WAF Gateway:

```bash
cd waf-proxy && npm start
```

Terminal 4 - Dashboard:

```bash
cd client-dashboard && npm run dev
```

## 🧪 Testing

Run the automated test suite:

```bash
node test_traffic.js
```

## 📡 API Endpoints

### WAF Gateway (port 3000)

- `GET/POST /proxy/*` - Proxied requests (WAF filtered)
- `GET /api/logs` - Fetch request logs
- `GET /api/stats` - Get attack statistics
- `GET /api/health` - Health check
- `GET /api/blacklist` - List blacklisted IPs
- `POST /api/blacklist` - Manually blacklist an IP
- `DELETE /api/blacklist/:ip` - Remove IP from blacklist
- `GET /api/top-attackers` - Get top attacking IPs with geolocation

### AI Engine (port 5000)

- `POST /analyze` - Analyze request payload
- `GET /health` - Health check

## 🛡️ Detected Attack Types

- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Web Fuzzing / Probe Behavior
- DDoS-style Flood Detection
- Port Scan Activity

## 📊 Dashboard Features

- Real-time request feed (Live/Blocked/Allowed)
- Attack statistics and Block Rate
- Interactive Charts (Attack Distribution, Traffic Overview)
- **Attacker Map**: Tab-based view of top attacking IPs with geolocation
- **Blacklist Manager**: View and unblock blacklisted IPs
- **Tier-based Insights**: See whether activity was blocked by Tier 1 payload checks or Tier 2 behavioral analysis
