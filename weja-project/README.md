# WEJÀ - AI-Powered Web Application Firewall

A microservices-based WAF MVP that combines rule-based detection with AI confidence scoring.

## 🏗️ Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│ WAF Gateway │────▶│   Target    │
│  Dashboard  │     │  (port 3000)│     │ (port 4000) │
│ (port 5173) │     └──────┬──────┘     └─────────────┘
└─────────────┘            │
                           ▼
                    ┌─────────────┐     ┌─────────────┐
                    │  AI Engine  │     │   MongoDB   │
                    │ (port 5000) │     │ (port 27017)│
                    └─────────────┘     └─────────────┘
```

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
source venv/bin/activate
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

### AI Engine (port 5000)
- `POST /analyze` - Analyze request payload
- `GET /health` - Health check

## 🛡️ Detected Attack Types
- SQL Injection
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection

## 📊 Dashboard Features
- Real-time request feed
- Attack statistics
- Attack type distribution chart
- Traffic overview
