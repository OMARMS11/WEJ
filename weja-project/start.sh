#!/bin/bash
# WEJÀ MVP Startup Script
# Run this script to start all services

echo "🛡️  Starting WEJÀ WAF MVP..."
echo "================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${RED}Shutting down services...${NC}"
    kill $AI_PID $TARGET_PID $WAF_PID $DASHBOARD_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start AI Engine (Python Flask)
echo -e "${BLUE}Starting AI Engine...${NC}"
cd "$SCRIPT_DIR/ai-engine"
source venv/bin/activate
python app.py &
AI_PID=$!
sleep 2

# Start Dummy Target
echo -e "${BLUE}Starting Dummy Target...${NC}"
cd "$SCRIPT_DIR/dummy-target"
node server.js &
TARGET_PID=$!
sleep 1

# Start WAF Gateway
echo -e "${BLUE}Starting WAF Gateway...${NC}"
cd "$SCRIPT_DIR/waf-proxy"
node server.js &
WAF_PID=$!
sleep 2

# Start Dashboard
echo -e "${BLUE}Starting Dashboard...${NC}"
cd "$SCRIPT_DIR/client-dashboard"
npm run dev &
DASHBOARD_PID=$!

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}All services started!${NC}"
echo ""
echo "📡 AI Engine:    http://localhost:5000"
echo "🎯 Target:       http://localhost:4000"
echo "🛡️  WAF Gateway:  http://localhost:3000"
echo "📊 Dashboard:    http://localhost:5173"
echo ""
echo "To test: node test_traffic.js"
echo ""
echo -e "${RED}Press Ctrl+C to stop all services${NC}"

# Wait for all background processes
wait
