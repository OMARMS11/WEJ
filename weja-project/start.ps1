Write-Host "Starting WEJÀ WAF Sandbox Environment..." -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Start AI Engine
Write-Host "Starting AI Engine..." -ForegroundColor Blue
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd ai-engine && venv\Scripts\activate && python app.py" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Dummy Target
Write-Host "Starting Dummy Target..." -ForegroundColor Blue
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd dummy-target && node server.js" -WindowStyle Normal
Start-Sleep -Seconds 1

# Start WAF Gateway
Write-Host "Starting WAF Gateway..." -ForegroundColor Blue
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd waf-proxy && npm start" -WindowStyle Normal
Start-Sleep -Seconds 2

# Start Dashboard
Write-Host "Starting Dashboard..." -ForegroundColor Blue
Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd client-dashboard && npm run dev" -WindowStyle Normal
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "================================" -ForegroundColor Green
Write-Host "All services started in separate windows!" -ForegroundColor Green
Write-Host ""
Write-Host "📡 AI Engine:    http://localhost:5000"
Write-Host "🎯 Target:       http://localhost:4000"
Write-Host "🛡️  WAF Gateway:  http://localhost:3000"
Write-Host "📊 Dashboard:    http://localhost:5173"
Write-Host ""
Write-Host "To test: node test_traffic.js"
Write-Host ""
