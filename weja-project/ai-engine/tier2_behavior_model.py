import time
import numpy as np
import joblib
import pandas as pd
from flask import Flask, request, abort

app = Flask(__name__)

# 1. Load your newly minted Tier 2 Behavioral Model
behavior_model = joblib.load('tier2_behavior_model.pkl')

# 2. In-memory storage to track incoming request patterns per IP address
# Structure: { ip_address: [(timestamp, payload_size), ...] }
traffic_history = {}
BANNED_IPS = set()

# Define feature names exactly as they were trained
FEATURE_NAMES = ['Flow Duration', 'Flow IAT Mean', 'Flow IAT Min', 'Fwd Packet Length Mean', 'Total Fwd Packets']

def extract_live_features(ip):
    """Calculates the 5 network flow features dynamically from the last 10 requests of an IP."""
    history = traffic_history[ip]
    timestamps = [item[0] for item in history]
    sizes = [item[1] for item in history]
    
    # Calculate Inter-Arrival Times (IAT)
    if len(timestamps) > 1:
        iats = np.diff(timestamps)
        flow_iat_mean = np.mean(iats)
        flow_iat_min = np.min(iats)
    else:
        flow_iat_mean = 0
        flow_iat_min = 0
        
    features = {
        'Flow Duration': timestamps[-1] - timestamps[0],
        'Flow IAT Mean': flow_iat_mean,
        'Flow IAT Min': flow_iat_min,
        'Fwd Packet Length Mean': np.mean(sizes),
        'Total Fwd Packets': len(timestamps)
    }
    return features

@app.before_request
def waf_behavioral_tier():
    client_ip = request.remote_addr
    
    # Fast path: Check if IP is already banned
    if client_ip in BANNED_IPS:
        print(f"[WAF ALERT] Blocked request from banned IP: {client_ip}")
        abort(403, description="Access Denied: Malicious activity detected from your IP.")

    # Track current request metrics
    current_time = time.time()
    payload_size = len(request.data) + len(request.query_string)
    
    if client_ip not in traffic_history:
        traffic_history[client_ip] = []
        
    traffic_history[client_ip].append((current_time, payload_size))
    
    # Keep only the last 10 requests to analyze the current active "flow window"
    traffic_history[client_ip] = traffic_history[client_ip][-10:]
    
    # Start checking behavior once we have a short sequence (e.g., 5 requests)
    if len(traffic_history[client_ip]) >= 5:
        live_metrics = extract_live_features(client_ip)
        
        # Format metrics as a DataFrame for the Scikit-learn model
        input_df = pd.DataFrame([live_metrics], columns=FEATURE_NAMES)
        
        # Predict live
        prediction = behavior_model.predict(input_df)[0]
        probability = behavior_model.predict_proba(input_df)[0][1]
        
        print(f"[WAF Monitor] IP: {client_ip} | Duration: {live_metrics['Flow Duration']:.4f}s | IAT Mean: {live_metrics['Flow IAT Mean']:.4f}s | Anomaly Confidence: {probability*100:.2f}%")
        
        # If model is highly confident it's an automated attack, ban the IP
        if prediction == 1 and probability > 0.90:
            print(f"\n[!!!] CRITICAL behavioral anomaly detected from {client_ip}. BANNING IP.")
            BANNED_IPS.add(client_ip)
            abort(403, description="Access Denied: Malicious behavior fingerprint detected.")

@app.route('/')
def home():
    return "Welcome to the Protected Secure Application! Real humans only."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)