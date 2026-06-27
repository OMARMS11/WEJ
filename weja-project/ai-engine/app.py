"""
WEJÀ AI Engine - Unified WAF
Refactored hybrid engine:
- Tier 2: Behavioral Flow detection (DDoS, Fuzzing)
- Tier 1: Weighted rule engine + Logistic Regression payload decision fusion
"""

import re
import sys
import time
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

app = Flask(__name__)
CORS(app)

# ==========================================
# 1. CUSTOM FEATURE EXTRACTION
# ==========================================
def extract_special_features(texts):
    features = []
    for text in texts:
        if not isinstance(text, str):
            text = str(text)
        text_lower = text.lower()
        features.append([
            int('../' in text or '..\\' in text),
            int('%' in text),
            int(text.count('/') > 3),
            int(re.search(r'etc/passwd|windows\\win', text_lower) is not None),
            len(re.findall(r'%[0-9a-f]{2}', text_lower)),
            text.count('.'),
            int(';' in text or '|' in text or '&' in text),
            int('=' in text and '../' in text),
        ])
    return np.array(features)

# Ensure extraction is available for unpickling
import __main__
current_module = sys.modules[__name__]
if '__main__' not in sys.modules or sys.modules['__main__'] is not current_module:
    sys.modules['__main__'] = current_module
setattr(sys.modules['__main__'], 'extract_special_features', extract_special_features)

# ==========================================
# 2. MODEL LOADING & STATE
# ==========================================
try:
    preTrainedModel = joblib.load("waf_ai_engine_logistic_regression.pkl")
    label_encoder = joblib.load("label_encoder.pkl")
    print("[Tier 1] NLP Model & Label Encoder loaded.")
except Exception as e:
    print(f"⚠️ Error loading Tier 1 models: {e}")

try:
    tier2_behavior_model = joblib.load('tier2_behavior_model2.pkl')
    print("[Tier 2] Behavioral Sequence model loaded.")
except Exception as e:
    print(f"⚠️ Error loading Tier 2 behavior model: {e}")

traffic_history = {}    
banned_behavior_ips = set()  

BEHAVIOR_FEATURES = [
    'Flow Duration', 
    'Flow IAT Mean', 
    'Flow IAT Min', 
    'Fwd Packet Length Mean', 
    'Total Fwd Packets'
]

# ==========================================
# 3. TIER 2: BEHAVIORAL LOGIC
# ==========================================
def calculate_network_metrics(client_ip, passed_total_packets=0):
    history = traffic_history.get(client_ip, [])
    if not history:
        return {
            'Flow Duration': 0.0,
            'Flow IAT Mean': 0.0,
            'Flow IAT Min': 0.0,
            'Fwd Packet Length Mean': 0.0,
            'Total Fwd Packets': passed_total_packets
        }
        
    timestamps = [item[0] for item in history]
    lengths = [item[1] for item in history]
    
    if len(timestamps) > 1:
        iat_deltas = np.diff(timestamps)
        iat_mean = float(np.mean(iat_deltas))
        iat_min = float(np.min(iat_deltas))
    else:
        iat_mean = 0.0
        iat_min = 0.0
        
    return {
        'Flow Duration': float(timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.0,
        'Flow IAT Mean': iat_mean,
        'Flow IAT Min': iat_min,
        'Fwd Packet Length Mean': float(np.mean(lengths)) if lengths else 0.0,
        'Total Fwd Packets': passed_total_packets if passed_total_packets > 0 else len(timestamps)
    }

def detect_behavioral_threat(client_ip, payload_len, passed_total_packets):
    current_time = time.time()
    traffic_history.setdefault(client_ip, [])
    traffic_history[client_ip].append((current_time, payload_len))
    traffic_history[client_ip] = traffic_history[client_ip][-200:]
    
    if len(traffic_history[client_ip]) < 5:
        return False, "SAFE", 0.0
        
    client_features = calculate_network_metrics(client_ip, passed_total_packets)
    features_df = pd.DataFrame([client_features], columns=BEHAVIOR_FEATURES)
    
    try:
        prediction_id = int(tier2_behavior_model.predict(features_df)[0])
        confidence = float(tier2_behavior_model.predict_proba(features_df)[0][prediction_id])
        prediction = 1 if prediction_id > 0 else 0
        
        if prediction == 1 and confidence > 0.6:
            return True, "AUTOMATED_ANOMALY_DDoS_FUZZ", confidence
            
    except Exception as e:
        app.logger.error(f"Tier 2 Inference error: {e}")
        
    return False, "SAFE", 0.0

# ==========================================
# 4. TIER 1: HYBRID PAYLOAD LOGIC
# ==========================================
SQLI_PATTERNS = [
    (r"(\%27)|(\')|(\-\-)|(\%23)|(#)",20),
    (r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",30),
    (r"\w*((\%27)|(\'))((\\%6F)|o|(\%4F))((\%72)|r|(\%52))",35),
    (r"((\%27)|(\'))union",40),
    (r"exec(\s|\+)+(s|x)p\w+",50),
    (r"(select|insert|update|delete|drop|truncate|alter)\s",25),
    (r"1\s*=\s*1",35),
    (r"\'\s*or\s*\'",35),
]

XSS_PATTERNS = [
    (r"<script[^>]*>.*?</script>",50),
    (r"javascript\s*:",35),
    (r"on\w+\s*=",25),
    (r"<\s*img[^>]+onerror",40),
    (r"<\s*svg[^>]+onload",40),
    (r"alert\s*\(",25),
    (r"eval\s*\(",40),
]

PATH_PATTERNS = [
    (r"\.\./",40),
    (r"\.\.\\",40),
    (r"%2e%2e%2f",40),
    (r"etc/passwd",60),
    (r"etc/shadow",60),
    (r"windows/system32",60),
]

CMD_PATTERNS = [
    (r";\s*(ls|cat|whoami|id|pwd|uname)",50),
    (r"\|\s*(ls|cat|whoami|id|pwd|uname)",50),
    (r"`[^`]+`",50),
    (r"\$\([^)]+\)",50),
    (r"&&\s*(ls|cat|whoami|id|pwd|uname)",50),
]

ATTACKS = {
    "SQL_INJECTION": SQLI_PATTERNS,
    "XSS": XSS_PATTERNS,
    "PATH_TRAVERSAL": PATH_PATTERNS,
    "COMMAND_INJECTION": CMD_PATTERNS,
}

def calculate_rule_confidence(payload, patterns):
    score = 0
    matched = []
    for regex, weight in patterns:
        if re.search(regex, payload, re.IGNORECASE):
            score += weight
            matched.append(regex)
    return min(score/100.0, 1.0), matched

def rule_based_detect(payload):
    payload = payload.lower()
    best_attack = "SAFE"
    best_conf = 0
    best_matches = []
    for attack, patterns in ATTACKS.items():
        conf, matches = calculate_rule_confidence(payload, patterns)
        if conf > best_conf:
            best_attack = attack
            best_conf = conf
            best_matches = matches
    return best_conf > 0, best_attack, best_conf, best_matches

def predict_threat(request_text: str):
    if not request_text.strip():
        return "SAFE", 0.1
    pred = preTrainedModel.predict([request_text])[0]
    probs = preTrainedModel.predict_proba([request_text])[0]
    conf = float(np.max(probs))
    label = label_encoder.inverse_transform([pred])[0]
    return label, conf

def detect_attack_type(payload):
    rule_hit, rule_type, rule_conf, matches = rule_based_detect(payload)
    if rule_hit and rule_conf >= 0.95:
        return {
            "blocked": True,
            "type": rule_type,
            "confidence": round(rule_conf,2),
            "rule_confidence": round(rule_conf,2),
            "ml_confidence": None,
            "ml_prediction": None,
            "matched_rules": matches,
            "decision": "RULE_ONLY"
        }

    ml_type, ml_conf = predict_threat(payload)
    blocked = False
    final_type = "SAFE"
    final_conf = max(1 - ml_conf, 0.05)
    decision = "SAFE"

    if rule_hit:
        if ml_type == rule_type:
            blocked = True
            final_type = rule_type
            final_conf = 0.4*rule_conf + 0.6*ml_conf
            decision = "FUSION"
        elif ml_conf >= 0.9 and ml_type != "norm":
            blocked = True
            final_type = ml_type
            final_conf = ml_conf
            decision = "ML_OVERRIDE"
        elif rule_conf >= 0.6:
            blocked = True
            final_type = rule_type
            final_conf = rule_conf
            decision = "RULE_PRIORITY"
    elif ml_type != "norm" and ml_conf >= 0.75:
        blocked = True
        final_type = ml_type
        final_conf = ml_conf
        decision = "ML_ONLY"

    return {
        "blocked": blocked,
        "type": final_type,
        "confidence": round(final_conf,2),
        "rule_confidence": round(rule_conf,2),
        "ml_prediction": ml_type,
        "ml_confidence": round(ml_conf,2),
        "matched_rules": matches,
        "decision": decision
    }

# ==========================================
# 5. UNIFIED API ENDPOINTS
# ==========================================
@app.route("/health")
def health():
    return jsonify({
        "status":"healthy",
        "engine":"Unified Hybrid WAF",
        "ml":"Logistic Regression",
        "behavioral": "Sequence Traffic Analysis",
        "rules":"Weighted Rule Engine"
    })

@app.route("/analyze", methods=["POST"])
@app.route("/behavioural/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided', 'blocked': False}), 400

        client_ip = data.get('ip', request.remote_addr)
        payload = data.get("payload","")
        path = data.get("path","")
        method = data.get("method","GET")
        total_packets = data.get("totalPackets", 0)
        
        # 1. Tier 2 Behavioral Flow Check
        if client_ip in banned_behavior_ips:
            return jsonify({
                'blocked': True, 
                'type': 'BANNED_IP_BEHAVIORAL', 
                'confidence': 1.0,
                'decision': 'BEHAVIORAL_BAN'
            }), 200

        is_behavioral_attack, b_type, b_conf = detect_behavioral_threat(client_ip, len(payload), total_packets)
        
        if is_behavioral_attack:
            banned_behavior_ips.add(client_ip)
            print(f"🚫 [Tier 2 BAN TRIGGERED] IP {client_ip} isolated! Confidence: {b_conf:.2f}")
            return jsonify({
                'blocked': True,
                'type': b_type,
                'confidence': round(b_conf, 2),
                'decision': 'BEHAVIORAL_TIER_2'
            }), 200

        # 2. Tier 1 Hybrid Payload Check (NLP + Rules)
        combined = f"{payload} {path}"
        result = detect_attack_type(combined)
        
        result.update({
            "payload_length": len(payload),
            "analyzed_method": method,
            "analyzed_path": path
        })
        
        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Unified analysis error: {str(e)}")
        return jsonify({
            "blocked": False,
            "type": "ERROR",
            "confidence": 0,
            "error": str(e)
        }), 500

if __name__=="__main__":
    import os
    app.run(host="0.0.0.0", port=5005, debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true')
