import re
import sys
import time
import pickle
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

app = Flask(__name__)
CORS(app)

# ==========================================
# 1. CUSTOM FEATURE EXTRACTION (MUST BE FIRST)
# ==========================================

def extract_special_features(texts):
    """
    Custom feature engineering function required by the Tier 1 Logistic Regression model.
    Must be defined before joblib.load() executes.
    """
    feature_matrix = []
    for text in texts:
        if not isinstance(text, str):
            text = str(text)
        lower_text = text.lower()
        
        features = [
            int('../' in text or '..\\' in text),
            int('%' in text),
            int(text.count('/') > 3),
            int(re.search(r'etc/passwd|windows\\win', lower_text) is not None),
            len(re.findall(r'%[0-9a-f]{2}', lower_text)),
            text.count('.'),
            int(';' in text or '|' in text or '&' in text),
            int('=' in text and '../' in text)
        ]
        feature_matrix.append(features)
    return np.array(feature_matrix)


# Ensure the custom feature extraction helper is available for legacy joblib unpickling
import __main__
current_module = sys.modules[__name__]
if '__main__' not in sys.modules or sys.modules['__main__'] is not current_module:
    sys.modules['__main__'] = current_module
setattr(sys.modules['__main__'], 'extract_special_features', extract_special_features)


# ==========================================
# 2. GLOBAL DATA PATHS & MODEL LOADING
# ==========================================

# Tier 1 Models (Payload Signature / Semantic Analytics)
try:
    payload_model = joblib.load('waf_ai_engine_logistic_regression.pkl')
    print("[Tier 1] Logistic Regression payload model loaded successfully.")
    
    label_encoder = joblib.load('label_encoder.pkl')
    print("[Tier 1] Label Encoder loaded successfully.")
except Exception as e:
    print(f"⚠️ Error loading Tier 1 core models: {e}")

# Tier 2 Model (Behavioral / Sequence / DDoS Detection)
try:
    tier2_behavior_model = joblib.load('tier2_behavior_model2.pkl')
    print("[Tier 2] Behavioral Sequence model loaded successfully.")
except Exception as e:
    print(f"⚠️ Error loading Tier 2 behavior model: {e}")

# In-memory monitoring states
traffic_history = {}    
banned_behavior_ips = set()  

BEHAVIOR_FEATURES = [
    'Flow Duration', 
    'Flow IAT Mean', 
    'Flow IAT Min', 
    'Fwd Packet Length Mean', 
    'Total Fwd Packets'
]

ATTACK_LABELS = {
    0: "BENIGN",
    1: "WEB_FUZZING_DETECTED",
    2: "DDOS_FLOOD_DETECTED",
    3: "PORT_SCAN_DETECTED"
}

# ==========================================
# 3. NETWORK METRICS FUNCTIONS
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
        
    metrics = {
        'Flow Duration': float(timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.0,
        'Flow IAT Mean': iat_mean,
        'Flow IAT Min': iat_min,
        'Fwd Packet Length Mean': float(np.mean(lengths)) if lengths else 0.0,
        'Total Fwd Packets': passed_total_packets if passed_total_packets > 0 else len(timestamps)
    }
    return metrics


def predict_payload_anomaly(request_text):
    if not request_text or len(request_text.strip()) == 0:
        return 'SAFE', 0.10
    try:
        pred_id = payload_model.predict([request_text])[0]
        probabilities = payload_model.predict_proba([request_text])[0]
        confidence = float(np.max(probabilities))
        attack_label = label_encoder.inverse_transform([pred_id])[0]
        return attack_label, confidence
    except Exception as err:
        app.logger.error(f"ML prediction error: {err}")
        return 'SAFE', 0.10

# ==========================================
# 4. SIGNATURE RULES DEFENSE (TIER 1)
# ==========================================

SQL_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\\\\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
    r"exec(\s|\+)+(s|x)p\w+",
    r"(select|insert|update|delete|drop|truncate|alter)\s",
    r"(\%27)|(\')\s*(or|and)\s*\d+\s*=\s*\d+",
    r"1\s*=\s*1",
    r"\'\s*or\s*\'"
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript\s*:",
    r"on\w+\s*=",
    r"<\s*img[^>]+onerror",
    r"<\s*svg[^>]+onload",
    r"<\s*iframe",
    r"<\s*embed",
    r"<\s*object",
    r"expression\s*\(",
    r"alert\s*\(",
    r"document\.(cookie|location|write)",
    r"eval\s*\("
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%252e%252e%252f",
    r"etc/passwd",
    r"etc/shadow",
    r"windows/system32"
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(ls|cat|whoami|id|pwd|uname)",
    r"\|\s*(ls|cat|whoami|id|pwd|uname)",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"&&\s*(ls|cat|whoami|id|pwd|uname)"
]

def scan_signature_rules(payload):
    lower_payload = payload.lower()
    for pattern in SQL_PATTERNS:
        if re.search(pattern, lower_payload, re.IGNORECASE):
            return True, 'SQL_INJECTION', 0.90
    for pattern in XSS_PATTERNS:
        if re.search(pattern, lower_payload, re.IGNORECASE):
            return True, 'XSS', 0.88
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, lower_payload, re.IGNORECASE):
            return True, 'PATH_TRAVERSAL', 0.92
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, lower_payload, re.IGNORECASE):
            return True, 'COMMAND_INJECTION', 0.94
    return False, 'SAFE', 0.10


def evaluate_hybrid_inspection(payload):
    is_malicious, attack_type, rule_conf = scan_signature_rules(payload)
    if is_malicious and rule_conf > 0.6:
        return True, attack_type, round(rule_conf * 0.85, 2)
    return False, 'SAFE', round(max(1 - rule_conf, 0.05), 2)

# ==========================================
# 5. FLASK SERVER CONTROLLERS / ENDPOINTS
# ==========================================

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'WEJÀ AI Engine',
        'version': '1.1.0',
        'ml_model': 'LogisticRegression',
        'detection': 'Hybrid (Rule-based + ML)'
    })


@app.route('/behavioural/analyze', methods=['POST'])
def behavioural_analysis():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided', 'blocked': False, 'confidence': 0.0, 'type': 'UNKNOWN'}), 400
        
        client_ip = data.get('ip', request.remote_addr)
        
        if client_ip in banned_behavior_ips:
            return jsonify({'blocked': True, 'type': 'AUTOMATED_ANOMALY_DDoS_FUZZ', 'confidence': 1.0}), 200

        payload_content = data.get('payload', '')
        payload_len = len(payload_content) if payload_content is not None else 0
        current_time = time.time()
        
        traffic_history.setdefault(client_ip, [])
        traffic_history[client_ip].append((current_time, payload_len))
        traffic_history[client_ip] = traffic_history[client_ip][-200:]
        
        passed_total_packets = data.get('totalPackets', 0)
        client_features = calculate_network_metrics(client_ip, passed_total_packets)

        features_df = pd.DataFrame([client_features], columns=BEHAVIOR_FEATURES)

        #debug print
        print(f"\n[ML INPUT MATRIX] Total Packets received from Node: {passed_total_packets}")
        print(f"{features_df.to_string(index=False)}\n")

        try:
            prediction_id = int(tier2_behavior_model.predict(features_df)[0])
            confidence = float(tier2_behavior_model.predict_proba(features_df)[0][prediction_id])
            prediction = 1 if prediction_id > 0 else 0

        
        except Exception as model_err:
            app.logger.error(f"Inference error: {model_err}")
            prediction = 0

            confidence = 0.0

        print(f"[Tier 2 Dedicated] IP={client_ip} | Window={len(traffic_history[client_ip])} | Pred={prediction} | Anomaly_Conf={confidence:.4f}")
        print(f"[FEATURES MATRIX] Duration: {client_features['Flow Duration']:.4f} | Total Packets: {client_features['Total Fwd Packets']}")

        if client_ip in banned_behavior_ips:
            return jsonify({
              'blocked': True,
              'type': "ALREADY_BANNED",
              'confidence': 1.0
          }), 200

        if prediction == 1 and confidence > 0.6:
            banned_behavior_ips.add(client_ip)
            print(f"🚫 [Tier 2 BAN TRIGGERED] IP {client_ip} isolated!")
            return jsonify({
                'blocked': True,
                'type': 'AUTOMATED_ANOMALY_DDoS_FUZZ',
                'confidence': round(confidence, 2)
            }), 200

        return jsonify({
            'blocked': False,
            'type': 'SAFE',
            'confidence': round(1 - confidence, 2)
        }), 200

    except Exception as global_err:
        app.logger.error(f"Dedicated Tier 2 route failed: {str(global_err)}")
        return jsonify({'error': str(global_err), 'blocked': False, 'confidence': 0.0, 'type': 'ERROR'}), 500


@app.route('/analyze', methods=['POST'])
def fallback_analyze():
    try:
        body_data = request.get_json()
        if not body_data:
            return jsonify({'error': 'No JSON body provided', 'blocked': False, 'confidence': 0.0, 'type': 'UNKNOWN'}), 400
        
        client_ip = body_data.get('ip', request.remote_addr)
        if client_ip in banned_behavior_ips:
            return jsonify({'blocked': True, 'type': 'BANNED_IP_BEHAVIORAL', 'confidence': 1.0}), 403
            
        payload = body_data.get('payload', '')
        current_time = time.time()
        payload_len = len(payload) if payload is not None else 0
        
        traffic_history.setdefault(client_ip, [])
        traffic_history[client_ip].append((current_time, payload_len))
        traffic_history[client_ip] = traffic_history[client_ip][-200:]
        
        if len(traffic_history[client_ip]) >= 5:
            metrics = calculate_network_metrics(client_ip)
            features_df = pd.DataFrame([metrics], columns=BEHAVIOR_FEATURES)
            try:
                tier2_pred = int(tier2_behavior_model.predict(features_df)[0])
                tier2_conf = float(tier2_behavior_model.predict_proba(features_df)[0][1])
            except Exception as e:
                app.logger.error(f"Tier2 execution failed inside fallback: {e}")
                tier2_pred = 0
                tier2_conf = 0.0
                
            if tier2_pred == 1 and tier2_conf > 0.9:
                banned_behavior_ips.add(client_ip)
                return jsonify({'blocked': True, 'type': 'AUTOMATED_ANOMALY_DDoS_FUZZ', 'confidence': tier2_conf}), 403
                
        req_path = body_data.get('path', '')
        req_method = body_data.get('method', 'GET')
        combined_string = f"{payload} {req_path}"
        
        is_blocked, attack_label, final_confidence = evaluate_hybrid_inspection(combined_string)
        ml_label, ml_conf = predict_payload_anomaly(combined_string)
        
        response_payload = {
            'blocked': is_blocked,
            'confidence': final_confidence,
            'type': attack_label,
            'analyzed_method': req_method,
            'analyzed_path': req_path,
            'payload_length': len(payload),
            'ml_prediction': ml_label,
            'ml_confidence': round(ml_conf, 2)
        }
        
        if is_blocked:
            app.logger.warning(f"Attack detected: {attack_label} (confidence: {final_confidence})")
        else:
            app.logger.info(f"✅ Request clean (confidence: {final_confidence})")
            
        return jsonify(response_payload)
        
    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({'error': str(e), 'blocked': False, 'confidence': 0.0, 'type': 'ERROR'}), 500


if __name__ == '__main__':
    print('[WEJA] AI Engine starting...')
    print('[*] Listening on http://localhost:5000')
    print('[*] Using hybrid detection: Rule-based + ML (LogisticRegression) + Tier 2 Sequence Behavior')
    app.run(host='0.0.0.0', port=5000, debug=True)