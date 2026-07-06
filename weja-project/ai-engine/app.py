import os
import re
import sys
import time
import math
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from collections import Counter

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
    tier2_isolation_model = joblib.load('tier2_isolation.pkl')
    print("[Tier 2] Isolation Forest model loaded successfully.")
except Exception as e:
    print(f"⚠️ Error loading Tier 2 isolation model: {e}")

# In-memory monitoring states
traffic_history = {}    
banned_behavior_ips = set()  

BEHAVIOR_FEATURES = [
    'req_count', 'iat_mean', 'iat_std', 'unique_path_ratio',
    'path_entropy_mean', 'payload_len_mean', 'payload_len_std', 'depth_mean',
    'error_rate_4xx'
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

def shannon_entropy(string):
    if not string: return 0.0
    entropy = 0.0
    for x in set(string):
        p_x = float(string.count(x)) / len(string)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def calculate_behavioral_features(client_ip):
    history = traffic_history.get(client_ip, [])
    if not history:
        return {f: 0.0 for f in BEHAVIOR_FEATURES}
    
    current_time = time.time()
    # 10-second rolling window
    window = [h for h in history if current_time - h['time'] <= 10.0]
    
    if not window:
        return {f: 0.0 for f in BEHAVIOR_FEATURES}

    timestamps = np.array([h['time'] for h in window])
    lengths = np.array([h['payload_len'] for h in window])
    paths = [h['path'] for h in window]
    
    # telemetry data
    status_codes = [h['status_code'] for h in window if h['status_code'] is not None]
    response_times = [h['response_time'] for h in window if h['response_time'] is not None]
    
    # 1. Volume
    req_count = len(window)
    
    # 2. Timing (IAT in milliseconds)
    iat_deltas = np.diff(timestamps) * 1000 
    iat_mean = float(np.mean(iat_deltas)) if len(iat_deltas) > 0 else 0.0
    iat_std = float(np.std(iat_deltas)) if len(iat_deltas) > 1 else 0.0
    
    # 3. Path Analysis
    unique_paths = len(set(paths))
    unique_path_ratio = unique_paths / req_count if req_count > 0 else 0.0
    
    path_entropies = [shannon_entropy(p) for p in paths]
    path_entropy_mean = float(np.mean(path_entropies))
    
    path_depths = [p.count('/') for p in paths]
    depth_mean = float(np.mean(path_depths))
    
    # 4. Payload Analysis
    payload_mean = float(np.mean(lengths))
    payload_std = float(np.std(lengths)) if len(lengths) > 1 else 0.0
    
     # Telemetry Metrics
    error_rate_4xx = sum(1 for code in status_codes if code >= 400) / len(status_codes) if status_codes else 0.0
    


    return {
        'req_count': req_count, 'iat_mean': iat_mean, 'iat_std': iat_std,
        'unique_path_ratio': unique_path_ratio, 'path_entropy_mean': path_entropy_mean,
        'payload_len_mean': payload_mean, 'payload_len_std': payload_std, 'depth_mean': depth_mean,
        'error_rate_4xx': float(error_rate_4xx)
    }




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

SQLI_PATTERNS = [
    (r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(\/\*)|(\*\/)|(;--)|(\%3B--)", 20),
    (r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;)|(\/\*))", 30),
    (r"(\b(or|and|xor)\b\s+\w+\s*=\s*\w+)", 35),
    (r"(\w*\s*(or|and|xor)\s+\w+\s*=\s*\w+)", 30),
    (r"((\%27)|(\')|(\%22)|(\"))\s*(union|UNION)\s+(all|ALL)?\s*select", 45),
    (r"(union|UNION)\s+(all|ALL)?\s*select\s+.*?\s+from", 40),
    (r"(exec|EXEC)\s*(\s|\+)+(s|x)p_\w+", 50),
    (r"(exec|EXECUTE)\s*(\s|\+)*\(.*?\)", 40),
    (r"\b(select|insert|update|delete|drop|truncate|alter|create|rename|replace)\s+", 25),
    (r"(1\s*=\s*1|1\s*=\s*'1'|1\s*=\s*\"1\"|'1'\s*=\s*'1'|\"1\"\s*=\s*\"1\")", 35),
    (r"(\'\s*(or|and|xor)\s*\'|\"\s*(or|and|xor)\s*\")", 35),
    (r"\b(sleep|benchmark|pg_sleep|waitfor)\s*\(", 45),
    (r"waitfor\s+delay\s+['\"]\d+:\d+:\d+['\"]", 50),
    (r"\b(convert|cast)\s*\(.*?\s+as\s+", 35),
    (r"\b(extractvalue|updatexml|floor)\s*\(.*?,.*?\)", 40),
    (r";\s*(select|insert|update|delete|drop|truncate|alter|exec|execute)", 35),
    (r"\b(database|user|version|current_user|system_user)\s*\(\)", 30),
    (r"\b(@@version|@@datadir|@@basedir)\b", 35),
    (r"0x[0-9a-fA-F]{4,}", 30),
    (r"char\s*\([\d,]+\)", 25),
    (r"unicode\s*(['\"][^'\"]+['\"])", 25),
    (r"(\b(and|or|xor)\b\s+.*?\s*[=<>!]+\s*.*?\s*(and|or|xor)?\s*\w+\s*[=<>!]+\s*\w+)", 35),
    (r"\b(substr|mid|left|right)\s*\(.*?,\s*\d+,\s*\d+\)\s*[=<>]", 35),
    (r"\b(information_schema|sys\.|master\.|mysql\.|performance_schema)\b", 40),
    (r"\b(load_file|into\s+outfile|into\s+dumpfile)\b", 50),
    (r"\b(xp_cmdshell|xp_regread|xp_regwrite)\b", 50),
    (r"\w+\s*\+\s*\w+\s*=\s*\w+", 25),
    (r"(\/\*.*?\*\/)", 20),
]

XSS_PATTERNS = [
    (r"<script[^>]*>.*?</script>", 50),
    (r"javascript\s*:", 35),
    (r"on\w+\s*=", 25),
    (r"<\s*img[^>]+onerror", 40),
    (r"<\s*svg[^>]+onload", 40),
    (r"alert\s*\(", 25),
    (r"eval\s*\(", 40),
]

PATH_PATTERNS = [
    (r"\.\./", 40),
    (r"\.\.\\", 40),
    (r"%2e%2e%2f", 40),
    (r"etc/passwd", 60),
    (r"etc/shadow", 60),
    (r"windows/system32", 60),
]

CMD_PATTERNS = [
    (r";\s*(ls|cat|whoami|id|pwd|uname)", 50),
    (r"\|\s*(ls|cat|whoami|id|pwd|uname)", 50),
    (r"`[^`]+`", 50),
    (r"\$\([^)]+\)", 50),
    (r"&&\s*(ls|cat|whoami|id|pwd|uname)", 50),
]

ATTACKS = {
    "sqli": SQLI_PATTERNS,
    "xss": XSS_PATTERNS,
    "path-traversal": PATH_PATTERNS,
    "cmdi": CMD_PATTERNS,
}


def calculate_rule_confidence(payload, patterns):
    score = 0
    matched = []

    for regex, weight in patterns:
        if re.search(regex, payload, re.IGNORECASE):
            score += weight
            matched.append(regex)

    return min(score / 100.0, 1.0), matched


def rule_based_detect(payload):
    payload_lower = payload.lower()

    best_attack = 'SAFE'
    best_conf = 0.0
    best_matches = []

    for attack, patterns in ATTACKS.items():
        conf, matches = calculate_rule_confidence(payload_lower, patterns)
        if conf > best_conf:
            best_attack = attack
            best_conf = conf
            best_matches = matches

    return best_conf > 0, best_attack, best_conf, best_matches


def should_run_logistic_regression(behavioral_result):
    if behavioral_result is None:
        return True
    if not isinstance(behavioral_result, dict):
        return True
    if behavioral_result.get('blocked') is True:
        return False
    if behavioral_result.get('safe') is False:
        return False
    if behavioral_result.get('behavioral_safe') is False:
        return False
    attack_type = str(behavioral_result.get('type', 'SAFE')).upper()
    if attack_type not in {'SAFE', '', 'NONE', 'UNKNOWN'}:
        return False
    return True


def normalize_ml_label(label):
    if label is None:
        return 'safe'
    label_str = str(label).strip().lower().replace(' ', '-')
    label_str = label_str.replace('_', '-')
    if label_str in {'safe', 'norm', 'benign'}:
        return 'safe'
    if label_str in {'path-traversal', 'path-traversal-detected'}:
        return 'path-traversal'
    if label_str in {'command-injection', 'cmdi', 'command-injection-detected'}:
        return 'cmdi'
    return label_str


def detect_attack_type(payload: str, behavioral_result=None) -> dict:
    if not should_run_logistic_regression(behavioral_result):
        return {
            'blocked': True,
            'type': behavioral_result.get('type', 'BEHAVIORAL_BLOCK'),
            'confidence': behavioral_result.get('confidence', 0.95),
            'rule_confidence': None,
            'ml_confidence': None,
            'matched_rules': [],
            'decision': 'BEHAVIORAL_GATE',
            'ml_ran': False
        }

    rule_hit, rule_type, rule_conf, matches = rule_based_detect(payload)

    if rule_hit and rule_conf >= 0.95:
        return {
            'blocked': True,
            'type': rule_type,
            'confidence': round(rule_conf, 2),
            'rule_confidence': round(rule_conf, 2),
            'ml_confidence': None,
            'ml_prediction': None,
            'matched_rules': matches,
            'decision': 'RULE_ONLY',
            'ml_ran': False
        }

    ml_type, ml_conf = predict_payload_anomaly(payload)
    ml_label = normalize_ml_label(ml_type)

    blocked = False
    final_type = 'SAFE'
    final_conf = max( 1-ml_conf, 0.05)
    decision = 'SAFE'

    if rule_hit:
        if ml_label == rule_type:
            blocked = True
            final_type = rule_type
            final_conf = round(0.4 * rule_conf + 0.6 * ml_conf, 2)
            decision = 'FUSION'
        elif ml_label != 'safe' and ml_conf >= 0.9:
            blocked = True
            final_type = ml_label
            final_conf = round(ml_conf, 2)
            decision = 'ML_OVERRIDE'
        elif rule_conf >= 0.6:
            blocked = True
            final_type = rule_type
            final_conf = round(rule_conf, 2)
            decision = 'RULE_PRIORITY'
    elif ml_label != 'safe' and ml_conf >= 0.75:
        blocked = True
        final_type = ml_label
        final_conf = round(ml_conf, 2)
        decision = 'ML_ONLY'

    if final_conf <= 0.05 and  final_type == 'SAFE':
        blocked = True
        decision = 'LOW_CONF_SAFE'

    return {
        'blocked': blocked,
        'type': final_type,
        'confidence': round(final_conf, 2),
        'rule_confidence': round(rule_conf, 2),
        'ml_prediction': ml_label,
        'ml_confidence': round(ml_conf, 2),
        'matched_rules': matches,
        'decision': decision,
        'ml_ran': True
    }

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
        path = data.get('path', '')
        current_time = time.time()
        
        request_id = data.get('requestId', str(current_time))
        traffic_history.setdefault(client_ip, [])
        traffic_history[client_ip].append({
            'id': request_id,
            'time': current_time,
            'payload_len': payload_len,
            'path': data.get('path', '/'),
            'status_code': None,      # Placeholder for Telemetry
            'response_time': None     # Placeholder for Telemetry
        })
        traffic_history[client_ip] = traffic_history[client_ip][-50:]
        
        passed_total_packets = data.get('totalPackets', 0)
        client_features = calculate_behavioral_features(client_ip)

        features_df = pd.DataFrame([client_features], columns=BEHAVIOR_FEATURES)

        #debug print
        print(f"\n[ML INPUT MATRIX] Total Packets received from Node: {passed_total_packets}")
        print(f"{features_df.to_string(index=False)}\n")

        try:
            # Isolation Forest returns 1 (Normal) or -1 (Anomaly)
            prediction_raw = int(tier2_behavior_model.predict(features_df)[0])
            raw_score = tier2_behavior_model.score_samples(features_df)[0]
            # Sigmoid function to map the score to a 0.0 - 1.0 percentage
            confidence = float(1 / (1 + np.exp(raw_score))) 
            prediction = 1 if prediction_raw == -1 else 0 

        
        except Exception as model_err:
            app.logger.error(f"Inference error: {model_err}")
            prediction = 0

            confidence = 0.0

        print(f"[Tier 2 Dedicated] IP={client_ip} | Window={len(traffic_history[client_ip])} | Pred={prediction} | Anomaly_Conf={confidence:.4f}")
        print(f"[FEATURES MATRIX] Req_Count: {client_features['req_count']} | IAT_Mean: {client_features['iat_mean']:.2f} | Path_Entropy: {client_features['path_entropy_mean']:.2f}")

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
        
        request_id = body_data.get('requestId', str(current_time))
        traffic_history.setdefault(client_ip, [])
        traffic_history[client_ip].append({
            'id': request_id,
            'time': current_time,
            'payload_len': payload_len,
            'path': body_data.get('path', '/'),
            'status_code': None,
            'response_time': None
        })
        traffic_history[client_ip] = traffic_history[client_ip][-200:]
        
        if len(traffic_history[client_ip]) >= 5:
            metrics = calculate_behavioral_features(client_ip)
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

        behavioral_result = body_data.get('behavioral_result') or body_data.get('behavioral')
        if isinstance(behavioral_result, dict) and behavioral_result.get('blocked') is True:
            return jsonify({
                'blocked': True,
                'confidence': behavioral_result.get('confidence', 1.0),
                'type': behavioral_result.get('type', 'BEHAVIORAL_BLOCK'),
                'analyzed_method': req_method,
                'analyzed_path': req_path,
                'payload_length': len(payload),
                'ml_ran': False,
                'behavioral_result': behavioral_result
            })

        if not should_run_logistic_regression(behavioral_result):
            return jsonify({
                'blocked': False,
                'confidence': behavioral_result.get('confidence', 0.1) if isinstance(behavioral_result, dict) else 0.1,
                'type': 'SAFE',
                'analyzed_method': req_method,
                'analyzed_path': req_path,
                'payload_length': len(payload),
                'ml_ran': False,
                'behavioral_result': behavioral_result
            })

        analysis_result = detect_attack_type(combined_string, behavioral_result=behavioral_result)
        response_payload = {
            'blocked': analysis_result['blocked'],
            'confidence': analysis_result['confidence'],
            'type': analysis_result['type'],
            'analyzed_method': req_method,
            'analyzed_path': req_path,
            'payload_length': len(payload),
            'ml_prediction': analysis_result['ml_prediction'],
            'ml_confidence': analysis_result['ml_confidence'],
            'rule_confidence': analysis_result['rule_confidence'],
            'matched_rules': analysis_result['matched_rules'],
            'decision': analysis_result['decision'],
            'ml_ran': analysis_result['ml_ran'],
            'behavioral_result': behavioral_result
        }
        
        if analysis_result['blocked']:
            app.logger.warning(f"Attack detected: {analysis_result['type']} (confidence: {analysis_result['confidence']})")
        else:
            app.logger.info(f"✅ Request clean (confidence: {analysis_result['confidence']}, type: {analysis_result['type']})")
            
        return jsonify(response_payload)
        
    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({'error': str(e), 'blocked': False, 'confidence': 0.0, 'type': 'ERROR'}), 500

@app.route('/behavioural/telemetry', methods=['POST'])
def receive_telemetry():
    try:
        data = request.get_json()
        client_ip = data.get('ip')
        request_id = data.get('requestId')
        status_code = data.get('statusCode', 200)
        response_time = data.get('responseTime', 0)
        
        if client_ip in traffic_history:
            # Iterate backwards (most recent first) to find the matching request ID
            for req_event in reversed(traffic_history[client_ip]):
                if req_event.get('id') == request_id:
                    # INJECT THE GROUND TRUTH
                    req_event['status_code'] = status_code
                    req_event['response_time'] = response_time
                    break # Found it, stop searching
                    
        return jsonify({'status': 'telemetry_received'}), 200
    except Exception as e:
        app.logger.error(f"Telemetry ingestion error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('AI_ENGINE_PORT', os.environ.get('PORT', '5000')))
    print('[WEJA] AI Engine starting...')
    print(f'[*] Listening on http://0.0.0.0:{port}')
    print('[*] Using hybrid detection: Rule-based + ML (LogisticRegression) + Tier 2 Sequence Behavior')
    app.run(host='0.0.0.0', port=port, debug=True)