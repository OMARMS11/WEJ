import os
import re
import sys
import time
import math
import hmac
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from collections import Counter

app = Flask(__name__)
CORS(app)

# ==========================================
# 0. TRAINING / OBSERVATION MODE CONFIG
# ==========================================
# WAF_TRAINING_MODE=1  -> requests carrying the shared secret are never banned,
#                         and every computed feature window is captured for export.
# WAF_OBSERVATION_MODE=1 -> model runs and logs, but NO IP is ever banned (global).
# WAF_TRAINING_SECRET  -> shared secret between Node proxy and this engine.
# WAF_ATTACK_LABEL     -> the integer label that means "Attack" in the trained
#                         model's classes_ (default 1). predict_proba columns are
#                         looked up from this, never hardcoded by position.
TRAINING_MODE = os.environ.get('WAF_TRAINING_MODE', '0') == '1'
OBSERVATION_MODE = os.environ.get('WAF_OBSERVATION_MODE', '0') == '1'
TRAINING_SECRET = os.environ.get('WAF_TRAINING_SECRET', '')
ATTACK_LABEL = int(os.environ.get('WAF_ATTACK_LABEL', '1'))

# Feature windows captured while in training mode (one row per analyzed request)
training_rows = []


def is_training_request(data):
    """True only when training mode is on AND the caller presents the shared secret
    (either forwarded by the Node proxy in the JSON body, or as a header for curl)."""
    if not (TRAINING_MODE and TRAINING_SECRET):
        return False
    supplied = ''
    if isinstance(data, dict):
        supplied = str(data.get('trainingSecret') or '')
    if not supplied:
        supplied = request.headers.get('x-waf-training', '')
    return hmac.compare_digest(supplied, TRAINING_SECRET)


def _admin_secret_ok():
    """Guard for the training admin endpoints (/training/*, /export_normal)."""
    if not TRAINING_SECRET:
        return True  # no secret configured -> local dev, leave open
    supplied = request.headers.get('x-waf-training', '') or request.args.get('secret', '')
    return hmac.compare_digest(supplied, TRAINING_SECRET)


def record_training_row(client_ip, features):
    training_rows.append({
        **{k: features[k] for k in features},
        '_ip': client_ip,
        '_ts': time.time(),
    })

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
TIER2_ATTACK_IDX = 1  # safe default; recomputed from classes_ below
try:
    tier2_isolation_model = joblib.load('randomforest_logs.pkl')
    print("[Tier 2] RandomForest behavioral model loaded successfully.")
    classes = list(tier2_isolation_model.classes_)
    if ATTACK_LABEL in classes:
        TIER2_ATTACK_IDX = classes.index(ATTACK_LABEL)
    else:
        # String-labeled model (e.g. ['Attack', 'Benign'] sorted alphabetically)
        for i, c in enumerate(classes):
            if str(c).strip().lower() in ('attack', 'anomaly', 'malicious', '1'):
                TIER2_ATTACK_IDX = i
                break
    print(f"[Tier 2] classes_={classes} -> using predict_proba[:, {TIER2_ATTACK_IDX}] "
          f"as P(Attack) (attack label = {classes[TIER2_ATTACK_IDX]!r})")
except Exception as e:
    print(f"⚠️ Error loading Tier 2 behavioral model: {e}")

# In-memory monitoring states
traffic_history = {}    
banned_behavior_ips = set()  

BEHAVIOR_FEATURES = [
    'req_count', 'iat_mean', 'iat_std', 'unique_path_ratio',
    'path_entropy_mean', 'depth_mean', 'payload_len_mean', 'payload_len_std', 
    'error_rate_4xx'
]

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
    path_lengths = np.array([len(p) for p in paths])
    payload_mean = float(np.mean(path_lengths))
    payload_std = float(np.std(path_lengths)) if len(path_lengths) > 1 else 0.0
    
     # Telemetry Metrics
    error_rate_4xx = sum(1 for code in status_codes if code >= 400) / len(status_codes) if status_codes else 0.0
    


    return {
        'req_count': req_count, 
        'iat_mean': iat_mean, 
        'iat_std': iat_std,
        'unique_path_ratio': unique_path_ratio, 
        'path_entropy_mean': path_entropy_mean,
        'depth_mean': depth_mean,
        'payload_len_mean': payload_mean, 
        'payload_len_std': payload_std, 
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

    # if final_conf <= 0.05 and  final_type == 'SAFE':
    #     blocked = True
    #     decision = 'LOW_CONF_SAFE'

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
        training = is_training_request(data)

        if training:
            # Self-heal: never let a stale ban block baseline capture
            banned_behavior_ips.discard(client_ip)
        elif client_ip in banned_behavior_ips:
            return jsonify({'blocked': True, 'type': 'AUTOMATED_ANOMALY_DDoS_FUZZ', 'confidence': 1.0}), 200

        payload_content = data.get('payload', '')
        path = data.get('path', '/')
        # FIX: Use path length to perfectly match the training script's len(url)
        payload_len = len(path)
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
     
        # === COLD START PROTECTION ===
        if client_features['req_count'] < 3:
            print(f"[Tier 2] IP={client_ip} | Window={client_features['req_count']} | Skipped (Cold Start)")
            return jsonify({
                'blocked': False,
                'type': 'SAFE',
                'confidence': 0.0
            }), 200
        # =============================

        # === TRAINING DATASET CAPTURE ===
        # Snapshot this window as one dataset row. Doing it per-request (instead of
        # one row per IP at export time) is what actually builds a baseline CSV.
        if training:
            record_training_row(client_ip, client_features)
        # ================================

        # === AUTO-ALIGN & DEBUG FIX ===
        if hasattr(tier2_isolation_model, 'feature_names_in_'):
            expected_cols = tier2_isolation_model.feature_names_in_
            # Force the dataframe to match the model's exact columns and order
            features_df = pd.DataFrame([client_features])[expected_cols]
        else:
            features_df = pd.DataFrame([client_features], columns=BEHAVIOR_FEATURES)
        # ==============================

        #debug print
        print(f"\n[ML INPUT MATRIX] Total Packets received from Node: {passed_total_packets}")
        print(f"{features_df.to_string(index=False)}\n")

        try:
            # Supervised Random Forest natively outputs perfect 0.0 to 1.0 probabilities
            probabilities = tier2_isolation_model.predict_proba(features_df)[0]

            # Column order comes from model.classes_ — resolved at load time,
            # never assumed. TIER2_ATTACK_IDX points at P(Attack).
            confidence = float(probabilities[TIER2_ATTACK_IDX])
            prediction = 1 if confidence > 0.75 else 0 

        
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

        if prediction == 1 and confidence > 0.85:
            if training or OBSERVATION_MODE:
                mode = 'TRAINING' if training else 'OBSERVATION'
                print(f"[{mode}] Tier 2 would ban IP {client_ip} (conf={confidence:.2f}) — not enforcing.")
            else:
                banned_behavior_ips.add(client_ip)
                print(f"🚫 [Tier 2 BAN TRIGGERED] IP {client_ip} isolated!")
                return jsonify({
                    'blocked': True,
                    'type': 'AUTOMATED_ANOMALY_DDoS_FUZZ',
                    'confidence': round(confidence, 2)
                }), 200

        return jsonify({
            'blocked': False,
            'type': 'TRAINING_SAFE' if training else 'SAFE',
            'confidence': round(1 - confidence, 2),
            'attack_confidence': round(confidence, 2),
            'training': training
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
        training = is_training_request(body_data)
        if training:
            banned_behavior_ips.discard(client_ip)
        elif client_ip in banned_behavior_ips:
            return jsonify({'blocked': True, 'type': 'BANNED_IP_BEHAVIORAL', 'confidence': 1.0}), 403
            
        payload = body_data.get('payload', '')
        current_time = time.time()
        
        path = body_data.get('path', '/')
        # FIX: Use path length to perfectly match the training script's len(url)
        payload_len = len(path)
        
        request_id = body_data.get('requestId', str(current_time))
        traffic_history.setdefault(client_ip, [])
        # DEDUPE FIX: the Node proxy calls /behavioural/analyze AND /analyze for the
        # same request (same requestId). Appending here again used to double every
        # event: req_count x2, IAT gaps alternating ~0ms, unique_path_ratio halved.
        # Only record the event if the dedicated route hasn't already recorded it.
        already_recorded = any(
            evt.get('id') == request_id for evt in traffic_history[client_ip][-10:]
        )
        if not already_recorded:
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

            if metrics['req_count'] >= 3:
                features_df = pd.DataFrame([metrics], columns=BEHAVIOR_FEATURES)
                try:
                    probabilities = tier2_isolation_model.predict_proba(features_df)[0]
                    tier2_conf = float(probabilities[TIER2_ATTACK_IDX])
                    tier2_pred = 1 if tier2_conf > 0.75 else 0
                except Exception as e:
                    app.logger.error(f"Tier2 execution failed inside fallback: {e}")
                    tier2_pred = 0
                    tier2_conf = 0.0
                
                if tier2_pred == 1 and tier2_conf > 0.85:
                    if training or OBSERVATION_MODE:
                        mode = 'TRAINING' if training else 'OBSERVATION'
                        print(f"[{mode}] Fallback Tier 2 would ban IP {client_ip} (conf={tier2_conf:.2f}) — not enforcing.")
                    else:
                        banned_behavior_ips.add(client_ip)
                        return jsonify({'blocked': True, 'type': 'AUTOMATED_ANOMALY_DDoS_FUZZ', 'confidence': tier2_conf}), 403
        else:
             print(f"[Fallback Tier 2] IP={client_ip} | Skipped (Cold Start)")

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

@app.route('/export_normal', methods=['GET'])
def export_normal():
    """Dump every feature window captured in training mode to a CSV.

    ?label=0 (default, benign browsing run) or ?label=1 (attack capture run:
    replay your fuzzer/DDoS script through the proxy with the training secret,
    then export with label=1). ?file= overrides the output filename.
    """
    import csv
    if not _admin_secret_ok():
        return jsonify({'error': 'invalid or missing training secret'}), 403

    label = int(request.args.get('label', 0))
    default_name = 'my_normal_traffic.csv' if label == 0 else 'my_attack_traffic.csv'
    filename = request.args.get('file', default_name)

    if not training_rows:
        return ("No captured windows. Enable WAF_TRAINING_MODE=1, browse through the "
                "proxy with the training secret, then export."), 400

    count = 0
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=BEHAVIOR_FEATURES + ['label'])
        writer.writeheader()
        for row in training_rows:
            out = {k: row[k] for k in BEHAVIOR_FEATURES}
            out['label'] = label
            writer.writerow(out)
            count += 1
    return f"✅ Exported {count} behavioral windows (label={label}) to {filename}"


@app.route('/training/status', methods=['GET'])
def training_status():
    if not _admin_secret_ok():
        return jsonify({'error': 'invalid or missing training secret'}), 403
    return jsonify({
        'training_mode': TRAINING_MODE,
        'observation_mode': OBSERVATION_MODE,
        'attack_proba_column': TIER2_ATTACK_IDX,
        'captured_rows': len(training_rows),
        'tracked_ips': {ip: len(h) for ip, h in traffic_history.items()},
        'banned_ips': sorted(banned_behavior_ips),
    })


@app.route('/training/reset', methods=['POST'])
def training_reset():
    """Clear ALL in-memory state: bans, traffic history, captured rows."""
    if not _admin_secret_ok():
        return jsonify({'error': 'invalid or missing training secret'}), 403
    banned_behavior_ips.clear()
    traffic_history.clear()
    training_rows.clear()
    return jsonify({'status': 'reset', 'banned_ips': 0, 'tracked_ips': 0, 'captured_rows': 0})


if __name__ == '__main__':
    port = int(os.environ.get('AI_ENGINE_PORT', os.environ.get('PORT', '5000')))
    print('[WEJA] AI Engine starting...')
    print(f'[*] Listening on http://0.0.0.0:{port}')
    print('[*] Using hybrid detection: Rule-based + ML (LogisticRegression) + Tier 2 Sequence Behavior')
    if TRAINING_MODE:
        print('⚠️  [*] TRAINING MODE IS ON — secret-bearing requests are never banned. Disable for demos.')
    if OBSERVATION_MODE:
        print('⚠️  [*] OBSERVATION MODE IS ON — Tier 2 logs but never bans anyone.')
    app.run(host='0.0.0.0', port=port, debug=True)