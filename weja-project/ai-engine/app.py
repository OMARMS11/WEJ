"""
WEJÀ AI Engine - Hybrid Attack Detection Service
Combines rule-based pattern matching with simulated ML confidence scoring.
"""

import re
import random
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ============ RULE-BASED DETECTION PATTERNS ============

SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # Basic SQL meta-characters
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",  # SQL injection attempts
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",  # OR based injection
    r"((\%27)|(\'))union",  # UNION attacks
    r"exec(\s|\+)+(s|x)p\w+",  # Stored procedure attacks
    r"(select|insert|update|delete|drop|truncate|alter)\s",  # SQL keywords
    r"(\%27)|(')\s*(or|and)\s*\d+\s*=\s*\d+",  # OR 1=1 patterns
    r"1\s*=\s*1",  # Tautology
    r"'\s*or\s*'",  # String OR injection
]

XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",  # Script tags
    r"javascript\s*:",  # JavaScript protocol
    r"on\w+\s*=",  # Event handlers (onclick, onerror, etc.)
    r"<\s*img[^>]+onerror",  # IMG tag with onerror
    r"<\s*svg[^>]+onload",  # SVG with onload
    r"<\s*iframe",  # Iframe injection
    r"<\s*embed",  # Embed tag
    r"<\s*object",  # Object tag
    r"expression\s*\(",  # CSS expression
    r"alert\s*\(",  # Alert function
    r"document\.(cookie|location|write)",  # DOM manipulation
    r"eval\s*\(",  # Eval function
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",  # Basic path traversal
    r"\.\.\\",  # Windows path traversal
    r"%2e%2e%2f",  # URL encoded ../
    r"%252e%252e%252f",  # Double URL encoded
    r"etc/passwd",  # Linux password file
    r"etc/shadow",  # Linux shadow file
    r"windows/system32",  # Windows system directory
]

COMMAND_INJECTION_PATTERNS = [
    r";\s*(ls|cat|whoami|id|pwd|uname)",  # Unix commands
    r"\|\s*(ls|cat|whoami|id|pwd|uname)",  # Pipe injection
    r"`[^`]+`",  # Backtick command execution
    r"\$\([^)]+\)",  # Command substitution
    r"&&\s*(ls|cat|whoami|id|pwd|uname)",  # Command chaining
]


def detect_attack_type(payload: str) -> tuple[bool, str, float]:
    """
    Analyze payload for potential attacks.
    Returns: (is_malicious, attack_type, confidence)
    """
    payload_lower = payload.lower()
    
    # Check SQL Injection
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            confidence = 0.85 + random.uniform(0, 0.14)  # 85-99% confidence
            return True, "SQL_INJECTION", round(confidence, 2)
    
    # Check XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            confidence = 0.82 + random.uniform(0, 0.17)  # 82-99% confidence
            return True, "XSS", round(confidence, 2)
    
    # Check Path Traversal
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            confidence = 0.88 + random.uniform(0, 0.11)  # 88-99% confidence
            return True, "PATH_TRAVERSAL", round(confidence, 2)
    
    # Check Command Injection
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, payload_lower, re.IGNORECASE):
            confidence = 0.90 + random.uniform(0, 0.09)  # 90-99% confidence
            return True, "COMMAND_INJECTION", round(confidence, 2)
    
    # No attack detected
    return False, "SAFE", round(random.uniform(0.01, 0.15), 2)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "WEJÀ AI Engine",
        "version": "1.0.0"
    })


@app.route('/analyze', methods=['POST'])
def analyze_request():
    """
    Analyze incoming request payload for potential attacks.
    
    Expected JSON body:
    {
        "payload": "string to analyze",
        "headers": {},  // optional
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
        
        # Extract payload to analyze
        payload = data.get('payload', '')
        path = data.get('path', '')
        method = data.get('method', 'GET')
        
        # Combine all inputs for analysis
        combined_payload = f"{payload} {path}"
        
        # Perform hybrid detection
        is_blocked, attack_type, confidence = detect_attack_type(combined_payload)
        
        response = {
            "blocked": is_blocked,
            "confidence": confidence,
            "type": attack_type,
            "analyzed_method": method,
            "analyzed_path": path,
            "payload_length": len(payload)
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
    print("🛡️  WEJÀ AI Engine starting...")
    print("📡 Listening on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
