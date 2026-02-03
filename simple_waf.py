#!/usr/bin/env python3
"""
SentinelShield Educational WAF
A simple Web Application Firewall for learning

Purpose: Demonstrate request inspection and threat detection
Author: [Your Name]
Date: [Today's Date]
"""

from flask import Flask, request, jsonify, Response
import requests
import re
import json
from datetime import datetime

# ============================================================
# STEP 1: DETECTION RULES (Start Simple)
# ============================================================

# These are regex patterns that match common attacks
# Regex tutorial: https://regexr.com/

DETECTION_RULES = {
    'sql_injection': [
        r"('.*(or|union|select|insert|update|delete).*)",  # SQL keywords
        r"(union\s+select)",                                # UNION attacks
        r"('.*--)",                                         # SQL comments
    ],
    
    'xss': [
        r"(<script.*?>.*?</script>)",                      # Script tags
        r"(onerror\s*=)",                                  # Event handlers
        r"(javascript:)",                                  # JS protocol
    ],
    
    'lfi': [
        r"(\.\./|\.\./\.\./)",                            # Directory traversal
        r"(/etc/passwd|/etc/shadow)",                     # System files
        r"(php://|file://)",                              # PHP wrappers
    ],
    
    'command_injection': [
    r"(;\\s*(cat|ls|pwd|whoami))",     # Command separators (semicolon)
    r"(\\|\\s*(cat|ls|pwd|whoami))",   # Pipe operator - NOW INCLUDES whoami
    r"(&&\\s*(cat|ls|pwd|whoami))",    # AND operator - NOW INCLUDES whoami
    ],

}


# ============================================================
# STEP 2: INSPECTION FUNCTION
# ============================================================

def inspect_request(method, path, params, headers):
    """
    Check if a request is malicious
    
    Args:
        method: HTTP method (GET, POST, etc.)
        path: URL path
        params: Query parameters
        headers: HTTP headers
    
    Returns:
        dict: {
            'is_malicious': True/False,
            'attack_type': 'sql_injection' or None,
            'reason': 'Why it was blocked',
            'matched_pattern': 'The pattern that matched'
        }
    """
    
    # Combine all request parts into one string to check
    # This is what attackers can control
    request_data = f"{method} {path} {params} {headers}"
    
    # Check each attack category
    for attack_type, patterns in DETECTION_RULES.items():
        for pattern in patterns:
            # Try to find the attack pattern
            match = re.search(pattern, request_data, re.IGNORECASE)
            
            if match:
                # Attack detected!
                return {
                    'is_malicious': True,
                    'attack_type': attack_type,
                    'reason': f'{attack_type.replace("_", " ").title()} detected',
                    'matched_pattern': pattern,
                    'matched_text': match.group(0)[:50]  # First 50 chars
                }
    
    # No attack found - request is clean
    return {
        'is_malicious': False,
        'attack_type': None,
        'reason': 'Request is clean',
        'matched_pattern': None,
        'matched_text': None
    }


# ============================================================
# STEP 3: LOGGING FUNCTION
# ============================================================

def log_request(client_ip, method, path, inspection_result):
    """
    Save request details to log file
    
    This helps us analyze attacks later
    """
    
    log_entry = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'client_ip': client_ip,
        'method': method,
        'path': path,
        'is_malicious': inspection_result['is_malicious'],
        'attack_type': inspection_result['attack_type'],
        'reason': inspection_result['reason']
    }
    
    # Save to file
    with open('logs/waf_log.txt', 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
    
    # If attack was blocked, also save to blocked log
    if inspection_result['is_malicious']:
        with open('logs/blocked_attacks.txt', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')


# ============================================================
# STEP 4: FLASK WEB APPLICATION
# ============================================================

app = Flask(__name__)

# This runs BEFORE every request
@app.before_request
def check_request():
    """
    Intercept every request and check if it's malicious
    """
    
    # Get request details
    client_ip = request.remote_addr
    method = request.method
    path = request.path
    params = str(request.args)  # Query parameters
    headers = str(request.headers)
    
    # Inspect the request
    inspection_result = inspect_request(method, path, params, headers)
    
    # Log the request
    log_request(client_ip, method, path, inspection_result)
    
    # If malicious, block it!
    if inspection_result['is_malicious']:
        print(f"[BLOCKED] {inspection_result['attack_type']} from {client_ip}")
        
        return jsonify({
            'status': 'BLOCKED',
            'message': 'Your request was blocked by SentinelShield WAF',
            'attack_type': inspection_result['attack_type'],
            'reason': inspection_result['reason'],
            'timestamp': datetime.now().isoformat()
        }), 403  # 403 = Forbidden
    
    # If clean, allow it
    print(f"[ALLOWED] {method} {path} from {client_ip}")


# ============================================================
# STEP 5: PROXY TO DVWA
# ============================================================

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    """
    Forward clean requests to DVWA
    """
    
    # Build target URL
    target_url = f"http://localhost:8080/{path}"
    if request.query_string:
        target_url += f"?{request.query_string.decode()}"
    
    # Forward the request
    try:
        if request.method == 'GET':
                # stream=True tells requests NOT to auto-decompress
            resp = requests.get(target_url, headers=dict(request.headers), stream=True)
        elif request.method == 'POST':
                # stream=True tells requests NOT to auto-decompress
            resp = requests.post(
            target_url,
            data=request.get_data(),
            headers=dict(request.headers),
            stream=True
        )
        else:
         resp = requests.request(
            request.method,
            target_url,
            headers=dict(request.headers)
        )
        
        # Return DVWA's response
        return Response(
            resp.content,
            status=resp.status_code,
            headers=dict(resp.headers)
        )
    
    except Exception as e:
        return jsonify({'error': 'Could not connect to DVWA'}), 502


# ============================================================
# STEP 6: STATUS ENDPOINT
# ============================================================

@app.route('/waf/status')
def waf_status():
    """
    Show WAF statistics
    """
    
    # Count total and blocked requests
    try:
        with open('logs/waf_log.txt', 'r') as f:
            total = len(f.readlines())
        
        with open('logs/blocked_attacks.txt', 'r') as f:
            blocked = len(f.readlines())
    except:
        total = 0
        blocked = 0
    
    return jsonify({
        'status': 'operational',
        'name': 'SentinelShield Educational WAF',
        'total_requests': total,
        'blocked_requests': blocked,
        'detection_rate': f"{(blocked/max(total, 1))*100:.1f}%"
    })


# ============================================================
# STEP 7: START THE WAF
# ============================================================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  SentinelShield Educational WAF Starting...")
    print("="*60)
    print("\n[✓] WAF is running on http://localhost:5000")
    print("[✓] DVWA is accessible through WAF")
    print("[→] Test: http://localhost:5000/waf/status")
    print("[!] Press Ctrl+C to stop\n")
    
    # Create log files
    open('logs/waf_log.txt', 'a').close()
    open('logs/blocked_attacks.txt', 'a').close()
    
    # Start Flask
    app.run(host='0.0.0.0', port=5000, debug=False)
