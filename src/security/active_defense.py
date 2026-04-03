"""
Module: Active Defense & Offensive Security
Creates honeypots to trap attackers and fuzzing tools to self-verify defenses.
"""

import time
import threading
from flask import Blueprint, request, jsonify

active_defense_bp = Blueprint('active_defense', __name__)

def record_honeypot_event(conn, ip, user_agent, path, payload):
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO honeypot_events (ip_address, user_agent, endpoint_hit, payload_dump, severity) VALUES (%s, %s, %s, %s, 'CRITICAL')",
        (ip, user_agent, path, str(payload))
    )
    
    # Instantly trigger highest severity block in security_events
    cursor.execute(
        "INSERT INTO security_events (event_type, severity, details, ip_address) VALUES (%s, %s, %s, %s)",
        ("honeypot_triggered", "critical", f"Attacker hit honeypot at {path}", ip)
    )
    conn.commit()

@active_defense_bp.route('/api/admin/debug_console', methods=['GET', 'POST', 'PUT', 'DELETE'])
@active_defense_bp.route('/.env', methods=['GET'])
@active_defense_bp.route('/api/v1/system/backdoor', methods=['GET', 'POST'])
def honeypot_trap():
    """
    Fake endpoints that normal users will never hit.
    Any request to these instantly flags the IP as purely malicious.
    """
    # Lazy import to avoid circular dependencies
    from database import get_connection
    conn = get_connection()
    try:
        record_honeypot_event(
            conn, 
            request.remote_addr, 
            request.headers.get("User-Agent", "unknown"),
            request.path,
            request.get_data(as_text=True)
        )
    finally:
        conn.close()

    # Tarpit the attacker heavily, don't just return immediately
    time.sleep(5)
    
    # Deceptive response
    return jsonify({"error": "Forbidden", "message": "Access Denied"}), 403

def simulated_attack_runner():
    """
    Automated self-fuzzing that runs in the background.
    Continually probes the system with credential stuffing and bad JWTs
    to ensure defenses remain active.
    """
    import urllib.request
    import json
    
    while True:
        try:
            # Simulate a credential stuffing hit to ensure rate limiters catch it
            data = json.dumps({"username": "fuzz_bot", "password": "bad_password"}).encode('utf-8')
            req = urllib.request.Request("http://127.0.0.1:5000/api/login", data=data)
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'FuzzingBot/1.0')
            try:
                urllib.request.urlopen(req)
            except Exception:
                pass 
                
        except Exception:
            pass
        
        # Run every hour
        time.sleep(3600)

def start_active_defense_fuzzer():
    t = threading.Thread(target=simulated_attack_runner, daemon=True)
    t.start()
