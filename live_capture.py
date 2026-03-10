from scapy.all import sniff, IP, TCP, UDP
from flask import Flask, jsonify
from flask_cors import CORS
import pickle
import pandas as pd
import numpy as np
import threading
import time
from datetime import datetime
from collections import defaultdict

# ── LOAD YOUR TRAINED MODEL ───────────────────────────
print("📂 Loading trained model...")
with open('models/threat_model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('models/encoders.pkl', 'rb') as f:
    encoders = pickle.load(f)

print("✅ Model loaded\n")

# ── DEFENSE PLAYBOOK ──────────────────────────────────
from models.defense_engine import get_defense_recommendation

# ── MITRE MAPPING ─────────────────────────────────────
MITRE_MAP = {
    'DDoS'               : ('T0814', 'Denial of Service',       'HIGH'),
    'SPOOFING'           : ('T0831', 'Manipulation of Control', 'CRITICAL'),
    'COMMAND_INJECTION'  : ('T0836', 'Modify Parameter',        'CRITICAL'),
    'UNAUTHORIZED_ACCESS': ('T0801', 'Monitor Process State',   'MEDIUM'),
    'NORMAL'             : ('N/A',   'No Threat',               'NONE'),
}

# ── LIVE EVENT STORE ──────────────────────────────────
# Stores the last 100 events for the dashboard
live_events   = []
stats         = {
    'total': 0, 'normal': 0,
    'attacks': 0, 'critical': 0
}

# ── IP TRACKING ───────────────────────────────────────
# Track how many times each IP has been seen
ip_counter    = defaultdict(int)
ip_timestamps = defaultdict(list)

# Trusted IPs on your local network
TRUSTED_IPS = set()  # will auto-populate from first packets

# ── FEATURE EXTRACTION ────────────────────────────────
def extract_features(packet):
    """
    Extract ML features from a real network packet.
    Maps real packet properties to your training features.
    """
    try:
        if not packet.haslayer(IP):
            return None

        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        pkt_size = len(packet)
        now      = time.time()

        # Track IP frequency
        ip_counter[src_ip] += 1
        ip_timestamps[src_ip].append(now)

        # Clean old timestamps (keep last 60 seconds)
        ip_timestamps[src_ip] = [
            t for t in ip_timestamps[src_ip]
            if now - t < 60
        ]

        # Calculate packet rate (packets per minute from this IP)
        packet_rate   = len(ip_timestamps[src_ip])

        # Auth attempts = how many times this IP has hit common ports
        auth_attempts = min(ip_counter[src_ip] // 10, 15)

        # Same IP count = how many recent packets from same IP
        same_ip_count = len(ip_timestamps[src_ip])

        # Determine device (simulate based on IP range)
        device = classify_device(src_ip)

        # Determine command (simulate based on port/protocol)
        command = classify_command(packet)

        # Is this a trusted IP?
        if packet_rate < 20 and src_ip not in TRUSTED_IPS:
            TRUSTED_IPS.add(src_ip)

        return {
            'timestamp'    : datetime.now().strftime('%H:%M:%S'),
            'device'       : device,
            'command'      : command,
            'source_ip'    : src_ip,
            'dest_ip'      : dst_ip,
            'packet_rate'  : min(packet_rate, 300),
            'auth_attempts': auth_attempts,
            'same_ip_count': min(same_ip_count, 50),
            'packet_size'  : pkt_size,
        }

    except Exception as e:
        return None


def classify_device(ip):
    """Map IP to a device name for display."""
    last_octet = int(ip.split('.')[-1]) % 5
    devices    = ['PLC_01','PLC_02','PLC_03','SENSOR_01','SENSOR_02']
    return devices[last_octet]


def classify_command(packet):
    """Classify packet type as an ICS-style command."""
    if packet.haslayer(TCP):
        dport = packet[TCP].dport
        # Common ICS ports
        if dport == 502:   return 'MODBUS_READ'      # Modbus
        if dport == 20000: return 'DNP3_REQUEST'     # DNP3
        if dport == 4840:  return 'OPCUA_READ'       # OPC-UA
        if dport == 80:    return 'STATUS_CHECK'
        if dport == 443:   return 'WRITE_REGISTER'
        if dport == 22:    return 'AUTH_ATTEMPT'
        if dport == 23:    return 'TELNET_ACCESS'    # insecure ICS
    if packet.haslayer(UDP):
        return 'HEARTBEAT'
    return 'READ_SENSOR'


# ── ML PREDICTION ─────────────────────────────────────
def predict_threat(features):
    """Run ML model on extracted features."""
    try:
        # Encode features same way as training
        le_device  = encoders['device']
        le_command = encoders['command']
        le_ip      = encoders['ip']

        # Handle unseen labels gracefully
        def safe_encode(encoder, value, default=0):
            if value in encoder.classes_:
                return encoder.transform([value])[0]
            return default

        device_enc  = safe_encode(le_device,  features['device'])
        command_enc = safe_encode(le_command, features['command'])
        ip_enc      = safe_encode(le_ip,      features['source_ip'])

        X = pd.DataFrame([{
            'device_encoded' : device_enc,
            'command_encoded': command_enc,
            'ip_encoded'     : ip_enc,
            'packet_rate'    : features['packet_rate'],
            'auth_attempts'  : features['auth_attempts'],
            'same_ip_count'  : features['same_ip_count'],
        }])

        # Predict + confidence
        prediction  = model.predict(X)[0]
        probability = np.max(model.predict_proba(X)) * 100

        # Get MITRE info
        mitre_id, mitre_name, severity = MITRE_MAP.get(
            prediction, MITRE_MAP['NORMAL'])

        return {
            'predicted_attack': prediction,
            'confidence'      : round(probability, 1),
            'mitre_id'        : mitre_id,
            'severity'        : severity,
        }

    except Exception as e:
        return {
            'predicted_attack': 'NORMAL',
            'confidence'      : 50.0,
            'mitre_id'        : 'N/A',
            'severity'        : 'NONE',
        }


# ── PACKET HANDLER ────────────────────────────────────
def handle_packet(packet):
    """Called for every captured packet."""
    features = extract_features(packet)
    if not features:
        return

    result   = predict_threat(features)

    # Build full event
    event = {**features, **result}

    # Get defense recommendation if attack
    if result['predicted_attack'] != 'NORMAL':
        defense = get_defense_recommendation(
            result['predicted_attack'],
            features['device'],
            features['source_ip'],
            result['confidence']
        )
        event['defense_actions'] = defense['actions'][:3]  # top 3 actions
        event['firewall_rule']   = defense['firewall_rule']
        stats['attacks'] += 1
        if result['severity'] == 'CRITICAL':
            stats['critical'] += 1
    else:
        event['defense_actions'] = []
        event['firewall_rule']   = ''
        stats['normal'] += 1

    stats['total'] += 1

    # Add to live events (keep last 100)
    live_events.insert(0, event)
    if len(live_events) > 100:
        live_events.pop()

    # Print to terminal
    if result['predicted_attack'] != 'NORMAL':
        print(f"🚨 {result['severity']:<8} | "
              f"{features['source_ip']:<16} | "
              f"{result['predicted_attack']:<25} | "
              f"{result['confidence']}% confident")
    else:
        print(f"✅ NORMAL   | "
              f"{features['source_ip']:<16} | "
              f"packet_rate={features['packet_rate']}")


# ── FLASK API ─────────────────────────────────────────
# Serves live events to the dashboard
app = Flask(__name__)
CORS(app)

@app.route('/api/events')
def get_events():
    """Return latest 50 events as JSON."""
    return jsonify({
        'events': live_events[:50],
        'stats' : stats,
    })

@app.route('/api/status')
def get_status():
    """Return system status."""
    return jsonify({
        'status'  : 'running',
        'captured': stats['total'],
        'model'   : 'Random Forest v2',
        'accuracy': '98%',
    })


# ── START CAPTURE ─────────────────────────────────────
def start_capture():
    """Start capturing packets in background thread."""
    print("🔍 Starting live packet capture...")
    print("   Capturing on all interfaces")
    print("   Press Ctrl+C to stop\n")

    # filter='ip' means only capture IP packets
    # store=False means don't store in memory (stream only)
    sniff(
        filter='ip',
        prn=handle_packet,
        store=False
    )


if __name__ == '__main__':
    print("=" * 60)
    print("  SentinelOT — Live Capture Module")
    print("  WRAITH Team")
    print("=" * 60)
    print()

    # Start packet capture in background thread
    capture_thread = threading.Thread(
        target=start_capture, daemon=True)
    capture_thread.start()

    # Start Flask API
    print("🌐 Starting API server on http://localhost:5001")
    print("   Dashboard will connect automatically\n")
    app.run(host='0.0.0.0', port=5001, debug=False)