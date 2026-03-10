from datetime import datetime
import json

# ── HONEYPOT CONFIGURATION ────────────────────────────
HONEYPOT_DEVICES = [
    {
        'id'         : 'HONEYPOT_PLC_99',
        'ip'         : '192.168.1.99',
        'type'       : 'Fake PLC',
        'description': 'Simulated Allen-Bradley PLC — no legitimate device should contact this',
        'port'       : 44818,  # Real Modbus port
    },
    {
        'id'         : 'HONEYPOT_SCADA_98',
        'ip'         : '192.168.1.98',
        'type'       : 'Fake SCADA Server',
        'description': 'Simulated SCADA server — decoy for attackers',
        'port'       : 102,    # Real S7 protocol port
    },
]

HONEYPOT_IPS = {d['ip'] for d in HONEYPOT_DEVICES}


class HoneypotMonitor:
    """
    Monitors for any traffic to honeypot devices.
    Any contact = confirmed attacker, zero false positives.
    """

    def __init__(self):
        self.alerts    = []
        self.alert_id  = 0

    def check_event(self, source_ip, dest_ip, device, command):
        """Check if event involves honeypot — instant CRITICAL if so."""
        
        # Check if destination is a honeypot
        if dest_ip in HONEYPOT_IPS or device in {d['id'] for d in HONEYPOT_DEVICES}:
            return self._generate_alert(source_ip, dest_ip, device, command)
        
        # Check if source claims to be a honeypot (spoofing attempt)
        if source_ip in HONEYPOT_IPS:
            return self._generate_alert(
                source_ip, dest_ip, device, command,
                spoofed=True
            )

        return None

    def _generate_alert(self, source_ip, dest_ip,
                         device, command, spoofed=False):
        """Generate honeypot alert."""
        self.alert_id += 1

        alert_type = 'HONEYPOT_SPOOF' if spoofed else 'HONEYPOT_CONTACT'
        description = (
            f"Attacker is spoofing honeypot IP {source_ip}"
            if spoofed else
            f"Confirmed attacker contacted honeypot device {device}"
        )

        alert = {
            'id'          : self.alert_id,
            'type'        : alert_type,
            'severity'    : 'CRITICAL',
            'confidence'  : 100.0,  # always 100% — no false positives
            'source_ip'   : source_ip,
            'dest_ip'     : dest_ip,
            'device'      : device,
            'command'     : command,
            'timestamp'   : datetime.now().strftime('%H:%M:%S'),
            'description' : description,
            'mitre_id'    : 'T0866',  # Exploitation of Remote Services
            'actions'     : [
                f"Block {source_ip} at all network perimeters immediately",
                "Capture full packet dump for forensic analysis",
                "Check all devices for lateral movement from this IP",
                "Escalate to incident response team immediately",
            ],
            'firewall_rule': f"iptables -A INPUT -s {source_ip} -j DROP",
        }

        self.alerts.append(alert)
        return alert

    def scan_predictions(self, predictions_df):
        """Scan existing predictions for honeypot contacts."""
        alerts = []
        for _, row in predictions_df.iterrows():
            alert = self.check_event(
                source_ip = str(row.get('source_ip', '')),
                dest_ip   = str(row.get('dest_ip', '')),
                device    = str(row.get('device', '')),
                command   = str(row.get('command', '')),
            )
            if alert:
                alerts.append(alert)
        return alerts

    def get_summary(self):
        return {
            'total_alerts'    : len(self.alerts),
            'honeypot_devices': HONEYPOT_DEVICES,
            'alerts'          : self.alerts,
        }


# ── TEST ──────────────────────────────────────────────
if __name__ == '__main__':
    monitor = HoneypotMonitor()

    print("🍯 HONEYPOT MONITOR — TEST")
    print("=" * 60)
    print(f"Active honeypots: {len(HONEYPOT_DEVICES)}")
    for d in HONEYPOT_DEVICES:
        print(f"  → {d['id']} ({d['ip']}) — {d['description']}")

    print("\nSimulating network events...")
    print("-" * 60)

    # Simulate events — some hitting honeypot
    test_events = [
        ('192.168.1.10', '192.168.1.11',  'PLC_01',          'HEARTBEAT'),
        ('10.0.0.55',    '192.168.1.99',  'HONEYPOT_PLC_99', 'FORCE_WRITE'),
        ('192.168.1.10', '192.168.1.12',  'PLC_02',          'READ_SENSOR'),
        ('172.16.0.88',  '192.168.1.98',  'HONEYPOT_SCADA_98','STATUS_CHECK'),
        ('192.168.1.11', '192.168.1.10',  'SENSOR_01',       'HEARTBEAT'),
    ]

    for src, dst, device, cmd in test_events:
        alert = monitor.check_event(src, dst, device, cmd)
        if alert:
            print(f"\n🚨 HONEYPOT TRIGGERED!")
            print(f"   Type      : {alert['type']}")
            print(f"   Severity  : {alert['severity']}")
            print(f"   Confidence: {alert['confidence']}% ← GUARANTEED")
            print(f"   Source IP : {alert['source_ip']}")
            print(f"   Device    : {alert['device']}")
            print(f"   Command   : {alert['command']}")
            print(f"   ⚠️  {alert['description']}")
            print(f"   🔥 Firewall: {alert['firewall_rule']}")
            print(f"   Actions:")
            for a in alert['actions']:
                print(f"      → {a}")
        else:
            print(f"   ✅ NORMAL  {src} → {device} [{cmd}]")

    print(f"\n{'='*60}")
    print(f"Total honeypot alerts: {monitor.get_summary()['total_alerts']}")