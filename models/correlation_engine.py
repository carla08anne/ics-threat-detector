from datetime import datetime, timedelta
from collections import defaultdict
import json

# ── KNOWN ATTACK PATTERNS ─────────────────────────────
# These are real ICS attack kill chain patterns
# Each pattern is a sequence of attack types that
# together indicate a coordinated campaign

KNOWN_PATTERNS = [
    {
        'name'       : 'ICS Reconnaissance & Takeover',
        'sequence'   : ['UNAUTHORIZED_ACCESS', 'COMMAND_INJECTION'],
        'severity'   : 'CRITICAL',
        'description': 'Attacker gained access then immediately injected commands — classic ICS takeover pattern',
        'mitre_chain': ['T0801', 'T0836'],
        'real_example': 'Ukraine Power Grid Attack 2015',
    },
    {
        'name'       : 'Stuxnet-Style Manipulation',
        'sequence'   : ['UNAUTHORIZED_ACCESS', 'SPOOFING', 'COMMAND_INJECTION'],
        'severity'   : 'CRITICAL',
        'description': 'Attacker accessed system, spoofed trusted device, then injected malicious commands — mirrors Stuxnet methodology',
        'mitre_chain': ['T0801', 'T0831', 'T0836'],
        'real_example': 'Stuxnet 2010 — Iran Nuclear Facility',
    },
    {
        'name'       : 'DDoS + Exploitation',
        'sequence'   : ['DDoS', 'COMMAND_INJECTION'],
        'severity'   : 'HIGH',
        'description': 'DDoS used to distract operators while command injection executes — common ICS attack pattern',
        'mitre_chain': ['T0814', 'T0836'],
        'real_example': 'Triton/TRISIS Attack 2017',
    },
    {
        'name'       : 'Persistent Access Campaign',
        'sequence'   : ['UNAUTHORIZED_ACCESS', 'UNAUTHORIZED_ACCESS', 'UNAUTHORIZED_ACCESS'],
        'severity'   : 'HIGH',
        'description': 'Repeated unauthorized access attempts indicate persistent attacker probing for weakness',
        'mitre_chain': ['T0801', 'T0801', 'T0801'],
        'real_example': 'Oldsmar Water Treatment Attack 2021',
    },
    {
        'name'       : 'Full ICS Kill Chain',
        'sequence'   : ['UNAUTHORIZED_ACCESS', 'SPOOFING', 'COMMAND_INJECTION', 'DDoS'],
        'severity'   : 'CRITICAL',
        'description': 'Complete attack kill chain detected — system fully compromised',
        'mitre_chain': ['T0801', 'T0831', 'T0836', 'T0814'],
        'real_example': 'Advanced Persistent Threat — Nation State Level',
    },
]


class CorrelationEngine:
    """
    Correlates multiple attack events to detect
    coordinated multi-stage attack campaigns.
    """

    def __init__(self, time_window_minutes=10):
        self.time_window   = timedelta(minutes=time_window_minutes)
        self.event_buffer  = []   # recent events
        self.campaigns     = []   # detected campaigns
        self.campaign_id   = 0

    def add_event(self, attack_type, source_ip, device,
                  timestamp=None, confidence=100):
        """Add new event and check for correlated campaigns."""
        if timestamp is None:
            timestamp = datetime.now()
        elif isinstance(timestamp, str):
            try:
                timestamp = datetime.strptime(timestamp, '%H:%M:%S')
            except:
                timestamp = datetime.now()

        event = {
            'attack_type': attack_type,
            'source_ip'  : source_ip,
            'device'     : device,
            'timestamp'  : timestamp,
            'confidence' : confidence,
        }

        self.event_buffer.append(event)
        self._clean_old_events()

        # Check for campaigns
        new_campaigns = self._detect_campaigns()
        return new_campaigns

    def _clean_old_events(self):
        """Remove events outside time window."""
        cutoff = datetime.now() - self.time_window
        self.event_buffer = [
            e for e in self.event_buffer
            if e['timestamp'] > cutoff
        ]

    def _detect_campaigns(self):
        """Check if recent events match known attack patterns."""
        new_campaigns = []

        # Group events by source IP
        by_ip = defaultdict(list)
        for event in self.event_buffer:
            if event['attack_type'] != 'NORMAL':
                by_ip[event['source_ip']].append(event)

        for ip, events in by_ip.items():
            if len(events) < 2:
                continue

            # Get attack sequence for this IP
            sequence = [e['attack_type'] for e in events]

            # Check against known patterns
            for pattern in KNOWN_PATTERNS:
                if self._sequence_matches(sequence, pattern['sequence']):

                    # Check if we already detected this campaign
                    already_detected = any(
                        c['source_ip'] == ip and
                        c['pattern_name'] == pattern['name']
                        for c in self.campaigns
                    )

                    if not already_detected:
                        self.campaign_id += 1
                        campaign = {
                            'id'          : self.campaign_id,
                            'pattern_name': pattern['name'],
                            'severity'    : pattern['severity'],
                            'description' : pattern['description'],
                            'mitre_chain' : pattern['mitre_chain'],
                            'real_example': pattern['real_example'],
                            'source_ip'   : ip,
                            'devices'     : list(set(
                                e['device'] for e in events)),
                            'events'      : events,
                            'detected_at' : datetime.now().strftime('%H:%M:%S'),
                            'event_count' : len(events),
                            'duration_min': self._get_duration(events),
                        }
                        self.campaigns.append(campaign)
                        new_campaigns.append(campaign)

        return new_campaigns

    def _sequence_matches(self, actual, pattern):
        """Check if pattern exists as subsequence in actual."""
        if len(pattern) > len(actual):
            return False

        pattern_idx = 0
        for attack in actual:
            if attack == pattern[pattern_idx]:
                pattern_idx += 1
            if pattern_idx == len(pattern):
                return True
        return False

    def _get_duration(self, events):
        """Get duration of attack campaign in minutes."""
        if len(events) < 2:
            return 0
        times = [e['timestamp'] for e in events]
        delta = max(times) - min(times)
        return round(delta.total_seconds() / 60, 1)

    def get_summary(self):
        """Get summary of all detected campaigns."""
        return {
            'total_campaigns' : len(self.campaigns),
            'critical'        : len([c for c in self.campaigns
                                    if c['severity'] == 'CRITICAL']),
            'high'            : len([c for c in self.campaigns
                                    if c['severity'] == 'HIGH']),
            'campaigns'       : self.campaigns,
        }


# ── TEST ──────────────────────────────────────────────
if __name__ == '__main__':
    engine = CorrelationEngine(time_window_minutes=10)

    print("🔗 ATTACK CORRELATION ENGINE — TEST")
    print("=" * 60)

    # Simulate a Stuxnet-style attack sequence
    test_events = [
        ('NORMAL',              '192.168.1.10', 'PLC_01'),
        ('UNAUTHORIZED_ACCESS', '172.16.0.88',  'PLC_02'),
        ('NORMAL',              '192.168.1.11', 'SENSOR_01'),
        ('SPOOFING',            '172.16.0.88',  'PLC_02'),
        ('COMMAND_INJECTION',   '172.16.0.88',  'PLC_02'),
        ('DDoS',                '10.0.0.55',    'SCADA'),
        ('UNAUTHORIZED_ACCESS', '10.0.0.55',    'SCADA'),
        ('UNAUTHORIZED_ACCESS', '10.0.0.55',    'PLC_01'),
        ('UNAUTHORIZED_ACCESS', '10.0.0.55',    'SENSOR_02'),
    ]

    for attack, ip, device in test_events:
        campaigns = engine.add_event(attack, ip, device)

        if campaigns:
            for c in campaigns:
                print(f"\n🚨 CAMPAIGN DETECTED!")
                print(f"   Pattern  : {c['pattern_name']}")
                print(f"   Severity : {c['severity']}")
                print(f"   Source IP: {c['source_ip']}")
                print(f"   Devices  : {', '.join(c['devices'])}")
                print(f"   Events   : {c['event_count']}")
                print(f"   MITRE    : {' → '.join(c['mitre_chain'])}")
                print(f"   ⚠️  {c['description']}")
                print(f"   📖 Real example: {c['real_example']}")
        else:
            if attack != 'NORMAL':
                print(f"   [{attack}] from {ip} — monitoring...")

    print(f"\n{'='*60}")
    summary = engine.get_summary()
    print(f"TOTAL CAMPAIGNS DETECTED: {summary['total_campaigns']}")
    print(f"CRITICAL: {summary['critical']} | HIGH: {summary['high']}")