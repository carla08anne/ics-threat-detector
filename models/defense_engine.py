# ── DEFENSE RECOMMENDATION ENGINE ─────────────────────
# Maps detected attacks to specific defense actions
# Generates firewall rules and response priorities

# ── DEFENSE PLAYBOOK ──────────────────────────────────
# Each attack type has a specific response plan
DEFENSE_PLAYBOOK = {

    'DDoS': {
        'severity'       : 'HIGH',
        'response_time'  : 'IMMEDIATE (< 5 minutes)',
        'mitre_id'       : 'T0814',
        'mitre_name'     : 'Denial of Service',
        'actions'        : [
            'Enable traffic rate limiting on affected device',
            'Block source IP at network perimeter',
            'Activate backup communication channel',
            'Alert network operations center (NOC)',
            'Monitor for secondary attack vectors',
        ],
        'firewall_rule'  : 'iptables -A INPUT -s {ip} -j DROP\n'
                           'iptables -A INPUT -p tcp --dport 502 '
                           '-m limit --limit 10/min -j ACCEPT',
        'isolate_device' : False,  # DDoS = network issue, don't isolate device
    },

    'SPOOFING': {
        'severity'       : 'CRITICAL',
        'response_time'  : 'IMMEDIATE (< 2 minutes)',
        'mitre_id'       : 'T0831',
        'mitre_name'     : 'Manipulation of Control',
        'actions'        : [
            'Verify authenticity of all commands from trusted IPs',
            'Enable strict IP-MAC address binding',
            'Isolate affected PLC and switch to manual control',
            'Audit all commands sent in last 10 minutes',
            'Reset authentication credentials for SCADA server',
        ],
        'firewall_rule'  : 'iptables -A INPUT -s {ip} -j DROP\n'
                           'iptables -A INPUT --mac-source {mac} -j DROP',
        'isolate_device' : True,
    },

    'COMMAND_INJECTION': {
        'severity'       : 'CRITICAL',
        'response_time'  : 'IMMEDIATE (< 2 minutes)',
        'mitre_id'       : 'T0836',
        'mitre_name'     : 'Modify Parameter',
        'actions'        : [
            'STOP all commands from unknown IP immediately',
            'Isolate affected PLC from network',
            'Switch PLC to manual/local control mode',
            'Block attacking IP at all network layers',
            'Review and rollback last 20 PLC register changes',
            'Notify plant safety officer',
        ],
        'firewall_rule'  : 'iptables -A INPUT -s {ip} -j DROP\n'
                           'iptables -A INPUT -p tcp --dport 502 '
                           '-s {ip} -j REJECT',
        'isolate_device' : True,
    },

    'UNAUTHORIZED_ACCESS': {
        'severity'       : 'MEDIUM',
        'response_time'  : 'URGENT (< 15 minutes)',
        'mitre_id'       : 'T0801',
        'mitre_name'     : 'Monitor Process State',
        'actions'        : [
            'Block IP after 3 failed authentication attempts',
            'Enable multi-factor authentication on SCADA',
            'Log all access attempts for forensic analysis',
            'Review user access permissions',
            'Check for credential theft or insider threat',
        ],
        'firewall_rule'  : 'iptables -A INPUT -s {ip} -m state '
                           '--state NEW -m recent --update '
                           '--seconds 60 --hitcount 3 -j DROP',
        'isolate_device' : False,
    },

    'NORMAL': {
        'severity'       : 'NONE',
        'response_time'  : 'N/A',
        'mitre_id'       : 'N/A',
        'mitre_name'     : 'No Threat',
        'actions'        : ['No action required — traffic is normal'],
        'firewall_rule'  : 'No rule needed',
        'isolate_device' : False,
    },
}

# ── SEVERITY COLORS (for dashboard) ───────────────────
SEVERITY_COLORS = {
    'CRITICAL': '#ff1744',
    'HIGH'    : '#ff6d00',
    'MEDIUM'  : '#ffd600',
    'LOW'     : '#69f0ae',
    'NONE'    : '#00e676',
}

def get_defense_recommendation(attack_type, device, source_ip,
                                confidence):
    """
    Given an attack detection, return full defense recommendation.
    
    Args:
        attack_type : detected attack (e.g. 'DDoS')
        device      : affected device (e.g. 'PLC_03')
        source_ip   : attacker IP (e.g. '192.168.9.99')
        confidence  : model confidence % (e.g. 94.5)
    
    Returns:
        dict with full recommendation
    """
    playbook = DEFENSE_PLAYBOOK.get(attack_type, DEFENSE_PLAYBOOK['NORMAL'])

    # Generate firewall rule with actual IP
    firewall = playbook['firewall_rule'].replace('{ip}', source_ip)
    firewall = firewall.replace('{mac}', 'XX:XX:XX:XX:XX:XX')

    return {
        'attack_type'   : attack_type,
        'device'        : device,
        'source_ip'     : source_ip,
        'confidence'    : confidence,
        'severity'      : playbook['severity'],
        'mitre_id'      : playbook['mitre_id'],
        'mitre_name'    : playbook['mitre_name'],
        'response_time' : playbook['response_time'],
        'actions'       : playbook['actions'],
        'firewall_rule' : firewall,
        'isolate_device': playbook['isolate_device'],
        'color'         : SEVERITY_COLORS[playbook['severity']],
    }

def print_recommendation(rec):
    """Print a formatted defense recommendation."""
    if rec['attack_type'] == 'NORMAL':
        print(f"✅ NORMAL traffic from {rec['device']} — no action needed")
        return

    severity_icons = {
        'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '🔶', 'LOW': '🔷'
    }
    icon = severity_icons.get(rec['severity'], '⚠️')

    print(f"\n{'='*60}")
    print(f"{icon}  {rec['severity']} ALERT DETECTED")
    print(f"{'='*60}")
    print(f"  Attack Type  : {rec['attack_type']}")
    print(f"  Device       : {rec['device']}")
    print(f"  Source IP    : {rec['source_ip']}")
    print(f"  Confidence   : {rec['confidence']}%")
    print(f"  MITRE ATT&CK : {rec['mitre_id']} — {rec['mitre_name']}")
    print(f"  Response Time: {rec['response_time']}")
    if rec['isolate_device']:
        print(f"  ⚡ ISOLATE DEVICE: {rec['device']} immediately")
    print()
    print("  Recommended Actions:")
    for i, action in enumerate(rec['actions'], 1):
        print(f"    {i}. {action}")
    print()
    print("  Firewall Rule:")
    for line in rec['firewall_rule'].split('\n'):
        print(f"    $ {line}")
    print(f"{'='*60}\n")


# ── TEST THE ENGINE ───────────────────────────────────
if __name__ == '__main__':
    print("🛡️  DEFENSE RECOMMENDATION ENGINE — TEST\n")

    # Test each attack type
    test_cases = [
        ('COMMAND_INJECTION',   'PLC_03',    '172.16.0.88', 94.5),
        ('DDoS',                'SENSOR_01', '10.0.0.55',   87.2),
        ('SPOOFING',            'PLC_01',    '192.168.1.10', 91.0),
        ('UNAUTHORIZED_ACCESS', 'PLC_02',    '10.10.10.5',  78.3),
        ('NORMAL',              'SENSOR_02', '192.168.1.11', 99.1),
    ]

    for attack, device, ip, conf in test_cases:
        rec = get_defense_recommendation(attack, device, ip, conf)
        print_recommendation(rec)