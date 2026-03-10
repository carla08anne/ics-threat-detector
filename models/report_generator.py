from datetime import datetime
import json
import os

MITRE_DETAILS = {
    'T0836': {
        'name'    : 'Modify Parameter',
        'tactic'  : 'Impair Process Control',
        'impact'  : 'Attacker modified PLC parameters to cause physical damage',
    },
    'T0831': {
        'name'    : 'Manipulation of Control',
        'tactic'  : 'Impair Process Control',
        'impact'  : 'Attacker manipulated control systems to alter physical processes',
    },
    'T0814': {
        'name'    : 'Denial of Service',
        'tactic'  : 'Inhibit Response Function',
        'impact'  : 'Attacker disrupted availability of ICS components',
    },
    'T0801': {
        'name'    : 'Monitor Process State',
        'tactic'  : 'Collection',
        'impact'  : 'Attacker monitored process state to identify targets',
    },
}

SEVERITY_COLORS = {
    'CRITICAL': '🔴',
    'HIGH'    : '🟠',
    'MEDIUM'  : '🟡',
    'LOW'     : '🟢',
    'NONE'    : '⚪',
}

def generate_report(events, campaign=None):
    """Generate a full incident report from attack events."""

    now        = datetime.now()
    report_id  = f"INC-{now.strftime('%Y%m%d-%H%M%S')}"
    
    # Summarise events
    attack_types  = list(set(e['predicted_attack'] for e in events
                            if e['predicted_attack'] != 'NORMAL'))
    devices       = list(set(e['device'] for e in events))
    source_ips    = list(set(e['source_ip'] for e in events))
    mitre_ids     = list(set(e.get('mitre_id','N/A') for e in events
                            if e.get('mitre_id') != 'N/A'))
    severities    = [e.get('severity','NONE') for e in events]
    
    # Determine overall severity
    if 'CRITICAL' in severities:
        overall_severity = 'CRITICAL'
    elif 'HIGH' in severities:
        overall_severity = 'HIGH'
    elif 'MEDIUM' in severities:
        overall_severity = 'MEDIUM'
    else:
        overall_severity = 'LOW'

    # Confidence stats
    confidences  = [float(e.get('confidence', 0)) for e in events]
    avg_conf     = round(sum(confidences)/len(confidences), 1) if confidences else 0

    # Generate recommended actions
    actions = _get_actions(attack_types, devices, source_ips)

    report = {
        'report_id'         : report_id,
        'generated_at'      : now.strftime('%Y-%m-%d %H:%M:%S'),
        'overall_severity'  : overall_severity,
        'severity_icon'     : SEVERITY_COLORS.get(overall_severity, '⚪'),
        'total_events'      : len(events),
        'attack_types'      : attack_types,
        'affected_devices'  : devices,
        'source_ips'        : source_ips,
        'mitre_ids'         : mitre_ids,
        'avg_confidence'    : avg_conf,
        'campaign'          : campaign,
        'timeline'          : _build_timeline(events),
        'mitre_details'     : [MITRE_DETAILS.get(m, {}) for m in mitre_ids],
        'recommended_actions': actions,
        'executive_summary' : _executive_summary(
            overall_severity, attack_types, devices,
            source_ips, len(events), avg_conf
        ),
    }

    return report


def _build_timeline(events):
    """Build chronological event timeline."""
    timeline = []
    for e in sorted(events, key=lambda x: x.get('timestamp','')):
        if e['predicted_attack'] != 'NORMAL':
            timeline.append({
                'time'      : e.get('timestamp', 'Unknown'),
                'attack'    : e['predicted_attack'],
                'device'    : e.get('device', 'Unknown'),
                'source_ip' : e.get('source_ip', 'Unknown'),
                'confidence': e.get('confidence', 0),
                'severity'  : e.get('severity', 'NONE'),
            })
    return timeline[:10]  # top 10 events


def _get_actions(attack_types, devices, source_ips):
    """Generate specific recommended actions."""
    actions = []

    # Immediate actions
    actions.append({
        'priority': 'IMMEDIATE',
        'action'  : f"Block source IPs at perimeter firewall: {', '.join(source_ips[:3])}",
    })

    if 'COMMAND_INJECTION' in attack_types:
        actions.append({
            'priority': 'IMMEDIATE',
            'action'  : f"Isolate affected PLCs from network: {', '.join(devices[:3])}",
        })
        actions.append({
            'priority': 'IMMEDIATE',
            'action'  : 'Switch affected PLCs to manual/local control mode',
        })

    if 'SPOOFING' in attack_types:
        actions.append({
            'priority': 'IMMEDIATE',
            'action'  : 'Verify IP-MAC bindings on all trusted devices',
        })
        actions.append({
            'priority': 'IMMEDIATE',
            'action'  : 'Enable dynamic ARP inspection on all switches',
        })

    if 'DDoS' in attack_types:
        actions.append({
            'priority': 'IMMEDIATE',
            'action'  : 'Enable rate limiting — max 50 packets/second per device',
        })

    if 'UNAUTHORIZED_ACCESS' in attack_types:
        actions.append({
            'priority': 'IMMEDIATE',
            'action'  : 'Force password reset on all SCADA operator accounts',
        })

    # Short term
    actions.append({
        'priority': 'SHORT_TERM',
        'action'  : 'Conduct full forensic analysis of affected devices',
    })
    actions.append({
        'priority': 'SHORT_TERM',
        'action'  : 'Review and update network segmentation policies',
    })
    actions.append({
        'priority': 'SHORT_TERM',
        'action'  : 'File regulatory incident report within 72 hours',
    })

    # Long term
    actions.append({
        'priority': 'LONG_TERM',
        'action'  : 'Deploy network segmentation between OT and IT networks',
    })
    actions.append({
        'priority': 'LONG_TERM',
        'action'  : 'Implement multi-factor authentication on all ICS access points',
    })

    return actions


def _executive_summary(severity, attack_types, devices,
                        source_ips, event_count, confidence):
    """Generate executive summary paragraph."""
    attack_str = ', '.join(attack_types) if attack_types else 'unknown'
    device_str = ', '.join(devices[:3]) if devices else 'unknown'
    ip_str     = ', '.join(source_ips[:2]) if source_ips else 'unknown'

    return (
        f"SentinelOT detected a {severity} severity security incident involving "
        f"{event_count} suspicious events across {len(devices)} industrial devices. "
        f"Attack types identified: {attack_str}. "
        f"Primary affected devices: {device_str}. "
        f"Attacks originated from {len(source_ips)} unique source IP(s) including {ip_str}. "
        f"Average model confidence: {confidence}%. "
        f"Immediate containment actions have been recommended. "
        f"Full forensic investigation is advised."
    )


def format_report_text(report):
    """Format report as readable text."""
    lines = []
    lines.append("=" * 65)
    lines.append("SENTINELOT INCIDENT REPORT")
    lines.append("Cipher Blitz — Industrial Cybersecurity Platform")
    lines.append("=" * 65)
    lines.append(f"Report ID    : {report['report_id']}")
    lines.append(f"Generated    : {report['generated_at']}")
    lines.append(f"Severity     : {report['severity_icon']} {report['overall_severity']}")
    lines.append(f"Total Events : {report['total_events']}")
    lines.append(f"Confidence   : {report['avg_confidence']}%")
    lines.append("")
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 65)
    lines.append(report['executive_summary'])
    lines.append("")
    lines.append("ATTACK DETAILS")
    lines.append("-" * 65)
    lines.append(f"Attack Types     : {', '.join(report['attack_types'])}")
    lines.append(f"Affected Devices : {', '.join(report['affected_devices'])}")
    lines.append(f"Source IPs       : {', '.join(report['source_ips'])}")
    lines.append(f"MITRE IDs        : {', '.join(report['mitre_ids'])}")
    lines.append("")
    lines.append("EVENT TIMELINE")
    lines.append("-" * 65)
    for e in report['timeline']:
        lines.append(
            f"  {e['time']}  {e['attack']:<25} {e['device']:<12} "
            f"{e['source_ip']:<16} {e['confidence']}%"
        )
    lines.append("")
    lines.append("RECOMMENDED ACTIONS")
    lines.append("-" * 65)
    for i, a in enumerate(report['recommended_actions'], 1):
        lines.append(f"  [{a['priority']}] {i}. {a['action']}")
    lines.append("")
    lines.append("=" * 65)
    lines.append("END OF REPORT — SentinelOT by Cipher Blitz")
    lines.append("=" * 65)
    return '\n'.join(lines)


# ── TEST ──────────────────────────────────────────────
if __name__ == '__main__':
    import pandas as pd

    df     = pd.read_csv('data/predictions.csv')
    events = df[df['predicted_attack'] != 'NORMAL'].head(20).to_dict('records')

    report = generate_report(events)
    print(format_report_text(report))

    # Save as JSON too
    with open('data/latest_incident.json', 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n✅ Report saved: data/latest_incident.json")