import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

# ── SETTINGS ──────────────────────────────────────────
RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# ── DEVICES & IPs ─────────────────────────────────────
devices     = ['PLC_01', 'PLC_02', 'PLC_03', 'SENSOR_01', 'SENSOR_02']
trusted_ips = ['192.168.1.10', '192.168.1.11', '192.168.1.12']
unknown_ips = ['192.168.9.99', '10.0.0.55', '172.16.0.88', '10.10.10.5']

normal_commands = ['READ_SENSOR', 'WRITE_REGISTER', 'STATUS_CHECK', 'HEARTBEAT']
attack_commands = ['STOP_MOTOR', 'OVERRIDE_VALVE', 'FORCE_WRITE', 'DISABLE_ALARM']

start_time = datetime(2024, 1, 1, 10, 0, 0)

def make_timestamp(i, gap=5):
    return (start_time + timedelta(seconds=i * gap)).strftime('%H:%M:%S')

logs = []

# ── NORMAL TRAFFIC (600 entries) ──────────────────────
for i in range(600):
    logs.append({
        'timestamp'    : make_timestamp(i, gap=random.randint(3, 10)),
        'device'       : random.choice(devices),
        'command'      : random.choice(normal_commands),
        'source_ip'    : random.choice(trusted_ips),
        'packet_rate'  : random.randint(10, 50),
        'auth_attempts': random.randint(0, 1),
        'same_ip_count': random.randint(1, 5),
        'attack_type'  : 'NORMAL'
    })

# ── ATTACK TYPE 1: DDoS ───────────────────────────────
for i in range(100):
    logs.append({
        'timestamp'    : make_timestamp(i, gap=random.randint(1, 2)),
        'device'       : random.choice(devices),
        'command'      : 'STATUS_CHECK',
        'source_ip'    : random.choice(unknown_ips),
        'packet_rate'  : random.randint(150, 300),
        'auth_attempts': random.randint(0, 2),
        'same_ip_count': random.randint(20, 50),
        'attack_type'  : 'DDoS'
    })

# ── ATTACK TYPE 2: SPOOFING ───────────────────────────
for i in range(100):
    logs.append({
        'timestamp'    : make_timestamp(i, gap=random.randint(2, 5)),
        'device'       : random.choice(devices),
        'command'      : random.choice(attack_commands),
        'source_ip'    : '192.168.1.10',
        'packet_rate'  : random.randint(40, 80),
        'auth_attempts': random.randint(0, 1),
        'same_ip_count': random.randint(1, 3),
        'attack_type'  : 'SPOOFING'
    })

# ── ATTACK TYPE 3: COMMAND INJECTION ─────────────────
for i in range(100):
    logs.append({
        'timestamp'    : make_timestamp(i, gap=random.randint(1, 3)),
        'device'       : random.choice(['PLC_01', 'PLC_02', 'PLC_03']),
        'command'      : random.choice(attack_commands),
        'source_ip'    : random.choice(unknown_ips),
        'packet_rate'  : random.randint(60, 120),
        'auth_attempts': random.randint(1, 3),
        'same_ip_count': random.randint(5, 15),
        'attack_type'  : 'COMMAND_INJECTION'
    })

# ── ATTACK TYPE 4: UNAUTHORIZED ACCESS ───────────────
for i in range(100):
    logs.append({
        'timestamp'    : make_timestamp(i, gap=random.randint(1, 4)),
        'device'       : random.choice(devices),
        'command'      : 'WRITE_REGISTER',
        'source_ip'    : random.choice(unknown_ips),
        'packet_rate'  : random.randint(20, 60),
        'auth_attempts': random.randint(5, 15),
        'same_ip_count': random.randint(10, 30),
        'attack_type'  : 'UNAUTHORIZED_ACCESS'
    })

# ── COMBINE, SHUFFLE, SAVE ────────────────────────────
df = pd.DataFrame(logs)
df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
df.to_csv('data/ics_network_logs.csv', index=False)

print(f"✅ Dataset created: {len(df)} total entries")
print()
print("Attack type breakdown:")
print(df['attack_type'].value_counts())
print()
print("Preview:")
print(df.head())
