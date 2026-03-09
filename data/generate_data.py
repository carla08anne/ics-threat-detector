import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

# ── SETTINGS ──────────────────────────────────────────
NUM_NORMAL  = 800   # normal log entries to generate
NUM_ATTACKS = 200   # attack log entries to generate
RANDOM_SEED = 42    # makes results reproducible

random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# ── KNOWN DEVICES & TRUSTED IPs ───────────────────────
devices      = ['PLC_01', 'PLC_02', 'PLC_03', 'SENSOR_01', 'SENSOR_02']
trusted_ips  = ['192.168.1.10', '192.168.1.11', '192.168.1.12']  # SCADA + controllers
unknown_ips  = ['192.168.9.99', '10.0.0.55', '172.16.0.88']      # attacker IPs

# ── COMMANDS ──────────────────────────────────────────
normal_commands = ['READ_SENSOR', 'WRITE_REGISTER', 'STATUS_CHECK', 'HEARTBEAT']
attack_commands = ['STOP_MOTOR', 'OVERRIDE_VALVE', 'FORCE_WRITE', 'DISABLE_ALARM']

# ── HELPER: generate a timestamp ──────────────────────
start_time = datetime(2024, 1, 1, 10, 0, 0)

def next_timestamp(i, is_attack=False):
    # attacks cluster together (closer timestamps)
    gap = random.randint(1, 3) if is_attack else random.randint(3, 10)
    return start_time + timedelta(seconds=i * gap)

# ── GENERATE NORMAL TRAFFIC ───────────────────────────
normal_logs = []
for i in range(NUM_NORMAL):
    normal_logs.append({
        'timestamp'  : next_timestamp(i).strftime('%H:%M:%S'),
        'device'     : random.choice(devices),
        'command'    : random.choice(normal_commands),
        'source_ip'  : random.choice(trusted_ips),
        'packet_rate': random.randint(10, 50),   # normal = low and steady
        'auth_attempts': random.randint(0, 1),   # rarely fails auth
        'status'     : 'NORMAL'
    })

# ── GENERATE ATTACK TRAFFIC ───────────────────────────
attack_logs = []
for i in range(NUM_ATTACKS):
    attack_logs.append({
        'timestamp'  : next_timestamp(i, is_attack=True).strftime('%H:%M:%S'),
        'device'     : random.choice(devices),
        'command'    : random.choice(attack_commands),
        'source_ip'  : random.choice(unknown_ips),
        'packet_rate': random.randint(80, 200),  # attacks = high traffic spike
        'auth_attempts': random.randint(3, 10),  # attackers keep trying to auth
        'status'     : 'ATTACK'
    })

# ── COMBINE, SHUFFLE, SAVE ────────────────────────────
df = pd.DataFrame(normal_logs + attack_logs)
df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)  # shuffle

output_path = 'data/ics_network_logs.csv'
df.to_csv(output_path, index=False)

print(f"✅ Dataset created: {len(df)} total entries")
print(f"   Normal entries : {len(normal_logs)}")
print(f"   Attack entries : {len(attack_logs)}")
print(f"   Saved to       : {output_path}")
print()
print("Preview of first 5 rows:")
print(df.head())