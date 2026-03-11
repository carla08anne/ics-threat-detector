import csv, random, json
from datetime import datetime, timedelta

PHYSICS_RULES = {
    "PLC-01": {"description":"Water pump","max_rate_per_second":10,"min_value":0,"max_value":100,"parameter":"pump_speed_%"},
    "PLC-02": {"description":"Pressure reg","max_rate_per_second":5,"min_value":0,"max_value":200,"parameter":"pressure_psi"},
    "PLC-03": {"description":"Temp controller","max_rate_per_second":2,"min_value":-10,"max_value":150,"parameter":"temp_celsius"},
    "RTU-01": {"description":"Flow rate","max_rate_per_second":15,"min_value":0,"max_value":500,"parameter":"flow_rate_lpm"},
    "RTU-02": {"description":"Valve ctrl","max_rate_per_second":8,"min_value":0,"max_value":100,"parameter":"valve_open_%"},
    "HMI-01": {"description":"HMI 1","max_rate_per_second":20,"min_value":0,"max_value":1000,"parameter":"setpoint"},
    "HMI-02": {"description":"HMI 2","max_rate_per_second":20,"min_value":0,"max_value":1000,"parameter":"setpoint"}
}

def check_physics(device, prev_value, new_value, time_delta):
    if device not in PHYSICS_RULES:
        return {"valid": True}
    rules = PHYSICS_RULES[device]
    if new_value < rules["min_value"] or new_value > rules["max_value"]:
        return {"valid":False,"violation_type":"OUT_OF_BOUNDS","severity":"CRITICAL","reason":f"Value {new_value} outside range","actual_rate":0,"max_allowed_rate":rules["max_rate_per_second"]}
    if time_delta > 0:
        rate = abs(new_value - prev_value) / time_delta
        if rate > rules["max_rate_per_second"]:
            return {"valid":False,"violation_type":"IMPOSSIBLE_RATE","severity":"HIGH","reason":f"Rate {rate:.1f} exceeds max {rules['max_rate_per_second']}","actual_rate":round(rate,2),"max_allowed_rate":rules["max_rate_per_second"]}
    return {"valid":True,"violation_type":"NONE","severity":"NONE","reason":"OK","actual_rate":0,"max_allowed_rate":rules.get("max_rate_per_second",0)}

records = []
base_time = datetime(2024,1,15,8,0,0)
states = {d:random.randint(20,60) for d in PHYSICS_RULES}
attack_ips = ["10.0.0.55","172.16.0.88","10.10.10.5","192.168.9.99"]
normal_ips = ["192.168.1.10","192.168.1.11","192.168.1.12"]

for i in range(200):
    ts = base_time + timedelta(seconds=i*3)
    device = random.choice(list(PHYSICS_RULES.keys()))
    cur = states[device]
    is_attack = random.random() < 0.25
    if is_attack:
        new_val = random.choice([random.randint(85,100), random.randint(0,5)])
        new_val = max(0, min(100, new_val))
        delta = random.uniform(0.1, 0.5)
        ip = random.choice(attack_ips)
    else:
        new_val = max(0, min(100, cur + random.uniform(-5,5)))
        delta = random.uniform(2,5)
        ip = random.choice(normal_ips)
    result = check_physics(device, cur, new_val, delta)
    states[device] = new_val
    records.append({
        "timestamp":ts.strftime("%Y-%m-%d %H:%M:%S"),
        "device":device,
        "parameter":PHYSICS_RULES[device]["parameter"],
        "prev_value":round(cur,1),
        "new_value":round(new_val,1),
        "time_delta_sec":round(delta,2),
        "rate_of_change":round(abs(new_val-cur)/delta,2),
        "source_ip":ip,
        "physics_valid":result["valid"],
        "violation_type":result.get("violation_type","NONE"),
        "violation_reason":result.get("reason",""),
        "severity":result.get("severity","NONE"),
        "actual_rate":result.get("actual_rate",0),
        "max_allowed_rate":result.get("max_allowed_rate",0)
    })

with open("data/physics_violations.csv","w",newline="") as f:
    w = csv.DictWriter(f, fieldnames=records[0].keys())
    w.writeheader()
    w.writerows(records)

with open("data/physics_rules.json","w") as f:
    json.dump(PHYSICS_RULES, f, indent=2)

violations = [r for r in records if not r["physics_valid"]]
print(f"✅ Total: {len(records)} | 🚨 Violations: {len(violations)}")
print("💾 Saved to data/physics_violations.csv")