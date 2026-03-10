import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os

# ── STEP 1: LOAD DATA ─────────────────────────────────
print("📂 Loading dataset...")
df = pd.read_csv('data/ics_network_logs.csv')
print(f"   Loaded {len(df)} rows\n")

# ── STEP 2: ENCODE TEXT TO NUMBERS ────────────────────
print("🔄 Encoding text columns...")
le_device  = LabelEncoder()
le_command = LabelEncoder()
le_ip      = LabelEncoder()

df['device_encoded']  = le_device.fit_transform(df['device'])
df['command_encoded'] = le_command.fit_transform(df['command'])
df['ip_encoded']      = le_ip.fit_transform(df['source_ip'])

print(f"   Devices  : {list(le_device.classes_)}")
print(f"   Commands : {list(le_command.classes_)}")
print()

# ── STEP 3: FEATURES & TARGET ─────────────────────────
# X = what the model learns FROM
# y = what the model is trying to PREDICT
features = ['device_encoded', 'command_encoded', 'ip_encoded',
            'packet_rate', 'auth_attempts', 'same_ip_count']

X = df[features]
y = df['attack_type']  # NORMAL, DDoS, SPOOFING, etc.

# ── STEP 4: SPLIT DATA ────────────────────────────────
# 80% for training, 20% for testing
# We test on data the model has NEVER seen — honest evaluation
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"📊 Training samples : {len(X_train)}")
print(f"   Testing samples  : {len(X_test)}\n")

# ── STEP 5: TRAIN RANDOM FOREST ───────────────────────
print("🤖 Training Random Forest classifier...")
model = RandomForestClassifier(
    n_estimators=100,   # 100 decision trees
    max_depth=10,       # how deep each tree can go
    random_state=42
)
model.fit(X_train, y_train)
print("   Model trained!\n")

# ── STEP 6: EVALUATE ──────────────────────────────────
print("📊 Model Evaluation on unseen test data:")
print("-" * 50)
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# ── STEP 7: CONFIDENCE SCORES ─────────────────────────
# predict_proba gives probability for each attack type
# We take the highest probability as our confidence score
y_prob = model.predict_proba(X_test)
confidence = np.max(y_prob, axis=1)

print(f"Average confidence : {confidence.mean()*100:.1f}%")
print(f"Min confidence     : {confidence.min()*100:.1f}%")
print(f"Max confidence     : {confidence.max()*100:.1f}%\n")

# ── STEP 8: FEATURE IMPORTANCE ────────────────────────
# Which features matter most for detection?
print("🔍 Feature Importance (Explainability):")
print("-" * 50)
importance = model.feature_importances_
for feat, imp in sorted(zip(features, importance),
                         key=lambda x: x[1], reverse=True):
    bar = "█" * int(imp * 50)
    print(f"  {feat:<25} {bar} {imp*100:.1f}%")
print()

# ── STEP 9: MITRE ATT&CK MAPPING ─────────────────────
# Map your attack types to real industry standard codes
# This is what makes your project look production-ready
MITRE_MAP = {
    'DDoS'               : ('T0814', 'Denial of Service',          'HIGH'),
    'SPOOFING'           : ('T0831', 'Manipulation of Control',    'CRITICAL'),
    'COMMAND_INJECTION'  : ('T0836', 'Modify Parameter',           'CRITICAL'),
    'UNAUTHORIZED_ACCESS': ('T0801', 'Monitor Process State',      'MEDIUM'),
    'NORMAL'             : ('N/A',   'No Threat',                  'NONE'),
}

print("🎯 MITRE ATT&CK for ICS Mapping:")
print("-" * 50)
for attack, (tid, name, severity) in MITRE_MAP.items():
    if attack != 'NORMAL':
        print(f"  {attack:<25} → {tid} | {name:<30} | Severity: {severity}")
print()

# ── STEP 10: GENERATE PREDICTIONS ON FULL DATASET ─────
print("💾 Generating predictions on full dataset...")
X_full = df[features]
df['predicted_attack'] = model.predict(X_full)
df['confidence']       = (np.max(model.predict_proba(X_full),
                           axis=1) * 100).round(1)

# Add MITRE info
df['mitre_id']   = df['predicted_attack'].map(
    lambda x: MITRE_MAP[x][0])
df['severity']   = df['predicted_attack'].map(
    lambda x: MITRE_MAP[x][2])

# ── STEP 11: SAVE EVERYTHING ──────────────────────────
os.makedirs('models', exist_ok=True)

# Save model
with open('models/threat_model.pkl', 'wb') as f:
    pickle.dump(model, f)

# Save label encoders
with open('models/encoders.pkl', 'wb') as f:
    pickle.dump({
        'device' : le_device,
        'command': le_command,
        'ip'     : le_ip
    }, f)

# Save predictions
df.to_csv('data/predictions.csv', index=False)

print("✅ Model saved     → models/threat_model.pkl")
print("✅ Encoders saved  → models/encoders.pkl")
print("✅ Predictions     → data/predictions.csv")
print()

# ── STEP 12: SAMPLE PREDICTIONS ───────────────────────
print("🔥 Sample High Risk Predictions:")
print("-" * 50)
attacks = df[df['predicted_attack'] != 'NORMAL'].nlargest(5, 'confidence')
for _, row in attacks.iterrows():
    print(f"  {row['timestamp']} | {row['device']:<12} | "
          f"{row['predicted_attack']:<25} | "
          f"{row['confidence']}% confident | "
          f"MITRE: {row['mitre_id']} | "
          f"Severity: {row['severity']}")