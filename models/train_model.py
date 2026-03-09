import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import pickle
import os

# ── STEP 1: LOAD YOUR DATASET ─────────────────────────
print("📂 Loading dataset...")
df = pd.read_csv('data/ics_network_logs.csv')
print(f"   Loaded {len(df)} rows\n")

# ── STEP 2: ENCODE TEXT COLUMNS INTO NUMBERS ──────────
# ML models only understand numbers, not text like "PLC_01" or "READ_SENSOR"
# LabelEncoder converts: PLC_01 → 0, PLC_02 → 1, PLC_03 → 2 etc.

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

# ── STEP 3: SELECT FEATURES ───────────────────────────
# These are the columns the model will learn from
# We do NOT include 'status' here — that's what we're trying to predict

features = ['device_encoded', 'command_encoded', 'ip_encoded',
            'packet_rate', 'auth_attempts']

X = df[features]

# ── STEP 4: TRAIN ISOLATION FOREST ────────────────────
# contamination = how much of the data we expect to be anomalies
# We generated 20% attacks, so we set contamination=0.2

print("🤖 Training Isolation Forest model...")
model = IsolationForest(
    n_estimators=100,      # number of trees in the forest
    contamination=0.2,     # expected % of anomalies
    random_state=42        # reproducible results
)
model.fit(X)
print("   Model trained!\n")

# ── STEP 5: MAKE PREDICTIONS ──────────────────────────
# Isolation Forest outputs: 1 = normal, -1 = anomaly
# We convert to: 0 = normal, 1 = attack (easier to read)

df['prediction'] = model.predict(X)
df['prediction'] = df['prediction'].map({1: 'NORMAL', -1: 'ATTACK'})

# ── STEP 6: EVALUATE THE MODEL ────────────────────────
print("📊 Model Evaluation:")
print("-" * 50)

# Convert status to match prediction format
actual    = df['status']
predicted = df['prediction']

print(classification_report(actual, predicted))

# Confusion matrix
cm = confusion_matrix(actual, predicted, labels=['NORMAL', 'ATTACK'])
print("Confusion Matrix:")
print(f"                 Predicted NORMAL  Predicted ATTACK")
print(f"Actual NORMAL  :      {cm[0][0]}               {cm[0][1]}")
print(f"Actual ATTACK  :      {cm[1][0]}               {cm[1][1]}")
print()

# ── STEP 7: RISK SCORE ────────────────────────────────
# Isolation Forest also gives a raw anomaly score
# We convert it to a 0-100 risk score (more intuitive for dashboard)

scores = model.decision_function(X)  # more negative = more anomalous
df['risk_score'] = ((scores.min() - scores) /
                    (scores.min() - scores.max()) * 100).round(1)

print("🔥 Top 5 Highest Risk Events:")
top_risks = df.nlargest(5, 'risk_score')[
    ['timestamp', 'device', 'command', 'source_ip', 'risk_score', 'status']
]
print(top_risks.to_string(index=False))
print()

# ── STEP 8: SAVE THE MODEL ────────────────────────────
os.makedirs('models', exist_ok=True)
with open('models/threat_model.pkl', 'wb') as f:
    pickle.dump(model, f)

# Save predictions for dashboard
df.to_csv('data/predictions.csv', index=False)

print("\n✅ Model saved to models/threat_model.pkl")
print("✅ Predictions saved to data/predictions.csv")