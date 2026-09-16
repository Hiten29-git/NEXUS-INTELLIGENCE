import json
from pathlib import Path

import joblib
import pandas as pd

LIVE_DATASET = "datasets/security_events/live_training_windows_v4.csv"

MODEL_DIR = Path("ai/models/v4")
MODEL_PATH = MODEL_DIR / "live_isolation_forest_v4.joblib"
SCALER_PATH = MODEL_DIR / "live_robust_scaler_v4.joblib"
SCHEMA_PATH = MODEL_DIR / "feature_schema_v4.json"

THRESHOLD = 34

print("=" * 70)
print("NEXUS INTELLIGENCE – V5.1 LIVE INFERENCE")
print("=" * 70)

df = pd.read_csv(LIVE_DATASET)

if df.empty:
    raise ValueError("Live dataset is empty.")

with open(SCHEMA_PATH) as f:
    schema = json.load(f)

FEATURES = schema["features"]

latest = df.iloc[-1]

X = pd.DataFrame(
    [[float(latest[f]) for f in FEATURES]],
    columns=FEATURES
)

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

X_scaled = scaler.transform(X)

prediction = int(model.predict(X_scaled)[0])
model_score = float(model.decision_function(X_scaled)[0])

# Convert model signal to a bounded 0–100 component.
# This is an engineering signal, not a probability.
model_component = max(
    0.0,
    min(100.0, (0.20 - model_score) * 100)
)

# Behavioral signals
process = float(latest["process_execution_frequency"])
network = float(latest["network_connection_frequency"])
unique_processes = float(latest["unique_processes"])
unique_destinations = float(latest["unique_destinations"])
process_burst = float(latest["process_burst"])
network_burst = float(latest["network_burst"])
new_process_ratio = float(latest["new_processes_ratio"])
new_destination_ratio = float(latest["new_destination_ratio"])

behavior_component = min(
    100.0,
    (
        process * 2.0
        + network * 2.0
        + unique_processes * 2.0
        + unique_destinations * 4.0
        + process_burst * 5.0
        + network_burst * 5.0
    )
)

novelty_component = min(
    100.0,
    (
        new_process_ratio * 50.0
        + new_destination_ratio * 50.0
    )
)

# Combine independent signals.
risk_score = (
    model_component * 0.40
    + behavior_component * 0.35
    + novelty_component * 0.25
)

risk_score = max(0.0, min(100.0, risk_score))

if risk_score >= 65:
    severity = "CRITICAL"
elif risk_score >= 50:
    severity = "HIGH"
elif risk_score >= THRESHOLD:
    severity = "MEDIUM"
else:
    severity = "LOW"

if severity == "CRITICAL":
    response = "ESCALATE_AND_CONTAIN"
elif severity == "HIGH":
    response = "ESCALATE"
elif severity == "MEDIUM":
    response = "MONITOR"
else:
    response = "ALLOW"

print("\nLATEST LIVE WINDOW")
print("-" * 70)
print("Window:", latest["window_start"])

print("\nFEATURES")
print("-" * 70)

for feature in FEATURES:
    print(f"{feature:30s}: {float(latest[feature]):.4f}")

print("\nMODEL SIGNAL")
print("-" * 70)
print("Isolation Forest prediction :", prediction)
print("Isolation Forest score      :", f"{model_score:.4f}")
print("Model component             :", f"{model_component:.2f}")

print("\nBEHAVIOR SIGNAL")
print("-" * 70)
print("Behavior component :", f"{behavior_component:.2f}")
print("Novelty component  :", f"{novelty_component:.2f}")

print("\nFINAL V5.1 DECISION")
print("-" * 70)
print("Risk score :", f"{risk_score:.2f}/100")
print("Threshold  :", THRESHOLD)
print("Severity   :", severity)
print("Response   :", response)

print("\n" + "=" * 70)
print("V5.1 LIVE INFERENCE COMPLETE")
print("=" * 70)
