import json
import joblib
import pandas as pd
from pathlib import Path

DATASET = Path("datasets/security_events/live_training_windows_v4.csv")
MODEL_DIR = Path("ai/models/v4")

MODEL_PATH = MODEL_DIR / "live_isolation_forest_v4.joblib"
SCALER_PATH = MODEL_DIR / "live_robust_scaler_v4.joblib"
SCHEMA_PATH = MODEL_DIR / "feature_schema_v4.json"

print("=" * 65)
print("NEXUS INTELLIGENCE — V4 ENSEMBLE RISK ENGINE")
print("=" * 65)

# ------------------------------------------------------------
# LOAD MODEL
# ------------------------------------------------------------

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

with open(SCHEMA_PATH) as f:
    schema = json.load(f)

FEATURES = schema["features"]

df = pd.read_csv(DATASET)

latest = df.iloc[-1:].copy()

X = latest[FEATURES]

X_scaled = scaler.transform(X)

ml_prediction = int(model.predict(X_scaled)[0])
ml_score = float(model.decision_function(X_scaled)[0])

# ------------------------------------------------------------
# ML ANOMALY COMPONENT
# ------------------------------------------------------------

if ml_prediction == -1:
    ml_component = 70.0
else:
    ml_component = max(
        0.0,
        min(40.0, (0.10 - ml_score) / 0.20 * 40)
    )

# ------------------------------------------------------------
# BEHAVIORAL COMPONENT
# ------------------------------------------------------------

process = float(latest["process_execution_frequency"].iloc[0])
network = float(latest["network_connection_frequency"].iloc[0])
unique_processes = float(latest["unique_processes"].iloc[0])
unique_destinations = float(latest["unique_destinations"].iloc[0])
process_burst = float(latest["process_burst"].iloc[0])
network_burst = float(latest["network_burst"].iloc[0])

behavior_component = 0.0

if process >= 8:
    behavior_component += 12

if network >= 8:
    behavior_component += 12

if unique_processes >= 8:
    behavior_component += 8

if unique_destinations >= 5:
    behavior_component += 8

if process_burst >= 2:
    behavior_component += 5

if network_burst >= 2:
    behavior_component += 5

behavior_component = min(40.0, behavior_component)

# ------------------------------------------------------------
# NOVELTY COMPONENT
# ------------------------------------------------------------

new_process_ratio = float(
    latest["new_processes_ratio"].iloc[0]
)

new_destination_ratio = float(
    latest["new_destination_ratio"].iloc[0]
)

novelty_component = 0.0

if new_process_ratio >= 0.75 and process >= 3:
    novelty_component += 10

if new_destination_ratio >= 0.75 and network >= 3:
    novelty_component += 10

novelty_component = min(20.0, novelty_component)

# ------------------------------------------------------------
# FINAL ENSEMBLE SCORE
# ------------------------------------------------------------

risk_score = (
    ml_component * 0.50
    + behavior_component * 0.35
    + novelty_component * 0.15
)

risk_score = max(0.0, min(100.0, risk_score))

# ------------------------------------------------------------
# SEVERITY
# ------------------------------------------------------------

if risk_score >= 75:
    severity = "CRITICAL"
elif risk_score >= 50:
    severity = "HIGH"
elif risk_score >= 25:
    severity = "MEDIUM"
else:
    severity = "LOW"

# ------------------------------------------------------------
# EXPLANATION
# ------------------------------------------------------------

reasons = []

if ml_prediction == -1:
    reasons.append("ML model detected behavioral anomaly")

if process >= 8:
    reasons.append("high process execution activity")

if network >= 8:
    reasons.append("high network connection activity")

if unique_processes >= 8:
    reasons.append("high process diversity")

if unique_destinations >= 5:
    reasons.append("high destination diversity")

if process_burst >= 2:
    reasons.append("process burst detected")

if network_burst >= 2:
    reasons.append("network burst detected")

if new_process_ratio >= 0.75 and process >= 3:
    reasons.append("high proportion of new processes")

if new_destination_ratio >= 0.75 and network >= 3:
    reasons.append("new network destination observed")

if not reasons:
    reasons.append("behavior consistent with learned baseline")

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

print("\nLATEST WINDOW")
print("-" * 65)
print("Window:", latest["window_start"].iloc[0])

print("\nMODEL SIGNAL")
print("-" * 65)
print("Isolation Forest prediction :", "ANOMALY" if ml_prediction == -1 else "NORMAL")
print("Isolation Forest score      :", f"{ml_score:.4f}")
print("ML component                :", f"{ml_component:.2f}")

print("\nBEHAVIOR SIGNAL")
print("-" * 65)
print("Process activity            :", process)
print("Network activity            :", network)
print("Unique processes            :", unique_processes)
print("Unique destinations         :", unique_destinations)
print("Process burst               :", process_burst)
print("Network burst               :", network_burst)
print("Behavior component          :", f"{behavior_component:.2f}")

print("\nNOVELTY SIGNAL")
print("-" * 65)
print("New process ratio           :", new_process_ratio)
print("New destination ratio       :", new_destination_ratio)
print("Novelty component           :", f"{novelty_component:.2f}")

print("\nFINAL NEXUS RISK")
print("-" * 65)
print("Risk score                  :", f"{risk_score:.2f}/100")
print("Severity                    :", severity)

print("\nEXPLANATION")
print("-" * 65)

for reason in reasons:
    print("•", reason)

print("\n" + "=" * 65)
print("V4 ENSEMBLE ANALYSIS COMPLETE")
print("=" * 65)
