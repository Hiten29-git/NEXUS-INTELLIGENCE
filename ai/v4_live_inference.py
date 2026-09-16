import json
import joblib
import pandas as pd
from pathlib import Path

MODEL_DIR = Path("ai/models/v4")
DATASET = Path("datasets/security_events/live_training_windows_v4.csv")

MODEL_PATH = MODEL_DIR / "live_isolation_forest_v4.joblib"
SCALER_PATH = MODEL_DIR / "live_robust_scaler_v4.joblib"
SCHEMA_PATH = MODEL_DIR / "feature_schema_v4.json"

print("=" * 60)
print("NEXUS INTELLIGENCE — V4 LIVE INFERENCE")
print("=" * 60)

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

with open(SCHEMA_PATH, "r") as f:
    schema = json.load(f)

FEATURES = schema["features"]

df = pd.read_csv(DATASET)

latest = df.iloc[-1:].copy()

X = latest[FEATURES]

X_scaled = scaler.transform(X)

prediction = int(model.predict(X_scaled)[0])
score = float(model.decision_function(X_scaled)[0])

status = "ANOMALY DETECTED" if prediction == -1 else "NORMAL"

# Convert Isolation Forest score into a simple 0–100 anomaly risk.
# This is a prototype risk indicator, not a probability.
risk = max(0.0, min(100.0, (0.15 - score) / 0.30 * 100))

if risk >= 75:
    severity = "CRITICAL"
elif risk >= 50:
    severity = "HIGH"
elif risk >= 25:
    severity = "MEDIUM"
else:
    severity = "LOW"

print("\nLATEST WINDOW")
print("-" * 60)
print("Window:", latest["window_start"].iloc[0])

print("\nFEATURES")
print("-" * 60)

for feature in FEATURES:
    print(f"{feature:35}: {float(latest[feature].iloc[0]):.4f}")

print("\nAI RESULT")
print("-" * 60)
print("Status          :", status)
print("Isolation Score :", f"{score:.4f}")
print("Anomaly Risk    :", f"{risk:.2f}/100")
print("Severity        :", severity)

print("\n" + "=" * 60)
print("V4 LIVE INFERENCE COMPLETE")
print("=" * 60)
