import json
from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# NEXUS INTELLIGENCE - V5.2 REAL-TIME INFERENCE
# ============================================================

LIVE_DATASET = "datasets/security_events/live_training_windows_v4.csv"

MODEL_DIR = Path("ai/models/v5_2")

MODEL_PATH = MODEL_DIR / "live_isolation_forest_v5_2.joblib"
SCALER_PATH = MODEL_DIR / "live_robust_scaler_v5_2.joblib"
SCHEMA_PATH = MODEL_DIR / "feature_schema_v5_2.json"


# ============================================================
# LOAD MODEL
# ============================================================

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

with open(SCHEMA_PATH) as f:
    schema = json.load(f)

FEATURES = schema["features"]


# ============================================================
# LOAD LATEST LIVE WINDOW
# ============================================================

df = pd.read_csv(LIVE_DATASET)

if df.empty:
    raise ValueError("Live dataset is empty.")

latest = df.iloc[-1]


# ============================================================
# PREPARE FEATURES
# ============================================================

X = pd.DataFrame(
    [[latest[feature] for feature in FEATURES]],
    columns=FEATURES
)

X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

X_scaled = scaler.transform(X)


# ============================================================
# MODEL INFERENCE
# ============================================================

prediction = int(model.predict(X_scaled)[0])

model_score = float(
    model.decision_function(X_scaled)[0]
)


# ============================================================
# NORMALIZED ANOMALY SCORE
# ============================================================

# More negative Isolation Forest score = more anomalous.
#
# This converts the model signal into a 0-100 component.
# It is a risk signal, NOT probability or accuracy.

anomaly_component = max(
    0.0,
    min(
        100.0,
        (0.10 - model_score) * 250
    )
)


# ============================================================
# BEHAVIOR SIGNALS
# ============================================================

process_count = float(
    latest["process_execution_frequency"]
)

network_count = float(
    latest["network_connection_frequency"]
)

unique_processes = float(
    latest["unique_processes"]
)

unique_destinations = float(
    latest["unique_destinations"]
)

process_burst = float(
    latest["process_burst"]
)

network_burst = float(
    latest["network_burst"]
)

new_process_ratio = float(
    latest["new_processes_ratio"]
)

new_destination_ratio = float(
    latest["new_destination_ratio"]
)

ioc_matches = float(
    latest["ioc_matches"]
)


# ============================================================
# BEHAVIOR RISK
# ============================================================

behavior_component = min(
    100.0,
    (
        min(process_count / 20.0, 1.0) * 25
        + min(network_count / 10.0, 1.0) * 25
        + min(process_burst / 10.0, 1.0) * 15
        + min(network_burst / 10.0, 1.0) * 15
        + min(new_process_ratio, 1.0) * 10
        + min(new_destination_ratio, 1.0) * 10
    )
)


# ============================================================
# IOC SIGNAL
# ============================================================

ioc_component = min(
    100.0,
    ioc_matches * 20.0
)


# ============================================================
# FINAL RISK
# ============================================================

risk_score = (
    anomaly_component * 0.50
    + behavior_component * 0.35
    + ioc_component * 0.15
)

risk_score = max(
    0.0,
    min(100.0, risk_score)
)


# ============================================================
# SEVERITY
# ============================================================

if risk_score >= 80:
    severity = "CRITICAL"

elif risk_score >= 65:
    severity = "HIGH"

elif risk_score >= 40:
    severity = "MEDIUM"

else:
    severity = "LOW"


# ============================================================
# RESPONSE DECISION
# ============================================================

if severity == "CRITICAL":
    response = "ESCALATE_AND_CONTAIN"

elif severity == "HIGH":
    response = "ESCALATE"

elif severity == "MEDIUM":
    response = "MONITOR"

else:
    response = "ALLOW"


# ============================================================
# EXPLANATION
# ============================================================

reasons = []

if prediction == -1:
    reasons.append(
        f"Isolation Forest detected anomalous behavior (score {model_score:.4f})"
    )

if process_burst >= 5:
    reasons.append(
        f"high process burst ({process_burst:.2f})"
    )

if network_burst >= 5:
    reasons.append(
        f"high network burst ({network_burst:.2f})"
    )

if new_process_ratio >= 0.5:
    reasons.append(
        f"high new-process ratio ({new_process_ratio:.2f})"
    )

if new_destination_ratio >= 0.5:
    reasons.append(
        f"high new-destination ratio ({new_destination_ratio:.2f})"
    )

if ioc_matches > 0:
    reasons.append(
        f"{int(ioc_matches)} IoC match(es)"
    )

if not reasons:
    reasons.append(
        "behavior is consistent with the learned baseline"
    )


# ============================================================
# DISPLAY
# ============================================================

print("=" * 72)
print("NEXUS INTELLIGENCE - V5.2 LIVE INFERENCE")
print("=" * 72)

print()
print("LATEST LIVE WINDOW")
print("-" * 72)
print("Window :", latest["window_start"])

print()
print("FEATURES")
print("-" * 72)

for feature in FEATURES:
    print(
        f"{feature:30s}: "
        f"{float(latest[feature]):.4f}"
    )


print()
print("MODEL SIGNAL")
print("-" * 72)

print(
    "Isolation Forest prediction :",
    prediction
)

print(
    "Isolation Forest score      :",
    f"{model_score:.4f}"
)

print(
    "Anomaly component           :",
    f"{anomaly_component:.2f}/100"
)


print()
print("BEHAVIOR SIGNAL")
print("-" * 72)

print(
    "Behavior component          :",
    f"{behavior_component:.2f}/100"
)

print(
    "IoC component               :",
    f"{ioc_component:.2f}/100"
)


print()
print("V5.2 DECISION")
print("-" * 72)

print(
    "Risk score                  :",
    f"{risk_score:.2f}/100"
)

print(
    "Severity                    :",
    severity
)

print(
    "Response                    :",
    response
)


print()
print("EXPLANATION")
print("-" * 72)

for reason in reasons:
    print("•", reason)


print()
print("=" * 72)
print("V5.2 LIVE INFERENCE COMPLETE")
print("=" * 72)
