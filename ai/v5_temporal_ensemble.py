import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

# ============================================================
# NEXUS INTELLIGENCE — V5 TEMPORAL + ENSEMBLE DETECTOR
# ============================================================

MODEL_DIR = Path("ai/models/v4")

BENCHMARK = "datasets/security_events/v3_4_attack_dataset.csv"

OUTPUT = "datasets/security_events/v5_temporal_ensemble_results.csv"

SUMMARY = "datasets/security_events/v5_temporal_ensemble_summary.json"

FEATURES = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
    "unique_destination_ports",
    "process_burst",
    "network_burst",
    "process_diversity",
    "destination_diversity",
    "process_network_ratio",
    "new_processes_ratio",
    "new_destination_ratio",
]

print("=" * 70)
print("NEXUS INTELLIGENCE — V5 TEMPORAL + ENSEMBLE DETECTOR")
print("=" * 70)

# ------------------------------------------------------------
# LOAD V4 MODEL
# ------------------------------------------------------------

model = joblib.load(
    MODEL_DIR / "live_isolation_forest_v4.joblib"
)

scaler = joblib.load(
    MODEL_DIR / "live_robust_scaler_v4.joblib"
)

# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

df = pd.read_csv(BENCHMARK)

print(f"\nBenchmark windows : {len(df)}")
print(f"Features           : {len(FEATURES)}")

missing = [f for f in FEATURES if f not in df.columns]

if missing:
    print("\nERROR — Missing features:")
    for f in missing:
        print(" ", f)
    raise SystemExit(1)

X = df[FEATURES].copy()

y_true = df["label"].astype(int).to_numpy()

# ------------------------------------------------------------
# V4 ISOLATION FOREST
# ------------------------------------------------------------

X_scaled = scaler.transform(X)

if_prediction = model.predict(X_scaled)

if_score = model.decision_function(X_scaled)

# Isolation Forest:
# +1 = normal
# -1 = anomaly

if_anomaly = (if_prediction == -1).astype(int)

# ------------------------------------------------------------
# NORMALIZE ISOLATION FOREST SCORE
# Higher = more suspicious
# ------------------------------------------------------------

score_min = float(if_score.min())
score_max = float(if_score.max())

if score_max != score_min:
    ml_component = (
        (score_max - if_score)
        / (score_max - score_min)
    )
else:
    ml_component = np.zeros(len(df))

ml_component = np.clip(ml_component, 0, 1)

# ------------------------------------------------------------
# BEHAVIOR COMPONENT
# ------------------------------------------------------------

behavior_features = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
    "unique_destination_ports",
    "process_burst",
    "network_burst",
    "process_diversity",
    "destination_diversity",
    "new_processes_ratio",
    "new_destination_ratio",
]

behavior_values = []

for feature in behavior_features:

    values = df[feature].astype(float).to_numpy()

    q25 = np.percentile(values, 25)
    q75 = np.percentile(values, 75)

    iqr = q75 - q25

    if iqr == 0:
        component = np.zeros(len(values))
    else:
        deviation = np.abs(values - np.median(values)) / iqr
        component = np.clip(deviation / 4.0, 0, 1)

    behavior_values.append(component)

behavior_component = np.mean(
    behavior_values,
    axis=0
)

# ------------------------------------------------------------
# TEMPORAL PERSISTENCE
# ------------------------------------------------------------

# Count consecutive suspicious windows.

persistence = np.zeros(len(df))

streak = 0

for i, anomaly in enumerate(if_anomaly):

    if anomaly == 1:
        streak += 1
    else:
        streak = 0

    # Persistence saturates at 5 windows.
    persistence[i] = min(streak / 5.0, 1.0)

# ------------------------------------------------------------
# ENSEMBLE SCORE
# ------------------------------------------------------------

# ML = 55%
# Behavior = 25%
# Temporal persistence = 20%

ensemble_score = (
    0.55 * ml_component
    + 0.25 * behavior_component
    + 0.20 * persistence
)

risk_score = ensemble_score * 100

# ------------------------------------------------------------
# DECISION
# ------------------------------------------------------------

# Conservative alert threshold.
v5_prediction = (risk_score >= 60).astype(int)

severity = []

for score in risk_score:

    if score >= 85:
        severity.append("CRITICAL")

    elif score >= 70:
        severity.append("HIGH")

    elif score >= 45:
        severity.append("MEDIUM")

    else:
        severity.append("LOW")

# ------------------------------------------------------------
# SAVE RESULTS
# ------------------------------------------------------------

result = df.copy()

result["v4_prediction"] = if_anomaly
result["v4_isolation_score"] = if_score
result["ml_component"] = ml_component
result["behavior_component"] = behavior_component
result["temporal_persistence"] = persistence
result["v5_ensemble_score"] = ensemble_score
result["v5_risk_score"] = risk_score
result["v5_prediction"] = v5_prediction
result["v5_severity"] = severity

result.to_csv(
    OUTPUT,
    index=False
)

# ------------------------------------------------------------
# METRICS
# ------------------------------------------------------------

tn = int(((y_true == 0) & (v5_prediction == 0)).sum())
fp = int(((y_true == 0) & (v5_prediction == 1)).sum())
fn = int(((y_true == 1) & (v5_prediction == 0)).sum())
tp = int(((y_true == 1) & (v5_prediction == 1)).sum())

total = len(y_true)

accuracy = (tp + tn) / total

precision = (
    tp / (tp + fp)
    if (tp + fp) else 0
)

recall = (
    tp / (tp + fn)
    if (tp + fn) else 0
)

f1 = (
    2 * precision * recall / (precision + recall)
    if (precision + recall) else 0
)

fpr = (
    fp / (fp + tn)
    if (fp + tn) else 0
)

fnr = (
    fn / (fn + tp)
    if (fn + tp) else 0
)

summary = {
    "version": "V5",
    "detector": "Temporal + Ensemble",
    "benchmark_windows": total,
    "true_positive": tp,
    "true_negative": tn,
    "false_positive": fp,
    "false_negative": fn,
    "accuracy": round(float(accuracy), 6),
    "precision": round(float(precision), 6),
    "recall": round(float(recall), 6),
    "f1": round(float(f1), 6),
    "false_positive_rate": round(float(fpr), 6),
    "false_negative_rate": round(float(fnr), 6),
    "weights": {
        "isolation_forest": 0.55,
        "behavior": 0.25,
        "temporal_persistence": 0.20
    },
    "alert_threshold": 60
}

with open(SUMMARY, "w") as f:
    json.dump(summary, f, indent=2)

# ------------------------------------------------------------
# DISPLAY
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("V5 BENCHMARK RESULT")
print("=" * 70)

print(f"Normal windows       : {(y_true == 0).sum()}")
print(f"Attack windows       : {(y_true == 1).sum()}")

print()

print(f"True Positive (TP)   : {tp}")
print(f"True Negative (TN)   : {tn}")
print(f"False Positive (FP)  : {fp}")
print(f"False Negative (FN)  : {fn}")

print()

print(f"Accuracy             : {accuracy:.4f}")
print(f"Precision            : {precision:.4f}")
print(f"Recall               : {recall:.4f}")
print(f"F1 Score             : {f1:.4f}")
print(f"False Positive Rate  : {fpr:.4f}")
print(f"False Negative Rate  : {fnr:.4f}")

print("\n" + "=" * 70)
print("V5 FILES SAVED")
print("=" * 70)

print(OUTPUT)
print(SUMMARY)

print("\nV5 TEMPORAL + ENSEMBLE COMPLETE")
print("=" * 70)
