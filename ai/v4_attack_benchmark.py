import json
import joblib
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

MODEL_DIR = Path("ai/models/v4")
DATASET = "datasets/security_events/v3_4_attack_dataset.csv"
OUTPUT = "datasets/security_events/v4_attack_benchmark_results.csv"
SUMMARY = "datasets/security_events/v4_attack_benchmark_summary.json"

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

print("=" * 65)
print("NEXUS INTELLIGENCE — V4 ATTACK BENCHMARK")
print("=" * 65)

# Load model
model = joblib.load(
    MODEL_DIR / "live_isolation_forest_v4.joblib"
)

scaler = joblib.load(
    MODEL_DIR / "live_robust_scaler_v4.joblib"
)

# Load benchmark dataset
df = pd.read_csv(DATASET)

print(f"\nDataset windows : {len(df)}")
print(f"Features used   : {len(FEATURES)}")

# Verify features
missing = [f for f in FEATURES if f not in df.columns]

if missing:
    print("\nERROR — Missing features:")
    for f in missing:
        print("  -", f)
    raise SystemExit(1)

# Prepare features
X = df[FEATURES].copy()

# Ground-truth labels
# label = 0 -> normal
# label = 1 -> attack
y_true = df["label"].astype(int)

# Apply the same scaler used during training
X_scaled = scaler.transform(X)

# V4 prediction
pred = model.predict(X_scaled)

# Isolation Forest:
# +1 = normal
# -1 = anomaly
y_pred = (pred == -1).astype(int)

# Scores
tn, fp, fn, tp = confusion_matrix(
    y_true,
    y_pred,
    labels=[0, 1]
).ravel()

accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(
    y_true, y_pred, zero_division=0
)
recall = recall_score(
    y_true, y_pred, zero_division=0
)
f1 = f1_score(
    y_true, y_pred, zero_division=0
)

fpr = fp / (fp + tn) if (fp + tn) else 0
fnr = fn / (fn + tp) if (fn + tp) else 0

# Save detailed results
result = df.copy()
result["v4_prediction"] = y_pred
result["v4_isolation_prediction"] = pred
result["v4_anomaly_score"] = model.decision_function(X_scaled)

result.to_csv(OUTPUT, index=False)

summary = {
    "version": "4.0",
    "dataset": DATASET,
    "training_windows": 232,
    "benchmark_windows": len(df),
    "true_positive": int(tp),
    "true_negative": int(tn),
    "false_positive": int(fp),
    "false_negative": int(fn),
    "accuracy": round(float(accuracy), 6),
    "precision": round(float(precision), 6),
    "recall": round(float(recall), 6),
    "f1": round(float(f1), 6),
    "false_positive_rate": round(float(fpr), 6),
    "false_negative_rate": round(float(fnr), 6),
    "detector": "V4 Isolation Forest",
    "feature_count": len(FEATURES),
}

with open(SUMMARY, "w") as f:
    json.dump(summary, f, indent=2)

print("\n" + "=" * 65)
print("V4 BENCHMARK RESULT")
print("=" * 65)

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

print("\n" + "=" * 65)
print("FILES SAVED")
print("=" * 65)
print(OUTPUT)
print(SUMMARY)

print("\nV4 ATTACK BENCHMARK COMPLETE")
print("=" * 65)
