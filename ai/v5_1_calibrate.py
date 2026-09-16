import pandas as pd
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

INPUT = "datasets/security_events/v5_temporal_ensemble_results.csv"
OUTPUT = "datasets/security_events/v5_1_threshold_results.csv"

print("=" * 70)
print("NEXUS INTELLIGENCE – V5.1 RISK CALIBRATION")
print("=" * 70)

df = pd.read_csv(INPUT)

print("\nColumns detected:")
print(df.columns.tolist())

# Find the risk-score column
risk_candidates = [
    "risk_score",
    "v5_risk_score",
    "final_risk",
    "nexus_risk",
    "score"
]

risk_col = next((c for c in risk_candidates if c in df.columns), None)

if risk_col is None:
    raise ValueError(
        "No risk-score column found. Available columns: "
        + ", ".join(df.columns)
    )

if "label" not in df.columns:
    raise ValueError("Column 'label' not found.")

df = df.dropna(subset=[risk_col, "label"]).copy()

df["label"] = df["label"].astype(int)

print(f"\nRisk column : {risk_col}")
print(f"Rows        : {len(df)}")
print(f"Normal      : {(df['label'] == 0).sum()}")
print(f"Attack      : {(df['label'] == 1).sum()}")

results = []

for threshold in np.arange(0, 81, 1):

    prediction = (df[risk_col] >= threshold).astype(int)

    accuracy = accuracy_score(df["label"], prediction)
    precision = precision_score(
        df["label"], prediction, zero_division=0
    )
    recall = recall_score(
        df["label"], prediction, zero_division=0
    )
    f1 = f1_score(
        df["label"], prediction, zero_division=0
    )

    tn = ((df["label"] == 0) & (prediction == 0)).sum()
    fp = ((df["label"] == 0) & (prediction == 1)).sum()
    fn = ((df["label"] == 1) & (prediction == 0)).sum()
    tp = ((df["label"] == 1) & (prediction == 1)).sum()

    fpr = fp / max(fp + tn, 1)
    fnr = fn / max(fn + tp, 1)

    results.append({
        "threshold": threshold,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn
    })

result = pd.DataFrame(results)

# Best F1
best_f1 = result.loc[result["f1"].idxmax()]

# Best balanced operating point:
# prioritize F1 while keeping false-positive rate <= 10%
acceptable = result[result["false_positive_rate"] <= 0.10]

if len(acceptable) > 0:
    best_balanced = acceptable.loc[
        acceptable["f1"].idxmax()
    ]
else:
    best_balanced = best_f1

print("\n" + "=" * 70)
print("BEST F1 THRESHOLD")
print("=" * 70)

print(f"Threshold : {int(best_f1['threshold'])}")
print(f"Accuracy  : {best_f1['accuracy']:.4f}")
print(f"Precision : {best_f1['precision']:.4f}")
print(f"Recall    : {best_f1['recall']:.4f}")
print(f"F1 Score  : {best_f1['f1']:.4f}")
print(f"FPR       : {best_f1['false_positive_rate']:.4f}")
print(f"FNR       : {best_f1['false_negative_rate']:.4f}")

print("\n" + "=" * 70)
print("RECOMMENDED BALANCED THRESHOLD")
print("=" * 70)

print(f"Threshold : {int(best_balanced['threshold'])}")
print(f"Accuracy  : {best_balanced['accuracy']:.4f}")
print(f"Precision : {best_balanced['precision']:.4f}")
print(f"Recall    : {best_balanced['recall']:.4f}")
print(f"F1 Score  : {best_balanced['f1']:.4f}")
print(f"FPR       : {best_balanced['false_positive_rate']:.4f}")
print(f"FNR       : {best_balanced['false_negative_rate']:.4f}")

print("\n" + "=" * 70)
print("TOP 10 THRESHOLDS BY F1")
print("=" * 70)

print(
    result.sort_values("f1", ascending=False)
    .head(10)
    .to_string(index=False)
)

result.to_csv(OUTPUT, index=False)

print("\nSaved:")
print(OUTPUT)

print("\nV5.1 CALIBRATION COMPLETE")
print("=" * 70)
