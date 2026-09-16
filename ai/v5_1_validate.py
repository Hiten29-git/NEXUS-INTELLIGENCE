import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

INPUT = "datasets/security_events/v5_1_calibrated_results.csv"

THRESHOLD = 34

print("=" * 70)
print("NEXUS INTELLIGENCE – V5.1 VALIDATION")
print("=" * 70)

df = pd.read_csv(INPUT)

y_true = df["label"].astype(int)
y_pred = df["v5_1_prediction"].astype(int)

tn, fp, fn, tp = confusion_matrix(
    y_true,
    y_pred,
    labels=[0, 1]
).ravel()

accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred, zero_division=0)
recall = recall_score(y_true, y_pred, zero_division=0)
f1 = f1_score(y_true, y_pred, zero_division=0)

fpr = fp / max(fp + tn, 1)
fnr = fn / max(fn + tp, 1)

print("\nDATASET")
print("-" * 70)
print("Total windows :", len(df))
print("Normal        :", (y_true == 0).sum())
print("Attack        :", (y_true == 1).sum())

print("\nCONFUSION MATRIX")
print("-" * 70)
print("True Negative  :", tn)
print("False Positive :", fp)
print("True Positive  :", tp)
print("False Negative :", fn)

print("\nV5.1 PERFORMANCE")
print("-" * 70)
print(f"Threshold          : {THRESHOLD}")
print(f"Accuracy            : {accuracy:.4f}")
print(f"Precision           : {precision:.4f}")
print(f"Recall              : {recall:.4f}")
print(f"F1 Score            : {f1:.4f}")
print(f"False Positive Rate : {fpr:.4f}")
print(f"False Negative Rate : {fnr:.4f}")

print("\nATTACK DETECTION")
print("-" * 70)
print(f"Attacks detected : {tp}/{tp + fn}")
print(f"Detection rate   : {recall * 100:.2f}%")

print("\nFALSE ALERTS")
print("-" * 70)
print(f"Normal flagged : {fp}/{fp + tn}")
print(f"False alert rate: {fpr * 100:.2f}%")

print("\n" + "=" * 70)
print("V5.1 VALIDATION COMPLETE")
print("=" * 70)
