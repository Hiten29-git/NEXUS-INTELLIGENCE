import pandas as pd
from pathlib import Path

INPUT = "datasets/security_events/v5_temporal_ensemble_results.csv"
OUTPUT = "datasets/security_events/v5_1_calibrated_results.csv"

THRESHOLD = 34

print("=" * 70)
print("NEXUS INTELLIGENCE – V5.1 CALIBRATED DETECTOR")
print("=" * 70)

df = pd.read_csv(INPUT)

if "v5_risk_score" not in df.columns:
    raise ValueError("v5_risk_score column not found")

df["v5_1_prediction"] = (
    df["v5_risk_score"] >= THRESHOLD
).astype(int)

def severity(row):
    score = float(row["v5_risk_score"])
    persistence = float(row.get("temporal_persistence", 0))

    if score >= 65 and persistence >= 0.5:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= THRESHOLD:
        return "MEDIUM"

    return "LOW"

df["v5_1_severity"] = df.apply(severity, axis=1)

def decision(row):
    if row["v5_1_prediction"] == 0:
        return "ALLOW"

    if row["v5_1_severity"] == "CRITICAL":
        return "ESCALATE_AND_CONTAIN"

    if row["v5_1_severity"] == "HIGH":
        return "ESCALATE"

    return "MONITOR"

df["v5_1_response"] = df.apply(decision, axis=1)

print("\nCALIBRATION")
print("-" * 70)
print(f"Risk threshold : {THRESHOLD}")

print("\nPREDICTION DISTRIBUTION")
print("-" * 70)
print(df["v5_1_prediction"].value_counts().sort_index())

print("\nSEVERITY DISTRIBUTION")
print("-" * 70)
print(df["v5_1_severity"].value_counts())

print("\nRESPONSE DISTRIBUTION")
print("-" * 70)
print(df["v5_1_response"].value_counts())

print("\nLATEST HIGH-RISK WINDOWS")
print("-" * 70)

cols = [
    "v5_risk_score",
    "temporal_persistence",
    "v5_1_prediction",
    "v5_1_severity",
    "v5_1_response"
]

available = [c for c in cols if c in df.columns]

print(
    df[df["v5_1_prediction"] == 1]
    .sort_values("v5_risk_score", ascending=False)
    [available]
    .head(10)
    .to_string(index=False)
)

Path(OUTPUT).parent.mkdir(parents=True, exist_ok=True)
df.to_csv(OUTPUT, index=False)

print("\n" + "=" * 70)
print("V5.1 CALIBRATED DETECTOR COMPLETE")
print("=" * 70)
print(f"Saved: {OUTPUT}")
