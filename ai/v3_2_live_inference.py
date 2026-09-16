import os
import joblib
import numpy as np
import pandas as pd


DATASET = "datasets/security_events/v3_live_training_windows.csv"
MODEL_DIR = "ai/models/v3_2"


# ------------------------------------------------------------
# LOAD FEATURE SCHEMA
# ------------------------------------------------------------

schema_path = os.path.join(MODEL_DIR, "feature_schema_v3_2.txt")

with open(schema_path, "r", encoding="utf-8") as f:
    FEATURES = [line.strip() for line in f if line.strip()]


# ------------------------------------------------------------
# LOAD MODELS
# ------------------------------------------------------------

if_model = joblib.load(
    os.path.join(MODEL_DIR, "isolation_forest.joblib")
)

lof_model = joblib.load(
    os.path.join(MODEL_DIR, "lof.joblib")
)

median = joblib.load(
    os.path.join(MODEL_DIR, "median.joblib")
)

mad = joblib.load(
    os.path.join(MODEL_DIR, "mad.joblib")
)


# ------------------------------------------------------------
# LOAD THRESHOLDS
# ------------------------------------------------------------

thresholds = {}

with open(
    os.path.join(MODEL_DIR, "thresholds.txt"),
    "r",
    encoding="utf-8"
) as f:

    for line in f:
        line = line.strip()

        if not line or "=" not in line:
            continue

        key, value = line.split("=", 1)
        thresholds[key.strip()] = float(value.strip())


IF_THRESHOLD = thresholds["if_threshold"]
LOF_THRESHOLD = thresholds["lof_threshold"]
ROBUST_THRESHOLD = thresholds["robust_threshold"]


# ------------------------------------------------------------
# LOAD LIVE DATASET
# ------------------------------------------------------------

if not os.path.exists(DATASET):
    raise FileNotFoundError(
        f"Dataset not found: {DATASET}"
    )

df = pd.read_csv(DATASET)

missing = [
    feature
    for feature in FEATURES
    if feature not in df.columns
]

if missing:
    raise ValueError(
        f"Missing live features: {missing}"
    )


X = df[FEATURES].copy()

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.fillna(0)


# ------------------------------------------------------------
# MODEL SCORES
# ------------------------------------------------------------

if_scores = if_model.score_samples(X)

lof_scores = lof_model.score_samples(
    X.to_numpy()
)


# ------------------------------------------------------------
# ROBUST MAD DETECTOR
# ------------------------------------------------------------

robust_z = (
    (X - median).abs()
    / (1.4826 * mad.replace(0, 1))
)

robust_scores = robust_z.max(axis=1)


# ------------------------------------------------------------
# VOTING
# ------------------------------------------------------------

if_anomaly = if_scores < IF_THRESHOLD

lof_anomaly = lof_scores < LOF_THRESHOLD

robust_anomaly = robust_scores > ROBUST_THRESHOLD


votes = (
    if_anomaly.astype(int)
    + lof_anomaly.astype(int)
    + robust_anomaly.astype(int)
)

ensemble_anomaly = votes >= 2


# ------------------------------------------------------------
# RESULTS
# ------------------------------------------------------------

results = pd.DataFrame({
    "window_start": df["window_start"],
    "isolation_forest_score": if_scores,
    "lof_score": lof_scores,
    "robust_score": robust_scores,
    "if_anomaly": if_anomaly,
    "lof_anomaly": lof_anomaly,
    "robust_anomaly": robust_anomaly,
    "votes": votes,
    "ensemble_anomaly": ensemble_anomaly
})


# ------------------------------------------------------------
# DISPLAY
# ------------------------------------------------------------

print()
print("=" * 65)
print("NEXUS INTELLIGENCE - V3.2 LIVE INFERENCE TEST")
print("=" * 65)

print(f"Windows analysed : {len(results)}")
print(f"Features used    : {len(FEATURES)}")

print()
print("THRESHOLDS")
print("-" * 65)
print(f"Isolation Forest : {IF_THRESHOLD}")
print(f"LOF              : {LOF_THRESHOLD}")
print(f"Robust MAD       : {ROBUST_THRESHOLD}")

print()
print("DETECTION SUMMARY")
print("-" * 65)

print(
    f"Isolation Forest anomalies : "
    f"{if_anomaly.sum()}"
)

print(
    f"LOF anomalies              : "
    f"{lof_anomaly.sum()}"
)

print(
    f"Robust anomalies            : "
    f"{robust_anomaly.sum()}"
)

print(
    f"V3.2 Ensemble anomalies     : "
    f"{ensemble_anomaly.sum()}"
)


# ------------------------------------------------------------
# TOP SUSPICIOUS WINDOWS
# ------------------------------------------------------------

print()
print("=" * 65)
print("TOP V3.2 SUSPICIOUS WINDOWS")
print("=" * 65)

top = results.sort_values(
    ["votes", "robust_score"],
    ascending=False
).head(10)


for _, row in top.iterrows():

    status = (
        "ANOMALY"
        if row["ensemble_anomaly"]
        else "NORMAL"
    )

    print(
        f"{row['window_start']} | "
        f"Votes={int(row['votes'])} | "
        f"Robust={row['robust_score']:.2f} | "
        f"{status}"
    )


# ------------------------------------------------------------
# SAVE RESULTS
# ------------------------------------------------------------

output = (
    "datasets/security_events/"
    "v3_2_live_inference_test.csv"
)

results.to_csv(
    output,
    index=False
)

print()
print("=" * 65)
print("V3.2 LIVE INFERENCE TEST COMPLETE")
print("=" * 65)
print(f"Results saved to : {output}")
