import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

# ============================================================
# NEXUS INTELLIGENCE — V3.3
# Calibrated Multi-Detector + Temporal Persistence
# ============================================================

DATA_PATH = "datasets/security_events/live_training_windows_v3_3.csv"
MODEL_DIR = "ai/models/v3_3"
RESULT_PATH = "datasets/security_events/v3_3_holdout_results.csv"

os.makedirs(MODEL_DIR, exist_ok=True)

# ------------------------------------------------------------
# FEATURE SET
# ------------------------------------------------------------

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
    "established_ratio",
    "syn_sent_ratio",
    "closed_ratio",
    "ioc_matches",
]

# ------------------------------------------------------------
# LOAD DATA
# ------------------------------------------------------------

if not os.path.exists(DATA_PATH):
    raise FileNotFoundError(
        f"Dataset not found: {DATA_PATH}"
    )

df = pd.read_csv(DATA_PATH)

missing = [f for f in FEATURES if f not in df.columns]

if missing:
    raise ValueError(
        "Missing required features:\n" + "\n".join(missing)
    )

df["window_start"] = pd.to_datetime(
    df["window_start"],
    errors="coerce"
)

df = df.sort_values("window_start").reset_index(drop=True)

X = df[FEATURES].copy()

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0.0)

# ------------------------------------------------------------
# REMOVE DUPLICATE WINDOWS
# ------------------------------------------------------------

df = df.loc[X.index].reset_index(drop=True)
X = X.reset_index(drop=True)

# ------------------------------------------------------------
# TIME ORDERED TRAIN / HOLDOUT
# ------------------------------------------------------------

TRAIN_RATIO = 0.80

split = int(len(df) * TRAIN_RATIO)

if split < 50:
    raise ValueError(
        "Not enough windows for V3.3 training. "
        "Collect more normal telemetry first."
    )

X_train = X.iloc[:split].copy()
X_test = X.iloc[split:].copy()

test_times = df.iloc[split:]["window_start"].copy()

# ------------------------------------------------------------
# DISPLAY
# ------------------------------------------------------------

print()
print("=" * 60)
print("NEXUS INTELLIGENCE — V3.3 AI TRAINING")
print("=" * 60)

print(f"Total windows : {len(df)}")
print(f"Features      : {len(FEATURES)}")
print(f"Training      : {len(X_train)}")
print(f"Holdout       : {len(X_test)}")

print()
print("V3.3 DETECTORS")
print("1. Isolation Forest")
print("2. Local Outlier Factor")
print("3. Robust MAD")
print("4. Calibrated 2-of-3 Ensemble")
print("5. Temporal Persistence")

# ------------------------------------------------------------
# ISOLATION FOREST
# ------------------------------------------------------------

if_model = IsolationForest(
    n_estimators=500,
    max_samples="auto",
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)

if_model.fit(X_train)

# ------------------------------------------------------------
# LOCAL OUTLIER FACTOR
# novelty=True allows inference on holdout data
# ------------------------------------------------------------

n_neighbors = min(
    35,
    max(10, len(X_train) // 10)
)

lof_model = LocalOutlierFactor(
    n_neighbors=n_neighbors,
    contamination="auto",
    novelty=True,
)

lof_model.fit(X_train)

# ------------------------------------------------------------
# TRAINING SCORES
# Lower IF / LOF score = more anomalous
# ------------------------------------------------------------

if_train_scores = if_model.score_samples(X_train)
lof_train_scores = lof_model.score_samples(X_train)

# ------------------------------------------------------------
# CALIBRATED THRESHOLDS
#
# Instead of arbitrary thresholds, use the lower tail of
# actual normal training behavior.
# ------------------------------------------------------------

IF_PERCENTILE = 1.0
LOF_PERCENTILE = 1.0

if_threshold = float(
    np.percentile(if_train_scores, IF_PERCENTILE)
)

lof_threshold = float(
    np.percentile(lof_train_scores, LOF_PERCENTILE)
)

# ------------------------------------------------------------
# ROBUST MAD BASELINE
# ------------------------------------------------------------

median = X_train.median()

mad = (
    X_train
    .sub(median)
    .abs()
    .median()
)

iqr = (
    X_train.quantile(0.75)
    - X_train.quantile(0.25)
)

std = X_train.std(ddof=0)

mad_scale = 1.4826 * mad
iqr_scale = iqr / 1.349

robust_scale = pd.concat(
    [
        mad_scale.rename("mad"),
        iqr_scale.rename("iqr"),
        std.rename("std"),
    ],
    axis=1,
).max(axis=1)

robust_scale = robust_scale.clip(lower=1.0)

robust_z = (
    X_train.sub(median)
    .abs()
    .div(robust_scale, axis=1)
)

robust_z = robust_z.clip(upper=6.0)

robust_train_scores = robust_z.max(axis=1)

# Calibrate robust threshold from normal behavior.
ROBUST_PERCENTILE = 99.0

robust_threshold = float(
    np.percentile(
        robust_train_scores,
        ROBUST_PERCENTILE
    )
)

# ------------------------------------------------------------
# HOLDOUT SCORES
# ------------------------------------------------------------

if_scores = if_model.score_samples(X_test)
lof_scores = lof_model.score_samples(X_test)

robust_z_test = (
    X_test.sub(median)
    .abs()
    .div(robust_scale, axis=1)
)

robust_z_test = robust_z_test.clip(upper=6.0)

robust_scores = robust_z_test.max(axis=1)

# ------------------------------------------------------------
# INDIVIDUAL DETECTIONS
# ------------------------------------------------------------

if_anomaly = if_scores < if_threshold
lof_anomaly = lof_scores < lof_threshold
robust_anomaly = robust_scores > robust_threshold

# ------------------------------------------------------------
# CALIBRATED 2-OF-3 ENSEMBLE
#
# At least TWO independent detectors must agree.
# This is intentionally conservative to reduce false alarms.
# ------------------------------------------------------------

votes = (
    if_anomaly.astype(int)
    + lof_anomaly.astype(int)
    + robust_anomaly.astype(int)
)

ensemble_anomaly = votes >= 2

# ------------------------------------------------------------
# TEMPORAL PERSISTENCE
#
# A single isolated anomaly is not enough for a strong alert.
# Require another ensemble anomaly in the previous two windows.
# ------------------------------------------------------------

persistent_anomaly = np.zeros(len(X_test), dtype=bool)

for i in range(len(X_test)):
    if not ensemble_anomaly.iloc[i]:
        continue

    previous_1 = (
        i >= 1 and ensemble_anomaly[i - 1]
    )

    previous_2 = (
        i >= 2 and ensemble_anomaly[i - 2]
    )

    if previous_1 or previous_2:
        persistent_anomaly[i] = True

# ------------------------------------------------------------
# RISK ENGINE
# ------------------------------------------------------------

risk_score = np.zeros(len(X_test), dtype=float)

# AI agreement
risk_score += if_anomaly.astype(float) * 30
risk_score += lof_anomaly.astype(float) * 25
risk_score += robust_anomaly.astype(float) * 10

# Ensemble agreement
risk_score += np.clip(
    (votes - 1) * 15,
    0,
    30
)

# Temporal persistence
risk_score += persistent_anomaly.astype(float) * 20

# Behavioral escalation
process_burst = X_test["process_burst"].to_numpy()
network_burst = X_test["network_burst"].to_numpy()
ioc_matches = X_test["ioc_matches"].to_numpy()

risk_score += np.clip(
    process_burst / 10,
    0,
    1
) * 5

risk_score += np.clip(
    network_burst / 10,
    0,
    1
) * 5

risk_score += np.clip(
    ioc_matches / 4,
    0,
    1
) * 15

risk_score = np.clip(
    risk_score,
    0,
    100
)

# ------------------------------------------------------------
# RISK LEVEL
# ------------------------------------------------------------

def risk_level(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"

risk_levels = [
    risk_level(x)
    for x in risk_score
]

# ------------------------------------------------------------
# RESULTS
# ------------------------------------------------------------

results = pd.DataFrame({
    "window_start": test_times.values,
    "isolation_forest": if_anomaly.astype(int),
    "lof": lof_anomaly.astype(int),
    "robust_detector": robust_anomaly.astype(int),
    "votes": votes,
    "ensemble_anomaly": ensemble_anomaly.astype(int),
    "persistent_anomaly": persistent_anomaly.astype(int),
    "risk_score": np.round(risk_score, 2),
    "risk_level": risk_levels,
})

for feature in FEATURES:
    results[feature] = X_test[feature].values

# ------------------------------------------------------------
# FALSE POSITIVE EVALUATION
#
# Holdout is assumed NORMAL because this dataset is normal
# telemetry. This is NOT attack accuracy.
# ------------------------------------------------------------

n_test = len(X_test)

if_fpr = if_anomaly.sum() / n_test * 100
lof_fpr = lof_anomaly.sum() / n_test * 100
robust_fpr = robust_anomaly.sum() / n_test * 100
ensemble_fpr = ensemble_anomaly.sum() / n_test * 100
persistent_fpr = persistent_anomaly.sum() / n_test * 100

# ------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------

print()
print("=" * 60)
print("V3.3 HELD-OUT NORMAL DATA EVALUATION")
print("=" * 60)

print(f"Isolation Forest FPR : {if_fpr:.2f}%")
print(f"LOF FPR              : {lof_fpr:.2f}%")
print(f"Robust detector FPR  : {robust_fpr:.2f}%")
print(f"2-of-3 Ensemble FPR  : {ensemble_fpr:.2f}%")
print(f"Persistent FPR       : {persistent_fpr:.2f}%")

print()
print("DETECTIONS IN HOLDOUT")
print(f"Isolation Forest : {if_anomaly.sum()}")
print(f"LOF              : {lof_anomaly.sum()}")
print(f"Robust detector  : {robust_anomaly.sum()}")
print(f"2-of-3 Ensemble  : {ensemble_anomaly.sum()}")
print(f"Persistent       : {persistent_anomaly.sum()}")

# ------------------------------------------------------------
# TOP ALERTS
# ------------------------------------------------------------

print()
print("=" * 60)
print("TOP V3.3 ALERT WINDOWS")
print("=" * 60)

alerts = results[
    results["persistent_anomaly"] == 1
].sort_values(
    ["risk_score", "votes"],
    ascending=False
)

if len(alerts) == 0:
    print("No persistent anomalies in normal holdout.")

else:
    for _, row in alerts.head(10).iterrows():
        print(
            f"{row['window_start']} | "
            f"Risk={row['risk_score']:.1f} | "
            f"{row['risk_level']} | "
            f"Votes={row['votes']} | "
            f"Persistent=YES"
        )

# ------------------------------------------------------------
# SAVE MODELS
# ------------------------------------------------------------

joblib.dump(
    if_model,
    f"{MODEL_DIR}/isolation_forest.joblib"
)

joblib.dump(
    lof_model,
    f"{MODEL_DIR}/lof.joblib"
)

joblib.dump(
    median,
    f"{MODEL_DIR}/median.joblib"
)

joblib.dump(
    robust_scale,
    f"{MODEL_DIR}/robust_scale.joblib"
)

with open(
    f"{MODEL_DIR}/thresholds.json",
    "w"
) as f:
    json.dump(
        {
            "if_threshold": if_threshold,
            "lof_threshold": lof_threshold,
            "robust_threshold": robust_threshold,
            "if_percentile": IF_PERCENTILE,
            "lof_percentile": LOF_PERCENTILE,
            "robust_percentile": ROBUST_PERCENTILE,
            "ensemble_rule": "2_of_3",
            "temporal_rule": "previous_1_or_2",
        },
        f,
        indent=2,
    )

with open(
    f"{MODEL_DIR}/feature_schema.json",
    "w"
) as f:
    json.dump(
        {
            "features": FEATURES,
            "feature_count": len(FEATURES),
        },
        f,
        indent=2,
    )

with open(
    f"{MODEL_DIR}/metadata.json",
    "w"
) as f:
    json.dump(
        {
            "version": "3.3",
            "training_windows": len(X_train),
            "holdout_windows": len(X_test),
            "detectors": [
                "IsolationForest",
                "LocalOutlierFactor",
                "RobustMAD",
            ],
            "ensemble": "2-of-3",
            "temporal_persistence": True,
            "note": (
                "Holdout contains normal telemetry only; "
                "FPR is not attack detection accuracy."
            ),
        },
        f,
        indent=2,
    )

# ------------------------------------------------------------
# SAVE RESULTS
# ------------------------------------------------------------

results.to_csv(
    RESULT_PATH,
    index=False
)

print()
print("=" * 60)
print("V3.3 TRAINING COMPLETE")
print("=" * 60)

print(f"Models saved : {MODEL_DIR}")
print(f"Results saved: {RESULT_PATH}")

print()
print("Saved:")
print(" - isolation_forest.joblib")
print(" - lof.joblib")
print(" - median.joblib")
print(" - robust_scale.joblib")
print(" - thresholds.json")
print(" - feature_schema.json")
print(" - metadata.json")

print()
print("IMPORTANT:")
print("This evaluates false positives on NORMAL data.")
print("Attack accuracy requires a separate labeled attack test set.")
