import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor


# ============================================================
# NEXUS INTELLIGENCE — V3.2 AI TRAINING
# ============================================================

INPUT = "datasets/security_events/v3_live_training_windows.csv"
MODEL_DIR = "ai/models/v3_2"
OUTPUT = "datasets/security_events/v3_2_normal_holdout_results.csv"

TRAIN_RATIO = 0.80
RANDOM_STATE = 42


# ============================================================
# FEATURE SET
# ============================================================

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


# ============================================================
# DIRECTORIES
# ============================================================

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)


# ============================================================
# LOAD DATASET
# ============================================================

if not os.path.exists(INPUT):
    raise FileNotFoundError(
        f"Dataset not found: {INPUT}"
    )

df = pd.read_csv(INPUT)

if len(df) < 50:
    raise ValueError(
        f"Not enough windows for V3.2 training. "
        f"Found {len(df)}, need at least 50."
    )


# ============================================================
# VALIDATE FEATURES
# ============================================================

missing = [f for f in FEATURES if f not in df.columns]

if missing:
    raise ValueError(
        "Missing required feature columns:\n"
        + "\n".join(f"- {x}" for x in missing)
    )


# ============================================================
# SORT CHRONOLOGICALLY
# ============================================================

if "window_start" in df.columns:
    df["window_start"] = pd.to_datetime(
        df["window_start"],
        utc=True,
        errors="coerce"
    )

    df = df.sort_values(
        "window_start"
    ).reset_index(drop=True)


# ============================================================
# CLEAN FEATURES
# ============================================================

X = df[FEATURES].copy()

for feature in FEATURES:
    X[feature] = pd.to_numeric(
        X[feature],
        errors="coerce"
    )

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.fillna(0.0)

# Ensure all values are finite
X = pd.DataFrame(
    np.nan_to_num(
        X.to_numpy(dtype=float),
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    ),
    columns=FEATURES
)


# ============================================================
# TRAIN / HOLDOUT SPLIT
# ============================================================

split = int(len(df) * TRAIN_RATIO)

if split < 30:
    raise ValueError(
        "Training portion is too small."
    )

if len(df) - split < 10:
    raise ValueError(
        "Holdout portion is too small."
    )


X_train = X.iloc[:split].copy()
X_test = X.iloc[split:].copy()

test_times = df.iloc[split:]["window_start"].copy()


# ============================================================
# CONVERT TO NUMPY
# ============================================================

X_train_np = X_train.to_numpy(dtype=float)
X_test_np = X_test.to_numpy(dtype=float)


# ============================================================
# HEADER
# ============================================================

print("=" * 60)
print("NEXUS INTELLIGENCE — V3.2 AI TRAINING")
print("=" * 60)

print(f"Total windows : {len(df)}")
print(f"Features      : {len(FEATURES)}")
print(f"Training      : {len(X_train)}")
print(f"Holdout       : {len(X_test)}")


# ============================================================
# TRAIN MODELS
# ============================================================

print()
print("V3.2 MODELS")
print("1. Isolation Forest")
print("2. Local Outlier Factor")
print("3. Robust MAD detector")
print("4. Conservative 2-of-3 ensemble")


# ============================================================
# 1. ISOLATION FOREST
# ============================================================

if_model = IsolationForest(
    n_estimators=300,
    contamination="auto",
    random_state=RANDOM_STATE,
    n_jobs=-1,
    max_samples="auto"
)

if_model.fit(X_train_np)


# ============================================================
# 2. LOCAL OUTLIER FACTOR
# ============================================================

n_neighbors = min(
    20,
    max(5, len(X_train_np) // 10)
)

lof_model = LocalOutlierFactor(
    n_neighbors=n_neighbors,
    contamination="auto",
    novelty=True
)

lof_model.fit(X_train_np)


# ============================================================
# 3. ROBUST MAD BASELINE
# ============================================================

# IMPORTANT:
# Median and robust scale are calculated ONLY from training data.
# They are later reused unchanged for holdout/live inference.

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

std = X_train.std(
    ddof=0
)

# Robust MAD scale
mad_scale = 1.4826 * mad

# IQR converted approximately to standard deviation
iqr_scale = iqr / 1.349


# Combine robust scale estimates.
# The maximum prevents unstable division for features
# with extremely small variance.
robust_scale = pd.concat(
    [
        mad_scale.rename("mad"),
        iqr_scale.rename("iqr"),
        std.rename("std"),
    ],
    axis=1
).max(axis=1)

# Prevent zero / extremely small denominators
robust_scale = robust_scale.clip(
    lower=1.0
)


# ============================================================
# TRAINING ROBUST SCORES
# ============================================================

train_robust_z = (
    X_train
    .sub(median)
    .abs()
    .div(robust_scale, axis=1)
)

# Prevent one feature from dominating indefinitely
train_robust_z = train_robust_z.clip(
    upper=6.0
)

train_robust_scores = train_robust_z.max(
    axis=1
)


# ============================================================
# CALIBRATE THRESHOLDS
# ============================================================

# Lower Isolation Forest / LOF scores are more anomalous.

if_train_scores = if_model.score_samples(
    X_train_np
)

lof_train_scores = lof_model.score_samples(
    X_train_np
)

# 1st percentile = approximately most unusual 1%
if_threshold = float(
    np.percentile(
        if_train_scores,
        1.0
    )
)

lof_threshold = float(
    np.percentile(
        lof_train_scores,
        1.0
    )
)

# Robust detector:
# Higher score = more anomalous.
robust_threshold = float(
    np.percentile(
        train_robust_scores,
        99.0
    )
)


# ============================================================
# HOLDOUT PREDICTIONS
# ============================================================

if_scores = if_model.score_samples(
    X_test_np
)

lof_scores = lof_model.score_samples(
    X_test_np
)


# ============================================================
# ROBUST HOLDOUT SCORE
# ============================================================

# IMPORTANT:
# Use training median + training robust scale.
# NEVER calculate MAD again using holdout data.

robust_z = (
    X_test
    .sub(median)
    .abs()
    .div(robust_scale, axis=1)
)

robust_z = robust_z.clip(
    upper=6.0
)

robust_scores = robust_z.max(
    axis=1
)


# ============================================================
# INDIVIDUAL DETECTION SIGNALS
# ============================================================

if_anomaly = (
    if_scores < if_threshold
)

lof_anomaly = (
    lof_scores < lof_threshold
)

robust_anomaly = (
    robust_scores >= robust_threshold
)


# ============================================================
# CONSERVATIVE 2-OF-3 ENSEMBLE
# ============================================================

votes = (
    if_anomaly.astype(int)
    + lof_anomaly.astype(int)
    + robust_anomaly.astype(int)
)

# Require at least two independent detectors
ensemble_anomaly = votes >= 2


# ============================================================
# RISK SCORE
# ============================================================

risk_score = np.zeros(
    len(X_test),
    dtype=float
)


# Primary anomaly evidence
risk_score += (
    if_anomaly.astype(float) * 35
)

risk_score += (
    lof_anomaly.astype(float) * 35
)


# Robust detector is supporting evidence
risk_score += (
    robust_anomaly.astype(float) * 10
)


# ============================================================
# BEHAVIORAL ESCALATION
# ============================================================

process_burst = X_test[
    "process_burst"
].to_numpy(dtype=float)

network_burst = X_test[
    "network_burst"
].to_numpy(dtype=float)

ioc_matches = X_test[
    "ioc_matches"
].to_numpy(dtype=float)


# Process burst contribution
risk_score += np.clip(
    process_burst / 10.0,
    0,
    1
) * 8


# Network burst contribution
risk_score += np.clip(
    network_burst / 10.0,
    0,
    1
) * 8


# IOC contribution
risk_score += np.clip(
    ioc_matches / 4.0,
    0,
    1
) * 12


# Keep score inside 0–100
risk_score = np.clip(
    risk_score,
    0,
    100
)


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


risk_levels = [
    get_risk_level(x)
    for x in risk_score
]


# ============================================================
# RESULTS DATAFRAME
# ============================================================

results = pd.DataFrame(
    {
        "window_start": test_times.values,

        "isolation_forest":
            if_anomaly.astype(int),

        "lof":
            lof_anomaly.astype(int),

        "robust_detector":
            robust_anomaly.astype(int),

        "votes":
            votes,

        "ensemble_anomaly":
            ensemble_anomaly.astype(int),

        "risk_score":
            np.round(
                risk_score,
                2
            ),

        "risk_level":
            risk_levels,

        "isolation_forest_score":
            if_scores,

        "lof_score":
            lof_scores,

        "robust_score":
            robust_scores,
    }
)


# ============================================================
# ADD FEATURE VALUES
# ============================================================

for feature in FEATURES:
    results[feature] = X_test[
        feature
    ].values


# ============================================================
# EVALUATION
# ============================================================

print()
print("=" * 60)
print("HELD-OUT NORMAL DATA EVALUATION")
print("=" * 60)

n_test = len(X_test)

if_fpr = (
    if_anomaly.sum()
    / n_test
    * 100
)

lof_fpr = (
    lof_anomaly.sum()
    / n_test
    * 100
)

robust_fpr = (
    robust_anomaly.sum()
    / n_test
    * 100
)

ensemble_fpr = (
    ensemble_anomaly.sum()
    / n_test
    * 100
)

print(
    f"Isolation Forest FPR : {if_fpr:.2f}%"
)

print(
    f"LOF FPR              : {lof_fpr:.2f}%"
)

print(
    f"Robust detector FPR  : {robust_fpr:.2f}%"
)

print(
    f"V3.2 Ensemble FPR    : {ensemble_fpr:.2f}%"
)


# ============================================================
# ANOMALY COUNTS
# ============================================================

print()
print("ANOMALIES IN HOLDOUT")

print(
    f"Isolation Forest : {if_anomaly.sum()}"
)

print(
    f"LOF             : {lof_anomaly.sum()}"
)

print(
    f"Robust detector : {robust_anomaly.sum()}"
)

print(
    f"V3.2 Ensemble   : {ensemble_anomaly.sum()}"
)


# ============================================================
# TOP SUSPICIOUS WINDOWS
# ============================================================

print()
print("=" * 60)
print("TOP V3.2 SUSPICIOUS WINDOWS")
print("=" * 60)

top_results = (
    results
    .sort_values(
        [
            "ensemble_anomaly",
            "risk_score",
            "votes"
        ],
        ascending=[
            False,
            False,
            False
        ]
    )
    .head(10)
)

for _, row in top_results.iterrows():

    timestamp = row["window_start"]

    if pd.isna(timestamp):
        timestamp = "UNKNOWN"

    else:
        timestamp = str(timestamp)

    print(
        f"{timestamp} | "
        f"Risk={row['risk_score']:.1f} | "
        f"{row['risk_level']} | "
        f"Votes={int(row['votes'])}"
    )


# ============================================================
# SAVE MODELS
# ============================================================

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


# ============================================================
# SAVE FEATURE SCHEMA
# ============================================================

with open(
    f"{MODEL_DIR}/feature_schema_v3_2.txt",
    "w"
) as f:

    for feature in FEATURES:
        f.write(
            f"{feature}\n"
        )


# ============================================================
# SAVE THRESHOLDS
# ============================================================

with open(
    f"{MODEL_DIR}/thresholds.txt",
    "w"
) as f:

    f.write(
        f"if_threshold={if_threshold}\n"
    )

    f.write(
        f"lof_threshold={lof_threshold}\n"
    )

    f.write(
        f"robust_threshold={robust_threshold}\n"
    )


# ============================================================
# SAVE TRAINING METADATA
# ============================================================

metadata = {
    "model_version": "V3.2",
    "total_windows": int(len(df)),
    "training_windows": int(len(X_train)),
    "holdout_windows": int(len(X_test)),
    "feature_count": int(len(FEATURES)),
    "train_ratio": TRAIN_RATIO,
    "random_state": RANDOM_STATE,
    "if_fpr_percent": round(
        float(if_fpr),
        4
    ),
    "lof_fpr_percent": round(
        float(lof_fpr),
        4
    ),
    "robust_fpr_percent": round(
        float(robust_fpr),
        4
    ),
    "ensemble_fpr_percent": round(
        float(ensemble_fpr),
        4
    ),
    "if_threshold": if_threshold,
    "lof_threshold": lof_threshold,
    "robust_threshold": robust_threshold,
    "ensemble_rule": "2_of_3",
}


with open(
    f"{MODEL_DIR}/metadata.json",
    "w"
) as f:

    json.dump(
        metadata,
        f,
        indent=2
    )


# ============================================================
# SAVE RESULTS
# ============================================================

results.to_csv(
    OUTPUT,
    index=False
)


# ============================================================
# FINAL STATUS
# ============================================================

print()
print("=" * 60)
print("V3.2 TRAINING COMPLETE")
print("=" * 60)

print(
    f"Models saved to : {MODEL_DIR}"
)

print(
    f"Results saved to: {OUTPUT}"
)

print()
print("Saved model files:")

print(
    " - isolation_forest.joblib"
)

print(
    " - lof.joblib"
)

print(
    " - median.joblib"
)

print(
    " - robust_scale.joblib"
)

print(
    " - feature_schema_v3_2.txt"
)

print(
    " - thresholds.txt"
)

print(
    " - metadata.json"
)
