import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor


INPUT = "datasets/security_events/v3_live_training_windows.csv"
MODEL_DIR = "ai/models/v3_2"
RESULTS = "datasets/security_events/v3_2_normal_holdout_results.csv"

TRAIN_RATIO = 0.80


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
# LOAD DATA
# ============================================================

if not os.path.exists(INPUT):
    raise FileNotFoundError(f"Dataset not found: {INPUT}")

df = pd.read_csv(INPUT)

if len(df) < 50:
    raise ValueError("Not enough windows for V3.2 training.")

df["window_start"] = pd.to_datetime(
    df["window_start"],
    utc=True,
)

df = df.sort_values("window_start").reset_index(drop=True)


missing = [f for f in FEATURES if f not in df.columns]

if missing:
    raise ValueError(f"Missing features: {missing}")


X = df[FEATURES].copy()

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)


split = int(len(df) * TRAIN_RATIO)

X_train = X.iloc[:split].copy()
X_test = X.iloc[split:].copy()

test_times = df.iloc[split:]["window_start"].copy()


# ============================================================
# TRAIN MODELS
# ============================================================

print("=" * 60)
print("NEXUS INTELLIGENCE — V3.2 AI TRAINING")
print("=" * 60)

print(f"Total windows : {len(df)}")
print(f"Features      : {len(FEATURES)}")
print(f"Training      : {len(X_train)}")
print(f"Holdout       : {len(X_test)}")

print()
print("V3.2 MODELS")
print("1. Isolation Forest")
print("2. Local Outlier Factor")
print("3. Robust MAD — supporting signal")
print("4. Conservative ensemble")


# ============================================================
# ISOLATION FOREST
# ============================================================

if_model = IsolationForest(
    n_estimators=400,
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)

if_model.fit(X_train)


# ============================================================
# LOF
# ============================================================

lof_model = LocalOutlierFactor(
    n_neighbors=min(20, max(5, len(X_train) // 10)),
    contamination="auto",
    novelty=True,
)

lof_model.fit(X_train.to_numpy())


# ============================================================
# CALIBRATE THRESHOLDS USING TRAINING DATA
# ============================================================

if_train_scores = if_model.score_samples(X_train)

lof_train_scores = lof_model.score_samples(X_train.to_numpy())


# Lower scores are more anomalous.
# Use the 1st percentile of normal training behavior.

if_threshold = np.percentile(if_train_scores, 1.0)
lof_threshold = np.percentile(lof_train_scores, 1.0)


# ============================================================
# ROBUST MAD BASELINE
# ============================================================

median = X_train.median()
mad = (X_train - median).abs().median()

mad = mad.replace(0, 1e-6)

# ============================================================
# ROBUST MAD DETECTOR
# ============================================================

# Calculate robust scale from training data.
# MAD is preferred, but extremely small MAD values are
# unreliable for sparse/count-based security telemetry.

median = X_train.median()
mad = (X_train - median).abs().median()

q1 = X_train.quantile(0.25)
q3 = X_train.quantile(0.75)
iqr = q3 - q1

std = X_train.std(ddof=0)

# Build a safe scale for every feature.
mad_scale = 1.4826 * mad
iqr_scale = iqr / 1.349

robust_scale = pd.concat(
    [
        mad_scale.rename("mad"),
        iqr_scale.rename("iqr"),
        std.rename("std")
    ],
    axis=1
).max(axis=1)

# Prevent division by extremely small values.
robust_scale = robust_scale.clip(lower=1.0)

# Robust z-score.
robust_z = (
    (X_test - median).abs()
    .div(robust_scale, axis=1)
)

# Cap individual feature influence.
robust_z = robust_z.clip(upper=6.0)

# Maximum deviation across behavioral features.
robust_scores = robust_z.max(axis=1)

# Supporting detector only.
robust_anomaly = robust_scores >= 4.0

robust_threshold = 4.5


# ============================================================
# HOLDOUT PREDICTIONS
# ============================================================

if_scores = if_model.score_samples(X_test)
lof_scores = lof_model.score_samples(X_test.to_numpy())

robust_z = (
    (X_test - median).abs() /
    (1.4826 * mad)
)

robust_scores = robust_z.max(axis=1)


if_anomaly = if_scores < if_threshold
lof_anomaly = lof_scores < lof_threshold
robust_anomaly = robust_scores > robust_threshold


# ============================================================
# CONSERVATIVE ENSEMBLE
# ============================================================

votes = (
    if_anomaly.astype(int)
    + lof_anomaly.astype(int)
    + robust_anomaly.astype(int)
)


# Primary decision:
# IF + LOF must agree.
#
# Robust MAD alone cannot trigger an alert.
#
# If all three agree, confidence is higher.

ensemble_anomaly = (
    (if_anomaly & lof_anomaly)
    | (if_anomaly & lof_anomaly & robust_anomaly)
)


# ============================================================
# RISK SCORE
# ============================================================

risk_score = np.zeros(len(X_test))


# Primary anomaly evidence
risk_score += if_anomaly.astype(float) * 35
risk_score += lof_anomaly.astype(float) * 35


# Robust detector is supporting evidence only
risk_score += robust_anomaly.astype(float) * 10


# Behavioral escalation
process_burst = X_test["process_burst"].to_numpy()
network_burst = X_test["network_burst"].to_numpy()
ioc_matches = X_test["ioc_matches"].to_numpy()

risk_score += np.clip(process_burst / 10, 0, 1) * 8
risk_score += np.clip(network_burst / 10, 0, 1) * 8
risk_score += np.clip(ioc_matches * 4, 0, 12)


risk_score = np.clip(risk_score, 0, 100)


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


# ============================================================
# RESULTS
# ============================================================

results = pd.DataFrame({
    "window_start": test_times.values,
    "isolation_forest": if_anomaly.astype(int),
    "lof": lof_anomaly.astype(int),
    "robust_detector": robust_anomaly.astype(int),
    "votes": votes,
    "ensemble_anomaly": ensemble_anomaly.astype(int),
    "risk_score": np.round(risk_score, 2),
    "risk_level": risk_levels,
})


for feature in FEATURES:
    results[feature] = X_test[feature].values


# ============================================================
# EVALUATION
# ============================================================

print()
print("=" * 60)
print("HELD-OUT NORMAL DATA EVALUATION")
print("=" * 60)

n_test = len(X_test)

if_fpr = if_anomaly.sum() / n_test * 100
lof_fpr = lof_anomaly.sum() / n_test * 100
robust_fpr = robust_anomaly.sum() / n_test * 100
ensemble_fpr = ensemble_anomaly.sum() / n_test * 100

print(f"Isolation Forest FPR : {if_fpr:.2f}%")
print(f"LOF FPR              : {lof_fpr:.2f}%")
print(f"Robust detector FPR  : {robust_fpr:.2f}%")
print(f"V3.2 Ensemble FPR    : {ensemble_fpr:.2f}%")

print()
print("ANOMALIES IN HOLDOUT")
print(f"Isolation Forest : {if_anomaly.sum()}")
print(f"LOF              : {lof_anomaly.sum()}")
print(f"Robust detector  : {robust_anomaly.sum()}")
print(f"V3.2 Ensemble    : {ensemble_anomaly.sum()}")


# ============================================================
# TOP SUSPICIOUS WINDOWS
# ============================================================

print()
print("=" * 60)
print("TOP V3.2 SUSPICIOUS WINDOWS")
print("=" * 60)

top = results.sort_values(
    ["risk_score", "votes"],
    ascending=False,
).head(10)

for _, row in top.iterrows():

    print(
        f"{row['window_start']} | "
        f"Risk={row['risk_score']:.1f} | "
        f"{row['risk_level']} | "
        f"Votes={row['votes']}"
    )


# ============================================================
# SAVE MODELS
# ============================================================

os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(
    if_model,
    f"{MODEL_DIR}/isolation_forest.joblib",
)

joblib.dump(
    lof_model,
    f"{MODEL_DIR}/lof.joblib",
)

joblib.dump(
    median,
    f"{MODEL_DIR}/median.joblib",
)

joblib.dump(
    mad,
    f"{MODEL_DIR}/mad.joblib",
)


with open(
    f"{MODEL_DIR}/feature_schema_v3_2.txt",
    "w",
) as f:

    for feature in FEATURES:
        f.write(feature + "\n")


with open(
    f"{MODEL_DIR}/thresholds.txt",
    "w",
) as f:

    f.write(f"if_threshold={if_threshold}\n")
    f.write(f"lof_threshold={lof_threshold}\n")
    f.write(f"robust_threshold={robust_threshold}\n")


results.to_csv(
    RESULTS,
    index=False,
)


print()
print("=" * 60)
print("V3.2 TRAINING COMPLETE")
print("=" * 60)

print(f"Models saved to  : {MODEL_DIR}")
print(f"Results saved to : {RESULTS}")
