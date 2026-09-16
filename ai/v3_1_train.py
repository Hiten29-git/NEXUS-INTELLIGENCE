import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import confusion_matrix


INPUT = "datasets/security_events/v3_live_training_windows.csv"
MODEL_DIR = "ai/models/v3_1"
RESULTS = "datasets/security_events/v3_1_normal_holdout_results.csv"

TRAIN_RATIO = 0.80


# ---------------------------------------------------------
# Load dataset
# ---------------------------------------------------------

if not os.path.exists(INPUT):
    raise FileNotFoundError(f"Dataset not found: {INPUT}")

df = pd.read_csv(INPUT)

if len(df) < 50:
    raise ValueError("Not enough windows for V3.1 training.")

df["window_start"] = pd.to_datetime(df["window_start"], utc=True)
df = df.sort_values("window_start").reset_index(drop=True)


# ---------------------------------------------------------
# Feature selection
# ---------------------------------------------------------

# Keep behavioral features.
# Hour and weekday are excluded from the anomaly model because
# the current dataset is still relatively small and these
# temporal variables can create unnecessary false positives.

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


missing = [f for f in FEATURES if f not in df.columns]

if missing:
    raise ValueError(f"Missing features: {missing}")


X = df[FEATURES].copy()

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)


# ---------------------------------------------------------
# Chronological split
# ---------------------------------------------------------

split = int(len(df) * TRAIN_RATIO)

train_df = df.iloc[:split].copy()
test_df = df.iloc[split:].copy()

X_train = X.iloc[:split].copy()
X_test = X.iloc[split:].copy()


print("=" * 60)
print("NEXUS INTELLIGENCE — V3.1 AI TRAINING")
print("=" * 60)

print(f"Total windows : {len(df)}")
print(f"Features      : {len(FEATURES)}")
print(f"Training      : {len(X_train)}")
print(f"Holdout       : {len(X_test)}")

print("\nV3.1 MODELS")
print("1. Isolation Forest")
print("2. LOF")
print("3. Robust MAD detector")
print("4. 2-of-3 Ensemble")


# ---------------------------------------------------------
# Isolation Forest
# ---------------------------------------------------------

isolation = IsolationForest(
    n_estimators=400,
    max_samples="auto",
    contamination=0.03,
    random_state=42,
    n_jobs=-1
)

isolation.fit(X_train)

if_pred = isolation.predict(X_test)
if_anomaly = if_pred == -1


# ---------------------------------------------------------
# LOF
# ---------------------------------------------------------

neighbors = min(20, max(5, len(X_train) - 1))

lof = LocalOutlierFactor(
    n_neighbors=neighbors,
    contamination=0.03,
    novelty=True
)

lof.fit(X_train)

lof_pred = lof.predict(X_test)
lof_anomaly = lof_pred == -1


# ---------------------------------------------------------
# Robust MAD detector
# ---------------------------------------------------------

median = X_train.median()
mad = (X_train - median).abs().median()

# Prevent division by zero for stable features.
mad = mad.replace(0, 1e-6)

robust_z = ((X_test - median).abs() / mad)

# A window is suspicious when several behavioral dimensions
# strongly deviate from the normal baseline.
robust_anomaly_count = (robust_z > 6.0).sum(axis=1)

robust_anomaly = robust_anomaly_count >= 2


# ---------------------------------------------------------
# Ensemble
# ---------------------------------------------------------

votes = (
    if_anomaly.astype(int)
    + lof_anomaly.astype(int)
    + robust_anomaly.astype(int)
)

ensemble_anomaly = votes >= 2


# ---------------------------------------------------------
# False-positive evaluation
# ---------------------------------------------------------

def fpr(values):
    return float(np.mean(values)) * 100


print("\n" + "=" * 60)
print("HELD-OUT NORMAL DATA EVALUATION")
print("=" * 60)

print(f"Isolation Forest FPR : {fpr(if_anomaly):.2f}%")
print(f"LOF FPR              : {fpr(lof_anomaly):.2f}%")
print(f"Robust FPR           : {fpr(robust_anomaly):.2f}%")
print(f"Ensemble FPR         : {fpr(ensemble_anomaly):.2f}%")


print("\nANOMALIES IN HELD-OUT NORMAL DATA")

print(f"Isolation Forest : {if_anomaly.sum()}")
print(f"LOF              : {lof_anomaly.sum()}")
print(f"Robust detector  : {robust_anomaly.sum()}")
print(f"Ensemble         : {ensemble_anomaly.sum()}")


# ---------------------------------------------------------
# Results table
# ---------------------------------------------------------

results = test_df[
    [
        "window_start"
    ]
].copy()

results["isolation_forest"] = if_anomaly.astype(int)
results["lof"] = lof_anomaly.astype(int)
results["robust_detector"] = robust_anomaly.astype(int)
results["votes"] = votes
results["ensemble_anomaly"] = ensemble_anomaly.astype(int)

results["risk_score"] = (
    results["votes"] / 3.0 * 100
).round(1)

results["risk_level"] = np.select(
    [
        results["risk_score"] >= 80,
        results["risk_score"] >= 50,
        results["risk_score"] >= 25,
    ],
    [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
    ],
    default="LOW"
)


# Add important behavioral features for analysis.

for feature in FEATURES:
    results[feature] = X_test[feature].values


# ---------------------------------------------------------
# Save models
# ---------------------------------------------------------

os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(
    isolation,
    f"{MODEL_DIR}/isolation_forest_v3_1.joblib"
)

joblib.dump(
    lof,
    f"{MODEL_DIR}/lof_v3_1.joblib"
)

joblib.dump(
    {
        "median": median,
        "mad": mad,
        "threshold": 6.0
    },
    f"{MODEL_DIR}/robust_detector_v3_1.joblib"
)

with open(f"{MODEL_DIR}/feature_schema_v3_1.txt", "w") as f:
    for feature in FEATURES:
        f.write(feature + "\n")


results.to_csv(RESULTS, index=False)


# ---------------------------------------------------------
# Show suspicious windows
# ---------------------------------------------------------

print("\n" + "=" * 60)
print("TOP V3.1 SUSPICIOUS WINDOWS")
print("=" * 60)

top = results.sort_values(
    ["risk_score", "votes"],
    ascending=False
).head(10)

for _, row in top.iterrows():
    print(
        f"{row['window_start']} | "
        f"Risk={row['risk_score']} | "
        f"{row['risk_level']} | "
        f"Votes={row['votes']}"
    )


print("\n" + "=" * 60)
print("V3.1 TRAINING COMPLETE")
print("=" * 60)

print(f"Models saved to : {MODEL_DIR}")
print(f"Results saved to: {RESULTS}")
