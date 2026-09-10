import os
import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM


DATA = "datasets/security_events/live_training_windows.csv"
MODEL_DIR = "ai/models/v2"

os.makedirs(MODEL_DIR, exist_ok=True)

BASE_FEATURES = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
]


def build_features(df):
    x = df[BASE_FEATURES].copy()

    # Behavioral features
    x["process_burst"] = x["process_execution_frequency"]
    x["network_burst"] = x["network_connection_frequency"]

    x["process_diversity"] = (
        x["unique_processes"] /
        x["process_execution_frequency"].clip(lower=1)
    )

    x["destination_diversity"] = (
        x["unique_destinations"] /
        x["network_connection_frequency"].clip(lower=1)
    )

    x["process_network_ratio"] = (
        x["process_execution_frequency"] /
        x["network_connection_frequency"].clip(lower=1)
    )

    # Log transforms reduce the effect of occasional large bursts
    x["log_process"] = np.log1p(
        x["process_execution_frequency"]
    )

    x["log_network"] = np.log1p(
        x["network_connection_frequency"]
    )

    return x.replace([np.inf, -np.inf], 0).fillna(0)


print("=" * 65)
print("NEXUS INTELLIGENCE - V2 AI TRAINING")
print("=" * 65)

df = pd.read_csv(DATA)

df["window_start"] = pd.to_datetime(df["window_start"], utc=True)
df = df.sort_values("window_start").reset_index(drop=True)

print(f"Total windows : {len(df)}")

X = build_features(df)

print(f"V2 features   : {X.shape[1]}")
print("Features      :", ", ".join(X.columns))

# Time-aware split.
# Earlier windows = training baseline
# Later windows = completely held-out normal test
split = int(len(X) * 0.80)

X_train = X.iloc[:split].copy()
X_test = X.iloc[split:].copy()

print(f"\nTraining windows : {len(X_train)}")
print(f"Test windows     : {len(X_test)}")

# Robust scaling is useful because security telemetry contains bursts.
scaler = RobustScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


# ---------------------------------------------------------
# 1. Isolation Forest
# ---------------------------------------------------------

isolation = IsolationForest(
    n_estimators=500,
    max_samples="auto",
    contamination=0.05,
    random_state=42,
    n_jobs=-1,
)

isolation.fit(X_train_scaled)


# ---------------------------------------------------------
# 2. LOF novelty detection
# ---------------------------------------------------------

neighbors = min(20, max(5, len(X_train) // 8))

lof = LocalOutlierFactor(
    n_neighbors=neighbors,
    contamination=0.05,
    novelty=True,
)

lof.fit(X_train_scaled)


# ---------------------------------------------------------
# 3. One-Class SVM
# ---------------------------------------------------------

ocsvm = OneClassSVM(
    kernel="rbf",
    gamma="scale",
    nu=0.05,
)

ocsvm.fit(X_train_scaled)


# ---------------------------------------------------------
# Predictions
# ---------------------------------------------------------

if_pred = isolation.predict(X_test_scaled)
lof_pred = lof.predict(X_test_scaled)
svm_pred = ocsvm.predict(X_test_scaled)

# sklearn:
# +1 = normal
# -1 = anomaly

if_anomaly = (if_pred == -1).astype(int)
lof_anomaly = (lof_pred == -1).astype(int)
svm_anomaly = (svm_pred == -1).astype(int)

# Majority vote
votes = if_anomaly + lof_anomaly + svm_anomaly
ensemble_anomaly = (votes >= 2).astype(int)

results = df.iloc[split:].copy()

results["isolation_anomaly"] = if_anomaly
results["lof_anomaly"] = lof_anomaly
results["ocsvm_anomaly"] = svm_anomaly
results["ensemble_votes"] = votes
results["ensemble_anomaly"] = ensemble_anomaly

# Decision score:
# higher = more suspicious
if_score = -isolation.decision_function(X_test_scaled)
lof_score = -lof.decision_function(X_test_scaled)
svm_score = -ocsvm.decision_function(X_test_scaled)

# Normalize scores independently to 0-1
def normalize(a):
    lo = np.min(a)
    hi = np.max(a)
    if hi - lo < 1e-12:
        return np.zeros_like(a)
    return (a - lo) / (hi - lo)


results["isolation_score"] = normalize(if_score)
results["lof_score"] = normalize(lof_score)
results["ocsvm_score"] = normalize(svm_score)

results["ensemble_score"] = (
    0.50 * results["isolation_score"]
    + 0.30 * results["lof_score"]
    + 0.20 * results["ocsvm_score"]
)


# ---------------------------------------------------------
# Evaluation on held-out NORMAL data
# ---------------------------------------------------------

fp_if = if_anomaly.mean()
fp_lof = lof_anomaly.mean()
fp_svm = svm_anomaly.mean()
fp_ensemble = ensemble_anomaly.mean()

print("\n" + "=" * 65)
print("HELD-OUT NORMAL DATA EVALUATION")
print("=" * 65)

print(f"Isolation Forest false-positive rate : {fp_if:.2%}")
print(f"LOF false-positive rate              : {fp_lof:.2%}")
print(f"One-Class SVM false-positive rate   : {fp_svm:.2%}")
print(f"ENSEMBLE false-positive rate        : {fp_ensemble:.2%}")

print("\nANOMALIES IN HELD-OUT NORMAL DATA")
print(f"Isolation Forest : {if_anomaly.sum()}")
print(f"LOF              : {lof_anomaly.sum()}")
print(f"One-Class SVM    : {svm_anomaly.sum()}")
print(f"Ensemble         : {ensemble_anomaly.sum()}")


# ---------------------------------------------------------
# Save models
# ---------------------------------------------------------

joblib.dump(isolation, f"{MODEL_DIR}/isolation_forest_v2.joblib")
joblib.dump(lof, f"{MODEL_DIR}/lof_v2.joblib")
joblib.dump(ocsvm, f"{MODEL_DIR}/one_class_svm_v2.joblib")
joblib.dump(scaler, f"{MODEL_DIR}/robust_scaler_v2.joblib")

with open(f"{MODEL_DIR}/feature_schema_v2.txt", "w") as f:
    for feature in X.columns:
        f.write(feature + "\n")

results.to_csv(
    "datasets/security_events/v2_normal_holdout_results.csv",
    index=False,
)

print("\nModels saved to:", MODEL_DIR)
print("Evaluation saved to:")
print("datasets/security_events/v2_normal_holdout_results.csv")

print("\nV2 TRAINING COMPLETE")
