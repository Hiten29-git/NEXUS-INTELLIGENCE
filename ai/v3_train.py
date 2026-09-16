import os
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import RobustScaler

DATA = "datasets/security_events/v3_live_training_windows.csv"
MODEL_DIR = "ai/models/v3"
RESULT = "datasets/security_events/v3_normal_holdout_results.csv"

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
    "new_process_ratio",
    "new_destination_ratio",
    "established_ratio",
    "syn_sent_ratio",
    "closed_ratio",
    "ioc_matches",
    "hour",
    "weekday"
]

os.makedirs(MODEL_DIR, exist_ok=True)

df = pd.read_csv(DATA)

if len(df) < 50:
    raise ValueError(f"Only {len(df)} windows available. Need at least 50.")

missing = [x for x in FEATURES if x not in df.columns]
if missing:
    raise ValueError(f"Missing features: {missing}")

X = df[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(0)

# Chronological 80/20 split
split = int(len(X) * 0.80)

X_train = X.iloc[:split].copy()
X_test = X.iloc[split:].copy()
df_test = df.iloc[split:].copy()

print("=" * 65)
print("NEXUS INTELLIGENCE - V3 AI TRAINING")
print("=" * 65)
print(f"Total windows    : {len(df)}")
print(f"Features         : {len(FEATURES)}")
print(f"Training windows : {len(X_train)}")
print(f"Test windows     : {len(X_test)}")

# Robust scaling
scaler = RobustScaler()
A = scaler.fit_transform(X_train)
B = scaler.transform(X_test)

# ------------------------------------------------------------
# MODEL 1: ISOLATION FOREST
# ------------------------------------------------------------
isolation = IsolationForest(
    n_estimators=400,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)
isolation.fit(A)
if_anomaly = isolation.predict(B) == -1

# ------------------------------------------------------------
# MODEL 2: LOF
# ------------------------------------------------------------
neighbors = min(20, max(5, len(X_train) // 10))

lof = LocalOutlierFactor(
    n_neighbors=neighbors,
    contamination=0.05,
    novelty=True
)
lof.fit(A)
lof_anomaly = lof.predict(B) == -1

# ------------------------------------------------------------
# MODEL 3: ONE CLASS SVM
# ------------------------------------------------------------
svm = OneClassSVM(
    kernel="rbf",
    gamma="scale",
    nu=0.05
)
svm.fit(A)
svm_anomaly = svm.predict(B) == -1

# ------------------------------------------------------------
# MODEL 4: ROBUST MEDIAN/MAD
# ------------------------------------------------------------
train = X_train.to_numpy(float)
test = X_test.to_numpy(float)

median = np.median(train, axis=0)
mad = np.median(np.abs(train - median), axis=0)
mad = np.where(mad < 1e-9, 1.0, mad)

z = 0.6745 * (test - median) / mad
robust_anomaly = np.any(np.abs(z) >= 6.0, axis=1)

# ------------------------------------------------------------
# ENSEMBLE: 2 OF 4
# ------------------------------------------------------------
votes = (
    if_anomaly.astype(int)
    + lof_anomaly.astype(int)
    + svm_anomaly.astype(int)
    + robust_anomaly.astype(int)
)

ensemble = votes >= 2

# ------------------------------------------------------------
# RISK SCORE
# ------------------------------------------------------------
risk = (
    if_anomaly * 25
    + lof_anomaly * 25
    + svm_anomaly * 20
    + robust_anomaly * 30
)

risk += np.minimum(X_test["ioc_matches"].to_numpy() * 15, 30)
risk += np.minimum(X_test["network_burst"].to_numpy() * 5, 20)
risk += np.minimum(X_test["process_burst"].to_numpy() * 3, 15)

risk = np.clip(risk, 0, 100)

def level(score, anomaly):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"

levels = [
    level(s, a)
    for s, a in zip(risk, ensemble)
]

# ------------------------------------------------------------
# RESULTS
# ------------------------------------------------------------
results = df_test.copy()

results["isolation_forest_anomaly"] = if_anomaly
results["lof_anomaly"] = lof_anomaly
results["one_class_svm_anomaly"] = svm_anomaly
results["robust_anomaly"] = robust_anomaly
results["ensemble_votes"] = votes
results["ensemble_anomaly"] = ensemble
results["risk_score"] = np.round(risk, 2)
results["risk_level"] = levels

# ------------------------------------------------------------
# EVALUATION
# ------------------------------------------------------------
print()
print("=" * 65)
print("HELD-OUT NORMAL DATA EVALUATION")
print("=" * 65)

print(f"Isolation Forest false-positive rate : {if_anomaly.mean()*100:.2f}%")
print(f"LOF false-positive rate              : {lof_anomaly.mean()*100:.2f}%")
print(f"One-Class SVM false-positive rate    : {svm_anomaly.mean()*100:.2f}%")
print(f"Robust detector false-positive rate  : {robust_anomaly.mean()*100:.2f}%")
print(f"ENSEMBLE false-positive rate         : {ensemble.mean()*100:.2f}%")

print()
print("ANOMALIES IN HELD-OUT DATA")
print("-" * 65)
print(f"Isolation Forest : {if_anomaly.sum()}")
print(f"LOF              : {lof_anomaly.sum()}")
print(f"One-Class SVM    : {svm_anomaly.sum()}")
print(f"Robust detector  : {robust_anomaly.sum()}")
print(f"ENSEMBLE         : {ensemble.sum()}")

print()
print("=" * 65)
print("TOP SUSPICIOUS WINDOWS")
print("=" * 65)

top = results.sort_values("risk_score", ascending=False).head(10)

for _, row in top.iterrows():
    print(
        f"{row['window_start']} | "
        f"Risk={row['risk_score']:.1f} | "
        f"{row['risk_level']} | "
        f"Votes={int(row['ensemble_votes'])}"
    )

# ------------------------------------------------------------
# SAVE MODELS
# ------------------------------------------------------------
joblib.dump(isolation, f"{MODEL_DIR}/isolation_forest_v3.joblib")
joblib.dump(lof, f"{MODEL_DIR}/lof_v3.joblib")
joblib.dump(svm, f"{MODEL_DIR}/one_class_svm_v3.joblib")
joblib.dump(scaler, f"{MODEL_DIR}/robust_scaler_v3.joblib")
joblib.dump(median, f"{MODEL_DIR}/robust_medians_v3.joblib")
joblib.dump(mad, f"{MODEL_DIR}/robust_mad_v3.joblib")

with open(f"{MODEL_DIR}/feature_schema_v3.json", "w") as f:
    json.dump({
        "features": FEATURES,
        "window_seconds": 60,
        "ensemble": "2_of_4",
        "models": [
            "IsolationForest",
            "LOF",
            "OneClassSVM",
            "RobustMAD"
        ]
    }, f, indent=2)

results.to_csv(RESULT, index=False)

print()
print("=" * 65)
print("V3 TRAINING COMPLETE")
print("=" * 65)
print(f"Models saved to  : {MODEL_DIR}")
print(f"Results saved to : {RESULT}")
