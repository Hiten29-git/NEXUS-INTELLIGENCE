import os
import json
import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

INPUT = "datasets/security_events/live_training_windows_v4.csv"
MODEL_DIR = "ai/models/v4"

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
]

os.makedirs(MODEL_DIR, exist_ok=True)

print("=" * 60)
print("NEXUS INTELLIGENCE — V4 LIVE MODEL TRAINING")
print("=" * 60)

df = pd.read_csv(INPUT)

print(f"Training windows : {len(df)}")
print(f"Candidate features: {len(FEATURES)}")

X = df[FEATURES].copy()

# Safety checks
if X.isna().any().any():
    raise ValueError("Dataset contains missing values.")

constant_features = [
    c for c in FEATURES
    if X[c].nunique(dropna=False) <= 1
]

if constant_features:
    print("\nRemoving constant features:")
    for c in constant_features:
        print(" -", c)

    FEATURES = [
        c for c in FEATURES
        if c not in constant_features
    ]

X = df[FEATURES].copy()

print(f"\nFinal model features: {len(FEATURES)}")
for i, feature in enumerate(FEATURES, 1):
    print(f"{i:2}. {feature}")

# Robust scaling
scaler = RobustScaler()
X_scaled = scaler.fit_transform(X)

# Dedicated window-based anomaly model
model = IsolationForest(
    n_estimators=400,
    contamination=0.05,
    max_samples="auto",
    random_state=42,
    n_jobs=-1
)

model.fit(X_scaled)

# Training diagnostics
raw_scores = model.decision_function(X_scaled)
predictions = model.predict(X_scaled)

anomalies = int((predictions == -1).sum())
normal = int((predictions == 1).sum())

print("\n" + "=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)

print(f"Normal windows   : {normal}")
print(f"Anomalous windows: {anomalies}")
print(f"Anomaly rate     : {anomalies / len(df) * 100:.2f}%")

print("\nScore statistics:")
print(f"Minimum : {raw_scores.min():.4f}")
print(f"Maximum : {raw_scores.max():.4f}")
print(f"Mean    : {raw_scores.mean():.4f}")

# Save artifacts
joblib.dump(
    model,
    f"{MODEL_DIR}/live_isolation_forest_v4.joblib"
)

joblib.dump(
    scaler,
    f"{MODEL_DIR}/live_robust_scaler_v4.joblib"
)

with open(f"{MODEL_DIR}/feature_schema_v4.json", "w") as f:
    json.dump(
        {
            "version": "V4",
            "window_type": "60-second behavioral window",
            "features": FEATURES,
            "training_windows": len(df),
            "contamination": 0.05,
            "constant_features_removed": constant_features
        },
        f,
        indent=2
    )

print("\nSaved:")
print(f"✓ {MODEL_DIR}/live_isolation_forest_v4.joblib")
print(f"✓ {MODEL_DIR}/live_robust_scaler_v4.joblib")
print(f"✓ {MODEL_DIR}/feature_schema_v4.json")

print("\nNEXUS V4 MODEL READY")
