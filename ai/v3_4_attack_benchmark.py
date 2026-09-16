import os
import json
import joblib
import numpy as np
import pandas as pd

# ============================================================
# NEXUS INTELLIGENCE — V3.4 ATTACK BENCHMARK
# ============================================================
#
# Purpose:
#   Evaluate the existing V3.3 detector against:
#       1. NORMAL held-out telemetry
#       2. Controlled attack-like behavioral windows
#
# Important:
#   The attack windows are synthetic benchmark data.
#   No malware, exploitation, credential theft, scanning,
#   or destructive activity is executed.
#
# ============================================================


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "security_events",
    "live_training_windows_v3_3.csv",
)

HOLDOUT_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "security_events",
    "v3_3_holdout_results.csv",
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "ai",
    "models",
    "v3_3",
)

RESULT_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "security_events",
    "v3_4_attack_benchmark_results.csv",
)

ATTACK_PATH = os.path.join(
    BASE_DIR,
    "datasets",
    "security_events",
    "v3_4_attack_dataset.csv",
)


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
# LOAD
# ============================================================

print("=" * 62)
print("NEXUS INTELLIGENCE — V3.4 ATTACK BENCHMARK")
print("=" * 62)

df = pd.read_csv(DATA_PATH)

missing = [f for f in FEATURES if f not in df.columns]

if missing:
    raise ValueError(
        "Missing benchmark features:\n" +
        "\n".join(missing)
    )

normal = df[FEATURES].copy()

print(f"Normal windows available : {len(normal)}")


# ============================================================
# LOAD V3.3 MODELS
# ============================================================

if_model = joblib.load(
    os.path.join(MODEL_DIR, "isolation_forest.joblib")
)

lof_model = joblib.load(
    os.path.join(MODEL_DIR, "lof.joblib")
)

median = joblib.load(
    os.path.join(MODEL_DIR, "median.joblib")
)

robust_scale = joblib.load(
    os.path.join(MODEL_DIR, "robust_scale.joblib")
)

with open(
    os.path.join(MODEL_DIR, "thresholds.json"),
    "r",
) as f:
    thresholds = json.load(f)


IF_THRESHOLD = float(thresholds["if_threshold"])
LOF_THRESHOLD = float(thresholds["lof_threshold"])
ROBUST_THRESHOLD = float(thresholds["robust_threshold"])


print()
print("V3.3 THRESHOLDS")
print("-" * 62)
print(f"Isolation Forest : {IF_THRESHOLD:.6f}")
print(f"LOF              : {LOF_THRESHOLD:.6f}")
print(f"Robust MAD       : {ROBUST_THRESHOLD:.2f}")


# ============================================================
# HELPER
# ============================================================

def make_attack(base, kind, multiplier=1.0):
    """
    Create harmless synthetic behavioral anomaly windows.

    These represent telemetry patterns only.
    """

    x = base.copy()

    if kind == "process_burst":
        x["process_execution_frequency"] *= 4.0 * multiplier
        x["unique_processes"] *= 3.0 * multiplier
        x["process_burst"] = np.maximum(
            x["process_burst"],
            2.5 * multiplier
        )
        x["process_diversity"] = np.maximum(
            x["process_diversity"],
            0.8
        )
        x["new_processes_ratio"] = np.maximum(
            x["new_processes_ratio"],
            0.8
        )

    elif kind == "network_burst":
        x["network_connection_frequency"] *= 5.0 * multiplier
        x["unique_destinations"] = np.maximum(
            x["unique_destinations"],
            5.0 * multiplier
        )
        x["unique_destination_ports"] = np.maximum(
            x["unique_destination_ports"],
            2.0
        )
        x["network_burst"] = np.maximum(
            x["network_burst"],
            2.5 * multiplier
        )
        x["destination_diversity"] = np.maximum(
            x["destination_diversity"],
            0.7
        )
        x["new_destination_ratio"] = np.maximum(
            x["new_destination_ratio"],
            0.8
        )

    elif kind == "discovery":
        x["network_connection_frequency"] *= 3.0 * multiplier
        x["unique_destinations"] = np.maximum(
            x["unique_destinations"],
            7.0 * multiplier
        )
        x["unique_destination_ports"] = np.maximum(
            x["unique_destination_ports"],
            3.0
        )
        x["destination_diversity"] = np.maximum(
            x["destination_diversity"],
            0.9
        )
        x["new_destination_ratio"] = np.maximum(
            x["new_destination_ratio"],
            0.9
        )

    elif kind == "collection":
        x["process_execution_frequency"] *= 3.0 * multiplier
        x["unique_processes"] = np.maximum(
            x["unique_processes"],
            5.0
        )
        x["process_burst"] = np.maximum(
            x["process_burst"],
            2.0
        )
        x["process_diversity"] = np.maximum(
            x["process_diversity"],
            0.7
        )
        x["process_network_ratio"] = np.maximum(
            x["process_network_ratio"],
            6.0 * multiplier
        )

    elif kind == "lateral_movement":
        x["process_execution_frequency"] *= 3.0 * multiplier
        x["network_connection_frequency"] *= 4.0 * multiplier

        x["unique_processes"] = np.maximum(
            x["unique_processes"],
            6.0
        )

        x["unique_destinations"] = np.maximum(
            x["unique_destinations"],
            6.0 * multiplier
        )

        x["unique_destination_ports"] = np.maximum(
            x["unique_destination_ports"],
            2.0
        )

        x["process_burst"] = np.maximum(
            x["process_burst"],
            2.5
        )

        x["network_burst"] = np.maximum(
            x["network_burst"],
            2.5
        )

        x["new_processes_ratio"] = np.maximum(
            x["new_processes_ratio"],
            0.8
        )

        x["new_destination_ratio"] = np.maximum(
            x["new_destination_ratio"],
            0.8
        )

    elif kind == "ioc_activity":
        x["ioc_matches"] = np.maximum(
            x["ioc_matches"],
            2.0
        )
        x["process_execution_frequency"] *= 2.5 * multiplier
        x["network_connection_frequency"] *= 2.5 * multiplier
        x["process_burst"] = np.maximum(
            x["process_burst"],
            2.0
        )
        x["network_burst"] = np.maximum(
            x["network_burst"],
            2.0
        )

    # Keep values finite and non-negative.
    x = x.replace([np.inf, -np.inf], 0)
    x = x.fillna(0)
    x = x.clip(lower=0)

    return x


# ============================================================
# BUILD ATTACK BENCHMARK
# ============================================================

rng = np.random.default_rng(42)

attack_types = [
    "process_burst",
    "network_burst",
    "discovery",
    "collection",
    "lateral_movement",
    "ioc_activity",
]

attack_frames = []

# 40 windows for each attack category.
# Each category is intentionally represented by multiple
# consecutive windows so temporal persistence can be evaluated.

for attack_type in attack_types:

    sample_indices = rng.choice(
        len(normal),
        size=40,
        replace=True,
    )

    base = normal.iloc[sample_indices].reset_index(drop=True)

    # Moderate variation prevents the benchmark from being
    # identical from row to row.
    variation = rng.uniform(
        0.90,
        1.10,
        size=base.shape,
    )

    attack = base * variation

    attack = make_attack(
        attack,
        attack_type,
        multiplier=1.0,
    )

    attack["attack_type"] = attack_type
    attack["label"] = 1

    attack_frames.append(attack)


attacks = pd.concat(
    attack_frames,
    ignore_index=True,
)

normal_benchmark = normal.copy()

normal_benchmark["attack_type"] = "normal"
normal_benchmark["label"] = 0

benchmark = pd.concat(
    [
        normal_benchmark,
        attacks,
    ],
    ignore_index=True,
)

# Shuffle only for the basic classification metrics.
benchmark = benchmark.sample(
    frac=1.0,
    random_state=42,
).reset_index(drop=True)


attack_dataset = benchmark.copy()

attack_dataset.to_csv(
    ATTACK_PATH,
    index=False,
)

print()
print("BENCHMARK DATASET")
print("-" * 62)
print(f"Normal windows : {len(normal_benchmark)}")
print(f"Attack windows : {len(attacks)}")
print(f"Total windows  : {len(benchmark)}")
print()
print("Attack categories:")
for name, count in attacks["attack_type"].value_counts().items():
    print(f"  {name:<20} {count}")


# ============================================================
# MODEL PREDICTIONS
# ============================================================

X = benchmark[FEATURES].copy()


# Isolation Forest
if_scores = if_model.score_samples(X)
if_anomaly = if_scores < IF_THRESHOLD


# LOF
# Keep DataFrame feature names to avoid sklearn warnings.
lof_scores = lof_model.score_samples(X)
lof_anomaly = lof_scores < LOF_THRESHOLD


# ============================================================
# ROBUST MAD
# ============================================================

median_series = pd.Series(median)

scale_series = pd.Series(robust_scale)

median_series = median_series.reindex(FEATURES)
scale_series = scale_series.reindex(FEATURES)

scale_series = scale_series.replace(
    [np.inf, -np.inf],
    np.nan,
).fillna(1.0)

scale_series = scale_series.clip(lower=1.0)

robust_z = (
    X - median_series
).abs().div(
    1.4826 * scale_series,
    axis=1,
)

robust_z = robust_z.replace(
    [np.inf, -np.inf],
    0,
).fillna(0)

robust_z = robust_z.clip(
    upper=6.0
)

robust_scores = robust_z.max(axis=1)

robust_anomaly = (
    robust_scores >= ROBUST_THRESHOLD
)


# ============================================================
# 2-OF-3 ENSEMBLE
# ============================================================

votes = (
    if_anomaly.astype(int)
    +
    lof_anomaly.astype(int)
    +
    robust_anomaly.astype(int)
)

ensemble_anomaly = votes >= 2


# ============================================================
# TEMPORAL PERSISTENCE
# ============================================================
#
# The benchmark contains attack windows in groups, but the
# shuffled dataframe cannot be used for temporal evaluation.
#
# Therefore we calculate a conservative persistence signal
# using the original attack category ordering.
#

ordered = pd.concat(
    [
        normal_benchmark,
        attacks,
    ],
    ignore_index=True,
)

X_ordered = ordered[FEATURES].copy()

if_ordered = (
    if_model.score_samples(X_ordered)
    < IF_THRESHOLD
)

lof_ordered = (
    lof_model.score_samples(X_ordered)
    < LOF_THRESHOLD
)

median_ordered = median_series
scale_ordered = scale_series

robust_z_ordered = (
    X_ordered - median_ordered
).abs().div(
    1.4826 * scale_ordered,
    axis=1,
)

robust_z_ordered = (
    robust_z_ordered
    .replace([np.inf, -np.inf], 0)
    .fillna(0)
    .clip(upper=6.0)
)

robust_score_ordered = robust_z_ordered.max(axis=1)

robust_ordered = (
    robust_score_ordered >= ROBUST_THRESHOLD
)

votes_ordered = (
    if_ordered.astype(int)
    + lof_ordered.astype(int)
    + robust_ordered.astype(int)
)

ensemble_ordered = votes_ordered >= 2

ensemble_series = pd.Series(
    ensemble_ordered.astype(int)
)

previous_1 = ensemble_series.shift(1).fillna(0).astype(bool)
previous_2 = ensemble_series.shift(2).fillna(0).astype(bool)

persistent_ordered = (
    ensemble_series.astype(bool)
    &
    (
        previous_1
        |
        previous_2
    )
)


# ============================================================
# BASIC CLASSIFICATION METRICS
# ============================================================

y_true = benchmark["label"].to_numpy()
y_pred = ensemble_anomaly.astype(int).to_numpy()

tp = int(((y_true == 1) & (y_pred == 1)).sum())
tn = int(((y_true == 0) & (y_pred == 0)).sum())
fp = int(((y_true == 0) & (y_pred == 1)).sum())
fn = int(((y_true == 1) & (y_pred == 0)).sum())

total = len(y_true)

accuracy = (
    (tp + tn) / total
    if total
    else 0
)

precision = (
    tp / (tp + fp)
    if (tp + fp)
    else 0
)

recall = (
    tp / (tp + fn)
    if (tp + fn)
    else 0
)

f1 = (
    2 * precision * recall / (precision + recall)
    if (precision + recall)
    else 0
)

fpr = (
    fp / (fp + tn)
    if (fp + tn)
    else 0
)

fnr = (
    fn / (fn + tp)
    if (fn + tp)
    else 0
)


# ============================================================
# PRINT RESULTS
# ============================================================

print()
print("=" * 62)
print("V3.4 ATTACK BENCHMARK RESULTS")
print("=" * 62)

print()
print("CONFUSION MATRIX")
print("-" * 62)
print(f"True Positive  : {tp}")
print(f"True Negative  : {tn}")
print(f"False Positive : {fp}")
print(f"False Negative : {fn}")

print()
print("PERFORMANCE")
print("-" * 62)
print(f"Accuracy       : {accuracy * 100:.2f}%")
print(f"Precision      : {precision * 100:.2f}%")
print(f"Recall         : {recall * 100:.2f}%")
print(f"F1 Score       : {f1 * 100:.2f}%")
print(f"FPR            : {fpr * 100:.2f}%")
print(f"FNR            : {fnr * 100:.2f}%")


# ============================================================
# PER-ATTACK PERFORMANCE
# ============================================================

print()
print("PER-ATTACK DETECTION")
print("-" * 62)

attack_result_rows = []

for attack_type in attack_types:

    mask = benchmark["attack_type"].eq(attack_type)

    total_attack = int(mask.sum())
    detected_attack = int(
        ensemble_anomaly[mask].sum()
    )

    detection_rate = (
        detected_attack / total_attack
        if total_attack
        else 0
    )

    print(
        f"{attack_type:<22}"
        f"{detected_attack:>3}/{total_attack:<3}"
        f"  {detection_rate * 100:>6.2f}%"
    )

    attack_result_rows.append(
        {
            "attack_type": attack_type,
            "samples": total_attack,
            "detected": detected_attack,
            "detection_rate": detection_rate,
        }
    )


# ============================================================
# SAVE RESULTS
# ============================================================

result_df = benchmark.copy()

result_df["if_score"] = if_scores
result_df["lof_score"] = lof_scores
result_df["robust_score"] = robust_scores

result_df["if_anomaly"] = (
    if_anomaly.astype(int)
)

result_df["lof_anomaly"] = (
    lof_anomaly.astype(int)
)

result_df["robust_anomaly"] = (
    robust_anomaly.astype(int)
)

result_df["votes"] = votes

result_df["ensemble_anomaly"] = (
    ensemble_anomaly.astype(int)
)

result_df.to_csv(
    RESULT_PATH,
    index=False,
)


# ============================================================
# SUMMARY JSON
# ============================================================

summary = {
    "version": "3.4",
    "normal_windows": int(len(normal_benchmark)),
    "attack_windows": int(len(attacks)),
    "total_windows": int(total),
    "true_positive": tp,
    "true_negative": tn,
    "false_positive": fp,
    "false_negative": fn,
    "accuracy": round(float(accuracy), 6),
    "precision": round(float(precision), 6),
    "recall": round(float(recall), 6),
    "f1": round(float(f1), 6),
    "false_positive_rate": round(float(fpr), 6),
    "false_negative_rate": round(float(fnr), 6),
    "detector": "V3.3 2-of-3 ensemble",
    "benchmark_type": "controlled synthetic attack-like telemetry",
}

summary_path = os.path.join(
    BASE_DIR,
    "datasets",
    "security_events",
    "v3_4_attack_benchmark_summary.json",
)

with open(summary_path, "w") as f:
    json.dump(
        summary,
        f,
        indent=2,
    )


print()
print("=" * 62)
print("V3.4 BENCHMARK COMPLETE")
print("=" * 62)

print(f"Results saved : {RESULT_PATH}")
print(f"Summary saved : {summary_path}")
print(f"Attack data   : {ATTACK_PATH}")

print()
print("IMPORTANT:")
print("This is a controlled benchmark.")
print("It is NOT real-world attack accuracy.")
print("Use the result to identify weaknesses before")
print("testing against an independent labeled dataset.")
