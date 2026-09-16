import json
from pathlib import Path
import pandas as pd

INPUT_FILE = Path("data/v5_15/latest_adaptive_baseline.json")
WINDOW_FILE = Path("datasets/security_events/live_training_windows.csv")
OUTPUT_FILE = Path("data/v5_16/latest_temporal_persistence.json")

FEATURES = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
]

def severity(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"

def main():
    print("=" * 64)
    print("NEXUS INTELLIGENCE - V5.16 TEMPORAL PERSISTENCE")
    print("=" * 64)

    if not WINDOW_FILE.exists():
        raise FileNotFoundError(f"Missing: {WINDOW_FILE}")

    df = pd.read_csv(WINDOW_FILE)

    if len(df) < 20:
        raise ValueError("At least 20 windows are required.")

    # Robust baseline using median + MAD.
    baseline = {}
    for feature in FEATURES:
        values = pd.to_numeric(df[feature], errors="coerce").fillna(0)
        median = float(values.median())
        mad = float((values - median).abs().median())

        # Prevent zero-MAD baselines from creating infinite deviation.
        scale = max(mad * 1.4826, 1.0)

        baseline[feature] = {
            "median": median,
            "scale": scale,
        }

    scores = []

    for _, row in df.iterrows():
        deviations = []

        for feature in FEATURES:
            value = float(row[feature])
            med = baseline[feature]["median"]
            scale = baseline[feature]["scale"]

            z = abs(value - med) / scale
            deviations.append(min(z / 5.0, 1.0))

        scores.append(sum(deviations) / len(deviations) * 100)

    df["persistence_anomaly_score"] = scores

    # A window is suspicious when its combined deviation is substantial.
    threshold = 60.0
    df["suspicious"] = df["persistence_anomaly_score"] >= threshold

    # Consecutive suspicious windows.
    streak = 0
    streaks = []

    for suspicious in df["suspicious"]:
        if suspicious:
            streak += 1
        else:
            streak = 0
        streaks.append(streak)

    df["suspicious_streak"] = streaks

    max_streak = int(df["suspicious_streak"].max())
    suspicious_windows = int(df["suspicious"].sum())

    # Persistence score rewards repeated anomalies rather than one spike.
    persistence_score = min(
        100.0,
        suspicious_windows * 8.0 + max_streak * 12.0
    )

    sev = severity(persistence_score)

    if persistence_score >= 80:
        action = "ESCALATE"
    elif persistence_score >= 60:
        action = "INVESTIGATE"
    elif persistence_score >= 40:
        action = "MONITOR"
    else:
        action = "MONITOR"

    reasons = []

    if suspicious_windows:
        reasons.append(
            f"{suspicious_windows} anomalous windows detected."
        )

    if max_streak >= 2:
        reasons.append(
            f"Maximum consecutive anomaly streak: {max_streak} windows."
        )

    if max_streak >= 3:
        reasons.append(
            "Persistent anomalous behavior detected across multiple windows."
        )

    if not reasons:
        reasons.append("No persistent anomalous behavior identified.")

    result = {
        "version": "V5.16",
        "windows_analyzed": len(df),
        "suspicious_windows": suspicious_windows,
        "maximum_streak": max_streak,
        "persistence_score": round(persistence_score, 2),
        "severity": sev,
        "action": action,
        "threshold": threshold,
        "reasons": reasons,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(result, indent=2))

    print()
    print("TEMPORAL ANALYSIS")
    print("-" * 64)
    print(f"Windows analyzed       : {len(df)}")
    print(f"Suspicious windows     : {suspicious_windows}")
    print(f"Maximum anomaly streak : {max_streak}")

    print()
    print("PERSISTENCE RESULT")
    print("-" * 64)
    print(f"Persistence score      : {persistence_score:.2f}/100")
    print(f"Severity               : {sev}")
    print(f"Action                 : {action}")

    print()
    print("REASONS")
    print("-" * 64)

    for reason in reasons:
        print(f"- {reason}")

    print()
    print("Saved:")
    print(OUTPUT_FILE)

    print()
    print("=" * 64)
    print("V5.16 TEMPORAL PERSISTENCE COMPLETE")
    print("=" * 64)

if __name__ == "__main__":
    main()
