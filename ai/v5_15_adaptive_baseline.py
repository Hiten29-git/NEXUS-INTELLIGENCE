from pathlib import Path
import json
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[1]

DATA_FILE = BASE_DIR / "datasets/security_events/live_training_windows.csv"
LIVE_FILE = BASE_DIR / "data/v5_13/latest_live_monitor.json"
OUTPUT_FILE = BASE_DIR / "data/v5_15/latest_adaptive_baseline.json"

FEATURES = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
    "ioc_matches",
]


def clamp(value, low=0.0, high=100.0):
    return max(low, min(high, float(value)))


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
    print("NEXUS INTELLIGENCE – V5.15 ADAPTIVE BASELINE")
    print("=" * 64)

    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Missing baseline dataset: {DATA_FILE}")

    if not LIVE_FILE.exists():
        raise FileNotFoundError(f"Missing live monitor output: {LIVE_FILE}")

    df = pd.read_csv(DATA_FILE)

    with open(LIVE_FILE, "r") as f:
        live = json.load(f)

    # Current live values
    live_features = live.get("features", {})

    # Support both the normal nested format and direct feature storage.
    if not live_features:
        live_features = live.get("live_features", {})

    current = {}
    for feature in FEATURES:
        value = live_features.get(feature, 0)
        try:
            current[feature] = float(value)
        except (TypeError, ValueError):
            current[feature] = 0.0

    scores = {}
    reasons = []

    for feature in FEATURES:
        baseline = pd.to_numeric(df[feature], errors="coerce").fillna(0)

        median = float(baseline.median())
        q1 = float(baseline.quantile(0.25))
        q3 = float(baseline.quantile(0.75))
        iqr = q3 - q1

        value = current[feature]

        # Robust deviation using IQR.
        # Small epsilon prevents division by zero.
        scale = max(iqr, 1.0)

        deviation = max(0.0, (value - median) / scale)

        # Convert deviation to a bounded risk score.
        score = clamp(deviation * 25.0)

        # IoC matches are treated as a direct security signal.
        if feature == "ioc_matches" and value > 0:
            score = 100.0

        scores[feature] = {
            "current": round(value, 3),
            "median": round(median, 3),
            "q1": round(q1, 3),
            "q3": round(q3, 3),
            "iqr": round(iqr, 3),
            "deviation": round(deviation, 3),
            "score": round(score, 2),
        }

        if score >= 50:
            reasons.append(
                f"{feature} is significantly above the learned baseline "
                f"({value:.0f} vs median {median:.0f})."
            )

    # Weighted adaptive risk.
    process_score = scores["process_execution_frequency"]["score"]
    network_score = scores["network_connection_frequency"]["score"]
    process_unique_score = scores["unique_processes"]["score"]
    destination_score = scores["unique_destinations"]["score"]
    ioc_score = scores["ioc_matches"]["score"]

    final_score = (
        process_score * 0.25
        + network_score * 0.25
        + process_unique_score * 0.15
        + destination_score * 0.15
        + ioc_score * 0.20
    )

    final_score = clamp(final_score)
    sev = severity(final_score)

    if final_score >= 80:
        action = "CONTAIN_AND_INVESTIGATE"
    elif final_score >= 60:
        action = "INVESTIGATE"
    elif final_score >= 40:
        action = "MONITOR_CLOSELY"
    else:
        action = "MONITOR"

    if not reasons:
        reasons.append("Current activity is within the learned behavioral baseline.")

    result = {
        "version": "V5.15",
        "baseline_windows": len(df),
        "features": current,
        "feature_analysis": scores,
        "adaptive_risk_score": round(final_score, 2),
        "severity": sev,
        "action": action,
        "reasons": reasons,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2)

    print()
    print("ADAPTIVE BASELINE")
    print("-" * 64)
    print(f"Baseline windows : {len(df)}")

    print()
    print("CURRENT ACTIVITY")
    print("-" * 64)

    for feature, value in current.items():
        print(f"{feature:<32}: {value:.0f}")

    print()
    print("ADAPTIVE RISK")
    print("-" * 64)
    print(f"Process deviation score     : {process_score:.2f}/100")
    print(f"Network deviation score    : {network_score:.2f}/100")
    print(f"Unique process deviation   : {process_unique_score:.2f}/100")
    print(f"Destination deviation       : {destination_score:.2f}/100")
    print(f"IoC score                   : {ioc_score:.2f}/100")

    print()
    print("FINAL RESULT")
    print("-" * 64)
    print(f"Adaptive Risk Score : {final_score:.2f}/100")
    print(f"Severity            : {sev}")
    print(f"Action              : {action}")

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
    print("V5.15 ADAPTIVE BASELINE COMPLETE")
    print("=" * 64)


if __name__ == "__main__":
    main()
