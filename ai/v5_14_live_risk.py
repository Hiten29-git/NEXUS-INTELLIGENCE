import json
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE / "data/v5_13/latest_live_monitor.json"
OUTPUT_FILE = BASE / "data/v5_14/latest_live_risk.json"


def clamp(value, low=0.0, high=100.0):
    return max(low, min(high, value))


def calculate_risk(data):
    features = data.get("features", {})

    anomaly = float(data.get("anomaly_score", 0))

    processes = float(
        features.get("process_execution_frequency", 0)
    )

    networks = float(
        features.get("network_connection_frequency", 0)
    )

    unique_processes = float(
        features.get("unique_processes", 0)
    )

    destinations = float(
        features.get("unique_destinations", 0)
    )

    iocs = float(
        features.get("ioc_matches", 0)
    )

    # -----------------------------
    # COMPONENT SCORES
    # -----------------------------

    ai_score = clamp(anomaly)

    # Process activity.
    process_score = clamp(
        processes * 3.0
        + unique_processes * 2.0
    )

    # Network activity.
    network_score = clamp(
        networks * 0.8
        + destinations * 2.5
    )

    # IoC evidence receives the strongest weight.
    ioc_score = clamp(iocs * 25.0)

    # -----------------------------
    # CONTEXTUAL RISK
    # -----------------------------

    risk = (
        ai_score * 0.45
        + process_score * 0.15
        + network_score * 0.20
        + ioc_score * 0.20
    )

    risk = clamp(risk)

    # -----------------------------
    # SEVERITY
    # -----------------------------

    if iocs > 0 and risk >= 70:
        severity = "CRITICAL"
    elif risk >= 70:
        severity = "HIGH"
    elif risk >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # -----------------------------
    # ACTION
    # -----------------------------

    if severity == "CRITICAL":
        action = "ESCALATE_AND_CONTAIN"
    elif severity == "HIGH":
        action = "ESCALATE"
    elif severity == "MEDIUM":
        action = "INVESTIGATE"
    else:
        action = "MONITOR"

    reasons = []

    if ai_score >= 30:
        reasons.append(
            f"AI anomaly score is elevated ({ai_score:.2f}/100)."
        )

    if processes >= 10:
        reasons.append(
            f"Elevated process activity ({int(processes)} events)."
        )

    if networks >= 20:
        reasons.append(
            f"Elevated network activity ({int(networks)} connections)."
        )

    if destinations >= 5:
        reasons.append(
            f"Multiple network destinations observed ({int(destinations)})."
        )

    if iocs > 0:
        reasons.append(
            f"{int(iocs)} IoC match(es) detected."
        )

    if not reasons:
        reasons.append(
            "No strong security signal identified."
        )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "V5.14",
        "risk_score": round(risk, 2),
        "severity": severity,
        "action": action,
        "components": {
            "ai_anomaly_score": round(ai_score, 2),
            "process_score": round(process_score, 2),
            "network_score": round(network_score, 2),
            "ioc_score": round(ioc_score, 2),
        },
        "features": features,
        "reasons": reasons,
        "source": "V5.13_REAL_TIME_MONITOR",
    }


def main():

    print("=" * 64)
    print("NEXUS INTELLIGENCE - V5.14 LIVE RISK ENGINE")
    print("=" * 64)

    if not INPUT_FILE.exists():
        print()
        print("ERROR: V5.13 live monitor output not found.")
        print(INPUT_FILE)
        return

    data = json.loads(
        INPUT_FILE.read_text(encoding="utf-8")
    )

    result = calculate_risk(data)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTPUT_FILE.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    print()
    print("LIVE RISK")
    print("-" * 64)

    print(
        f"AI anomaly score : "
        f"{result['components']['ai_anomaly_score']:.2f}/100"
    )

    print(
        f"Process score    : "
        f"{result['components']['process_score']:.2f}/100"
    )

    print(
        f"Network score    : "
        f"{result['components']['network_score']:.2f}/100"
    )

    print(
        f"IoC score        : "
        f"{result['components']['ioc_score']:.2f}/100"
    )

    print()
    print("FINAL RISK")
    print("-" * 64)

    print(
        f"Risk Score       : "
        f"{result['risk_score']:.2f}/100"
    )

    print(
        f"Severity         : "
        f"{result['severity']}"
    )

    print(
        f"Action           : "
        f"{result['action']}"
    )

    print()
    print("REASONS")
    print("-" * 64)

    for reason in result["reasons"]:
        print(f"- {reason}")

    print()
    print("Saved:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()
