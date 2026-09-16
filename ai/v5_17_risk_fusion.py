import json
from pathlib import Path

BASE = Path("data")

AI_FILE = BASE / "v5_13" / "latest_live_monitor.json"
RISK_FILE = BASE / "v5_14" / "latest_live_risk.json"
ADAPTIVE_FILE = BASE / "v5_15" / "latest_adaptive_baseline.json"
PERSISTENCE_FILE = BASE / "v5_16" / "latest_temporal_persistence.json"

OUTPUT = BASE / "v5_17" / "latest_risk_fusion.json"


def load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def get_number(data, *keys, default=0.0):
    for key in keys:
        value = data.get(key)
        if isinstance(value, (int, float)):
            return float(value)

    for container_key in ("components", "live_risk", "adaptive_risk"):
        nested = data.get(container_key)
        if isinstance(nested, dict):
            for key in keys:
                value = nested.get(key)
                if isinstance(value, (int, float)):
                    return float(value)

    return default


def severity_from_risk(risk):
    if risk >= 80:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 40:
        return "MEDIUM"
    return "LOW"


def action_from_severity(severity):
    if severity == "CRITICAL":
        return "ESCALATE"
    if severity == "HIGH":
        return "INVESTIGATE"
    if severity == "MEDIUM":
        return "INVESTIGATE"
    return "MONITOR"


def main():
    ai = load_json(AI_FILE)
    risk = load_json(RISK_FILE)
    adaptive = load_json(ADAPTIVE_FILE)
    persistence = load_json(PERSISTENCE_FILE)

    # V5.13 AI anomaly signal
    ai_score = get_number(
        ai,
        "anomaly_score",
        "ai_anomaly",
        "ai_score",
        default=0.0,
    )

    # V5.14 component signals
    network_score = get_number(
        risk,
        "network_score",
        "network",
        default=0.0,
    )

    process_score = get_number(
        risk,
        "process_score",
        "process",
        default=0.0,
    )

    ioc_score = get_number(
        risk,
        "ioc_score",
        "ioc",
        default=0.0,
    )

    # V5.15 adaptive baseline
    adaptive_score = get_number(
        adaptive,
        "adaptive_risk_score",
        "adaptive_score",
        "risk_score",
        default=0.0,
    )

    # V5.16 temporal persistence
    persistence_score = get_number(
        persistence,
        "persistence_score",
        "temporal_persistence",
        default=0.0,
    )

    # Prevent persistence from dominating the final score.
    persistence_cap = 60.0
    persistence_normalized = min(persistence_score, persistence_cap)

    # Weighted security-signal fusion.
    risk_score = (
        ai_score * 0.20
        + adaptive_score * 0.20
        + network_score * 0.15
        + process_score * 0.10
        + ioc_score * 0.10
        + persistence_normalized / persistence_cap * 100 * 0.25
    )

    risk_score = max(0.0, min(100.0, risk_score))

    severity = severity_from_risk(risk_score)
    action = action_from_severity(severity)

    reasons = []

    if ai_score >= 30:
        reasons.append(
            f"AI anomaly signal is elevated ({ai_score:.2f}/100)."
        )

    if adaptive_score >= 50:
        reasons.append(
            f"Behavior deviates significantly from the adaptive baseline ({adaptive_score:.2f}/100)."
        )

    if network_score >= 50:
        reasons.append(
            f"Network activity is elevated ({network_score:.2f}/100)."
        )

    if process_score >= 50:
        reasons.append(
            f"Process activity is elevated ({process_score:.2f}/100)."
        )

    if ioc_score > 0:
        reasons.append(
            f"Potential IoC signal detected ({ioc_score:.2f}/100)."
        )

    if persistence_score >= 50:
        reasons.append(
            f"Suspicious activity persists across multiple windows ({persistence_score:.2f}/100)."
        )

    if not reasons:
        reasons.append("No strong security signal identified.")

    result = {
        "version": "V5.17",
        "risk_score": round(risk_score, 2),
        "severity": severity,
        "action": action,
        "components": {
            "ai_anomaly": round(ai_score, 2),
            "adaptive_baseline": round(adaptive_score, 2),
            "network": round(network_score, 2),
            "process": round(process_score, 2),
            "ioc": round(ioc_score, 2),
            "temporal_persistence": round(persistence_score, 2),
        },
        "persistence_cap": persistence_cap,
        "reasons": reasons,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))

    print("=" * 64)
    print("NEXUS INTELLIGENCE - V5.17 RISK FUSION")
    print("=" * 64)

    print()
    print("FUSED SECURITY SIGNALS")
    print("-" * 64)
    print(f"AI anomaly           : {ai_score:.2f}/100")
    print(f"Adaptive baseline    : {adaptive_score:.2f}/100")
    print(f"Network              : {network_score:.2f}/100")
    print(f"Process              : {process_score:.2f}/100")
    print(f"IoC                  : {ioc_score:.2f}/100")
    print(f"Temporal persistence : {persistence_score:.2f}/100")

    print()
    print("FINAL FUSED RISK")
    print("-" * 64)
    print(f"Risk Score           : {risk_score:.2f}/100")
    print(f"Severity             : {severity}")
    print(f"Action               : {action}")

    print()
    print("REASONS")
    print("-" * 64)

    for reason in reasons:
        print(f"- {reason}")

    print()
    print("Saved:")
    print(OUTPUT)

    print()
    print("=" * 64)
    print("V5.17 RISK FUSION COMPLETE")
    print("=" * 64)


if __name__ == "__main__":
    main()
