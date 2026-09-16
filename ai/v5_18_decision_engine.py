import json
from pathlib import Path

INPUT = Path("data/v5_17/latest_risk_fusion.json")
OUTPUT = Path("data/v5_18/latest_decision.json")


def load_input():
    if not INPUT.exists():
        raise FileNotFoundError(f"Missing input: {INPUT}")

    return json.loads(INPUT.read_text())


def decide(risk_score, severity, components):
    reasons = []
    recommendations = []

    if risk_score >= 80 or severity == "CRITICAL":
        decision = "ESCALATE"
        response_level = "CRITICAL"

        recommendations.extend([
            "Require immediate analyst review.",
            "Consider isolating the affected endpoint after human approval.",
            "Review related processes, users, and network destinations.",
        ])

        reasons.append("Critical fused risk requires immediate escalation.")

    elif risk_score >= 60 or severity == "HIGH":
        decision = "CONTAIN"
        response_level = "HIGH"

        recommendations.extend([
            "Require SOC analyst investigation.",
            "Consider temporary containment after human approval.",
            "Inspect suspicious processes and network destinations.",
        ])

        reasons.append("High fused risk indicates coordinated suspicious activity.")

    elif risk_score >= 40 or severity == "MEDIUM":
        decision = "INVESTIGATE"
        response_level = "MEDIUM"

        recommendations.extend([
            "Investigate the affected activity.",
            "Review recent process and network behavior.",
        ])

        reasons.append("Medium risk warrants analyst investigation.")

    else:
        decision = "MONITOR"
        response_level = "LOW"

        recommendations.extend([
            "Continue monitoring.",
            "Collect additional behavioral evidence.",
        ])

        reasons.append("Risk remains within the monitoring range.")

    if components.get("network", 0) >= 70:
        recommendations.append(
            "Review unusually high network activity and destinations."
        )

    if components.get("temporal_persistence", 0) >= 70:
        recommendations.append(
            "Review persistent anomalous behavior across time windows."
        )

    if components.get("adaptive_baseline", 0) >= 60:
        recommendations.append(
            "Compare activity against the learned behavioral baseline."
        )

    if components.get("ioc", 0) > 0:
        recommendations.append(
            "Investigate matched indicators of compromise."
        )

    return decision, response_level, reasons, recommendations


def main():
    data = load_input()

    risk_score = float(data.get("risk_score", 0))
    severity = str(data.get("severity", "LOW"))

    components = data.get("components", {})
    if not isinstance(components, dict):
        components = {}

    decision, response_level, reasons, recommendations = decide(
        risk_score,
        severity,
        components,
    )

    result = {
        "version": "V5.18",
        "risk_score": round(risk_score, 2),
        "severity": severity,
        "decision": decision,
        "response_level": response_level,
        "source": "V5.17 Risk Fusion",
        "components": components,
        "reasons": reasons,
        "recommendations": recommendations,
        "human_approval_required": True,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))

    print("=" * 64)
    print("NEXUS INTELLIGENCE - V5.18 DECISION ENGINE")
    print("=" * 64)

    print()
    print("INPUT")
    print("-" * 64)
    print(f"Risk Score     : {risk_score:.2f}/100")
    print(f"Severity       : {severity}")

    print()
    print("DECISION")
    print("-" * 64)
    print(f"Decision       : {decision}")
    print(f"Response Level : {response_level}")

    print()
    print("REASONS")
    print("-" * 64)

    for reason in reasons:
        print(f"- {reason}")

    print()
    print("RECOMMENDED RESPONSE")
    print("-" * 64)

    for item in recommendations:
        print(f"- {item}")

    print()
    print(f"Human approval : {result['human_approval_required']}")
    print()
    print("Saved:")
    print(OUTPUT)

    print()
    print("=" * 64)
    print("V5.18 DECISION ENGINE COMPLETE")
    print("=" * 64)


if __name__ == "__main__":
    main()
