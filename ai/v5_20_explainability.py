import json
from pathlib import Path
from datetime import datetime

INPUT = Path("data/v5_19/latest_attack_path.json")
OUTPUT = Path("data/v5_20/latest_explanation.json")


def main():

    print("=" * 64)
    print("NEXUS INTELLIGENCE – V5.20 EXPLAINABLE SECURITY")
    print("=" * 64)

    if not INPUT.exists():
        print(f"ERROR: Missing input file: {INPUT}")
        return

    data = json.loads(INPUT.read_text())

    source = data.get("source_decision", {})
    attack_path = data.get("attack_path", {})
    graph = data.get("graph", {})
    signals = data.get("signals", {})
    reasons = data.get("reasons", [])

    risk_score = float(source.get("risk_score", 0))
    severity = source.get("severity", "UNKNOWN")
    decision = source.get("decision", "UNKNOWN")

    # --------------------------------------------------
    # SIGNAL CONTRIBUTION
    # --------------------------------------------------

    signal_weights = {
        "ai_anomaly": 0.20,
        "adaptive_baseline": 0.20,
        "network": 0.20,
        "process": 0.15,
        "ioc": 0.10,
        "temporal_persistence": 0.15,
    }

    contributions = {}

    for signal, weight in signal_weights.items():
        value = float(signals.get(signal, 0))
        contributions[signal] = round(value * weight, 2)

    ranked = sorted(
        contributions.items(),
        key=lambda x: x[1],
        reverse=True
    )

    top_signals = [
        {
            "signal": name,
            "score": round(float(signals.get(name, 0)), 2),
            "contribution": contribution
        }
        for name, contribution in ranked
        if contribution > 0
    ]

    # --------------------------------------------------
    # ATTACK PATH EXPLANATION
    # --------------------------------------------------

    stages = attack_path.get("stages", [])

    graph_nodes = graph.get("nodes", [])
    graph_edges = graph.get("edges", [])

    path_explanation = []

    if stages:
        for index, stage in enumerate(stages, start=1):
            path_explanation.append({
                "order": index,
                "stage": stage
            })

    # --------------------------------------------------
    # HUMAN-READABLE EXPLANATION
    # --------------------------------------------------

    explanation = []

    explanation.append(
        f"NEXUS assigned a {severity} severity with a risk score "
        f"of {risk_score:.2f}/100."
    )

    if top_signals:
        strongest = top_signals[0]

        explanation.append(
            f"The strongest contributing signal was "
            f"{strongest['signal']} with a score of "
            f"{strongest['score']:.2f}/100."
        )

    if attack_path.get("status"):
        explanation.append(
            f"Attack-path analysis classified the activity as "
            f"{attack_path['status']}."
        )

    if stages:
        explanation.append(
            f"The observed activity spans {len(stages)} "
            f"security stage(s)."
        )

    if graph_nodes:
        explanation.append(
            f"The correlated security graph contains "
            f"{len(graph_nodes)} nodes and {len(graph_edges)} relationships."
        )

    if decision != "UNKNOWN":
        explanation.append(
            f"The resulting response decision is {decision}."
        )

    # --------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------

    if risk_score >= 80:
        confidence = "HIGH"
    elif risk_score >= 60:
        confidence = "MEDIUM-HIGH"
    elif risk_score >= 40:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # --------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------

    result = {
        "version": "V5.20",
        "generated_at": datetime.now().isoformat(),

        "source": {
            "risk_score": round(risk_score, 2),
            "severity": severity,
            "decision": decision,
        },

        "explainability": {
            "confidence": confidence,
            "top_signals": top_signals,
            "attack_path": path_explanation,
            "reasons": reasons,
            "human_explanation": explanation,
        },

        "graph_summary": {
            "nodes": len(graph_nodes),
            "relationships": len(graph_edges),
        },
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))

    # --------------------------------------------------
    # DISPLAY
    # --------------------------------------------------

    print()
    print("EXPLAINABLE SECURITY")
    print("-" * 64)

    print(f"Risk Score       : {risk_score:.2f}/100")
    print(f"Severity         : {severity}")
    print(f"Decision         : {decision}")
    print(f"Explanation      : {confidence}")

    print()
    print("TOP CONTRIBUTING SIGNALS")
    print("-" * 64)

    if top_signals:
        for item in top_signals:
            print(
                f"- {item['signal']}: "
                f"{item['score']:.2f}/100 "
                f"(contribution {item['contribution']:.2f})"
            )
    else:
        print("- No significant signal contribution.")

    print()
    print("ATTACK PATH")
    print("-" * 64)

    for item in path_explanation:
        print(f"{item['order']}. {item['stage']}")

    print()
    print("WHY NEXUS MADE THIS DECISION")
    print("-" * 64)

    for item in explanation:
        print(f"- {item}")

    print()
    print("Saved:")
    print(OUTPUT)

    print()
    print("=" * 64)
    print("V5.20 EXPLAINABLE SECURITY COMPLETE")
    print("=" * 64)


if __name__ == "__main__":
    main()
