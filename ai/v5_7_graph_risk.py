import json
import os
from datetime import datetime, timezone

V5_5_INPUT = "data/v5_5/latest_attack_stage.json"
V5_6_INPUT = "data/v5_6/latest_attack_path.json"

OUTPUT_DIR = "data/v5_7"
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "latest_graph_risk.json"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def clamp(value, low=0.0, high=100.0):
    return max(low, min(high, value))


def severity_from_score(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def build_graph_risk(v5_5, v5_6):

    # ---------------------------------------------------------
    # V5.5 = AUTHORITATIVE RISK SOURCE
    # ---------------------------------------------------------

    risk_raw = str(
        v5_5.get("risk_score", "0")
    )

    risk_score = float(
        risk_raw
        .replace("/100", "")
        .replace("%", "")
        .strip()
        or 0
    )

    severity = str(
        v5_5.get("severity", "LOW")
    ).upper()

    stage = str(
        v5_5.get(
            "attack_stage",
            v5_6.get(
                "attack_stage",
                "NO_SIGNIFICANT_THREAT"
            )
        )
    ).upper()

    confidence = float(
        str(
            v5_5.get(
                "confidence",
                v5_6.get("confidence", 0)
            )
        )
        .replace("%", "")
        .strip()
        or 0
    )

    # ---------------------------------------------------------
    # COPY EXISTING V5.6 GRAPH
    # ---------------------------------------------------------

    nodes = list(v5_6.get("nodes", []))
    edges = list(v5_6.get("edges", []))

    # ---------------------------------------------------------
    # GRAPH RISK PROPAGATION
    # ---------------------------------------------------------
    #
    # IMPORTANT:
    # Confidence does NOT artificially increase risk.
    #
    # V5.5 risk remains the base risk.
    # Attack-stage propagation is added only when an
    # actual significant stage exists.
    # ---------------------------------------------------------

    stage_weight = {
        "LATERAL_MOVEMENT": 25.0,
        "CREDENTIAL_ACCESS": 24.0,
        "COLLECTION": 18.0,
        "NETWORK_DISCOVERY": 14.0,
        "SUSPICIOUS_ACTIVITY": 10.0,
        "NO_SIGNIFICANT_THREAT": 0.0
    }

    propagation = stage_weight.get(stage, 5.0)

    if stage == "NO_SIGNIFICANT_THREAT":
        graph_risk = risk_score
    else:
        graph_risk = risk_score + (
            propagation * (confidence / 100.0)
        )

    graph_risk = clamp(graph_risk)

    # ---------------------------------------------------------
    # ADD ATTACK-STAGE NODE
    # ---------------------------------------------------------

    if stage != "NO_SIGNIFICANT_THREAT":

        nodes.append({
            "id": "attack_stage",
            "type": "ATTACK_STAGE",
            "label": stage,
            "risk": round(graph_risk, 2)
        })

        edges.append({
            "source": "device",
            "target": "attack_stage",
            "relationship": "INDICATES",
            "confidence": round(confidence, 2)
        })

    graph_severity = severity_from_score(graph_risk)

    # ---------------------------------------------------------
    # EXPLANATION
    # ---------------------------------------------------------

    reasons = [
        f"Base contextual risk from V5.5: {risk_score:.2f}/100."
    ]

    if stage == "NO_SIGNIFICANT_THREAT":
        reasons.append(
            "No significant attack-stage propagation applied."
        )
    else:
        reasons.append(
            f"{stage} contributed "
            f"{propagation * (confidence / 100.0):.2f} "
            "risk points."
        )

    reasons.append(
        f"Graph risk calculated as {graph_risk:.2f}/100."
    )

    # ---------------------------------------------------------
    # FINAL RESULT
    # ---------------------------------------------------------

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "V5.7",
        "source_versions": [
            "V5.5",
            "V5.6"
        ],

        "base_risk": round(risk_score, 2),
        "base_severity": severity,

        "attack_stage": stage,
        "prediction_confidence": round(confidence, 2),

        "graph_risk": round(graph_risk, 2),
        "graph_severity": graph_severity,

        "nodes": nodes,
        "edges": edges,

        "explanation": reasons
    }


def main():

    print("=" * 70)
    print("NEXUS INTELLIGENCE - V5.7 GRAPH RISK PROPAGATION")
    print("=" * 70)

    v5_5 = load_json(V5_5_INPUT)
    v5_6 = load_json(V5_6_INPUT)

    result = build_graph_risk(v5_5, v5_6)

    print()
    print("GRAPH RISK")
    print("-" * 70)

    print(
        f"Base Risk              : "
        f"{result['base_risk']:.2f}/100"
    )

    print(
        f"Attack Stage           : "
        f"{result['attack_stage']}"
    )

    print(
        f"Prediction Confidence : "
        f"{result['prediction_confidence']:.1f}%"
    )

    print(
        f"Graph Risk             : "
        f"{result['graph_risk']:.2f}/100"
    )

    print(
        f"Graph Severity         : "
        f"{result['graph_severity']}"
    )

    print()
    print("GRAPH")
    print("-" * 70)

    print(
        f"Nodes                  : "
        f"{len(result['nodes'])}"
    )

    print(
        f"Edges                  : "
        f"{len(result['edges'])}"
    )

    print()
    print("EXPLANATION")
    print("-" * 70)

    for reason in result["explanation"]:
        print(f"- {reason}")

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            result,
            f,
            indent=2
        )

    print()
    print("=" * 70)
    print("V5.7 GRAPH RISK PROPAGATION COMPLETE")
    print("=" * 70)

    print()
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
