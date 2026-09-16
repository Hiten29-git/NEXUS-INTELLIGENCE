import json
import os
from datetime import datetime, timezone

INPUT_FILE = "data/v5_10/latest_temporal_correlation.json"
OUTPUT_DIR = "data/v5_10_1"
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "latest_calibrated_risk.json"
)


def calculate_risk(data):

    correlations = data.get("correlations", [])

    if not correlations:
        return 0.0, "LOW", []


    # --------------------------------------------------
    # 1. TEMPORAL CORRELATION DENSITY
    # --------------------------------------------------

    correlation_score = min(
        20.0,
        len(correlations) / 200.0
    )


    # --------------------------------------------------
    # 2. HIGH-CONFIDENCE TEMPORAL RELATIONSHIPS
    # --------------------------------------------------

    high_confidence = sum(
        1
        for c in correlations
        if c.get("confidence", 0) >= 0.8
    )

    high_confidence_score = min(
        20.0,
        high_confidence / 50.0
    )


    # --------------------------------------------------
    # 3. IoC SIGNAL
    # --------------------------------------------------

    ioc_matches = sum(
        1
        for c in correlations
        if c.get("ioc_match", False)
    )

    ioc_score = min(
        30.0,
        ioc_matches * 10.0
    )


    # --------------------------------------------------
    # 4. DESTINATION NOVELTY
    # --------------------------------------------------

    destinations = set(
        c.get("destination")
        for c in correlations
        if c.get("destination")
    )

    novelty_score = min(
        15.0,
        len(destinations) / 20.0
    )


    # --------------------------------------------------
    # 5. TEMPORAL BURST
    # --------------------------------------------------

    burst_score = 0.0

    if len(correlations) >= 1000:
        burst_score = 15.0
    elif len(correlations) >= 500:
        burst_score = 10.0
    elif len(correlations) >= 100:
        burst_score = 5.0


    # --------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------

    risk = min(
        100.0,
        correlation_score
        + high_confidence_score
        + ioc_score
        + novelty_score
        + burst_score
    )

    risk = round(risk, 2)


    if risk >= 80:
        severity = "CRITICAL"
    elif risk >= 60:
        severity = "HIGH"
    elif risk >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"


    explanation = [
        f"{len(correlations)} temporal correlations analyzed.",
        f"{high_confidence} high-confidence temporal relationships.",
        f"{ioc_matches} IoC-linked correlations.",
        f"{len(destinations)} unique destinations observed.",
        f"Temporal risk score calculated as {risk}/100."
    ]

    return risk, severity, explanation


def main():

    print("=" * 68)
    print("NEXUS INTELLIGENCE - V5.10.1 CALIBRATED TEMPORAL RISK")
    print("=" * 68)


    if not os.path.exists(INPUT_FILE):

        print(f"Input not found: {INPUT_FILE}")
        return


    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)


    risk, severity, explanation = calculate_risk(data)


    result = {

        "timestamp":
            datetime.now(timezone.utc).isoformat(),

        "version":
            "V5.10.1",

        "source_version":
            "V5.10",

        "risk_score":
            risk,

        "severity":
            severity,

        "temporal_correlations":
            len(data.get("correlations", [])),

        "graph_nodes":
            data.get("graph_nodes", 0),

        "graph_edges":
            data.get("graph_edges", 0),

        "explanation":
            explanation,

        "method":
            "Calibrated temporal risk",

        "causal_claim":
            False
    }


    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )


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
    print("CALIBRATED RISK")
    print("-" * 68)

    print(
        f"Temporal correlations : "
        f"{result['temporal_correlations']}"
    )

    print(
        f"Graph nodes            : "
        f"{result['graph_nodes']}"
    )

    print(
        f"Graph edges            : "
        f"{result['graph_edges']}"
    )

    print(
        f"Risk score             : "
        f"{risk}/100"
    )

    print(
        f"Severity               : "
        f"{severity}"
    )


    print()
    print("EXPLANATION")
    print("-" * 68)

    for item in explanation:
        print(f"- {item}")


    print()
    print("=" * 68)
    print("V5.10.1 CALIBRATED RISK COMPLETE")
    print("=" * 68)

    print()
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
