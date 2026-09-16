import json
from pathlib import Path
from datetime import datetime

INPUT = Path("data/v5_20/latest_explanation.json")
OUTPUT = Path("data/v5_21/latest_prediction.json")


def predict_next_stage(data):

    source = data.get("source", {})
    explanation = data.get("explainability", {})
    attack_path = explanation.get("attack_path", [])
    top_signals = explanation.get("top_signals", [])

    risk = float(source.get("risk_score", 0))
    decision = source.get("decision", "UNKNOWN")

    stages = [
        item.get("stage", "")
        for item in attack_path
    ]

    signal_scores = {
        item.get("signal"): float(item.get("score", 0))
        for item in top_signals
    }

    network = signal_scores.get("network", 0)
    temporal = signal_scores.get("temporal_persistence", 0)
    baseline = signal_scores.get("adaptive_baseline", 0)
    ai = signal_scores.get("ai_anomaly", 0)
    process = signal_scores.get("process", 0)
    ioc = signal_scores.get("ioc", 0)

    candidates = []

    # --------------------------------------------------
    # DISCOVERY
    # --------------------------------------------------

    discovery_score = 0

    if network >= 60:
        discovery_score += 30

    if network >= 80:
        discovery_score += 15

    if process >= 50:
        discovery_score += 15

    if risk >= 50:
        discovery_score += 10

    candidates.append({
        "stage": "Discovery",
        "score": min(discovery_score, 100),
        "reason": "Elevated network/process activity may precede discovery behavior."
    })

    # --------------------------------------------------
    # CREDENTIAL ACCESS
    # --------------------------------------------------

    credential_score = 0

    if process >= 60:
        credential_score += 25

    if ai >= 60:
        credential_score += 20

    if baseline >= 60:
        credential_score += 15

    if risk >= 70:
        credential_score += 20

    candidates.append({
        "stage": "Credential Access",
        "score": min(credential_score, 100),
        "reason": "Behavioral deviation and process activity may indicate preparation for credential-focused activity."
    })

    # --------------------------------------------------
    # LATERAL MOVEMENT
    # --------------------------------------------------

    lateral_score = 0

    if network >= 70:
        lateral_score += 35

    if network >= 90:
        lateral_score += 20

    if temporal >= 70:
        lateral_score += 15

    if risk >= 60:
        lateral_score += 15

    candidates.append({
        "stage": "Lateral Movement",
        "score": min(lateral_score, 100),
        "reason": "Persistent elevated network activity can indicate movement between systems."
    })

    # --------------------------------------------------
    # COLLECTION
    # --------------------------------------------------

    collection_score = 0

    if process >= 50:
        collection_score += 20

    if baseline >= 60:
        collection_score += 20

    if temporal >= 70:
        collection_score += 15

    if risk >= 60:
        collection_score += 15

    candidates.append({
        "stage": "Collection",
        "score": min(collection_score, 100),
        "reason": "Persistent anomalous behavior may precede collection of valuable resources."
    })

    # --------------------------------------------------
    # COMMAND & CONTROL
    # --------------------------------------------------

    c2_score = 0

    if network >= 80:
        c2_score += 40

    if temporal >= 70:
        c2_score += 20

    if ai >= 40:
        c2_score += 15

    if risk >= 60:
        c2_score += 15

    candidates.append({
        "stage": "Command & Control",
        "score": min(c2_score, 100),
        "reason": "Strong persistent network activity may indicate continued external communication."
    })

    # --------------------------------------------------
    # PERSISTENCE
    # --------------------------------------------------

    persistence_score = 0

    if temporal >= 80:
        persistence_score += 35

    if baseline >= 60:
        persistence_score += 20

    if risk >= 60:
        persistence_score += 15

    candidates.append({
        "stage": "Persistence",
        "score": min(persistence_score, 100),
        "reason": "Repeated anomalous behavior across time windows increases persistence likelihood."
    })

    # --------------------------------------------------
    # REMOVE CURRENTLY OBSERVED STAGE
    # --------------------------------------------------

    current_stage = stages[-1] if stages else ""

    for candidate in candidates:

        if candidate["stage"].lower() in current_stage.lower():
            candidate["score"] = max(
                0,
                candidate["score"] - 20
            )

    candidates.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    best = candidates[0]

    # --------------------------------------------------
    # CONFIDENCE BAND
    # --------------------------------------------------

    if best["score"] >= 80:
        confidence = "HIGH"
    elif best["score"] >= 60:
        confidence = "MEDIUM-HIGH"
    elif best["score"] >= 40:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # --------------------------------------------------
    # MONITORING RECOMMENDATIONS
    # --------------------------------------------------

    monitoring = []

    if best["stage"] == "Discovery":
        monitoring = [
            "Monitor unusual destination discovery activity.",
            "Track newly contacted internal resources.",
            "Correlate process and network events."
        ]

    elif best["stage"] == "Credential Access":
        monitoring = [
            "Monitor unusual authentication-related activity.",
            "Watch for abnormal process execution.",
            "Review behavior against the learned baseline."
        ]

    elif best["stage"] == "Lateral Movement":
        monitoring = [
            "Monitor connections to previously unseen destinations.",
            "Correlate source and destination entities.",
            "Increase scrutiny of repeated network activity."
        ]

    elif best["stage"] == "Collection":
        monitoring = [
            "Monitor unusual resource access.",
            "Track repeated access to sensitive resources.",
            "Correlate process and file activity."
        ]

    elif best["stage"] == "Command & Control":
        monitoring = [
            "Monitor persistent external destinations.",
            "Correlate network activity with executing processes.",
            "Investigate unusual communication patterns."
        ]

    elif best["stage"] == "Persistence":
        monitoring = [
            "Monitor repeated anomalous activity.",
            "Track recurring processes and sessions.",
            "Compare future windows against the adaptive baseline."
        ]

    else:
        monitoring = [
            "Continue monitoring the endpoint.",
            "Correlate future events with existing security signals."
        ]

    return {
        "predicted_stage": best["stage"],
        "prediction_score": round(best["score"], 2),
        "confidence": confidence,
        "reason": best["reason"],
        "current_stage": current_stage,
        "risk_score": risk,
        "decision": decision,
        "candidate_stages": candidates,
        "monitoring_recommendations": monitoring
    }


def main():

    print("=" * 64)
    print("NEXUS INTELLIGENCE – V5.21 NEXT-STAGE PREDICTION")
    print("=" * 64)

    if not INPUT.exists():
        print(f"ERROR: Missing input file: {INPUT}")
        return

    data = json.loads(INPUT.read_text())

    prediction = predict_next_stage(data)

    result = {
        "version": "V5.21",
        "generated_at": datetime.now().isoformat(),
        "prediction": prediction
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(result, indent=2)
    )

    print()
    print("CURRENT SECURITY STATE")
    print("-" * 64)
    print(
        f"Risk Score       : "
        f"{prediction['risk_score']:.2f}/100"
    )
    print(
        f"Decision         : "
        f"{prediction['decision']}"
    )

    print()
    print("NEXT-STAGE PREDICTION")
    print("-" * 64)

    print(
        f"Predicted Stage  : "
        f"{prediction['predicted_stage']}"
    )

    print(
        f"Prediction Score : "
        f"{prediction['prediction_score']:.2f}/100"
    )

    print(
        f"Confidence       : "
        f"{prediction['confidence']}"
    )

    print()
    print("REASON")
    print("-" * 64)
    print(
        f"- {prediction['reason']}"
    )

    print()
    print("CANDIDATE STAGES")
    print("-" * 64)

    for candidate in prediction["candidate_stages"]:
        print(
            f"- {candidate['stage']}: "
            f"{candidate['score']:.2f}/100"
        )

    print()
    print("RECOMMENDED MONITORING")
    print("-" * 64)

    for item in prediction["monitoring_recommendations"]:
        print(f"- {item}")

    print()
    print("Saved:")
    print(OUTPUT)

    print()
    print("=" * 64)
    print("V5.21 NEXT-STAGE PREDICTION COMPLETE")
    print("=" * 64)


if __name__ == "__main__":
    main()
