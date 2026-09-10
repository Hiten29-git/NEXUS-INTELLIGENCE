import pandas as pd
from pathlib import Path

INPUT_FILE = "datasets/security_events/prediction_results.csv"
OUTPUT_FILE = "datasets/security_events/explainability_results.csv"


def generate_explanation(row):

    reasons = []
    severity = []

    risk = row["risk_score"]
    ioc = row["ioc_matches"]
    process = row["process_execution_frequency"]
    files = row["file_access_frequency"]
    network = row["network_connection_frequency"]

    # Risk level
    if risk >= 80:
        severity.append("CRITICAL risk score")
    elif risk >= 60:
        severity.append("HIGH risk score")
    elif risk >= 30:
        severity.append("MEDIUM risk score")

    # IoC evidence
    if ioc >= 5:
        reasons.append(
            f"{ioc} IoC matches detected"
        )
    elif ioc > 0:
        reasons.append(
            f"{ioc} IoC match detected"
        )

    # Process behavior
    if process >= 7:
        reasons.append(
            f"elevated process execution ({process})"
        )

    # File behavior
    if files >= 8:
        reasons.append(
            f"high file/resource access ({files})"
        )

    # Network behavior
    if network >= 8:
        reasons.append(
            f"unusual network activity ({network})"
        )

    # Overall explanation
    if reasons:
        explanation = (
            "Threat indicators: "
            + "; ".join(reasons)
            + "."
        )
    else:
        explanation = (
            "No significant behavioral threat indicators."
        )

    # Confidence explanation
    confidence = row["prediction_confidence"]

    prediction_explanation = (
        f"Predicted next stage: "
        f"{row['predicted_stage']} "
        f"with {confidence * 100:.0f}% confidence."
    )

    return pd.Series({
        "severity_evidence": (
            "; ".join(severity)
            if severity
            else "LOW risk"
        ),
        "threat_explanation": explanation,
        "prediction_explanation": prediction_explanation
    })


def main():

    print("\n===== NEXUS EXPLAINABILITY ENGINE =====")

    if not Path(INPUT_FILE).exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE}"
        )

    df = pd.read_csv(INPUT_FILE)

    print(f"Profiles analyzed: {len(df)}")

    explanations = df.apply(
        generate_explanation,
        axis=1
    )

    results = pd.concat(
        [
            df[
                [
                    "user_id",
                    "risk_score",
                    "risk_level",
                    "predicted_stage",
                    "prediction_confidence",
                    "ioc_matches",
                    "process_execution_frequency",
                    "file_access_frequency",
                    "network_connection_frequency"
                ]
            ],
            explanations
        ],
        axis=1
    )

    results.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n===== TOP 10 EXPLAINABLE THREATS =====")

    top = results[
        results["risk_score"] >= 80
    ].sort_values(
        "risk_score",
        ascending=False
    ).head(10)

    for _, row in top.iterrows():

        print("\n--------------------------------")
        print(f"User: {row['user_id']}")
        print(f"Risk Score: {row['risk_score']}")
        print(f"Risk Level: {row['risk_level']}")
        print(
            f"Predicted Stage: "
            f"{row['predicted_stage']}"
        )
        print(
            f"Confidence: "
            f"{row['prediction_confidence'] * 100:.0f}%"
        )
        print(
            f"Why: "
            f"{row['threat_explanation']}"
        )

    print("\n===== OUTPUT =====")
    print(
        f"Saved results to: {OUTPUT_FILE}"
    )

    print(
        "\nExplainability completed successfully."
    )


if __name__ == "__main__":
    main()
