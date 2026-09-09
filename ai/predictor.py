import pandas as pd
from pathlib import Path

RISK_FILE = "datasets/security_events/risk_results.csv"
OUTPUT_FILE = "datasets/security_events/prediction_results.csv"


def predict_attack_stage(row):

    process_freq = row["process_execution_frequency"]
    file_freq = row["file_access_frequency"]
    network_freq = row["network_connection_frequency"]
    ioc_matches = row["ioc_matches"]
    risk_score = row["risk_score"]

    evidence = []

    if ioc_matches >= 1:
        evidence.append("IoC match detected")

    if process_freq >= 5:
        evidence.append("elevated process execution")

    if network_freq >= 8:
        evidence.append("unusual network activity")

    if file_freq >= 8:
        evidence.append("high file/resource access")

    # Next-stage prediction
    if (
        ioc_matches >= 5
        and network_freq >= 8
        and risk_score >= 80
    ):
        stage = "Lateral Movement"
        confidence = 0.85

    elif (
        process_freq >= 7
        and network_freq >= 6
        and risk_score >= 70
    ):
        stage = "Credential Access"
        confidence = 0.78

    elif (
        file_freq >= 8
        and risk_score >= 70
    ):
        stage = "Collection"
        confidence = 0.74

    elif (
        network_freq >= 6
        and risk_score >= 60
    ):
        stage = "Network Discovery"
        confidence = 0.70

    elif risk_score >= 30:
        stage = "Suspicious Activity"
        confidence = 0.60

    else:
        stage = "No Significant Threat"
        confidence = 0.90

    return pd.Series({
        "predicted_stage": stage,
        "prediction_confidence": confidence,
        "evidence": (
            "; ".join(evidence)
            if evidence
            else "No significant evidence"
        )
    })


def main():

    print("\n===== NEXUS NEXT-STAGE PREDICTOR =====")

    if not Path(RISK_FILE).exists():
        raise FileNotFoundError(
            f"Risk file not found: {RISK_FILE}"
        )

    df = pd.read_csv(RISK_FILE)

    print(f"Profiles analyzed: {len(df)}")

    predictions = df.apply(
        predict_attack_stage,
        axis=1
    )

    results = pd.concat(
        [
            df[
                [
                    "user_id",
                    "risk_score",
                    "risk_level",
                    "anomaly_label",
                    "anomaly_score",
                    "ioc_matches",
                    "process_execution_frequency",
                    "file_access_frequency",
                    "network_connection_frequency",
                ]
            ],
            predictions,
        ],
        axis=1,
    )

    results.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n===== TOP 10 PREDICTIONS =====")

    print(
        results.sort_values(
            "risk_score",
            ascending=False
        )
        .head(10)
        .to_string(index=False)
    )

    print("\n===== PREDICTION DISTRIBUTION =====")

    print(
        results["predicted_stage"]
        .value_counts()
        .to_string()
    )

    print(
        f"\nSaved results to: {OUTPUT_FILE}"
    )

    print(
        "\nNext-stage prediction completed successfully."
    )


if __name__ == "__main__":
    main()
