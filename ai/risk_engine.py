import pandas as pd


def calculate_risk(row):
    """
    Calculate a contextual security risk score from 0 to 100.

    This is a prototype risk model. The weights will be
    validated and improved during evaluation.
    """

    score = 0

    # Behavioral anomaly
    if row["anomaly_label"] == -1:
        score += 35

    # IoC evidence
    ioc_score = min(row["ioc_matches"] * 8, 25)
    score += ioc_score

    # Suspicious process behavior
    process_score = min(
        row["process_execution_frequency"] * 2,
        15
    )
    score += process_score

    # File access behavior
    file_score = min(
        row["file_access_frequency"] * 1.5,
        15
    )
    score += file_score

    # Network behavior
    network_score = min(
        row["network_connection_frequency"] * 0.5,
        10
    )
    score += network_score

    return min(round(score, 2), 100)


def risk_level(score):
    """Convert numerical risk into a security level."""

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def main():

    input_file = (
        "datasets/security_events/anomaly_results.csv"
    )

    output_file = (
        "datasets/security_events/risk_results.csv"
    )

    results = pd.read_csv(input_file)

    results["risk_score"] = results.apply(
        calculate_risk,
        axis=1
    )

    results["risk_level"] = results["risk_score"].apply(
        risk_level
    )

    results = results.sort_values(
        "risk_score",
        ascending=False
    )

    results.to_csv(
        output_file,
        index=False
    )

    print("\n===== NEXUS CONTEXTUAL RISK ENGINE =====")

    print(
        f"Profiles analyzed: {len(results)}"
    )

    print("\n===== TOP 10 RISKS =====")

    columns = [
        "user_id",
        "anomaly_label",
        "anomaly_score",
        "ioc_matches",
        "process_execution_frequency",
        "file_access_frequency",
        "network_connection_frequency",
        "risk_score",
        "risk_level",
    ]

    print(
        results[columns]
        .head(10)
        .to_string(index=False)
    )

    print("\n===== RISK DISTRIBUTION =====")

    print(
        results["risk_level"]
        .value_counts()
        .to_string()
    )

    print(
        f"\nSaved results to: {output_file}"
    )


if __name__ == "__main__":
    main()
