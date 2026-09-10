import pandas as pd


FEATURE_COLUMNS = [
    "login_frequency",
    "file_access_frequency",
    "process_execution_frequency",
    "network_connection_frequency",
    "ioc_matches",
]


def load_events(path: str) -> pd.DataFrame:
    """Load security events from a CSV file."""
    return pd.read_csv(path)


def build_features(events: pd.DataFrame) -> pd.DataFrame:
    """Convert raw security events into user-level features."""

    features = events.groupby("user_id").agg(
        login_frequency=(
            "event_type",
            lambda x: (x == "LOGIN").sum()
        ),
        file_access_frequency=(
            "event_type",
            lambda x: (x == "FILE_ACCESS").sum()
        ),
        process_execution_frequency=(
            "event_type",
            lambda x: (x == "PROCESS_EXECUTION").sum()
        ),
        network_connection_frequency=(
            "event_type",
            lambda x: (x == "NETWORK_CONNECTION").sum()
        ),
        ioc_matches=(
            "ioc_match",
            lambda x: (x == True).sum()
        ),
    )

    return features.reset_index()


if __name__ == "__main__":

    dataset_path = "datasets/security_events/security_events.csv"

    events = load_events(dataset_path)

    print("\n===== RAW SECURITY EVENTS =====")
    print(events)

    features = build_features(events)

    print("\n===== GENERATED SECURITY FEATURES =====")
    print(features)
