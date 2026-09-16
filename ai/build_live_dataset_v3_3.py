import os
import json
import pandas as pd
import numpy as np

# ============================================================
# NEXUS INTELLIGENCE — V3.3 LIVE DATASET BUILDER
# 16 behavioral features from real-time event telemetry
# ============================================================

EVENT_PATH = "data/live/live_events.jsonl"
OUTPUT_PATH = "datasets/security_events/live_training_windows_v3_3.csv"

WINDOW_SECONDS = 60

FEATURES = [
    "process_execution_frequency",
    "network_connection_frequency",
    "unique_processes",
    "unique_destinations",
    "unique_destination_ports",
    "process_burst",
    "network_burst",
    "process_diversity",
    "destination_diversity",
    "process_network_ratio",
    "new_processes_ratio",
    "new_destination_ratio",
    "established_ratio",
    "syn_sent_ratio",
    "closed_ratio",
    "ioc_matches",
]


# ============================================================
# LOAD EVENTS
# ============================================================

if not os.path.exists(EVENT_PATH):
    raise FileNotFoundError(
        f"Event file not found: {EVENT_PATH}"
    )

events = []

with open(EVENT_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        try:
            event = json.loads(line)
            events.append(event)
        except json.JSONDecodeError:
            continue


if not events:
    raise ValueError(
        "No valid events found in live_events.jsonl"
    )


df = pd.DataFrame(events)


# ============================================================
# REQUIRED EVENT COLUMNS
# ============================================================

defaults = {
    "timestamp": None,
    "event_type": "",
    "process": "",
    "destination": "",
    "destination_ip": "",
    "destination_port": "",
    "status": "",
    "ioc_match": False,
}

for column, default in defaults.items():

    if column not in df.columns:
        df[column] = default


df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce",
    utc=True
)

df = df.dropna(
    subset=["timestamp"]
).sort_values(
    "timestamp"
).reset_index(drop=True)


# ============================================================
# NORMALIZE VALUES
# ============================================================

df["event_type"] = (
    df["event_type"]
    .fillna("")
    .astype(str)
    .str.upper()
)

df["process"] = (
    df["process"]
    .fillna("")
    .astype(str)
)

df["destination_ip"] = (
    df["destination_ip"]
    .fillna("")
    .astype(str)
)

df["destination"] = (
    df["destination"]
    .fillna("")
    .astype(str)
)

df["status"] = (
    df["status"]
    .fillna("")
    .astype(str)
    .str.upper()
)

df["ioc_match"] = (
    df["ioc_match"]
    .fillna(False)
    .astype(bool)
)


# ============================================================
# DESTINATION NORMALIZATION
# ============================================================

def get_destination(row):

    ip = str(row["destination_ip"]).strip()

    destination = str(
        row["destination"]
    ).strip()

    if ip and ip.lower() != "nan":
        return ip

    if destination and destination.lower() != "nan":
        return destination

    return ""


df["normalized_destination"] = df.apply(
    get_destination,
    axis=1
)


# ============================================================
# PORT NORMALIZATION
# ============================================================

def get_port(value):

    try:
        value = str(value).strip()

        if not value or value.lower() == "nan":
            return ""

        return int(float(value))

    except Exception:
        return ""


df["normalized_port"] = (
    df["destination_port"]
    .apply(get_port)
)


# ============================================================
# EVENT CLASSIFICATION
# ============================================================

PROCESS_TYPES = {
    "PROCESS_EXECUTION",
    "PROCESS_START",
    "PROCESS",
}

NETWORK_TYPES = {
    "NETWORK_CONNECTION",
    "NETWORK",
    "TCP_CONNECTION",
    "UDP_CONNECTION",
}

FILE_TYPES = {
    "FILE_ACCESS",
    "FILE_CREATE",
    "FILE_MODIFY",
}


df["is_process"] = (
    df["event_type"].isin(PROCESS_TYPES)
)

df["is_network"] = (
    df["event_type"].isin(NETWORK_TYPES)
)

df["is_file"] = (
    df["event_type"].isin(FILE_TYPES)
)


# ============================================================
# WINDOW GENERATION
# ============================================================

start_time = df["timestamp"].min().floor("min")
end_time = df["timestamp"].max().ceil("min")

windows = []

current = start_time

while current < end_time:

    window_end = (
        current +
        pd.Timedelta(seconds=WINDOW_SECONDS)
    )

    window_events = df[
        (df["timestamp"] >= current)
        &
        (df["timestamp"] < window_end)
    ]

    if len(window_events) == 0:

        current = window_end
        continue

    windows.append(
        (
            current,
            window_end,
            window_events.copy()
        )
    )

    current = window_end


# ============================================================
# BUILD FEATURES
# ============================================================

rows = []

previous_processes = set()
previous_destinations = set()


for window_start, window_end, w in windows:

    # --------------------------------------------------------
    # PROCESS EVENTS
    # --------------------------------------------------------

    process_events = w[
        w["is_process"]
    ]

    process_count = len(process_events)

    processes = set(
        x.strip()
        for x in process_events["process"].tolist()
        if x.strip()
    )

    unique_processes = len(processes)

    # --------------------------------------------------------
    # NETWORK EVENTS
    # --------------------------------------------------------

    network_events = w[
        w["is_network"]
    ]

    network_count = len(network_events)

    destinations = set(
        x.strip()
        for x in network_events[
            "normalized_destination"
        ].tolist()
        if x.strip()
    )

    unique_destinations = len(destinations)

    ports = set()

    for p in network_events[
        "normalized_port"
    ].tolist():

        if p != "":
            ports.add(p)

    unique_ports = len(ports)

    # --------------------------------------------------------
    # IOC
    # --------------------------------------------------------

    ioc_count = int(
        w["ioc_match"].sum()
    )

    # --------------------------------------------------------
    # BURST FEATURES
    # --------------------------------------------------------

    process_burst = (
        process_count
        / max(1, WINDOW_SECONDS / 10)
    )

    network_burst = (
        network_count
        / max(1, WINDOW_SECONDS / 10)
    )

    # --------------------------------------------------------
    # DIVERSITY
    # --------------------------------------------------------

    process_diversity = (
        unique_processes
        / max(1, process_count)
    )

    destination_diversity = (
        unique_destinations
        / max(1, network_count)
    )

    # --------------------------------------------------------
    # PROCESS / NETWORK RELATIONSHIP
    # --------------------------------------------------------

    process_network_ratio = (
        process_count
        / max(1, network_count)
    )

    # --------------------------------------------------------
    # NEW PROCESS RATIO
    # --------------------------------------------------------

    if process_count > 0:

        new_processes = (
            processes - previous_processes
        )

        new_processes_ratio = (
            len(new_processes)
            / process_count
        )

    else:

        new_processes_ratio = 0.0

    # --------------------------------------------------------
    # NEW DESTINATION RATIO
    # --------------------------------------------------------

    if network_count > 0:

        new_destinations = (
            destinations
            - previous_destinations
        )

        new_destination_ratio = (
            len(new_destinations)
            / network_count
        )

    else:

        new_destination_ratio = 0.0

    # --------------------------------------------------------
    # NETWORK STATUS FEATURES
    # --------------------------------------------------------

    if network_count > 0:

        established_count = (
            network_events["status"]
            == "ESTABLISHED"
        ).sum()

        syn_count = (
            network_events["status"]
            .isin(
                {
                    "SYN_SENT",
                    "SYN-SENT",
                }
            )
        ).sum()

        closed_count = (
            network_events["status"]
            == "CLOSED"
        ).sum()

        established_ratio = (
            established_count
            / network_count
        )

        syn_sent_ratio = (
            syn_count
            / network_count
        )

        closed_ratio = (
            closed_count
            / network_count
        )

    else:

        established_ratio = 0.0
        syn_sent_ratio = 0.0
        closed_ratio = 0.0

    # --------------------------------------------------------
    # BUILD ROW
    # --------------------------------------------------------

    row = {

        "window_start":
            window_start.isoformat(),

        "process_execution_frequency":
            process_count,

        "network_connection_frequency":
            network_count,

        "unique_processes":
            unique_processes,

        "unique_destinations":
            unique_destinations,

        "unique_destination_ports":
            unique_ports,

        "process_burst":
            round(process_burst, 4),

        "network_burst":
            round(network_burst, 4),

        "process_diversity":
            round(process_diversity, 4),

        "destination_diversity":
            round(destination_diversity, 4),

        "process_network_ratio":
            round(process_network_ratio, 4),

        "new_processes_ratio":
            round(new_processes_ratio, 4),

        "new_destination_ratio":
            round(new_destination_ratio, 4),

        "established_ratio":
            round(established_ratio, 4),

        "syn_sent_ratio":
            round(syn_sent_ratio, 4),

        "closed_ratio":
            round(closed_ratio, 4),

        "ioc_matches":
            ioc_count,
    }

    rows.append(row)

    # --------------------------------------------------------
    # UPDATE HISTORY
    # --------------------------------------------------------

    previous_processes = processes
    previous_destinations = destinations


# ============================================================
# CREATE DATASET
# ============================================================

result = pd.DataFrame(rows)


# ============================================================
# CLEAN NUMERIC DATA
# ============================================================

for feature in FEATURES:

    result[feature] = pd.to_numeric(
        result[feature],
        errors="coerce"
    ).fillna(0.0)


# ============================================================
# REMOVE INVALID WINDOWS
# ============================================================

result = result[
    result[FEATURES].notna().all(axis=1)
].copy()


# ============================================================
# SORT
# ============================================================

result["window_start"] = pd.to_datetime(
    result["window_start"],
    errors="coerce",
    utc=True
)

result = result.sort_values(
    "window_start"
).reset_index(drop=True)


result["window_start"] = (
    result["window_start"]
    .dt.strftime("%Y-%m-%dT%H:%M:%S%z")
)


# ============================================================
# SAVE
# ============================================================

os.makedirs(
    os.path.dirname(OUTPUT_PATH),
    exist_ok=True
)

result.to_csv(
    OUTPUT_PATH,
    index=False
)


# ============================================================
# REPORT
# ============================================================

print()
print("=" * 60)
print("NEXUS INTELLIGENCE — V3.3 DATASET BUILDER")
print("=" * 60)

print(f"Raw events      : {len(df)}")
print(f"Windows created : {len(result)}")
print(f"Features        : {len(FEATURES)}")

print()
print("FEATURES")
print("-" * 60)

for i, feature in enumerate(
    FEATURES,
    start=1
):
    print(f"{i:02d}. {feature}")

print()
print("=" * 60)
print("DATASET SUMMARY")
print("=" * 60)

if len(result) > 0:

    print(
        result[FEATURES]
        .describe()
        .round(3)
        .to_string()
    )

else:

    print("No windows generated.")


print()
print("=" * 60)
print("DATASET SAVED")
print("=" * 60)

print(OUTPUT_PATH)

print()
print("V3.3 dataset generation complete.")
