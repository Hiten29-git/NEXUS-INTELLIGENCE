import json
import os
from datetime import datetime, timezone

INPUT_FILE = "data/live/live_events_v4.jsonl"
OUTPUT_DIR = "data/v5_10"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "latest_temporal_correlation.json")

CORRELATION_SECONDS = 5


def parse_timestamp(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def load_events():
    events = []

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                ts = parse_timestamp(event.get("timestamp", ""))

                if ts:
                    event["_parsed_time"] = ts
                    events.append(event)

            except json.JSONDecodeError:
                continue

    events.sort(key=lambda x: x["_parsed_time"])

    return events


def correlate(events):
    process_events = [
        e for e in events
        if e.get("event_type") == "PROCESS_EXECUTION"
    ]

    network_events = [
        e for e in events
        if e.get("event_type") == "NETWORK_CONNECTION"
    ]

    correlations = []

    for network in network_events:

        network_time = network["_parsed_time"]

        nearest_process = None
        nearest_delta = None

        for process in process_events:

            if process["_parsed_time"] > network_time:
                break

            delta = (
                network_time - process["_parsed_time"]
            ).total_seconds()

            if delta <= CORRELATION_SECONDS:

                if nearest_delta is None or delta < nearest_delta:
                    nearest_process = process
                    nearest_delta = delta

        if nearest_process is not None:

            correlations.append({
                "relationship": "TEMPORAL_ASSOCIATION",

                "process_timestamp":
                    nearest_process["timestamp"],

                "network_timestamp":
                    network["timestamp"],

                "time_delta_seconds":
                    round(nearest_delta, 3),

                "process":
                    nearest_process.get("process"),

                "process_pid":
                    nearest_process.get("resource"),

                "destination":
                    network.get("destination_ip"),

                "destination_port":
                    network.get("destination_port"),

                "protocol":
                    network.get("protocol"),

                "ioc_match":
                    bool(network.get("ioc_match", False)),

                "confidence": round(
                    max(
                        0.0,
                        1.0 - (
                            nearest_delta /
                            CORRELATION_SECONDS
                        )
                    ),
                    3
                ),

                "evidence": (
                    "Process execution occurred within "
                    "the configured temporal correlation "
                    "window before the network event."
                ),

                "causal_claim": False
            })

    return correlations


def build_graph(correlations):

    nodes = {}
    edges = []

    for item in correlations:

        process_name = item.get("process") or "UNKNOWN_PROCESS"
        destination = item.get("destination") or "UNKNOWN_DESTINATION"

        process_id = f"process:{process_name}"
        destination_id = f"network:{destination}"

        if process_id not in nodes:

            nodes[process_id] = {
                "id": process_id,
                "type": "PROCESS",
                "label": process_name
            }

        if destination_id not in nodes:

            nodes[destination_id] = {
                "id": destination_id,
                "type": "NETWORK_DESTINATION",
                "label": destination
            }

        edges.append({
            "source": process_id,
            "target": destination_id,
            "relationship": "TEMPORAL_ASSOCIATION",
            "time_delta_seconds":
                item["time_delta_seconds"],
            "confidence":
                item["confidence"],
            "causal_claim": False
        })

    return list(nodes.values()), edges


def calculate_risk(correlations):

    if not correlations:
        return 0.0

    unique_destinations = len(
        set(
            c.get("destination")
            for c in correlations
            if c.get("destination")
        )
    )

    high_confidence = sum(
        1
        for c in correlations
        if c.get("confidence", 0) >= 0.7
    )

    risk = min(
        100.0,
        (
            len(correlations) * 0.8
            + unique_destinations * 1.5
            + high_confidence * 1.0
        )
    )

    return round(risk, 2)


def severity(risk):

    if risk >= 80:
        return "CRITICAL"

    if risk >= 60:
        return "HIGH"

    if risk >= 30:
        return "MEDIUM"

    return "LOW"


def main():

    print("=" * 68)
    print("NEXUS INTELLIGENCE - V5.10 TEMPORAL CORRELATION")
    print("=" * 68)

    if not os.path.exists(INPUT_FILE):

        print(f"Input file not found: {INPUT_FILE}")
        return

    events = load_events()

    correlations = correlate(events)

    nodes, edges = build_graph(correlations)

    risk = calculate_risk(correlations)

    result = {

        "timestamp":
            datetime.now(timezone.utc).isoformat(),

        "version":
            "V5.10",

        "input":
            INPUT_FILE,

        "correlation_window_seconds":
            CORRELATION_SECONDS,

        "events_analyzed":
            len(events),

        "process_events":
            sum(
                1 for e in events
                if e.get("event_type") ==
                "PROCESS_EXECUTION"
            ),

        "network_events":
            sum(
                1 for e in events
                if e.get("event_type") ==
                "NETWORK_CONNECTION"
            ),

        "temporal_correlations":
            len(correlations),

        "graph_nodes":
            len(nodes),

        "graph_edges":
            len(edges),

        "risk_score":
            risk,

        "severity":
            severity(risk),

        "causal_claims":
            False,

        "nodes":
            nodes,

        "edges":
            edges,

        "correlations":
            correlations[:100]
    }

    os.makedirs(OUTPUT_DIR, exist_ok=True)

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
    print("INPUT")
    print("-" * 68)
    print(f"Events analyzed       : {len(events)}")

    print()
    print("TEMPORAL CORRELATION")
    print("-" * 68)
    print(
        "Correlation window    : "
        f"{CORRELATION_SECONDS} seconds"
    )

    print(
        "Process events        : "
        f"{result['process_events']}"
    )

    print(
        "Network events        : "
        f"{result['network_events']}"
    )

    print(
        "Temporal correlations : "
        f"{len(correlations)}"
    )

    print()
    print("CORRELATED GRAPH")
    print("-" * 68)

    print(f"Nodes                 : {len(nodes)}")
    print(f"Edges                 : {len(edges)}")

    print()
    print("RISK")
    print("-" * 68)

    print(f"Risk score             : {risk}/100")
    print(f"Severity               : {severity(risk)}")

    print()
    print("IMPORTANT")
    print("-" * 68)
    print(
        "Relationships are temporal associations only."
    )
    print(
        "No causal process-to-network claim is made."
    )

    print()
    print("=" * 68)
    print("V5.10 TEMPORAL CORRELATION COMPLETE")
    print("=" * 68)

    print()
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
