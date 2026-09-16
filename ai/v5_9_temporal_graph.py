import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timezone

INPUT_FILE = "data/live/live_events_v4.jsonl"
GRAPH_FILE = "data/v5_8/latest_dynamic_graph.json"
OUTPUT_DIR = "data/v5_9"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "latest_temporal_graph.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_jsonl(path):
    events = []

    if not os.path.exists(path):
        return events

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events


def load_graph():
    if not os.path.exists(GRAPH_FILE):
        return {"nodes": [], "edges": []}

    with open(GRAPH_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_time(event):
    value = event.get("timestamp")

    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def build_temporal_graph(events, base_graph):
    nodes = list(base_graph.get("nodes", []))
    edges = list(base_graph.get("edges", []))

    node_ids = {n.get("id") for n in nodes}

    # Temporal activity statistics
    hourly_activity = Counter()
    process_activity = Counter()
    destination_activity = Counter()

    first_seen = {}
    last_seen = {}

    for event in events:
        timestamp = parse_time(event)

        if timestamp:
            hour_key = timestamp.strftime("%Y-%m-%d %H:00")
            hourly_activity[hour_key] += 1

        process = event.get("process")
        destination = event.get("destination_ip") or event.get("destination")

        if process:
            process_activity[process] += 1

        if destination:
            destination_activity[destination] += 1

        for value in [process, destination]:
            if not value:
                continue

            if value not in first_seen:
                first_seen[value] = event.get("timestamp")

            last_seen[value] = event.get("timestamp")

    # Add temporal process nodes
    for process, count in process_activity.items():
        node_id = f"process:{process}"

        if node_id not in node_ids:
            nodes.append({
                "id": node_id,
                "type": "PROCESS",
                "label": process,
                "event_count": count,
                "first_seen": first_seen.get(process),
                "last_seen": last_seen.get(process)
            })
            node_ids.add(node_id)

    # Add temporal destination nodes
    for destination, count in destination_activity.items():
        node_id = f"destination:{destination}"

        if node_id not in node_ids:
            nodes.append({
                "id": node_id,
                "type": "NETWORK_DESTINATION",
                "label": str(destination),
                "event_count": count,
                "first_seen": first_seen.get(destination),
                "last_seen": last_seen.get(destination)
            })
            node_ids.add(node_id)

    # Temporal relationships
    temporal_edges = []
    edge_keys = set()

    for event in events:
        process = event.get("process")
        destination = event.get("destination_ip") or event.get("destination")

        if not process or not destination:
            continue

        source = f"process:{process}"
        target = f"destination:{destination}"
        key = (source, target)

        if key not in edge_keys:
            temporal_edges.append({
                "source": source,
                "target": target,
                "relationship": "CONNECTS_TO",
                "temporal": True,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp")
            })
            edge_keys.add(key)

    edges.extend(temporal_edges)

    # Temporal risk calculation
    total_events = len(events)
    unique_processes = len(process_activity)
    unique_destinations = len(destination_activity)

    burst_score = 0

    if total_events >= 1000:
        burst_score += 30
    elif total_events >= 500:
        burst_score += 20
    elif total_events >= 100:
        burst_score += 10

    if unique_destinations >= 50:
        burst_score += 25
    elif unique_destinations >= 20:
        burst_score += 15
    elif unique_destinations >= 10:
        burst_score += 8

    if unique_processes >= 30:
        burst_score += 20
    elif unique_processes >= 15:
        burst_score += 12

    temporal_risk = min(100, burst_score)

    if temporal_risk >= 70:
        severity = "CRITICAL"
    elif temporal_risk >= 50:
        severity = "HIGH"
    elif temporal_risk >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "V5.9",
        "source_version": "V5.8",
        "temporal_risk": round(temporal_risk, 2),
        "severity": severity,
        "statistics": {
            "events": total_events,
            "unique_processes": unique_processes,
            "unique_destinations": unique_destinations,
            "temporal_edges": len(temporal_edges),
            "active_time_windows": len(hourly_activity)
        },
        "activity_by_hour": dict(hourly_activity),
        "nodes": nodes,
        "edges": edges,
        "explanation": [
            f"{total_events} live security events were analyzed.",
            f"{unique_processes} unique processes were observed.",
            f"{unique_destinations} unique network destinations were observed.",
            f"{len(temporal_edges)} temporal process-to-network relationships were identified.",
            f"Temporal risk calculated as {temporal_risk:.2f}/100."
        ]
    }


def main():
    print("=" * 68)
    print("NEXUS INTELLIGENCE - V5.9 TEMPORAL GRAPH")
    print("=" * 68)

    events = load_jsonl(INPUT_FILE)
    base_graph = load_graph()

    print()
    print("INPUT")
    print("-" * 68)
    print(f"Live events       : {len(events)}")
    print(f"Base graph nodes  : {len(base_graph.get('nodes', []))}")
    print(f"Base graph edges  : {len(base_graph.get('edges', []))}")

    result = build_temporal_graph(events, base_graph)

    print()
    print("TEMPORAL GRAPH")
    print("-" * 68)
    print(f"Events analyzed   : {result['statistics']['events']}")
    print(f"Processes         : {result['statistics']['unique_processes']}")
    print(f"Destinations      : {result['statistics']['unique_destinations']}")
    print(f"Temporal edges    : {result['statistics']['temporal_edges']}")
    print(f"Time windows      : {result['statistics']['active_time_windows']}")

    print()
    print("TEMPORAL RISK")
    print("-" * 68)
    print(f"Risk              : {result['temporal_risk']}/100")
    print(f"Severity          : {result['severity']}")

    print()
    print("EXPLANATION")
    print("-" * 68)

    for reason in result["explanation"]:
        print(f"- {reason}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print()
    print("=" * 68)
    print("V5.9 TEMPORAL GRAPH COMPLETE")
    print("=" * 68)
    print()
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
