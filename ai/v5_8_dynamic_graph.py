import json
import os
from datetime import datetime, timezone
from collections import defaultdict


# ============================================================
# NEXUS INTELLIGENCE - V5.8 DYNAMIC EVIDENCE GRAPH
# ============================================================

INPUT_FILE = "data/live/live_events_v4.jsonl"
OUTPUT_DIR = "data/v5_8"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "latest_dynamic_graph.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# HELPERS
# ============================================================

def safe_text(value):
    if value is None:
        return None

    value = str(value).strip()

    if value.lower() in ("", "none", "null", "nan"):
        return None

    return value


def add_node(nodes, node_id, node_type, label, properties=None):
    if not node_id:
        return

    if node_id not in nodes:
        nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "properties": properties or {}
        }


def add_edge(edges, source, target, relationship, evidence=None):
    if not source or not target:
        return

    edge = {
        "source": source,
        "target": target,
        "relationship": relationship
    }

    if evidence:
        edge["evidence"] = evidence

    # Avoid duplicate relationships
    for existing in edges:
        if (
            existing["source"] == source
            and existing["target"] == target
            and existing["relationship"] == relationship
        ):
            return

    edges.append(edge)


def load_events():
    events = []

    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        return events

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
                if isinstance(event, dict):
                    events.append(event)
            except json.JSONDecodeError:
                continue

    return events


# ============================================================
# BUILD DYNAMIC GRAPH
# ============================================================

def build_dynamic_graph(events):

    nodes = {}
    edges = []

    counters = defaultdict(int)

    users = set()
    devices = set()
    processes = set()
    destinations = set()
    resources = set()

    ioc_count = 0

    # --------------------------------------------------------
    # Process every live event
    # --------------------------------------------------------

    for event in events:

        user = safe_text(
            event.get("user_id") or event.get("user")
        )

        device = safe_text(
            event.get("device_id") or event.get("device")
        )

        process = safe_text(
            event.get("process")
        )

        parent_process = safe_text(
            event.get("parent_process")
        )

        destination_ip = safe_text(
            event.get("destination_ip")
            or event.get("destination")
        )

        destination_port = safe_text(
            event.get("destination_port")
        )

        resource = safe_text(
            event.get("resource")
        )

        event_type = safe_text(
            event.get("event_type")
        ) or "UNKNOWN"

        ioc_match = event.get("ioc_match", False)

        # ----------------------------------------------------
        # USER
        # ----------------------------------------------------

        if user:
            user_id = f"user:{user}"

            users.add(user)

            add_node(
                nodes,
                user_id,
                "USER",
                user,
                {
                    "source": "live_telemetry"
                }
            )

        # ----------------------------------------------------
        # DEVICE
        # ----------------------------------------------------

        if device:
            device_id = f"device:{device}"

            devices.add(device)

            add_node(
                nodes,
                device_id,
                "DEVICE",
                device,
                {
                    "source": "live_telemetry"
                }
            )

            if user:
                add_edge(
                    edges,
                    f"user:{user}",
                    device_id,
                    "USES"
                )

        # ----------------------------------------------------
        # PROCESS
        # ----------------------------------------------------

        if process and device:

            process_id = f"process:{process}"

            processes.add(process)

            add_node(
                nodes,
                process_id,
                "PROCESS",
                process,
                {
                    "source": "live_telemetry"
                }
            )

            add_edge(
                edges,
                f"device:{device}",
                process_id,
                "EXECUTES",
                {
                    "event_type": event_type
                }
            )

            counters["process_events"] += 1

            # Parent-child process relationship
            if parent_process and parent_process not in ("0", "1"):

                parent_id = f"process:{parent_process}"

                add_node(
                    nodes,
                    parent_id,
                    "PROCESS",
                    parent_process,
                    {
                        "source": "live_telemetry"
                    }
                )

                add_edge(
                    edges,
                    parent_id,
                    process_id,
                    "SPAWNS"
                )

        # ----------------------------------------------------
        # NETWORK DESTINATION
        # ----------------------------------------------------

        if destination_ip and device:

            destination_id = f"destination:{destination_ip}"

            destinations.add(destination_ip)

            label = destination_ip

            if destination_port:
                label = f"{destination_ip}:{destination_port}"

            add_node(
                nodes,
                destination_id,
                "NETWORK_DESTINATION",
                label,
                {
                    "ip": destination_ip,
                    "port": destination_port
                }
            )

            add_edge(
                edges,
                f"device:{device}",
                destination_id,
                "CONNECTS_TO",
                {
                    "event_type": event_type,
                    "port": destination_port
                }
            )

            counters["network_events"] += 1

            # Process -> network relationship
            if process:
                add_edge(
                    edges,
                    f"process:{process}",
                    destination_id,
                    "CONNECTS_TO",
                    {
                        "event_type": event_type
                    }
                )

        # ----------------------------------------------------
        # RESOURCE
        # ----------------------------------------------------

        if resource and device:

            resource_id = f"resource:{resource}"

            resources.add(resource)

            add_node(
                nodes,
                resource_id,
                "RESOURCE",
                resource
            )

            add_edge(
                edges,
                f"device:{device}",
                resource_id,
                "ACCESSES",
                {
                    "event_type": event_type
                }
            )

            counters["resource_events"] += 1

        # ----------------------------------------------------
        # IOC
        # ----------------------------------------------------

        if ioc_match is True or str(ioc_match).lower() == "true":

            ioc_count += 1

            ioc_id = f"ioc:{ioc_count}"

            add_node(
                nodes,
                ioc_id,
                "IOC",
                f"IOC-{ioc_count}",
                {
                    "matched": True
                }
            )

            if process:
                add_edge(
                    edges,
                    f"process:{process}",
                    ioc_id,
                    "MATCHES_IOC"
                )

            elif device:
                add_edge(
                    edges,
                    f"device:{device}",
                    ioc_id,
                    "MATCHES_IOC"
                )


    # ========================================================
    # GRAPH RISK
    # ========================================================

    process_events = counters["process_events"]
    network_events = counters["network_events"]
    resource_events = counters["resource_events"]

    unique_processes = len(processes)
    unique_destinations = len(destinations)

    # Evidence-based graph score.
    # This is a prototype graph-risk score, not a validated
    # probability of compromise.
    graph_score = 0.0

    graph_score += min(process_events * 0.5, 15.0)
    graph_score += min(network_events * 1.0, 20.0)
    graph_score += min(unique_processes * 1.5, 15.0)
    graph_score += min(unique_destinations * 2.0, 15.0)
    graph_score += min(resource_events * 0.5, 10.0)
    graph_score += min(ioc_count * 10.0, 40.0)

    graph_score = min(graph_score, 100.0)

    if ioc_count > 0 and graph_score >= 60:
        severity = "CRITICAL"
    elif graph_score >= 70:
        severity = "CRITICAL"
    elif graph_score >= 45:
        severity = "HIGH"
    elif graph_score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"


    # ========================================================
    # GRAPH PATH SUMMARY
    # ========================================================

    path_patterns = []

    if users and devices:
        path_patterns.append("USER -> DEVICE")

    if devices and processes:
        path_patterns.append("DEVICE -> PROCESS")

    if processes and destinations:
        path_patterns.append("PROCESS -> NETWORK_DESTINATION")

    if devices and resources:
        path_patterns.append("DEVICE -> RESOURCE")

    if ioc_count > 0:
        path_patterns.append("PROCESS/DEVICE -> IOC")


    # ========================================================
    # EXPLANATION
    # ========================================================

    explanation = []

    explanation.append(
        f"Dynamic graph contains {len(nodes)} nodes and {len(edges)} relationships."
    )

    if process_events:
        explanation.append(
            f"{process_events} process execution events contributed to the graph."
        )

    if network_events:
        explanation.append(
            f"{network_events} network events contributed to the graph."
        )

    if resource_events:
        explanation.append(
            f"{resource_events} resource access events contributed to the graph."
        )

    if ioc_count:
        explanation.append(
            f"{ioc_count} IoC match(es) increased graph risk."
        )

    if not ioc_count and graph_score < 25:
        explanation.append(
            "No strong malicious graph evidence was observed."
        )

    if graph_score >= 45:
        explanation.append(
            "Multiple connected security entities increased contextual graph risk."
        )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "V5.8",
        "source": "live_events_v4.jsonl",

        "graph_risk": round(graph_score, 2),
        "severity": severity,

        "statistics": {
            "events_processed": len(events),
            "users": len(users),
            "devices": len(devices),
            "processes": len(processes),
            "destinations": len(destinations),
            "resources": len(resources),
            "ioc_matches": ioc_count,
            "nodes": len(nodes),
            "edges": len(edges)
        },

        "path_patterns": path_patterns,

        "explanation": explanation,

        "nodes": list(nodes.values()),
        "edges": edges
    }

    return result


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("NEXUS INTELLIGENCE - V5.8 DYNAMIC EVIDENCE GRAPH")
    print("=" * 70)

    print()
    print(f"Input : {INPUT_FILE}")

    events = load_events()

    print(f"Events loaded : {len(events)}")

    if not events:
        print()
        print("No live events available.")
        print("Start the NEXUS collector first.")
        return

    result = build_dynamic_graph(events)

    print()
    print("DYNAMIC GRAPH")
    print("-" * 70)

    print(f"Events processed      : {result['statistics']['events_processed']}")
    print(f"Users                 : {result['statistics']['users']}")
    print(f"Devices               : {result['statistics']['devices']}")
    print(f"Processes             : {result['statistics']['processes']}")
    print(f"Destinations          : {result['statistics']['destinations']}")
    print(f"Resources             : {result['statistics']['resources']}")
    print(f"IoC matches           : {result['statistics']['ioc_matches']}")
    print(f"Nodes                 : {result['statistics']['nodes']}")
    print(f"Edges                 : {result['statistics']['edges']}")

    print()
    print("GRAPH RISK")
    print("-" * 70)

    print(f"Graph Risk            : {result['graph_risk']}/100")
    print(f"Severity              : {result['severity']}")

    print()
    print("ATTACK PATH EVIDENCE")
    print("-" * 70)

    if result["path_patterns"]:
        for path in result["path_patterns"]:
            print(f"- {path}")
    else:
        print("- No connected security path identified.")

    print()
    print("EXPLANATION")
    print("-" * 70)

    for item in result["explanation"]:
        print(f"- {item}")

    print()

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

    print("=" * 70)
    print("V5.8 DYNAMIC EVIDENCE GRAPH COMPLETE")
    print("=" * 70)

    print()
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
