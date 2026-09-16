import json
import os
import re
from typing import Any

from neo4j import GraphDatabase


NEO4J_URI = os.getenv(
    "NEO4J_URI",
    "bolt://127.0.0.1:7687"
)

NEO4J_USER = os.getenv(
    "NEO4J_USER",
    "neo4j"
)

NEO4J_PASSWORD = os.getenv(
    "NEO4J_PASSWORD",
    "nexusdemo123"
)

LIVE_EVENTS_FILE = "data/live/live_events.jsonl"


driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASSWORD)
)


# ============================================================
# CONNECTION
# ============================================================

def check_connection() -> bool:
    try:
        with driver.session() as session:
            session.run("RETURN 1").single()

        return True

    except Exception:
        return False


# ============================================================
# LIVE EVENTS
# ============================================================

def read_live_events() -> list[dict[str, Any]]:
    if not os.path.exists(LIVE_EVENTS_FILE):
        return []

    events = []

    with open(
        LIVE_EVENTS_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events


# ============================================================
# IP / PORT NORMALIZATION
# ============================================================

def normalize_ip_and_port(
    value: Any,
    port: Any = None
) -> tuple[str | None, int | None]:

    if value is None:
        return None, None

    value = str(value).strip()

    if not value:
        return None, None

    normalized_port = None

    if port is not None:
        try:
            normalized_port = int(port)
        except (TypeError, ValueError):
            normalized_port = None

    # --------------------------------------------------------
    # IPv4 accidentally stored as:
    # 8.8.8.8.443
    # 34.36.133.15.443
    # --------------------------------------------------------

    parts = value.split(".")

    if len(parts) == 5 and parts[-1].isdigit():

        possible_ip = ".".join(parts[:4])
        possible_port = int(parts[-1])

        valid_ipv4 = all(
            part.isdigit()
            and 0 <= int(part) <= 255
            for part in parts[:4]
        )

        if (
            valid_ipv4
            and 0 < possible_port <= 65535
        ):
            value = possible_ip

            if normalized_port is None:
                normalized_port = possible_port

    # --------------------------------------------------------
    # IPv6 accidentally stored as:
    # fe80::1bfe:816a:.1024
    # --------------------------------------------------------

    if ":" in value:

        match = re.match(
            r"^(.*)\.(\d{1,5})$",
            value
        )

        if match:

            possible_ip = match.group(1)
            possible_port = int(match.group(2))

            if (
                ":" in possible_ip
                and 0 < possible_port <= 65535
            ):
                value = possible_ip

                if normalized_port is None:
                    normalized_port = possible_port

    return value, normalized_port


# ============================================================
# RESOURCE FILTER
# ============================================================

IGNORED_RESOURCE_VALUES = {
    "ESTABLISHED",
    "CLOSE_WAIT",
    "SYN_SENT",
    "TIME_WAIT",
    "LISTEN",
    "FIN_WAIT",
    "FIN_WAIT_1",
    "FIN_WAIT_2",
    "LAST_ACK",
    "CLOSING",
    "NONE",
    "NULL",
}


def is_meaningful_resource(resource):
    """
    Return True only for meaningful resources.
    Network endpoints must remain IP nodes, not Resource nodes.
    """

    if resource is None:
        return False

    value = str(resource).strip()

    if not value:
        return False

    upper_value = value.upper()

    if upper_value in IGNORED_RESOURCE_VALUES:
        return False

    # Never treat process IDs as resources.
    if value.lower().startswith("pid:"):
        return False

    # IPv4 address + port.
    # Example: 148.113.17.95:443
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", value):
        return False

    # IPv6 address + port.
    # Example: fe80::1bfe:816a:1024
    if ":" in value:
        parts = value.rsplit(":", 1)

        if len(parts) == 2:
            possible_host = parts[0]
            possible_port = parts[1]

            if ":" in possible_host and possible_port.isdigit():
                return False

    return True

def ingest_event(
    event: dict[str, Any]
) -> None:

    with driver.session() as session:
        session.execute_write(
            _ingest_event,
            event
        )


def _ingest_event(
    tx,
    event: dict[str, Any]
):

    user_id = event.get("user_id")
    device_id = event.get("device_id")
    process = event.get("process")

    destination_ip = event.get(
        "destination_ip"
    )

    destination_port = event.get(
        "destination_port"
    )

    resource = event.get("resource")
    event_type = event.get("event_type")
    timestamp = event.get("timestamp")

    normalized_ip, normalized_port = (
        normalize_ip_and_port(
            destination_ip,
            destination_port
        )
    )

    # ========================================================
    # USER -> DEVICE
    # ========================================================

    if user_id and device_id:

        tx.run(
            """
            MERGE (u:User {id: $user_id})
            MERGE (d:Device {id: $device_id})
            MERGE (u)-[:USES]->(d)
            """,
            user_id=str(user_id),
            device_id=str(device_id)
        )

    # ========================================================
    # DEVICE -> PROCESS
    # ========================================================

    if device_id and process:

        tx.run(
            """
            MERGE (d:Device {id: $device_id})
            MERGE (p:Process {name: $process})

            MERGE (d)-[r:EXECUTES]->(p)

            SET r.last_seen = $timestamp
            """,
            device_id=str(device_id),
            process=str(process),
            timestamp=timestamp
        )

    # ========================================================
    # PROCESS -> IP
    # ========================================================

    if process and normalized_ip:

        tx.run(
            """
            MERGE (p:Process {name: $process})
            MERGE (ip:IP {address: $destination_ip})

            MERGE (p)-[r:CONNECTS_TO]->(ip)

            SET
                r.port = $destination_port,
                r.last_seen = $timestamp
            """,
            process=str(process),
            destination_ip=normalized_ip,
            destination_port=normalized_port,
            timestamp=timestamp
        )

    # ========================================================
    # DEVICE -> IP
    # ========================================================

    if device_id and normalized_ip:

        tx.run(
            """
            MERGE (d:Device {id: $device_id})
            MERGE (ip:IP {address: $destination_ip})

            MERGE (d)-[r:CONNECTS_TO]->(ip)

            SET
                r.port = $destination_port,
                r.last_seen = $timestamp
            """,
            device_id=str(device_id),
            destination_ip=normalized_ip,
            destination_port=normalized_port,
            timestamp=timestamp
        )

    # ========================================================
    # DEVICE -> REAL RESOURCE
    # ========================================================

    if (
        device_id
        and is_meaningful_resource(resource)
    ):

        tx.run(
            """
            MERGE (d:Device {id: $device_id})
            MERGE (r:Resource {name: $resource})

            MERGE (d)-[rel:ACCESSES]->(r)

            SET
                rel.event_type = $event_type,
                rel.last_seen = $timestamp
            """,
            device_id=str(device_id),
            resource=str(resource),
            event_type=event_type,
            timestamp=timestamp
        )


# ============================================================
# INGEST
# ============================================================

def ingest_live_events() -> dict[str, Any]:

    events = read_live_events()

    for event in events:
        ingest_event(event)

    return {
        "events_processed": len(events),
        "neo4j_connected": check_connection()
    }


# ============================================================
# REBUILD GRAPH
# ============================================================

def clear_graph() -> dict[str, Any]:

    with driver.session() as session:

        result = session.run(
            """
            MATCH (n)
            DETACH DELETE n
            RETURN count(n) AS deleted
            """
        ).single()

    return {
        "deleted_nodes":
            result["deleted"]
            if result
            else 0
    }


def rebuild_live_graph() -> dict[str, Any]:

    cleared = clear_graph()

    ingested = ingest_live_events()

    return {
        "graph_cleared": cleared,
        "events_processed":
            ingested["events_processed"],
        "neo4j_connected":
            ingested["neo4j_connected"]
    }


# ============================================================
# TOPOLOGY
# ============================================================

def get_topology() -> dict[str, Any]:

    with driver.session() as session:

        result = session.run(
            """
            MATCH (n)
            OPTIONAL MATCH (n)-[r]->(m)

            RETURN
                collect(DISTINCT {
                    element_id: elementId(n),
                    labels: labels(n),
                    value: coalesce(
                        n.id,
                        n.name,
                        n.address
                    )
                }) AS nodes,

                collect(DISTINCT CASE
                    WHEN r IS NOT NULL THEN {
                        source_element:
                            elementId(startNode(r)),

                        target_element:
                            elementId(endNode(r)),

                        type: type(r),

                        port: r.port,

                        last_seen: r.last_seen
                    }
                END) AS relationships
            """
        ).single()

    raw_nodes = (
        result["nodes"]
        if result
        else []
    )

    raw_relationships = (
        result["relationships"]
        if result
        else []
    )

    node_map = {}
    nodes = []

    # --------------------------------------------------------
    # Build stable node IDs
    # --------------------------------------------------------

    for node in raw_nodes:

        labels = node.get(
            "labels",
            []
        )

        value = node.get(
            "value"
        )

        if "User" in labels:
            stable_id = f"user:{value}"
            node_type = "User"

        elif "Device" in labels:
            stable_id = f"device:{value}"
            node_type = "Device"

        elif "Process" in labels:
            stable_id = f"process:{value}"
            node_type = "Process"

        elif "IP" in labels:
            stable_id = f"ip:{value}"
            node_type = "IP"

        elif "Resource" in labels:
            stable_id = f"resource:{value}"
            node_type = "Resource"

        else:
            continue

        node_map[
            node["element_id"]
        ] = stable_id

        nodes.append(
            {
                "data": {
                    "id": stable_id,
                    "label": str(value),
                    "type": node_type,
                    "isCriticalPath": False
                }
            }
        )

    relationships = []

    # --------------------------------------------------------
    # Build frontend-compatible relationships
    # --------------------------------------------------------

    for relationship in raw_relationships:

        if relationship is None:
            continue

        source = node_map.get(
            relationship.get(
                "source_element"
            )
        )

        target = node_map.get(
            relationship.get(
                "target_element"
            )
        )

        if not source or not target:
            continue

        relationship_type = relationship.get(
            "type"
        )

        relationship_id = (
            f"{source}|"
            f"{relationship_type}|"
            f"{target}"
        )

        relationships.append(
            {
                "data": {
                    "id": relationship_id,
                    "source": source,
                    "target": target,
                    "type": relationship_type,
                    "port": relationship.get("port"),
                    "last_seen": relationship.get("last_seen"),
                    "isCriticalPath": False
                }
            }
        )

    return {
        "nodes": nodes,
        "relationships": relationships
    }


# ============================================================
# ASSET COMPATIBILITY
# ============================================================

def get_asset_inventory():

    from backend.services.asset_service import (
        get_assets
    )

    return get_assets()
