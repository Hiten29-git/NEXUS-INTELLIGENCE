import json
import os
from typing import Any

from neo4j import GraphDatabase


NEO4J_URI = os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "nexusdemo123")

LIVE_EVENTS_FILE = "data/live/live_events.jsonl"

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USER, NEO4J_PASSWORD)
)


def check_connection() -> bool:
    try:
        with driver.session() as session:
            session.run("RETURN 1").single()
        return True
    except Exception:
        return False


def read_live_events() -> list[dict[str, Any]]:
    if not os.path.exists(LIVE_EVENTS_FILE):
        return []

    events = []

    with open(LIVE_EVENTS_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events


def ingest_event(event: dict[str, Any]) -> None:
    with driver.session() as session:
        session.execute_write(_ingest_event, event)


def _ingest_event(tx, event: dict[str, Any]):

    user_id = event.get("user_id")
    device_id = event.get("device_id")
    process = event.get("process")
    destination_ip = event.get("destination_ip")
    destination_port = event.get("destination_port")
    resource = event.get("resource")

    # USER -> DEVICE
    if user_id and device_id:
        tx.run(
            """
            MERGE (u:User {id: $user_id})
            MERGE (d:Device {id: $device_id})
            MERGE (u)-[:USES]->(d)
            """,
            user_id=user_id,
            device_id=device_id
        )

    # DEVICE -> PROCESS
    if device_id and process:
        tx.run(
            """
            MERGE (d:Device {id: $device_id})
            MERGE (p:Process {name: $process})
            MERGE (d)-[:EXECUTES]->(p)
            """,
            device_id=device_id,
            process=process
        )

    # PROCESS -> IP
    if process and destination_ip:
        tx.run(
            """
            MERGE (p:Process {name: $process})
            MERGE (ip:IP {address: $destination_ip})
            MERGE (p)-[r:CONNECTS_TO]->(ip)
            SET r.port = $destination_port
            """,
            process=process,
            destination_ip=destination_ip,
            destination_port=destination_port
        )

    # DEVICE -> IP
    if device_id and destination_ip:
        tx.run(
            """
            MERGE (d:Device {id: $device_id})
            MERGE (ip:IP {address: $destination_ip})
            MERGE (d)-[r:CONNECTS_TO]->(ip)
            SET r.port = $destination_port
            """,
            device_id=device_id,
            destination_ip=destination_ip,
            destination_port=destination_port
        )

    # DEVICE -> RESOURCE
    if device_id and resource:
        tx.run(
            """
            MERGE (d:Device {id: $device_id})
            MERGE (r:Resource {name: $resource})
            MERGE (d)-[:ACCESSES]->(r)
            """,
            device_id=device_id,
            resource=resource
        )


def ingest_live_events() -> dict[str, Any]:
    events = read_live_events()

    for event in events:
        ingest_event(event)

    return {
        "events_processed": len(events),
        "neo4j_connected": check_connection()
    }


def get_topology() -> dict[str, Any]:

    with driver.session() as session:
        result = session.run(
            """
            MATCH (n)
            OPTIONAL MATCH (n)-[r]->(m)

            RETURN
                collect(DISTINCT {
                    id:
                        CASE labels(n)[0]
                            WHEN 'User' THEN 'user:' + n.id
                            WHEN 'Device' THEN 'device:' + n.id
                            WHEN 'Process' THEN 'process:' + n.name
                            WHEN 'IP' THEN 'ip:' + n.address
                            WHEN 'Resource' THEN 'resource:' + n.name
                            ELSE 'node:' + elementId(n)
                        END,

                    label:
                        coalesce(n.id, n.name, n.address),

                    type:
                        labels(n)[0]
                }) AS nodes,

                collect(DISTINCT CASE
                    WHEN r IS NOT NULL THEN {
                        source:
                            CASE labels(startNode(r))[0]
                                WHEN 'User' THEN 'user:' + startNode(r).id
                                WHEN 'Device' THEN 'device:' + startNode(r).id
                                WHEN 'Process' THEN 'process:' + startNode(r).name
                                WHEN 'IP' THEN 'ip:' + startNode(r).address
                                WHEN 'Resource' THEN 'resource:' + startNode(r).name
                                ELSE 'node:' + elementId(startNode(r))
                            END,

                        target:
                            CASE labels(endNode(r))[0]
                                WHEN 'User' THEN 'user:' + endNode(r).id
                                WHEN 'Device' THEN 'device:' + endNode(r).id
                                WHEN 'Process' THEN 'process:' + endNode(r).name
                                WHEN 'IP' THEN 'ip:' + endNode(r).address
                                WHEN 'Resource' THEN 'resource:' + endNode(r).name
                                ELSE 'node:' + elementId(endNode(r))
                            END,

                        type: type(r)
                    }
                END) AS relationships
            """
        ).single()

    relationships = [
        relationship
        for relationship in result["relationships"]
        if relationship is not None
    ]

    return {
        "nodes": result["nodes"],
        "relationships": relationships
    }
