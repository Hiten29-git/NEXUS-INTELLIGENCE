import json
import sys
from jsonschema import validate
from neo4j_client import get_driver, get_database

SCHEMA_PATH = "integration/nexus_event_schema.json"

with open(SCHEMA_PATH, "r", encoding="utf-8-sig") as f:
    SCHEMA = json.load(f)


def ingest_event(event):
    validate(instance=event, schema=SCHEMA)

    driver = get_driver()

    event_id = event.get("event_id") or f"EVENT-{event['timestamp']}"

    query = """
    MERGE (u:User {user_id: $user_id})
    MERGE (d:Device {device_id: $device_id})
    MERGE (e:Event {event_id: $event_id})

    SET e.timestamp = $timestamp,
        e.event_type = $event_type,
        e.source_ip = $source_ip,
        e.source_port = $source_port,
        e.destination_ip = $destination_ip,
        e.destination_port = $destination_port,
        e.process = $process,
        e.parent_process = $parent_process,
        e.resource = $resource,
        e.ioc_match = $ioc_match

    MERGE (u)-[:USES]->(d)
    MERGE (d)-[:INVOLVES]->(e)

    FOREACH (_ IN CASE
        WHEN $source_ip IS NOT NULL THEN [1]
        ELSE []
    END |
        MERGE (src:IP {address: $source_ip})
        MERGE (e)-[:ORIGINATES_FROM]->(src)
    )

    FOREACH (_ IN CASE
        WHEN $destination_ip IS NOT NULL THEN [1]
        ELSE []
    END |
        MERGE (dst:IP {address: $destination_ip})
        MERGE (e)-[:DESTINED_FOR]->(dst)
    )

    FOREACH (_ IN CASE
        WHEN $process IS NOT NULL THEN [1]
        ELSE []
    END |
        MERGE (p:Process {process_id: $process})
        MERGE (d)-[:EXECUTES]->(p)
        MERGE (p)-[:INVOLVES]->(e)
        SET p.last_seen = $timestamp,
            p.last_event_type = $event_type,
            p.last_event_id = $event_id
    )

    FOREACH (_ IN CASE
        WHEN $destination_ip IS NOT NULL THEN [1]
        ELSE []
    END |
        MERGE (dest:Destination {destination_id: $destination_ip})
        MERGE (p2:Process {process_id: coalesce($process, "UNKNOWN")})
        MERGE (p2)-[:CONNECTS_TO]->(dest)
    )

    FOREACH (_ IN CASE
        WHEN $ioc_match = true AND $destination_ip IS NOT NULL THEN [1]
        ELSE []
    END |
        MERGE (ioc:IOC {value: $destination_ip})
        SET ioc.type = "ip"
        MERGE (e)-[:MATCHED]->(ioc)
    )

    RETURN e.event_id AS event_id
    """

    params = {
        "user_id": event["user_id"],
        "device_id": event["device_id"],
        "event_id": event_id,
        "timestamp": event["timestamp"],
        "event_type": event["event_type"],
        "source_ip": event.get("source_ip"),
        "source_port": event.get("source_port"),
        "destination_ip": event.get("destination_ip"),
        "destination_port": event.get("destination_port"),
        "process": event.get("process"),
        "parent_process": event.get("parent_process"),
        "resource": event.get("resource"),
        "ioc_match": event.get("ioc_match")
    }

    with driver.session(database=get_database()) as session:
        result = session.run(query, params).single()
        return result["event_id"]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python graph/ingest_event.py <event.json>")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8-sig") as f:
        event = json.load(f)

    event_id = ingest_event(event)
    print(f"Event ingested successfully: {event_id}")
