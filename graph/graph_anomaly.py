import json
from neo4j_client import get_driver, get_database

OUTPUT = r"graph\data\graph_anomalies.json"

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (u:User)-[:USES]->(d:Device)-[:EXECUTES]->(p:Process)
        OPTIONAL MATCH (p)-[:CONNECTS_TO]->(s:Server)
        OPTIONAL MATCH (p)-[:CONNECTS_TO]->(dest:Destination)
        OPTIONAL MATCH (p)-[:INVOLVES]->(e:Event)
        OPTIONAL MATCH (e)-[:MATCHED]->(ioc:IOC)

        RETURN
            u.user_id AS user_id,
            d.device_id AS device_id,
            p.process_id AS process_id,
            collect(DISTINCT s.server_id) AS connected_servers,
            collect(DISTINCT dest.destination_id) AS destinations,
            collect(DISTINCT e.event_id) AS event_ids,
            collect(DISTINCT ioc.value) AS ioc_nodes
    """)

    anomalies = []

    for record in result:
        servers = [x for x in record["connected_servers"] if x]
        destinations = [x for x in record["destinations"] if x]
        events = [x for x in record["event_ids"] if x]
        iocs = [x for x in record["ioc_nodes"] if x]

        reasons = []

        if iocs:
            reasons.append("IOC_LINKED_ACTIVITY")

        if len(destinations) > 0:
            reasons.append("DESTINATION_ACTIVITY")

        if len(servers) > 1:
            reasons.append("MULTIPLE_CONNECTED_SERVERS")

        if len(events) > 1:
            reasons.append("MULTIPLE_EVENTS")

        if reasons:
            anomalies.append({
                "user_id": record["user_id"],
                "device_id": record["device_id"],
                "process_id": record["process_id"],
                "anomaly_reasons": reasons,
                "connected_servers": servers,
                "destinations": destinations,
                "event_ids": events,
                "ioc_linked_nodes": iocs
            })

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(anomalies, f, indent=2)

print("=== GRAPH ANOMALY/CORRELATION ===")
print("PATTERNS FLAGGED:", len(anomalies))
print("OUTPUT:", OUTPUT)

for item in anomalies:
    print(item)

driver.close()
