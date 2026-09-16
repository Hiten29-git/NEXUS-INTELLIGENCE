import json
from neo4j_client import get_driver, get_database

OUTPUT = r"graph\data\graph_evidence.json"

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH p =
            (u:User)-[:USES]->
            (d:Device)-[:EXECUTES]->
            (pr:Process)-[:CONNECTS_TO]->
            (s:Server)-[:ACCESSES]->
            (db:Database)

        OPTIONAL MATCH (pr)-[:INVOLVES]->(e:Event)
        OPTIONAL MATCH (e)-[:MATCHED]->(ioc:IOC)

        RETURN
            u.user_id AS user_id,
            [n IN nodes(p) |
                CASE
                    WHEN n:User THEN "User:" + n.user_id
                    WHEN n:Device THEN "Device:" + n.device_id
                    WHEN n:Process THEN "Process:" + n.process_id
                    WHEN n:Server THEN "Server:" + n.server_id
                    WHEN n:Database THEN "Database:" + n.database_id
                END
            ] AS attack_path,
            collect(DISTINCT e.event_id) AS event_ids,
            collect(DISTINCT ioc.value) AS ioc_linked_nodes,
            length(p) AS path_length,
            s.server_id AS server_id,
            s.criticality AS server_criticality,
            db.database_id AS database_id,
            db.criticality AS database_criticality
    """)

    evidence = []

    for record in result:
        event_ids = [x for x in record["event_ids"] if x]
        iocs = [x for x in record["ioc_linked_nodes"] if x]

        server_criticality = record["server_criticality"]
        database_criticality = record["database_criticality"]

        sensitive = (
            server_criticality in ["HIGH", "CRITICAL"]
            or database_criticality in ["HIGH", "CRITICAL"]
        )

        sensitive_assets = []

        if server_criticality in ["HIGH", "CRITICAL"]:
            sensitive_assets.append(
                f"Server:{record['server_id']}:{server_criticality}"
            )

        if database_criticality in ["HIGH", "CRITICAL"]:
            sensitive_assets.append(
                f"Database:{record['database_id']}:{database_criticality}"
            )

        evidence.append({
            "user_id": record["user_id"],
            "attack_path": record["attack_path"],
            "evidence_count": len(event_ids),
            "sensitive_asset_reached": sensitive,
            "sensitive_assets": sensitive_assets,
            "ioc_linked_nodes": iocs,
            "path_length": record["path_length"],
            "graph_features": {
                "connected_server_count": 1,
                "new_destination_count": len(iocs),
                "ioc_linked_entity_count": len(iocs),
                "sensitive_assets_reached": len(sensitive_assets),
                "entities_in_path": len(record["attack_path"])
            }
        })

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(evidence, f, indent=2)

print("=== SENSITIVE ASSET DETECTION ===")
print("PATHS:", len(evidence))

for item in evidence:
    print({
        "user_id": item["user_id"],
        "attack_path": item["attack_path"],
        "sensitive_asset_reached": item["sensitive_asset_reached"],
        "sensitive_assets": item["sensitive_assets"]
    })

print("OUTPUT:", OUTPUT)

driver.close()
