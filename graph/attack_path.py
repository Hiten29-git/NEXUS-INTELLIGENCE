from neo4j_client import get_driver, get_database

driver = get_driver()

query = """
MATCH p =
    (u:User)-[:USES]->(d:Device)-[:EXECUTES]->(pr:Process)-[:INVOLVES]->(e:Event)

OPTIONAL MATCH (pr)-[:CONNECTS_TO]->(s:Server)
OPTIONAL MATCH (pr)-[:CONNECTS_TO]->(dest:Destination)
OPTIONAL MATCH (e)-[:DESTINED_FOR]->(ip:IP)
OPTIONAL MATCH (e)-[:MATCHED]->(ioc:IOC)

WITH
    u,
    d,
    pr,
    e,
    p,
    collect(DISTINCT s.server_id) AS servers,
    collect(DISTINCT dest.destination_id) AS destinations,
    collect(DISTINCT ip.address) AS destination_ips,
    collect(DISTINCT ioc.value) AS iocs

RETURN
    u.user_id AS user_id,
    d.device_id AS device_id,
    pr.process_id AS process_id,
    e.event_id AS event_id,
    e.timestamp AS timestamp,
    e.event_type AS event_type,

    [u.user_id, d.device_id, pr.process_id, e.event_id] AS attack_path,

    size(iocs) AS evidence_count,
    iocs AS ioc_linked_nodes,

    false AS sensitive_asset_reached,

    servers AS connected_servers,
    destinations AS connected_destinations,
    destination_ips AS destination_ips,

    length(p) AS path_length,

    {
        connected_server_count: size([x IN servers WHERE x IS NOT NULL]),
        new_destination_count: size([x IN destinations WHERE x IS NOT NULL]),
        ioc_linked_entity_count: size(iocs),
        entities_in_path: 4
    } AS graph_features

ORDER BY timestamp, event_id
"""

with driver.session(database=get_database()) as session:
    result = session.run(query)

    for record in result:
        print({
            "user_id": record["user_id"],
            "attack_path": record["attack_path"],
            "event_id": record["event_id"],
            "event_type": record["event_type"],
            "evidence_count": record["evidence_count"],
            "sensitive_asset_reached": record["sensitive_asset_reached"],
            "ioc_linked_nodes": record["ioc_linked_nodes"],
            "connected_servers": record["connected_servers"],
            "connected_destinations": record["connected_destinations"],
            "destination_ips": record["destination_ips"],
            "path_length": record["path_length"],
            "graph_features": record["graph_features"]
        })

driver.close()
