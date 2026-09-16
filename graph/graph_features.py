from neo4j_client import get_driver, get_database

driver = get_driver()

query = """
MATCH p =
    (u:User)-[:USES]->(d:Device)-[:EXECUTES]->(pr:Process)-[:INVOLVES]->(e:Event)

OPTIONAL MATCH (pr)-[:CONNECTS_TO]->(s:Server)
OPTIONAL MATCH (pr)-[:CONNECTS_TO]->(dest:Destination)
OPTIONAL MATCH (e)-[:MATCHED]->(ioc:IOC)
OPTIONAL MATCH (e)-[:DESTINED_FOR]->(ip:IP)

WITH
    u,
    d,
    pr,
    e,
    p,
    collect(DISTINCT s.server_id) AS servers,
    collect(DISTINCT dest.destination_id) AS destinations,
    collect(DISTINCT ioc.value) AS iocs,
    collect(DISTINCT ip.address) AS destination_ips

RETURN
    u.user_id AS user_id,
    d.device_id AS device_id,
    pr.process_id AS process_id,
    e.event_id AS event_id,
    e.event_type AS event_type,

    [u.user_id, d.device_id, pr.process_id, e.event_id] AS attack_path,

    size(servers) AS connected_server_count,
    size(destinations) AS new_destination_count,
    size(iocs) AS ioc_linked_entity_count,

    iocs AS ioc_linked_nodes,
    servers AS connected_servers,
    destinations AS destinations,
    destination_ips AS destination_ips,

    false AS sensitive_asset_reached,

    length(p) AS path_length,

    {
        connected_server_count: size(servers),
        new_destination_count: size(destinations),
        ioc_linked_entity_count: size(iocs),
        sensitive_assets_reached: 0,
        entities_in_path: 4
    } AS graph_features

ORDER BY e.timestamp, e.event_id
"""

with driver.session(database=get_database()) as session:
    for record in session.run(query):
        print({
            "user_id": record["user_id"],
            "attack_path": record["attack_path"],
            "event_id": record["event_id"],
            "event_type": record["event_type"],
            "connected_server_count": record["connected_server_count"],
            "new_destination_count": record["new_destination_count"],
            "ioc_linked_entity_count": record["ioc_linked_entity_count"],
            "ioc_linked_nodes": record["ioc_linked_nodes"],
            "connected_servers": record["connected_servers"],
            "destinations": record["destinations"],
            "destination_ips": record["destination_ips"],
            "sensitive_asset_reached": record["sensitive_asset_reached"],
            "path_length": record["path_length"],
            "graph_features": record["graph_features"]
        })

driver.close()
