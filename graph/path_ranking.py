from neo4j_client import get_driver, get_database

driver = get_driver()

query = """
MATCH p =
    (u:User)-[:USES]->(d:Device)-[:EXECUTES]->(pr:Process)-[:INVOLVES]->(e:Event)

OPTIONAL MATCH (pr)-[:CONNECTS_TO]->(s:Server)
OPTIONAL MATCH (pr)-[:CONNECTS_TO]->(dest:Destination)
OPTIONAL MATCH (e)-[:MATCHED]->(ioc:IOC)

WITH
    u,
    d,
    pr,
    e,
    p,
    collect(DISTINCT s.server_id) AS servers,
    collect(DISTINCT dest.destination_id) AS destinations,
    collect(DISTINCT ioc.value) AS iocs

WITH
    u,
    d,
    pr,
    e,
    p,
    servers,
    destinations,
    iocs,
    (
        size(iocs) * 3 +
        size(servers) * 2 +
        size(destinations)
    ) AS ranking_score

RETURN
    u.user_id AS user_id,
    [u.user_id, d.device_id, pr.process_id, e.event_id] AS attack_path,
    e.event_id AS event_id,
    size(iocs) AS evidence_count,
    iocs AS ioc_linked_nodes,
    size(servers) AS connected_server_count,
    size(destinations) AS destination_count,
    length(p) AS path_length,
    ranking_score

ORDER BY ranking_score DESC, path_length ASC, event_id ASC
"""

with driver.session(database=get_database()) as session:
    print("=== NEXUS ATTACK-PATH RANKING ===")

    for record in session.run(query):
        print({
            "user_id": record["user_id"],
            "attack_path": record["attack_path"],
            "event_id": record["event_id"],
            "evidence_count": record["evidence_count"],
            "ioc_linked_nodes": record["ioc_linked_nodes"],
            "connected_server_count": record["connected_server_count"],
            "destination_count": record["destination_count"],
            "path_length": record["path_length"],
            "ranking_score": record["ranking_score"]
        })

driver.close()
