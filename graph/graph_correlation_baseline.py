from neo4j_client import get_driver, get_database

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
            count(DISTINCT s) AS server_count,
            count(DISTINCT dest) AS destination_count,
            count(DISTINCT e) AS event_count,
            count(DISTINCT ioc) AS ioc_count
        ORDER BY ioc_count DESC, destination_count DESC, process_id
    """)

    print("=== GRAPH CORRELATION BASELINE ===")

    for record in result:
        print(dict(record))

driver.close()
