from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (u:User)-[:USES]->(d:Device)-[:EXECUTES]->(pr:Process)-[:INVOLVES]->(e:Event)
        OPTIONAL MATCH (pr)-[:CONNECTS_TO]->(s:Server)
        OPTIONAL MATCH (pr)-[:CONNECTS_TO]->(dest:Destination)
        OPTIONAL MATCH (e)-[:MATCHED]->(ioc:IOC)
        RETURN
            e.event_id AS event_id,
            pr.process_id AS process_id,
            collect(DISTINCT s.server_id) AS servers,
            collect(DISTINCT dest.destination_id) AS destinations,
            collect(DISTINCT ioc.value) AS iocs
        ORDER BY event_id
    """)

    for record in result:
        print(dict(record))

driver.close()
