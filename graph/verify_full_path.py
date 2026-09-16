from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH p =
            (u:User)-[:USES]->(d:Device)-[:EXECUTES]->(pr:Process)-[:INVOLVES]->(e:Event)
            -[:MATCHED]->(ioc:IOC)
        WHERE e.event_id = "M2-TEST-001"
        RETURN
            u.user_id AS user_id,
            d.device_id AS device_id,
            pr.process_id AS process_id,
            e.event_id AS event_id,
            ioc.value AS ioc,
            length(p) AS path_length
    """)

    for record in result:
        print(dict(record))

driver.close()
