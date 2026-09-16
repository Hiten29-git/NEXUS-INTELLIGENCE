from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    record = session.run(
        """
        MATCH (e:Event {event_id: $id})
        OPTIONAL MATCH (d:Device)-[:INVOLVES]->(e)
        OPTIONAL MATCH (u:User)-[:USES]->(d)
        RETURN
            e.event_id AS event_id,
            e.event_type AS event_type,
            d.device_id AS device_id,
            u.user_id AS user_id
        """,
        id="M2-TEST-001"
    ).single()

    print(dict(record) if record else "NOT FOUND")

driver.close()
