from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (p:Process)-[r:CONNECTS_TO]->(s:Server {server_id: "UNKNOWN"})
        DELETE r
        WITH s
        WHERE NOT (s)--()
        DELETE s
        RETURN count(*) AS cleaned
    """)

    print("UNKNOWN SERVER CLEANUP:", result.single()["cleaned"])

driver.close()
