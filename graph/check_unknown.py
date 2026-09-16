from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (s:Server {server_id: "UNKNOWN"})
        OPTIONAL MATCH (p:Process)-[r:CONNECTS_TO]->(s)
        RETURN count(s) AS server_count,
               count(r) AS relationship_count,
               collect(p.process_id) AS processes
    """).single()

    print(dict(result))

driver.close()
