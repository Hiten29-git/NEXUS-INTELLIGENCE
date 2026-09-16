from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (pr:Process)-[rel]->(x)
        RETURN pr.process_id AS process_id,
               type(rel) AS relationship,
               labels(x) AS labels,
               properties(x) AS properties
        ORDER BY process_id, relationship
    """)

    for record in result:
        print(dict(record))

driver.close()
