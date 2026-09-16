from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (s:Server {server_id: "SERVER02"})-[r]-(n)
        RETURN type(r) AS relationship,
               startNode(r).server_id AS start_server,
               labels(n) AS node_labels,
               properties(n) AS node_properties
    """)

    for record in result:
        print(dict(record))

driver.close()
