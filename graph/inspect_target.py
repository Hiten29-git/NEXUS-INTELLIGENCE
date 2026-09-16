from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (x)
        WHERE (x:Destination AND x.destination_id = "10.0.0.50")
           OR (x:IP AND x.address = "10.0.0.50")
        OPTIONAL MATCH (a)-[rel]-(x)
        RETURN labels(x) AS node_labels,
               properties(x) AS node_properties,
               type(rel) AS relationship,
               labels(a) AS connected_labels,
               properties(a) AS connected_properties
        ORDER BY relationship
    """)

    for record in result:
        print(dict(record))

driver.close()
