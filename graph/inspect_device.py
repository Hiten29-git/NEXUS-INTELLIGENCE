from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (d:Device {device_id: "PC001"})-[rel]->(x)
        RETURN type(rel) AS relationship,
               labels(x) AS labels,
               properties(x) AS properties
        ORDER BY relationship
    """)

    for record in result:
        print(dict(record))

driver.close()
