from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH ()-[r]->()
        RETURN type(r) AS relationship, count(r) AS count
        ORDER BY relationship
    """)

    print("=== CURRENT RELATIONSHIPS ===")
    for record in result:
        print(dict(record))

driver.close()
