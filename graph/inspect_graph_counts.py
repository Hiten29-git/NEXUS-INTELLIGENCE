from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (n)
        RETURN labels(n) AS labels, count(n) AS count
        ORDER BY labels(n)[0]
    """)

    print("=== CURRENT GRAPH ===")
    for record in result:
        print(dict(record))

driver.close()
