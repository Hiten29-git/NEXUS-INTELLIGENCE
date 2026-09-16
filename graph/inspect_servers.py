from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (s:Server)
        RETURN s
    """)

    for record in result:
        print(dict(record["s"]))

driver.close()
