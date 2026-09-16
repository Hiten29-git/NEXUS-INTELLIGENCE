from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (n)
        WHERE n:Server OR n:Database
        RETURN labels(n) AS labels,
               coalesce(n.server_id, n.database_id) AS asset_id,
               n.criticality AS criticality
        ORDER BY asset_id
    """)

    print("=== SERVER / DATABASE CRITICALITY ===")

    for record in result:
        print(dict(record))

driver.close()
