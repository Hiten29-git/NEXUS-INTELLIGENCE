from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    session.run("""
        MATCH (s:Server {server_id: "SERVER02"})
        SET s.criticality = "HIGH"

        WITH s
        MATCH (d:Database {database_id: "DATABASE01"})
        SET d.criticality = "CRITICAL"

        RETURN
            s.server_id AS server_id,
            s.criticality AS server_criticality,
            d.database_id AS database_id,
            d.criticality AS database_criticality
    """)

    result = session.run("""
        MATCH (n)
        WHERE n:Server OR n:Database
        RETURN labels(n) AS labels,
               coalesce(n.server_id, n.database_id) AS asset_id,
               n.criticality AS criticality
        ORDER BY asset_id
    """)

    print("=== CRITICALITY UPDATED ===")
    for record in result:
        print(dict(record))

driver.close()
