from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (p:Process {process_id: "powershell.exe"})
        MATCH (s:Server {server_id: "SERVER02"})
        MERGE (p)-[:CONNECTS_TO]->(s)
        RETURN p.process_id AS process_id, s.server_id AS server_id
    """)

    print("SERVER LINK:", dict(result.single()))

driver.close()
