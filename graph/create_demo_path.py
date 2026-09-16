from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (u:User {user_id: "U001"})
        MATCH (d:Device {device_id: "PC001"})
        MATCH (p:Process {process_id: "powershell.exe"})
        MATCH (s:Server {server_id: "SERVER02"})

        MERGE (db:Database {database_id: "DATABASE01"})

        MERGE (s)-[:ACCESSES]->(db)

        RETURN
            u.user_id AS user_id,
            d.device_id AS device_id,
            p.process_id AS process_id,
            s.server_id AS server_id,
            db.database_id AS database_id
    """)

    print("SYNTHETIC PATH:", dict(result.single()))

driver.close()
