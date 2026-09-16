from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH p =
            (u:User {user_id: "U001"})
            -[:USES]->
            (d:Device {device_id: "PC001"})
            -[:EXECUTES]->
            (pr:Process {process_id: "powershell.exe"})
            -[:CONNECTS_TO]->
            (s:Server {server_id: "SERVER02"})
            -[:ACCESSES]->
            (db:Database {database_id: "DATABASE01"})

        RETURN
            [n IN nodes(p) |
                CASE
                    WHEN n:User THEN "User:" + n.user_id
                    WHEN n:Device THEN "Device:" + n.device_id
                    WHEN n:Process THEN "Process:" + n.process_id
                    WHEN n:Server THEN "Server:" + n.server_id
                    WHEN n:Database THEN "Database:" + n.database_id
                END
            ] AS path,
            length(p) AS path_length

    """)

    record = result.single()

    if record:
        print("=== VERIFIED MULTI-STAGE PATH ===")
        print("PATH:", record["path"])
        print("PATH LENGTH:", record["path_length"])
    else:
        print("PATH NOT FOUND")

driver.close()
