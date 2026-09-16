from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH p =
            (u:User)-[:USES]->
            (d:Device)-[:EXECUTES]->
            (pr:Process)-[:CONNECTS_TO]->
            (s:Server)-[:ACCESSES]->
            (db:Database)

        RETURN
            u.user_id AS user_id,
            [n IN nodes(p) |
                CASE
                    WHEN n:User THEN "User:" + n.user_id
                    WHEN n:Device THEN "Device:" + n.device_id
                    WHEN n:Process THEN "Process:" + n.process_id
                    WHEN n:Server THEN "Server:" + n.server_id
                    WHEN n:Database THEN "Database:" + n.database_id
                END
            ] AS attack_path,
            length(p) AS path_length,
            s.server_id AS server_id,
            db.database_id AS database_id

        ORDER BY user_id, path_length
    """)

    records = list(result)

    print("=== MULTI-STAGE ATTACK PATHS ===")

    if not records:
        print("NO MULTI-STAGE PATHS FOUND")
    else:
        for record in records:
            print({
                "user_id": record["user_id"],
                "attack_path": record["attack_path"],
                "path_length": record["path_length"],
                "server_id": record["server_id"],
                "database_id": record["database_id"]
            })

driver.close()
