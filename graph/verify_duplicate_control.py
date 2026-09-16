from neo4j_client import get_driver, get_database

driver = get_driver()

with driver.session(database=get_database()) as session:
    result = session.run("""
        MATCH (e:Event {event_id: "M2-TEST-001"})
        OPTIONAL MATCH (u:User {user_id: "U001"})
        OPTIONAL MATCH (d:Device {device_id: "PC001"})
        OPTIONAL MATCH (p:Process {process_id: "powershell.exe"})
        OPTIONAL MATCH (ioc:IOC {value: "10.0.0.50"})

        RETURN
            count(DISTINCT e) AS event_count,
            count(DISTINCT u) AS user_count,
            count(DISTINCT d) AS device_count,
            count(DISTINCT p) AS process_count,
            count(DISTINCT ioc) AS ioc_count
    """)

    print("DUPLICATE CONTROL:", dict(result.single()))

driver.close()
