from neo4j import GraphDatabase
from neo4j_client import get_driver, get_database

driver = get_driver()
database = get_database()

with driver.session(database=database) as session:
    session.run("CREATE CONSTRAINT user_id_unique IF NOT EXISTS FOR (n:User) REQUIRE n.user_id IS UNIQUE")
    session.run("CREATE CONSTRAINT device_id_unique IF NOT EXISTS FOR (n:Device) REQUIRE n.device_id IS UNIQUE")
    session.run("CREATE CONSTRAINT process_id_unique IF NOT EXISTS FOR (n:Process) REQUIRE n.process_id IS UNIQUE")
    session.run("CREATE CONSTRAINT server_id_unique IF NOT EXISTS FOR (n:Server) REQUIRE n.server_id IS UNIQUE")
    session.run("CREATE CONSTRAINT event_id_unique IF NOT EXISTS FOR (n:Event) REQUIRE n.event_id IS UNIQUE")
    session.run("CREATE CONSTRAINT ioc_value_unique IF NOT EXISTS FOR (n:IOC) REQUIRE n.value IS UNIQUE")
    session.run("CREATE CONSTRAINT destination_id_unique IF NOT EXISTS FOR (n:Destination) REQUIRE n.destination_id IS UNIQUE")

print("NEXUS graph constraints created successfully.")
driver.close()
