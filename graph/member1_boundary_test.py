import json
from jsonschema import validate

schema_path = r"integration\nexus_event_schema.json"
event_path = r"graph\data\test_event.json"

with open(schema_path, "r", encoding="utf-8-sig") as f:
    schema = json.load(f)

with open(event_path, "r", encoding="utf-8-sig") as f:
    event = json.load(f)

validate(instance=event, schema=schema)

print("=== MEMBER 1 ? MEMBER 2 CONTRACT TEST ===")
print("SCHEMA VALID: YES")
print("EVENT TYPE:", event["event_type"])
print("USER:", event["user_id"])
print("DEVICE:", event["device_id"])
print("SOURCE IP:", event["source_ip"])
print("DESTINATION IP:", event["destination_ip"])
print("PROCESS:", event["process"])
print("IOC MATCH:", event["ioc_match"])
print("MEMBER 2 READY: YES")
