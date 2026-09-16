import csv
from pathlib import Path
from datetime import datetime, timezone
OUTPUT = Path("data/scenarios/ioc_test_events.csv")
fields = [
    "event_id",
    "timestamp",
    "user_id",
    "device_id",
    "event_type",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "process",
    "parent_process",
    "resource",
    "ioc_match",
]
now = datetime.now(timezone.utc).isoformat()
events = [
    {
        "event_id": "IOC-TEST-001",
        "timestamp": now,
        "user_id": "TEST_USER",
        "device_id": "TEST_DEVICE",
        "event_type": "PROCESS_EXECUTION",
        "source_ip": "192.168.56.10",
        "source_port": "",
        "destination_ip": "",
        "destination_port": "",
        "process": "evil_demo.exe",
        "parent_process": "explorer.exe",
        "resource": "PID:9999",
        "ioc_match": "False",
    },
    {
        "event_id": "IOC-TEST-002",
        "timestamp": now,
        "user_id": "TEST_USER",
        "device_id": "TEST_DEVICE",
        "event_type": "NETWORK_CONNECTION",
        "source_ip": "192.168.56.10",
        "source_port": "51500",
        "destination_ip": "203.0.113.10",
        "destination_port": "443",
        "process": "demo_client.exe",
        "parent_process": "explorer.exe",
        "resource": "",
        "ioc_match": "False",
    },
    {
        "event_id": "IOC-TEST-003",
        "timestamp": now,
        "user_id": "TEST_USER",
        "device_id": "TEST_DEVICE",
        "event_type": "NETWORK_CONNECTION",
        "source_ip": "192.168.56.10",
        "source_port": "51501",
        "destination_ip": "198.51.100.25",
        "destination_port": "443",
        "process": "demo_client.exe",
        "parent_process": "explorer.exe",
        "resource": "",
        "ioc_match": "False",
    },
]
with OUTPUT.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(events)
print()
print("=" * 70)
print("NEXUS SYNTHETIC IoC TEST EVENTS")
print("=" * 70)
print(f"Events created : {len(events)}")
print(f"Output         : {OUTPUT}")
print("Safety         : Synthetic telemetry only")
print("=" * 70)
