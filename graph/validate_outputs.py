import json

files = [
    r"graph\data\graph_anomalies.json",
    r"graph\data\graph_evidence.json",
    r"graph\data\nexus_graph_handoff.json"
]

expected = {
    "graph_anomalies.json": [
        "user_id",
        "device_id",
        "process_id",
        "anomaly_reasons",
        "connected_servers",
        "destinations",
        "event_ids",
        "ioc_linked_nodes"
    ],
    "graph_evidence.json": [
        "user_id",
        "attack_path",
        "evidence_count",
        "sensitive_asset_reached",
        "sensitive_assets",
        "ioc_linked_nodes",
        "path_length",
        "graph_features"
    ],
    "nexus_graph_handoff.json": [
        "user_id",
        "attack_path",
        "evidence_count",
        "sensitive_asset_reached",
        "ioc_linked_nodes",
        "path_length",
        "graph_features"
    ]
}

print("=== MEMBER 2 OUTPUT CONSISTENCY CHECK ===")

for path in files:
    name = path.split("\\")[-1]

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"{name}: VALID JSON = YES")
    print(f"{name}: RECORD COUNT = {len(data)}")

    actual = list(data[0].keys()) if data else []
    missing = [field for field in expected[name] if field not in actual]

    print(f"{name}: REQUIRED FIELDS = {'PASS' if not missing else 'FAIL'}")

    if missing:
        print(f"MISSING: {missing}")

print("=== CHECK COMPLETE ===")
