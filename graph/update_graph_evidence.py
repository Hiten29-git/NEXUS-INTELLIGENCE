import json

path = "graph\data\graph_evidence.json"

with open(path, "r", encoding="utf-8") as f:
    evidence = json.load(f)

for item in evidence:
    item["evidence_count"] = len(item.get("event_ids", []))

    item["graph_features"] = {
        "path_length": item.get("path_length", 0),
        "ioc_linked_entity_count": len(item.get("ioc_linked_nodes", [])),
        "sensitive_assets_reached": 1 if item.get("sensitive_asset_reached") else 0,
        "entities_in_path": len(item.get("attack_path", [])),
        "connected_server_count": 1 if item.get("server_id") else 0
    }

with open(path, "w", encoding="utf-8") as f:
    json.dump(evidence, f, indent=2)

print("GRAPH EVIDENCE UPDATED:", len(evidence), "paths")
print("FIELDS:", list(evidence[0].keys()))
