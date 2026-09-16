import json

SOURCE = r"graph\data\graph_evidence.json"
OUTPUT = r"graph\data\nexus_graph_handoff.json"

with open(SOURCE, "r", encoding="utf-8") as f:
    evidence = json.load(f)

handoff = []

for item in evidence:
    handoff.append({
        "user_id": item["user_id"],
        "attack_path": item["attack_path"],
        "evidence_count": item["evidence_count"],
        "sensitive_asset_reached": item["sensitive_asset_reached"],
        "ioc_linked_nodes": item["ioc_linked_nodes"],
        "path_length": item["path_length"],
        "graph_features": item["graph_features"]
    })

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(handoff, f, indent=2)

print("NEXUS GRAPH HANDOFF CREATED")
print("PATHS:", len(handoff))
print("OUTPUT:", OUTPUT)
print("FIELDS:", list(handoff[0].keys()) if handoff else [])
