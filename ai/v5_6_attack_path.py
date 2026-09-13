import json
import os
from datetime import datetime, timezone

INPUT_FILE = "data/v5_5/latest_attack_stage.json"
OUTPUT_DIR = "data/v5_6"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "latest_attack_path.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_attack_stage():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def build_attack_path(data):
    risk_score = float(data.get("risk_score", "0").replace("/100", ""))
    severity = data.get("severity", "LOW")
    stage = data.get("stage", "NO_SIGNIFICANT_THREAT")

    confidence_raw = str(data.get("confidence", 0))
    confidence = float(confidence_raw.replace("%", "").strip())
    nodes = [
        {
            "id": "user",
            "type": "USER",
            "label": "Observed User"
        },
        {
            "id": "device",
            "type": "DEVICE",
            "label": "Observed Device"
        }
    ]

    edges = [
        {
            "source": "user",
            "target": "device",
            "relationship": "USES"
        }
    ]

    if stage != "NO_SIGNIFICANT_THREAT":
        nodes.append({
            "id": "attack_stage",
            "type": "ATTACK_STAGE",
            "label": stage
        })

        edges.append({
            "source": "device",
            "target": "attack_stage",
            "relationship": "INDICATES"
        })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "V5.6",
        "source_version": "V5.5",
        "attack_stage": stage,
        "confidence": confidence,
        "nodes": nodes,
        "edges": edges
    }


def main():
    print("=" * 72)
    print("NEXUS INTELLIGENCE – V5.6 ATTACK PATH INTELLIGENCE")
    print("=" * 72)

    data = load_attack_stage()
    result = build_attack_path(data)

    print()
    print("ATTACK PATH")
    print("-" * 72)
    print(f"Stage      : {result['attack_stage']}")
    print(f"Confidence : {result['confidence']:.1f}%")
    print(f"Nodes      : {len(result['nodes'])}")
    print(f"Edges      : {len(result['edges'])}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print()
    print("Saved:")
    print(OUTPUT_FILE)
    print("=" * 72)


if __name__ == "__main__":
    main()
