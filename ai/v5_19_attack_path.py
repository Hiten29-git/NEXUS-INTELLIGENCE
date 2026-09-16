import json
from pathlib import Path

INPUT = Path("data/v5_18/latest_decision.json")
OUTPUT = Path("data/v5_19/latest_attack_path.json")


def main():
    data = json.loads(INPUT.read_text())

    risk = float(data.get("risk_score", 0))
    severity = data.get("severity", "LOW")
    decision = data.get("decision", "MONITOR")
    components = data.get("components", {})

    network = float(components.get("network", 0))
    process = float(components.get("process", 0))
    ai_anomaly = float(components.get("ai_anomaly", 0))
    adaptive = float(components.get("adaptive_baseline", 0))
    persistence = float(components.get("temporal_persistence", 0))
    ioc = float(components.get("ioc", 0))

    nodes = []
    edges = []
    attack_stages = []
    reasons = []

    # Root entity
    nodes.append({
        "type": "USER",
        "label": "Current User"
    })

    # Behavioral anomaly
    if ai_anomaly >= 30 or adaptive >= 50:
        nodes.append({
            "type": "BEHAVIOR",
            "label": "Anomalous Behavior"
        })
        edges.append({
            "source": "Current User",
            "target": "Anomalous Behavior",
            "relation": "EXHIBITS"
        })
        attack_stages.append("Initial Access / Suspicious Activity")
        reasons.append("Behavior deviates from the learned baseline.")

    # Process activity
    if process >= 25:
        nodes.append({
            "type": "PROCESS",
            "label": "Suspicious Process Activity"
        })
        edges.append({
            "source": "Current User",
            "target": "Suspicious Process Activity",
            "relation": "EXECUTES"
        })
        attack_stages.append("Execution")
        reasons.append("Elevated process activity was observed.")

    # Network activity
    if network >= 50:
        nodes.append({
            "type": "NETWORK",
            "label": "Multiple Network Destinations"
        })
        edges.append({
            "source": "Current User",
            "target": "Multiple Network Destinations",
            "relation": "CONNECTS_TO"
        })
        attack_stages.append("Discovery / Command & Control")
        reasons.append("Elevated network activity and multiple destinations were observed.")

    # IOC activity
    if ioc > 0:
        nodes.append({
            "type": "IOC",
            "label": "Threat Indicator Match"
        })
        edges.append({
            "source": "Current User",
            "target": "Threat Indicator Match",
            "relation": "MATCHES"
        })
        attack_stages.append("Threat Indicator Association")
        reasons.append("Threat intelligence indicators were matched.")

    # Persistence / repeated activity
    if persistence >= 60:
        nodes.append({
            "type": "TEMPORAL",
            "label": "Persistent Suspicious Activity"
        })
        edges.append({
            "source": "Current User",
            "target": "Persistent Suspicious Activity",
            "relation": "PERSISTS_ACROSS"
        })
        attack_stages.append("Persistence / Continued Activity")
        reasons.append("Suspicious activity persists across multiple time windows.")

    # Attack-path score
    path_score = min(
        100,
        (
            risk * 0.40
            + network * 0.20
            + process * 0.10
            + adaptive * 0.10
            + persistence * 0.15
            + ioc * 0.05
        )
    )

    if path_score >= 70:
        path_severity = "CRITICAL"
    elif path_score >= 50:
        path_severity = "HIGH"
    elif path_score >= 30:
        path_severity = "MEDIUM"
    else:
        path_severity = "LOW"

    if len(nodes) >= 4:
        path_status = "MULTI_STAGE_ACTIVITY"
    elif len(nodes) >= 2:
        path_status = "SUSPICIOUS_ACTIVITY"
    else:
        path_status = "NO_SIGNIFICANT_PATH"

    result = {
        "version": "V5.19",
        "source_decision": {
            "risk_score": risk,
            "severity": severity,
            "decision": decision
        },
        "attack_path": {
            "status": path_status,
            "path_score": round(path_score, 2),
            "severity": path_severity,
            "stages": attack_stages
        },
        "graph": {
            "nodes": nodes,
            "edges": edges
        },
        "signals": {
            "ai_anomaly": ai_anomaly,
            "adaptive_baseline": adaptive,
            "network": network,
            "process": process,
            "ioc": ioc,
            "temporal_persistence": persistence
        },
        "reasons": reasons
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2))

    print("=" * 64)
    print("NEXUS INTELLIGENCE - V5.19 ATTACK-PATH INTELLIGENCE")
    print("=" * 64)

    print()
    print("INPUT")
    print("-" * 64)
    print(f"Risk Score       : {risk:.2f}/100")
    print(f"Severity         : {severity}")
    print(f"Decision         : {decision}")

    print()
    print("ATTACK PATH")
    print("-" * 64)
    print(f"Status           : {path_status}")
    print(f"Path Score       : {path_score:.2f}/100")
    print(f"Path Severity    : {path_severity}")

    print()
    print("STAGES")
    print("-" * 64)

    if attack_stages:
        for stage in attack_stages:
            print(f"- {stage}")
    else:
        print("- No significant attack stage identified.")

    print()
    print("GRAPH")
    print("-" * 64)
    print(f"Nodes            : {len(nodes)}")
    print(f"Relationships    : {len(edges)}")

    print()
    print("REASONS")
    print("-" * 64)

    if reasons:
        for reason in reasons:
            print(f"- {reason}")
    else:
        print("- No strong graph signal identified.")

    print()
    print("Saved:")
    print(OUTPUT)

    print()
    print("=" * 64)
    print("V5.19 ATTACK-PATH INTELLIGENCE COMPLETE")
    print("=" * 64)


if __name__ == "__main__":
    main()
