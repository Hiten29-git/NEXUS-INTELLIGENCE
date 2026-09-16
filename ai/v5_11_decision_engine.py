import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent

FILES = {
    "calibrated": BASE_DIR / "data/v5_10_1/latest_calibrated_risk.json",
    "temporal": BASE_DIR / "data/v5_10/latest_temporal_correlation.json",
    "temporal_graph": BASE_DIR / "data/v5_9/latest_temporal_graph.json",
    "dynamic_graph": BASE_DIR / "data/v5_8/latest_dynamic_graph.json",
    "graph_risk": BASE_DIR / "data/v5_7/latest_graph_risk.json",
    "attack_path": BASE_DIR / "data/v5_6/latest_attack_path.json",
    "attack_stage": BASE_DIR / "data/v5_5/latest_attack_stage.json",
}

OUTPUT = BASE_DIR / "data/v5_11/latest_decision.json"


def load(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARNING] {path}: {e}")
        return {}


def value(data, *keys, default=0):
    for key in keys:
        if key in data:
            return data[key]
    return default


def count_value(data, *keys):
    v = value(data, *keys, default=0)

    if isinstance(v, list):
        return len(v)

    if isinstance(v, dict):
        return len(v)

    try:
        return int(v)
    except (ValueError, TypeError):
        return 0


def severity(risk):
    if risk >= 80:
        return "CRITICAL"
    if risk >= 60:
        return "HIGH"
    if risk >= 30:
        return "MEDIUM"
    return "LOW"


def main():

    print("=" * 68)
    print("NEXUS INTELLIGENCE - V5.11.1 UNIFIED DECISION ENGINE")
    print("=" * 68)

    calibrated = load(FILES["calibrated"])
    temporal = load(FILES["temporal"])
    temporal_graph = load(FILES["temporal_graph"])
    dynamic_graph = load(FILES["dynamic_graph"])
    graph_risk = load(FILES["graph_risk"])
    attack_path = load(FILES["attack_path"])
    attack_stage = load(FILES["attack_stage"])

    # --------------------------------------------------------
    # CALIBRATED RISK - PRIMARY SIGNAL
    # --------------------------------------------------------

    calibrated_risk = float(
        value(
            calibrated,
            "risk_score",
            "calibrated_risk",
            "risk",
            default=0,
        )
    )

    calibrated_severity = value(
        calibrated,
        "severity",
        default=severity(calibrated_risk),
    )

    # --------------------------------------------------------
    # GRAPH RISK
    # --------------------------------------------------------

    graph_score = float(
        value(
            graph_risk,
            "graph_risk",
            "risk_score",
            "base_risk",
            default=0,
        )
    )

    graph_severity = value(
        graph_risk,
        "graph_severity",
        "severity",
        default=severity(graph_score),
    )

    # --------------------------------------------------------
    # CALIBRATED TEMPORAL INTELLIGENCE
    # --------------------------------------------------------

    calibrated_correlations = count_value(
        calibrated,
        "temporal_correlations",
        "correlations",
    )

    high_confidence = count_value(
        calibrated,
        "high_confidence_correlations",
        "high_confidence_relationships",
        "high_confidence_links",
    )

    ioc_correlations = count_value(
        calibrated,
        "ioc_linked_correlations",
        "ioc_correlations",
    )

    # Fallback to V5.10 if needed
    if calibrated_correlations == 0:
        calibrated_correlations = count_value(
            temporal,
            "temporal_correlations",
            "correlations",
        )

    # --------------------------------------------------------
    # GRAPH SIZE
    # --------------------------------------------------------

    dynamic_nodes = count_value(
        dynamic_graph,
        "nodes",
        "node_count",
    )

    dynamic_edges = count_value(
        dynamic_graph,
        "edges",
        "edge_count",
    )

    temporal_nodes = count_value(
        temporal_graph,
        "nodes",
        "node_count",
    )

    temporal_edges = count_value(
        temporal_graph,
        "edges",
        "edge_count",
    )

    graph_nodes = max(dynamic_nodes, temporal_nodes)

    graph_edges = max(dynamic_edges, temporal_edges)

    # --------------------------------------------------------
    # ATTACK PATH
    # --------------------------------------------------------

    attack_path_nodes = count_value(
        attack_path,
        "nodes",
    )

    attack_path_edges = count_value(
        attack_path,
        "edges",
    )

    # --------------------------------------------------------
    # ATTACK STAGE
    # --------------------------------------------------------

    attack_stage_name = value(
        attack_stage,
        "attack_stage",
        "predicted_stage",
        "stage",
        default="UNKNOWN",
    )

    attack_confidence_raw = value(
        attack_stage,
        "confidence",
        "prediction_confidence",
        "model_confidence",
        default=0,
    )

    if isinstance(attack_confidence_raw, str):
        attack_confidence_raw = attack_confidence_raw.strip().replace("%", "")

    attack_confidence = float(attack_confidence_raw)

    if attack_confidence <= 1:
        attack_confidence *= 100

    # EVIDENCE
    # --------------------------------------------------------

    signals = 0
    evidence = []

    if calibrated_risk >= 30:
        signals += 1
        evidence.append(
            f"Calibrated risk elevated to {calibrated_risk:.2f}/100."
        )

    if graph_score >= 60:
        signals += 1
        evidence.append(
            f"Graph risk elevated to {graph_score:.2f}/100."
        )

    if high_confidence > 0:
        signals += 1
        evidence.append(
            f"{high_confidence} high-confidence temporal relationships observed."
        )

    if ioc_correlations > 0:
        signals += 1
        evidence.append(
            f"{ioc_correlations} IoC-linked correlations observed."
        )

    if attack_path_edges > 0:
        signals += 1
        evidence.append(
            f"{attack_path_edges} attack-path relationships identified."
        )

    if attack_stage_name not in [
        "UNKNOWN",
        "NO_SIGNIFICANT_THREAT",
        "",
        None,
    ]:
        signals += 1
        evidence.append(
            f"Predicted attack stage: {attack_stage_name}."
        )

    # --------------------------------------------------------
    # FINAL RISK
    # --------------------------------------------------------

    final_risk = calibrated_risk

    # Graph evidence only reinforces an already elevated risk.
    if calibrated_risk >= 60 and graph_score >= 60:
        final_risk = min(100, calibrated_risk + 10)

    elif calibrated_risk >= 30 and graph_score >= 60:
        final_risk = min(100, calibrated_risk + 5)

    final_severity = severity(final_risk)

    if final_risk >= 80:
        action = "CONTAIN_AND_ESCALATE"
    elif final_risk >= 60:
        action = "ALERT_AND_INVESTIGATE"
    elif final_risk >= 30:
        action = "INCREASE_MONITORING"
    elif signals >= 2:
        action = "MONITOR_WITH_CORRELATION"
    else:
        action = "MONITOR"

    # --------------------------------------------------------
    # FINAL EXPLANATION
    # --------------------------------------------------------

    explanation = [
        f"Calibrated behavioral risk: {calibrated_risk:.2f}/100.",
        f"Supporting graph risk: {graph_score:.2f}/100.",
        f"Temporal correlations: {calibrated_correlations}.",
        f"High-confidence relationships: {high_confidence}.",
        f"Graph size: {graph_nodes} nodes / {graph_edges} edges.",
        f"Attack stage: {attack_stage_name} "
        f"({attack_confidence:.1f}% confidence).",
        f"NEXUS identified {signals} corroborating security signal(s).",
        f"Final action: {action}.",
    ]

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "V5.11.1",

        "decision": {
            "risk_score": round(final_risk, 2),
            "severity": final_severity,
            "action": action,
            "corroborating_signals": signals,
        },

        "risk_layers": {
            "calibrated_risk": round(calibrated_risk, 2),
            "calibrated_severity": calibrated_severity,
            "graph_risk": round(graph_score, 2),
            "graph_severity": graph_severity,
        },

        "temporal_intelligence": {
            "correlations": calibrated_correlations,
            "high_confidence_relationships": high_confidence,
            "ioc_linked_correlations": ioc_correlations,
        },

        "graph_intelligence": {
            "nodes": graph_nodes,
            "edges": graph_edges,
        },

        "attack_intelligence": {
            "stage": attack_stage_name,
            "confidence": round(attack_confidence, 2),
            "path_nodes": attack_path_nodes,
            "path_edges": attack_path_edges,
        },

        "evidence": evidence,
        "explanation": explanation,

        "pipeline": [
            "REAL_TIME_EVENTS",
            "AI_ANOMALY_DETECTION",
            "BEHAVIORAL_RISK",
            "DYNAMIC_GRAPH",
            "TEMPORAL_CORRELATION",
            "CALIBRATED_RISK",
            "ATTACK_STAGE_PREDICTION",
            "UNIFIED_SECURITY_DECISION",
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # --------------------------------------------------------
    # TERMINAL DISPLAY
    # --------------------------------------------------------

    print()
    print("UNIFIED NEXUS DECISION")
    print("-" * 68)

    print(f"Calibrated Risk       : {calibrated_risk:.2f}/100")
    print(f"Graph Risk            : {graph_score:.2f}/100")
    print(f"Temporal Correlations : {calibrated_correlations}")
    print(f"High-Confidence Links : {high_confidence}")
    print(f"IoC Correlations      : {ioc_correlations}")
    print(f"Graph Nodes           : {graph_nodes}")
    print(f"Graph Edges           : {graph_edges}")
    print(f"Attack Stage          : {attack_stage_name}")
    print(f"Prediction Confidence : {attack_confidence:.1f}%")

    print()
    print("FINAL NEXUS DECISION")
    print("-" * 68)

    print(f"Risk Score : {final_risk:.2f}/100")
    print(f"Severity   : {final_severity}")
    print(f"Action     : {action}")

    print()
    print("EXPLANATION")
    print("-" * 68)

    for item in explanation:
        print(f"- {item}")

    print()
    print("=" * 68)
    print("V5.11.1 UNIFIED DECISION ENGINE COMPLETE")
    print("=" * 68)
    print()
    print(f"Saved: {OUTPUT}")


if __name__ == "__main__":
    main()
