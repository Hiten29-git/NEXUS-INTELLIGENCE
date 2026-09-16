import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parent.parent

OUTPUT_DIR = ROOT / "data" / "v5_12"
OUTPUT_FILE = OUTPUT_DIR / "latest_nexus_result.json"

DECISION_FILE = ROOT / "data" / "v5_11" / "latest_decision.json"


STEPS = [
    ("TEMPORAL GRAPH", ROOT / "ai" / "v5_9_temporal_graph.py"),
    ("TEMPORAL CORRELATION", ROOT / "ai" / "v5_10_temporal_correlation.py"),
    ("CALIBRATED RISK", ROOT / "ai" / "v5_10_1_calibrated_risk.py"),
    ("UNIFIED DECISION", ROOT / "ai" / "v5_11_decision_engine.py"),
]


def run_step(name, script):

    print()
    print("=" * 65)
    print(f"NEXUS V5.12 → {name}")
    print("=" * 65)

    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=ROOT,
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(result.stdout)

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr)

        raise RuntimeError(f"{name} failed.")

    print(f"✓ {name} completed")


def load_json(path):

    if not path.exists():
        raise FileNotFoundError(
            f"Required JSON file not found: {path}"
        )

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_confidence(value):

    if value is None:
        return 0.0

    if isinstance(value, str):
        value = value.strip().replace("%", "")

    value = float(value)

    if value <= 1:
        value *= 100

    return round(value, 2)


def main():

    print("=" * 65)
    print("NEXUS INTELLIGENCE — V5.12 ORCHESTRATOR")
    print("=" * 65)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # RUN COMPLETE PIPELINE
    # ---------------------------------------------------------

    for name, script in STEPS:
        run_step(name, script)

    # ---------------------------------------------------------
    # LOAD V5.11 UNIFIED DECISION
    # ---------------------------------------------------------

    decision_data = load_json(DECISION_FILE)

    # ---------------------------------------------------------
    # READ NESTED V5.11 STRUCTURE
    # ---------------------------------------------------------

    decision = decision_data.get("decision", {})

    risk_layers = decision_data.get(
        "risk_layers",
        {}
    )

    temporal = decision_data.get(
        "temporal_intelligence",
        {}
    )

    graph = decision_data.get(
        "graph_intelligence",
        {}
    )

    attack = decision_data.get(
        "attack_intelligence",
        {}
    )

    evidence = decision_data.get(
        "evidence",
        []
    )

    explanation = decision_data.get(
        "explanation",
        []
    )

    pipeline = decision_data.get(
        "pipeline",
        []
    )

    # ---------------------------------------------------------
    # EXTRACT VALUES
    # ---------------------------------------------------------

    risk_score = float(
        decision.get(
            "risk_score",
            risk_layers.get(
                "calibrated_risk",
                0
            )
        )
    )

    severity = decision.get(
        "severity",
        risk_layers.get(
            "calibrated_severity",
            "UNKNOWN"
        )
    )

    action = decision.get(
        "action",
        "MONITOR"
    )

    temporal_correlations = int(
        temporal.get(
            "correlations",
            0
        )
    )

    high_confidence_links = int(
        temporal.get(
            "high_confidence_relationships",
            0
        )
    )

    ioc_correlations = int(
        temporal.get(
            "ioc_linked_correlations",
            0
        )
    )

    graph_nodes = int(
        graph.get(
            "nodes",
            0
        )
    )

    graph_edges = int(
        graph.get(
            "edges",
            0
        )
    )

    attack_stage = attack.get(
        "stage",
        "UNKNOWN"
    )

    prediction_confidence = normalize_confidence(
        attack.get(
            "confidence",
            0
        )
    )

    path_nodes = int(
        attack.get(
            "path_nodes",
            0
        )
    )

    path_edges = int(
        attack.get(
            "path_edges",
            0
        )
    )

    # ---------------------------------------------------------
    # BUILD UNIFIED NEXUS RESULT
    # ---------------------------------------------------------

    final_result = {

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "version": "V5.12",

        "status": "PIPELINE_COMPLETE",

        "decision": {

            "risk_score": risk_score,

            "severity": severity,

            "action": action,

            "attack_stage": attack_stage,

            "prediction_confidence": prediction_confidence
        },

        "risk_intelligence": {

            "calibrated_risk": risk_layers.get(
                "calibrated_risk",
                risk_score
            ),

            "calibrated_severity": risk_layers.get(
                "calibrated_severity",
                severity
            ),

            "graph_risk": risk_layers.get(
                "graph_risk",
                0
            ),

            "graph_severity": risk_layers.get(
                "graph_severity",
                "UNKNOWN"
            )
        },

        "temporal_intelligence": {

            "correlations": temporal_correlations,

            "high_confidence_relationships":
                high_confidence_links,

            "ioc_linked_correlations":
                ioc_correlations
        },

        "graph_intelligence": {

            "nodes": graph_nodes,

            "edges": graph_edges
        },

        "attack_intelligence": {

            "stage": attack_stage,

            "confidence": prediction_confidence,

            "path_nodes": path_nodes,

            "path_edges": path_edges
        },

        "evidence": evidence,

        "explanation": explanation,

        "pipeline": pipeline
    }

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            final_result,
            f,
            indent=2
        )

    # ---------------------------------------------------------
    # DISPLAY
    # ---------------------------------------------------------

    print()
    print("=" * 65)
    print("NEXUS V5.12 FINAL RESULT")
    print("=" * 65)

    print()
    print("DECISION")
    print("-" * 65)

    print(
        f"Risk Score           : "
        f"{risk_score}/100"
    )

    print(
        f"Severity             : "
        f"{severity}"
    )

    print(
        f"Action               : "
        f"{action}"
    )

    print(
        f"Attack Stage         : "
        f"{attack_stage}"
    )

    print(
        f"Prediction Confidence: "
        f"{prediction_confidence}%"
    )

    print()
    print("TEMPORAL INTELLIGENCE")
    print("-" * 65)

    print(
        f"Correlations         : "
        f"{temporal_correlations}"
    )

    print(
        f"High-confidence     : "
        f"{high_confidence_links}"
    )

    print(
        f"IoC correlations    : "
        f"{ioc_correlations}"
    )

    print()
    print("GRAPH INTELLIGENCE")
    print("-" * 65)

    print(
        f"Graph Nodes          : "
        f"{graph_nodes}"
    )

    print(
        f"Graph Edges          : "
        f"{graph_edges}"
    )

    print()
    print("ATTACK PATH")
    print("-" * 65)

    print(
        f"Path Nodes           : "
        f"{path_nodes}"
    )

    print(
        f"Path Edges           : "
        f"{path_edges}"
    )

    print()
    print("=" * 65)
    print("V5.12 NEXUS PIPELINE COMPLETE")
    print("=" * 65)

    print()
    print(
        f"Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
