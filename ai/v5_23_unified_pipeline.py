#!/usr/bin/env python3

"""
NEXUS INTELLIGENCE - V5.23
UNIFIED INTELLIGENCE PIPELINE

Combines:
V5.18 - Risk Decision
V5.19 - Attack Path
V5.20 - Explainability
V5.21 - Next-Stage Prediction
V5.22 - Response Orchestrator

Safety:
- Recommendation only
- No destructive automatic actions
- Human approval required
"""

import json
from pathlib import Path
from datetime import datetime


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

V18_FILE = DATA_DIR / "v5_18" / "latest_decision.json"
V19_FILE = DATA_DIR / "v5_19" / "latest_attack_path.json"
V20_FILE = DATA_DIR / "v5_20" / "latest_explanation.json"
V21_FILE = DATA_DIR / "v5_21" / "latest_prediction.json"
V22_FILE = DATA_DIR / "v5_22" / "latest_response_plan.json"

OUTPUT_DIR = DATA_DIR / "v5_23"
OUTPUT_FILE = OUTPUT_DIR / "latest_unified_intelligence.json"


# ============================================================
# JSON LOADER
# ============================================================

def load_json(path):
    """Load JSON safely."""
    if not path.exists():
        raise FileNotFoundError(f"Required file not found: {path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# ============================================================
# SAFE HELPERS
# ============================================================

def safe_dict(value):
    """Return dictionary or empty dictionary."""
    return value if isinstance(value, dict) else {}


def safe_list(value):
    """Return list or empty list."""
    return value if isinstance(value, list) else []


def safe_float(value, default=0.0):
    """Convert value to float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value, default=0):
    """
    Convert scalar values to int.

    If value is a list/dict, use its length.
    This prevents the previous graph-nodes error.
    """
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ============================================================
# GRAPH EXTRACTION
# ============================================================

def extract_graph_summary(attack_path_data, explanation_data, response_data):
    """
    Extract graph information regardless of whether the source
    stores nodes/relationships as lists or numeric counts.
    """

    candidates = [
        safe_dict(attack_path_data.get("graph")),
        safe_dict(explanation_data.get("graph_summary")),
        safe_dict(response_data.get("graph")),
    ]

    nodes = 0
    relationships = 0

    for graph in candidates:

        if not graph:
            continue

        if nodes == 0:
            nodes = safe_int(
                graph.get("nodes", graph.get("node_count", 0))
            )

        if relationships == 0:
            relationships = safe_int(
                graph.get(
                    "relationships",
                    graph.get("relationship_count", 0)
                )
            )

        if nodes > 0 and relationships > 0:
            break

    return {
        "nodes": nodes,
        "relationships": relationships
    }


# ============================================================
# RISK EXTRACTION
# ============================================================

def extract_risk(decision_data):
    risk_score = safe_float(
        decision_data.get("risk_score", 0)
    )

    severity = decision_data.get(
        "severity",
        "UNKNOWN"
    )

    decision = decision_data.get(
        "decision",
        "MONITOR"
    )

    response_level = decision_data.get(
        "response_level",
        "LOW"
    )

    return {
        "risk_score": round(risk_score, 2),
        "severity": severity,
        "decision": decision,
        "response_level": response_level
    }


# ============================================================
# ATTACK PATH EXTRACTION
# ============================================================

def extract_attack_path(attack_path_data):

    attack_path = safe_dict(
        attack_path_data.get("attack_path")
    )

    return {
        "status": attack_path.get(
            "status",
            "UNKNOWN"
        ),

        "path_score": round(
            safe_float(
                attack_path.get("path_score", 0)
            ),
            2
        ),

        "path_severity": attack_path.get(
            "severity",
            "UNKNOWN"
        ),

        "current_stage": attack_path.get(
            "current_stage",
            "UNKNOWN"
        ),

        "stages": safe_list(
            attack_path.get("stages", [])
        )
    }


# ============================================================
# EXPLAINABILITY EXTRACTION
# ============================================================

def extract_explainability(explanation_data):

    explainability = safe_dict(
        explanation_data.get("explainability")
    )

    top_signals = safe_list(
        explainability.get("top_signals", [])
    )

    reasons = safe_list(
        explanation_data.get("reasons", [])
    )

    human_explanation = safe_list(
        explanation_data.get("human_explanation", [])
    )

    return {
        "confidence": explainability.get(
            "confidence",
            "UNKNOWN"
        ),

        "top_signals": top_signals,

        "reasons": reasons,

        "human_explanation": human_explanation
    }


# ============================================================
# NEXT-STAGE PREDICTION
# ============================================================

def extract_prediction(prediction_data):

    prediction = safe_dict(
        prediction_data.get("prediction")
    )

    return {
        "predicted_stage": prediction.get(
            "predicted_stage",
            "UNKNOWN"
        ),

        "prediction_score": round(
            safe_float(
                prediction.get(
                    "prediction_score",
                    0
                )
            ),
            2
        ),

        "confidence": prediction.get(
            "confidence",
            "UNKNOWN"
        ),

        "reason": prediction.get(
            "reason",
            "No prediction reason available."
        ),

        "candidate_stages": safe_list(
            prediction.get(
                "candidate_stages",
                []
            )
        )
    }


# ============================================================
# RESPONSE EXTRACTION
# ============================================================

def extract_response(response_data):

    response_decision = safe_dict(
        response_data.get(
            "response_decision"
        )
    )

    safety = safe_dict(
        response_data.get("safety")
    )

    recommended_actions = safe_list(
        response_data.get(
            "recommended_actions",
            []
        )
    )

    return {
        "action": response_decision.get(
            "action",
            response_data.get(
                "decision",
                "MONITOR"
            )
        ),

        "priority": response_decision.get(
            "priority",
            response_data.get(
                "response_level",
                "LOW"
            )
        ),

        "recommended_actions": recommended_actions,

        "human_approval_required": bool(
            safety.get(
                "human_approval_required",
                True
            )
        ),

        "automatic_destructive_action": bool(
            safety.get(
                "automatic_destructive_action",
                False
            )
        ),

        "operating_mode": safety.get(
            "operating_mode",
            "RECOMMENDATION_ONLY"
        )
    }


# ============================================================
# OVERALL THREAT LEVEL
# ============================================================

def calculate_threat_level(
    risk_score,
    path_score,
    prediction_score
):

    combined_score = (
        (risk_score * 0.50)
        + (path_score * 0.25)
        + (prediction_score * 0.25)
    )

    if combined_score >= 80:
        level = "CRITICAL"

    elif combined_score >= 60:
        level = "HIGH"

    elif combined_score >= 40:
        level = "MEDIUM"

    elif combined_score >= 20:
        level = "LOW"

    else:
        level = "MINIMAL"

    return {
        "combined_score": round(
            combined_score,
            2
        ),
        "threat_level": level
    }


# ============================================================
# BUILD UNIFIED OUTPUT
# ============================================================

def build_unified_intelligence(
    decision_data,
    attack_path_data,
    explanation_data,
    prediction_data,
    response_data
):

    risk = extract_risk(
        decision_data
    )

    attack_path = extract_attack_path(
        attack_path_data
    )

    explainability = extract_explainability(
        explanation_data
    )

    prediction = extract_prediction(
        prediction_data
    )

    response = extract_response(
        response_data
    )

    graph = extract_graph_summary(
        attack_path_data,
        explanation_data,
        response_data
    )

    threat = calculate_threat_level(
        risk["risk_score"],
        attack_path["path_score"],
        prediction["prediction_score"]
    )

    unified_reasons = []

    if risk["risk_score"] >= 60:
        unified_reasons.append(
            "Elevated contextual risk was detected."
        )

    if attack_path["path_score"] >= 60:
        unified_reasons.append(
            "Multiple correlated security stages "
            "increase attack-path concern."
        )

    if prediction["prediction_score"] >= 70:
        unified_reasons.append(
            f"Next-stage prediction indicates elevated "
            f"likelihood of {prediction['predicted_stage']}."
        )

    if graph["nodes"] > 0:
        unified_reasons.append(
            f"Security graph contains {graph['nodes']} "
            f"nodes and {graph['relationships']} relationships."
        )

    if not unified_reasons:
        unified_reasons.append(
            "Current telemetry does not indicate a high-confidence threat."
        )

    return {

        "version": "V5.23",

        "generated_at": datetime.now().isoformat(),

        "system": {
            "name": "NEXUS INTELLIGENCE",
            "module": "Unified Intelligence Pipeline",
            "operating_mode": "RECOMMENDATION_ONLY"
        },

        "overall_assessment": {
            "combined_score": threat["combined_score"],
            "threat_level": threat["threat_level"]
        },

        "risk": risk,

        "attack_path": attack_path,

        "prediction": prediction,

        "explainability": explainability,

        "graph": graph,

        "response": response,

        "unified_reasons": unified_reasons,

        "pipeline": {
            "v5_18_risk": "COMPLETE",
            "v5_19_attack_path": "COMPLETE",
            "v5_20_explainability": "COMPLETE",
            "v5_21_prediction": "COMPLETE",
            "v5_22_response": "COMPLETE"
        },

        "safety": {
            "human_approval_required": True,
            "automatic_destructive_action": False,
            "operating_mode": "RECOMMENDATION_ONLY"
        }
    }


# ============================================================
# SAVE
# ============================================================

def save_result(result):

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            indent=2
        )


# ============================================================
# DISPLAY
# ============================================================

def print_result(result):

    risk = result["risk"]
    attack = result["attack_path"]
    prediction = result["prediction"]
    graph = result["graph"]
    response = result["response"]
    overall = result["overall_assessment"]

    print()
    print("=" * 68)
    print("NEXUS INTELLIGENCE - V5.23 UNIFIED PIPELINE")
    print("=" * 68)

    print()
    print("OVERALL SECURITY ASSESSMENT")
    print("-" * 68)

    print(
        f"Combined Threat Score : "
        f"{overall['combined_score']:.2f}/100"
    )

    print(
        f"Threat Level          : "
        f"{overall['threat_level']}"
    )

    print()
    print("RISK INTELLIGENCE")
    print("-" * 68)

    print(
        f"Risk Score            : "
        f"{risk['risk_score']:.2f}/100"
    )

    print(
        f"Severity              : "
        f"{risk['severity']}"
    )

    print(
        f"Decision              : "
        f"{risk['decision']}"
    )

    print(
        f"Response Level        : "
        f"{risk['response_level']}"
    )

    print()
    print("ATTACK PATH")
    print("-" * 68)

    print(
        f"Status                : "
        f"{attack['status']}"
    )

    print(
        f"Path Score            : "
        f"{attack['path_score']:.2f}/100"
    )

    print(
        f"Path Severity         : "
        f"{attack['path_severity']}"
    )

    print(
        f"Current Stage         : "
        f"{attack['current_stage']}"
    )

    if attack["stages"]:

        print("Stages:")

        for index, stage in enumerate(
            attack["stages"],
            start=1
        ):

            print(
                f"  {index}. {stage}"
            )

    print()
    print("NEXT-STAGE PREDICTION")
    print("-" * 68)

    print(
        f"Predicted Stage       : "
        f"{prediction['predicted_stage']}"
    )

    print(
        f"Prediction Score      : "
        f"{prediction['prediction_score']:.2f}/100"
    )

    print(
        f"Confidence            : "
        f"{prediction['confidence']}"
    )

    print(
        f"Reason                : "
        f"{prediction['reason']}"
    )

    print()
    print("EXPLAINABILITY")
    print("-" * 68)

    print(
        f"Confidence            : "
        f"{result['explainability']['confidence']}"
    )

    print("Top Signals:")

    for signal in result["explainability"]["top_signals"]:

        if isinstance(signal, dict):

            name = signal.get(
                "signal",
                "unknown"
            )

            score = safe_float(
                signal.get(
                    "score",
                    0
                )
            )

            contribution = safe_float(
                signal.get(
                    "contribution",
                    0
                )
            )

            print(
                f"  - {name}: "
                f"{score:.2f}/100 "
                f"(contribution {contribution:.2f})"
            )

    print()
    print("SECURITY GRAPH")
    print("-" * 68)

    print(
        f"Nodes                 : "
        f"{graph['nodes']}"
    )

    print(
        f"Relationships         : "
        f"{graph['relationships']}"
    )

    print()
    print("RESPONSE")
    print("-" * 68)

    print(
        f"Action                : "
        f"{response['action']}"
    )

    print(
        f"Priority              : "
        f"{response['priority']}"
    )

    print(
        f"Human Approval        : "
        f"{response['human_approval_required']}"
    )

    print(
        f"Automatic Destructive : "
        f"{response['automatic_destructive_action']}"
    )

    print(
        f"Operating Mode        : "
        f"{response['operating_mode']}"
    )

    print()
    print("RECOMMENDED ACTIONS")
    print("-" * 68)

    for action in response["recommended_actions"]:

        print(
            f"- {action}"
        )

    print()
    print("WHY NEXUS REACHED THIS ASSESSMENT")
    print("-" * 68)

    for reason in result["unified_reasons"]:

        print(
            f"- {reason}"
        )

    print()
    print("PIPELINE STATUS")
    print("-" * 68)

    for module, status in result["pipeline"].items():

        print(
            f"{module:<25} : {status}"
        )

    print()
    print("SAFETY")
    print("-" * 68)

    print(
        "Human approval required : TRUE"
    )

    print(
        "Automatic destructive action : FALSE"
    )

    print(
        "Mode : RECOMMENDATION_ONLY"
    )

    print()
    print("Saved:")
    print(OUTPUT_FILE)

    print()
    print("=" * 68)
    print("V5.23 UNIFIED INTELLIGENCE PIPELINE COMPLETE")
    print("=" * 68)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 68)
    print("NEXUS INTELLIGENCE - V5.23 UNIFIED PIPELINE")
    print("=" * 68)

    try:

        decision_data = load_json(
            V18_FILE
        )

        attack_path_data = load_json(
            V19_FILE
        )

        explanation_data = load_json(
            V20_FILE
        )

        prediction_data = load_json(
            V21_FILE
        )

        response_data = load_json(
            V22_FILE
        )

        result = build_unified_intelligence(
            decision_data,
            attack_path_data,
            explanation_data,
            prediction_data,
            response_data
        )

        save_result(result)

        print_result(result)

    except Exception as error:

        print()
        print("ERROR")
        print("-" * 68)
        print(
            f"{type(error).__name__}: {error}"
        )
        print("-" * 68)

        raise


if __name__ == "__main__":
    main()
