"""
NEXUS INTELLIGENCE - V5.22 RESPONSE ORCHESTRATOR

Purpose:
    Combine:
        V5.18 Risk Decision
        V5.19 Attack-Path Intelligence
        V5.20 Explainable Security
        V5.21 Next-Stage Prediction

    into one safe response plan.

Safety:
    - Recommendation-only mode
    - Human approval required
    - No automatic destructive actions
"""

import json
from pathlib import Path
from datetime import datetime


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DECISION_FILE = BASE_DIR / "data" / "v5_18" / "latest_decision.json"
ATTACK_PATH_FILE = BASE_DIR / "data" / "v5_19" / "latest_attack_path.json"
EXPLANATION_FILE = BASE_DIR / "data" / "v5_20" / "latest_explanation.json"
PREDICTION_FILE = BASE_DIR / "data" / "v5_21" / "latest_prediction.json"

OUTPUT_DIR = BASE_DIR / "data" / "v5_22"
OUTPUT_FILE = OUTPUT_DIR / "latest_response_plan.json"


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def load_json(file_path):
    """Load a JSON file safely."""

    if not file_path.exists():
        raise FileNotFoundError(
            f"Required input file not found: {file_path}"
        )

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_result(result):
    """Save final response plan."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)

    return OUTPUT_FILE


def safe_float(value, default=0.0):
    """Convert a value to float safely."""

    try:
        if value is None:
            return default

        if isinstance(value, bool):
            return float(value)

        return float(value)

    except (TypeError, ValueError):
        return default


def safe_string(value, default="UNKNOWN"):
    """Convert value to a clean string."""

    if value is None:
        return default

    if isinstance(value, str):
        value = value.strip()

        if value:
            return value

    return default


def get_graph_count(value):
    """
    Handle graph values that may be:
        - list
        - integer
        - float
        - missing
    """

    if isinstance(value, list):
        return len(value)

    if isinstance(value, tuple):
        return len(value)

    if isinstance(value, (int, float)):
        return int(value)

    return 0


# ============================================================
# DATA EXTRACTION
# ============================================================

def extract_decision_data(decision_data):
    """Extract V5.18 risk decision."""

    if not isinstance(decision_data, dict):
        raise TypeError("V5.18 decision data must be a JSON object.")

    risk_score = safe_float(
        decision_data.get("risk_score", 0)
    )

    severity = safe_string(
        decision_data.get("severity", "UNKNOWN")
    )

    decision = safe_string(
        decision_data.get("decision", "REVIEW")
    )

    response_level = safe_string(
        decision_data.get("response_level", severity)
    )

    components = decision_data.get("components", {})

    if not isinstance(components, dict):
        components = {}

    return {
        "risk_score": round(risk_score, 2),
        "severity": severity,
        "decision": decision,
        "response_level": response_level,
        "components": components,
    }


def extract_attack_path_data(attack_path_data):
    """
    Extract V5.19 attack-path information.

    Expected structure:

    {
        "attack_path": {
            "status": "...",
            "path_score": 68.37,
            "severity": "HIGH",
            "stages": [...]
        },
        "graph": {
            "nodes": [...],
            "edges": [...]
        }
    }
    """

    if not isinstance(attack_path_data, dict):
        raise TypeError(
            "V5.19 attack-path data must be a JSON object."
        )

    # --------------------------------------------------------
    # IMPORTANT:
    # V5.19 stores these values INSIDE attack_path.
    # --------------------------------------------------------

    attack_path = attack_path_data.get("attack_path", {})

    if not isinstance(attack_path, dict):
        attack_path = {}

    attack_path_status = safe_string(
        attack_path.get("status", "UNKNOWN")
    )

    path_score = safe_float(
        attack_path.get("path_score", 0)
    )

    path_severity = safe_string(
        attack_path.get("severity", "UNKNOWN")
    )

    stages = attack_path.get("stages", [])

    if not isinstance(stages, list):
        stages = []

    # --------------------------------------------------------
    # GRAPH
    # --------------------------------------------------------

    graph_data = attack_path_data.get("graph", {})

    if not isinstance(graph_data, dict):
        graph_data = {}

    nodes = get_graph_count(
        graph_data.get("nodes", [])
    )

    relationships = get_graph_count(
        graph_data.get("edges", [])
    )

    return {
        "status": attack_path_status,
        "path_score": round(path_score, 2),
        "severity": path_severity,
        "stages": stages,
        "nodes": nodes,
        "relationships": relationships,
    }


def extract_explanation_data(explanation_data):
    """Extract V5.20 explainability information."""

    if not isinstance(explanation_data, dict):
        raise TypeError(
            "V5.20 explanation data must be a JSON object."
        )

    explainability = explanation_data.get(
        "explainability",
        {}
    )

    if not isinstance(explainability, dict):
        explainability = {}

    confidence = safe_string(
        explainability.get(
            "confidence",
            "UNKNOWN"
        )
    )

    top_signals = explainability.get(
        "top_signals",
        []
    )

    if not isinstance(top_signals, list):
        top_signals = []

    reasons = explanation_data.get(
        "reasons",
        []
    )

    if not isinstance(reasons, list):
        reasons = []

    human_explanation = explanation_data.get(
        "human_explanation",
        []
    )

    if not isinstance(human_explanation, list):
        human_explanation = []

    graph_summary = explanation_data.get(
        "graph_summary",
        {}
    )

    if not isinstance(graph_summary, dict):
        graph_summary = {}

    return {
        "confidence": confidence,
        "top_signals": top_signals,
        "reasons": reasons,
        "human_explanation": human_explanation,
        "graph_summary": graph_summary,
    }


def extract_prediction_data(prediction_data):
    """Extract V5.21 next-stage prediction."""

    if not isinstance(prediction_data, dict):
        raise TypeError(
            "V5.21 prediction data must be a JSON object."
        )

    prediction = prediction_data.get(
        "prediction",
        {}
    )

    if not isinstance(prediction, dict):
        prediction = {}

    predicted_stage = safe_string(
        prediction.get(
            "predicted_stage",
            "UNKNOWN"
        )
    )

    prediction_score = safe_float(
        prediction.get(
            "prediction_score",
            0
        )
    )

    confidence = safe_string(
        prediction.get(
            "confidence",
            "UNKNOWN"
        )
    )

    reason = safe_string(
        prediction.get(
            "reason",
            "No prediction reason available."
        ),
        "No prediction reason available."
    )

    candidate_stages = prediction.get(
        "candidate_stages",
        []
    )

    if not isinstance(candidate_stages, list):
        candidate_stages = []

    monitoring_recommendations = prediction_data.get(
        "monitoring_recommendations",
        []
    )

    if not isinstance(monitoring_recommendations, list):
        monitoring_recommendations = []

    return {
        "predicted_stage": predicted_stage,
        "prediction_score": round(prediction_score, 2),
        "confidence": confidence,
        "reason": reason,
        "candidate_stages": candidate_stages,
        "monitoring_recommendations": monitoring_recommendations,
    }


# ============================================================
# RESPONSE LOGIC
# ============================================================

def build_recommended_actions(
    decision,
    severity,
    attack_path,
    prediction,
):
    """Build safe recommended actions."""

    actions = []

    # --------------------------------------------------------
    # General investigation
    # --------------------------------------------------------

    if severity in ["HIGH", "CRITICAL"]:
        actions.append(
            "Require SOC analyst investigation."
        )

    else:
        actions.append(
            "Review the alert and validate the observed behavior."
        )

    # --------------------------------------------------------
    # Decision-specific actions
    # --------------------------------------------------------

    if decision == "CONTAIN":
        actions.append(
            "Consider temporary containment after human approval."
        )

    elif decision == "BLOCK":
        actions.append(
            "Consider blocking the relevant activity only after human approval."
        )

    elif decision == "ESCALATE":
        actions.append(
            "Escalate the alert to the appropriate security analyst."
        )

    else:
        actions.append(
            "Continue monitoring before taking containment action."
        )

    # --------------------------------------------------------
    # Process activity
    # --------------------------------------------------------

    actions.append(
        "Inspect suspicious processes and network destinations."
    )

    # --------------------------------------------------------
    # Persistent activity
    # --------------------------------------------------------

    if attack_path["status"] != "UNKNOWN":
        actions.append(
            "Review persistent anomalous behavior across time windows."
        )

    # --------------------------------------------------------
    # Prediction-specific monitoring
    # --------------------------------------------------------

    predicted_stage = prediction["predicted_stage"]

    if predicted_stage != "UNKNOWN":
        actions.append(
            f"Monitor telemetry associated with the predicted stage: "
            f"{predicted_stage}."
        )

    # --------------------------------------------------------
    # Graph investigation
    # --------------------------------------------------------

    if attack_path["nodes"] > 0:
        actions.append(
            f"Review correlated security graph containing "
            f"{attack_path['nodes']} nodes and "
            f"{attack_path['relationships']} relationships."
        )

    if attack_path["relationships"] > 0:
        actions.append(
            "Review network destinations and source-destination relationships."
        )

    return actions


def build_reasons(
    decision_data,
    attack_path,
    prediction,
):
    """Build concise reasons explaining the response."""

    reasons = []

    risk_score = decision_data["risk_score"]
    severity = decision_data["severity"]
    decision = decision_data["decision"]

    # Risk reason
    if risk_score >= 80:
        reasons.append(
            f"Critical fused risk indicates highly suspicious activity "
            f"with a score of {risk_score:.2f}/100."
        )

    elif risk_score >= 60:
        reasons.append(
            f"High fused risk indicates coordinated suspicious activity "
            f"with a score of {risk_score:.2f}/100."
        )

    elif risk_score >= 30:
        reasons.append(
            f"Moderate risk indicates activity requiring investigation "
            f"with a score of {risk_score:.2f}/100."
        )

    else:
        reasons.append(
            f"Low risk was observed with a score of {risk_score:.2f}/100."
        )

    # Attack path
    if attack_path["status"] != "UNKNOWN":
        reasons.append(
            f"Attack-path analysis classified the activity as "
            f"{attack_path['status']}."
        )

    if attack_path["path_score"] > 0:
        reasons.append(
            f"Attack-path score is "
            f"{attack_path['path_score']:.2f}/100."
        )

    # Prediction
    if prediction["predicted_stage"] != "UNKNOWN":
        reasons.append(
            f"Next-stage prediction indicates elevated likelihood of "
            f"{prediction['predicted_stage']}."
        )

    # Graph
    if attack_path["nodes"] > 0:
        reasons.append(
            f"The correlated security graph contains "
            f"{attack_path['nodes']} nodes and "
            f"{attack_path['relationships']} relationships."
        )

    # Decision
    reasons.append(
        f"The resulting response decision is {decision}."
    )

    return reasons


# ============================================================
# MAIN RESPONSE PLAN
# ============================================================

def build_response_plan(
    decision_data,
    attack_path_data,
    explanation_data,
    prediction_data,
):
    """Build the complete V5.22 response plan."""

    # --------------------------------------------------------
    # Extract each stage
    # --------------------------------------------------------

    decision = extract_decision_data(
        decision_data
    )

    attack_path = extract_attack_path_data(
        attack_path_data
    )

    explanation = extract_explanation_data(
        explanation_data
    )

    prediction = extract_prediction_data(
        prediction_data
    )

    # --------------------------------------------------------
    # Recommended actions
    # --------------------------------------------------------

    recommended_actions = build_recommended_actions(
        decision=decision["decision"],
        severity=decision["severity"],
        attack_path=attack_path,
        prediction=prediction,
    )

    # --------------------------------------------------------
    # Reasons
    # --------------------------------------------------------

    reasons = build_reasons(
        decision_data=decision,
        attack_path=attack_path,
        prediction=prediction,
    )

    # --------------------------------------------------------
    # Final response plan
    # --------------------------------------------------------

    result = {
        "version": "V5.22",

        "generated_at": datetime.now().isoformat(),

        "source_versions": {
            "risk_decision": "V5.18",
            "attack_path": "V5.19",
            "explainability": "V5.20",
            "next_stage_prediction": "V5.21",
        },

        # ====================================================
        # INPUT
        # ====================================================

        "input": {
            "risk_score": decision["risk_score"],
            "severity": decision["severity"],
            "decision": decision["decision"],
            "response_level": decision["response_level"],
        },

        # ====================================================
        # RESPONSE DECISION
        # ====================================================

        "response_decision": {
            "action": decision["decision"],
            "priority": decision["response_level"],
        },

        # ====================================================
        # ATTACK PATH
        # ====================================================

        "attack_path": {
            "status": attack_path["status"],
            "path_score": attack_path["path_score"],
            "severity": attack_path["severity"],
            "current_stage": (
                attack_path["stages"][-1]
                if attack_path["stages"]
                else "UNKNOWN"
            ),
            "predicted_stage": prediction["predicted_stage"],
            "prediction_score": prediction["prediction_score"],
            "stages": attack_path["stages"],
        },

        # ====================================================
        # GRAPH
        # ====================================================

        "graph": {
            "nodes": attack_path["nodes"],
            "relationships": attack_path["relationships"],
        },

        # ====================================================
        # EXPLAINABILITY
        # ====================================================

        "explainability": {
            "confidence": explanation["confidence"],
            "top_signals": explanation["top_signals"],
            "reasons": explanation["reasons"],
        },

        # ====================================================
        # NEXT-STAGE PREDICTION
        # ====================================================

        "prediction": {
            "predicted_stage": prediction["predicted_stage"],
            "prediction_score": prediction["prediction_score"],
            "confidence": prediction["confidence"],
            "reason": prediction["reason"],
            "candidate_stages": prediction["candidate_stages"],
        },

        # ====================================================
        # REASONS
        # ====================================================

        "reasons": reasons,

        # ====================================================
        # RECOMMENDED ACTIONS
        # ====================================================

        "recommended_actions": recommended_actions,

        # ====================================================
        # SAFETY
        # ====================================================

        "safety": {
            "human_approval_required": True,
            "automatic_destructive_action": False,
            "operating_mode": "RECOMMENDATION_ONLY",
        },
    }

    return result


# ============================================================
# PRINT RESULT
# ============================================================

def print_result(result):
    """Print the response plan in readable format."""

    print()
    print("=" * 64)
    print("NEXUS INTELLIGENCE - V5.22 RESPONSE ORCHESTRATOR")
    print("=" * 64)

    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    print()
    print("INPUT")
    print("-" * 64)

    print(
        f"Risk Score          : "
        f"{result['input']['risk_score']:.2f}/100"
    )

    print(
        f"Severity            : "
        f"{result['input']['severity']}"
    )

    print(
        f"Decision            : "
        f"{result['input']['decision']}"
    )

    print(
        f"Response Level      : "
        f"{result['input']['response_level']}"
    )

    # --------------------------------------------------------
    # RESPONSE DECISION
    # --------------------------------------------------------

    print()
    print("RESPONSE DECISION")
    print("-" * 64)

    print(
        f"Action              : "
        f"{result['response_decision']['action']}"
    )

    print(
        f"Priority            : "
        f"{result['response_decision']['priority']}"
    )

    # --------------------------------------------------------
    # ATTACK PATH
    # --------------------------------------------------------

    print()
    print("ATTACK PATH")
    print("-" * 64)

    print(
        f"Status              : "
        f"{result['attack_path']['status']}"
    )

    print(
        f"Path Score          : "
        f"{result['attack_path']['path_score']:.2f}/100"
    )

    print(
        f"Path Severity       : "
        f"{result['attack_path']['severity']}"
    )

    print(
        f"Current Stage       : "
        f"{result['attack_path']['current_stage']}"
    )

    print(
        f"Predicted Stage     : "
        f"{result['attack_path']['predicted_stage']}"
    )

    print(
        f"Prediction Score    : "
        f"{result['attack_path']['prediction_score']:.2f}/100"
    )

    # --------------------------------------------------------
    # STAGES
    # --------------------------------------------------------

    if result["attack_path"]["stages"]:

        print()
        print("STAGES")
        print("-" * 64)

        for index, stage in enumerate(
            result["attack_path"]["stages"],
            start=1
        ):
            print(f"{index}. {stage}")

    # --------------------------------------------------------
    # GRAPH
    # --------------------------------------------------------

    print()
    print("GRAPH")
    print("-" * 64)

    print(
        f"Nodes               : "
        f"{result['graph']['nodes']}"
    )

    print(
        f"Relationships       : "
        f"{result['graph']['relationships']}"
    )

    # --------------------------------------------------------
    # EXPLAINABILITY
    # --------------------------------------------------------

    print()
    print("EXPLAINABILITY")
    print("-" * 64)

    print(
        f"Confidence          : "
        f"{result['explainability']['confidence']}"
    )

    if result["explainability"]["top_signals"]:

        print()
        print("Top Signals:")

        for signal in result["explainability"]["top_signals"]:

            if isinstance(signal, dict):

                name = signal.get(
                    "signal",
                    "UNKNOWN"
                )

                score = safe_float(
                    signal.get("score", 0)
                )

                contribution = safe_float(
                    signal.get("contribution", 0)
                )

                print(
                    f"- {name}: "
                    f"{score:.2f}/100 "
                    f"(contribution {contribution:.2f})"
                )

            else:
                print(f"- {signal}")

    # --------------------------------------------------------
    # REASONS
    # --------------------------------------------------------

    print()
    print("REASONS")
    print("-" * 64)

    for reason in result["reasons"]:
        print(f"- {reason}")

    # --------------------------------------------------------
    # RECOMMENDED ACTIONS
    # --------------------------------------------------------

    print()
    print("RECOMMENDED ACTIONS")
    print("-" * 64)

    for action in result["recommended_actions"]:
        print(f"- {action}")

    # --------------------------------------------------------
    # SAFETY
    # --------------------------------------------------------

    print()
    print("SAFETY")
    print("-" * 64)

    print(
        f"Human approval      : "
        f"{result['safety']['human_approval_required']}"
    )

    print(
        f"Automatic destructive: "
        f"{result['safety']['automatic_destructive_action']}"
    )

    print(
        f"Operating mode      : "
        f"{result['safety']['operating_mode']}"
    )

    # --------------------------------------------------------
    # SAVED
    # --------------------------------------------------------

    print()
    print("Saved:")
    print(OUTPUT_FILE)

    print()
    print("=" * 64)
    print("V5.22 RESPONSE ORCHESTRATOR COMPLETE")
    print("=" * 64)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 64)
    print("NEXUS INTELLIGENCE - V5.22 RESPONSE ORCHESTRATOR")
    print("=" * 64)

    try:

        # ----------------------------------------------------
        # Load V5.18
        # ----------------------------------------------------

        decision_data = load_json(
            DECISION_FILE
        )

        # ----------------------------------------------------
        # Load V5.19
        # ----------------------------------------------------

        attack_path_data = load_json(
            ATTACK_PATH_FILE
        )

        # ----------------------------------------------------
        # Load V5.20
        # ----------------------------------------------------

        explanation_data = load_json(
            EXPLANATION_FILE
        )

        # ----------------------------------------------------
        # Load V5.21
        # ----------------------------------------------------

        prediction_data = load_json(
            PREDICTION_FILE
        )

        # ----------------------------------------------------
        # Build
        # ----------------------------------------------------

        result = build_response_plan(
            decision_data,
            attack_path_data,
            explanation_data,
            prediction_data,
        )

        # ----------------------------------------------------
        # Save
        # ----------------------------------------------------

        save_result(result)

        # ----------------------------------------------------
        # Print
        # ----------------------------------------------------

        print_result(result)

    except Exception as error:

        print()
        print("ERROR")
        print("-" * 64)

        print(
            f"{type(error).__name__}: {error}"
        )

        print()

        raise


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
