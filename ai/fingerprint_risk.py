from typing import Any, Dict


ML_WEIGHT = 0.50
FINGERPRINT_WEIGHT = 0.30
IOC_WEIGHT = 0.15
GRAPH_WEIGHT = 0.05


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        value = float(value)
        if value != value:
            return default
        return value
    except (TypeError, ValueError):
        return default


def clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


def ioc_score(ioc_matches: Any) -> float:
    matches = max(0.0, safe_float(ioc_matches))
    return clamp(matches * 20.0)


def calculate_contextual_risk(
    ml_risk: Any,
    fingerprint_drift: Any,
    ioc_matches: Any = 0,
    graph_evidence: Any = 0,
) -> Dict[str, Any]:

    ml = clamp(safe_float(ml_risk))
    fingerprint = clamp(safe_float(fingerprint_drift))
    ioc = ioc_score(ioc_matches)
    graph = clamp(safe_float(graph_evidence))

    contextual_score = (
        ml * ML_WEIGHT
        + fingerprint * FINGERPRINT_WEIGHT
        + ioc * IOC_WEIGHT
        + graph * GRAPH_WEIGHT
    )

    contextual_score = round(
        clamp(contextual_score),
        2
    )

    if contextual_score >= 80:
        level = "CRITICAL"
    elif contextual_score >= 60:
        level = "HIGH"
    elif contextual_score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    evidence = []

    if ml >= 50:
        evidence.append(
            "V3.1 ML ensemble indicates anomalous behavior"
        )

    if fingerprint >= 40:
        evidence.append(
            "Behavioral activity differs from historical fingerprint"
        )

    if ioc > 0:
        evidence.append(
            f"IoC evidence present ({int(ioc_matches)} match(es))"
        )

    if graph >= 40:
        evidence.append(
            "Security graph indicates suspicious relationship/path evidence"
        )

    if not evidence:
        evidence.append(
            "No strong contextual evidence detected"
        )

    return {
        "contextual_risk_score": contextual_score,
        "risk_level": level,

        "components": {
            "ml_risk": round(ml, 2),
            "fingerprint_drift": round(fingerprint, 2),
            "ioc_evidence": round(ioc, 2),
            "graph_evidence": round(graph, 2),
        },

        "evidence": evidence,
    }


def calculate_from_fingerprint_result(
    ml_risk: Any,
    fingerprint_result: Dict[str, Any],
    ioc_matches: Any = 0,
    graph_evidence: Any = 0,
) -> Dict[str, Any]:

    if not isinstance(fingerprint_result, dict):
        fingerprint_result = {}

    result = calculate_contextual_risk(
        ml_risk=ml_risk,
        fingerprint_drift=fingerprint_result.get(
            "drift_score",
            0.0
        ),
        ioc_matches=ioc_matches,
        graph_evidence=graph_evidence,
    )

    result["fingerprint"] = {
        "available": fingerprint_result.get(
            "available",
            False
        ),

        "drift_score": fingerprint_result.get(
            "drift_score",
            0.0
        ),

        "status": fingerprint_result.get(
            "status",
            "UNKNOWN"
        ),

        "new_processes": fingerprint_result.get(
            "new_processes",
            []
        ),

        "new_destinations": fingerprint_result.get(
            "new_destinations",
            []
        ),

        "new_ports": fingerprint_result.get(
            "new_ports",
            []
        ),

        "new_resources": fingerprint_result.get(
            "new_resources",
            []
        ),

        "categorical_deviation_score":
            fingerprint_result.get(
                "categorical_deviation_score",
                0.0
            ),

        "numerical_deviation_score":
            fingerprint_result.get(
                "numerical_deviation_score",
                0.0
            ),
    }

    return result


if __name__ == "__main__":

    print("=" * 60)
    print("NEXUS FINGERPRINT + AI RISK TEST")
    print("=" * 60)

    fingerprint = {
        "available": True,
        "drift_score": 72.38,
        "status": "STRONG_DEVIATION",
        "new_processes": [],
        "new_destinations": [],
        "new_ports": [],
        "new_resources": [],
        "categorical_deviation_score": 74.35,
        "numerical_deviation_score": 63.42,
    }

    result = calculate_from_fingerprint_result(
        ml_risk=66.7,
        fingerprint_result=fingerprint,
        ioc_matches=0,
        graph_evidence=0,
    )

    print()
    print(
        f"ML risk           : "
        f"{result['components']['ml_risk']}/100"
    )

    print(
        f"Fingerprint drift : "
        f"{result['components']['fingerprint_drift']}/100"
    )

    print(
        f"IoC evidence      : "
        f"{result['components']['ioc_evidence']}/100"
    )

    print(
        f"Graph evidence    : "
        f"{result['components']['graph_evidence']}/100"
    )

    print("-" * 60)

    print(
        f"CONTEXTUAL RISK   : "
        f"{result['contextual_risk_score']}/100"
    )

    print(
        f"RISK LEVEL        : "
        f"{result['risk_level']}"
    )

    print()
    print("EVIDENCE")

    for item in result["evidence"]:
        print(f" - {item}")

    print("=" * 60)
