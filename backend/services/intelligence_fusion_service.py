from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


BASE_DIR = Path(__file__).resolve().parents[2]

LIVE_EVENTS_FILE = (
    BASE_DIR / "data" / "live" / "live_events.jsonl"
)

FEATURE_SCHEMA_FILE = (
    BASE_DIR / "ai" / "models" / "nexus_v25_live_feature_schema.json"
)


# ============================================================
# BASIC HELPERS
# ============================================================

def _safe_number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)

        if math.isnan(number) or math.isinf(number):
            return default

        return number

    except (TypeError, ValueError):
        return default


def _clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    return round(max(minimum, min(maximum, value)), 2)


def _load_events() -> List[Dict[str, Any]]:
    if not LIVE_EVENTS_FILE.exists():
        return []

    events: List[Dict[str, Any]] = []

    try:
        with LIVE_EVENTS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                    if isinstance(event, dict):
                        events.append(event)

                except json.JSONDecodeError:
                    continue

    except OSError:
        return []

    return events


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None

    try:
        text = str(value).strip()

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        parsed = datetime.fromisoformat(text)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed

    except (TypeError, ValueError):
        return None


def _latest_window(
    events: List[Dict[str, Any]],
    window_seconds: int = 60,
) -> List[Dict[str, Any]]:

    timestamped = []

    for event in events:
        timestamp = _parse_timestamp(
            event.get("timestamp")
        )

        if timestamp is not None:
            timestamped.append(
                (timestamp, event)
            )

    if not timestamped:
        return []

    timestamped.sort(
        key=lambda item: item[0]
    )

    latest_timestamp = timestamped[-1][0]

    window_start = (
        latest_timestamp.timestamp()
        - window_seconds
    )

    result = []

    for timestamp, event in timestamped:

        if timestamp.timestamp() >= window_start:
            result.append(event)

    return result


# ============================================================
# ENTITY EXTRACTION
# ============================================================

def _unique_values(
    events: List[Dict[str, Any]],
    field: str,
) -> List[str]:

    values = set()

    for event in events:

        value = event.get(field)

        if value is None:
            continue

        value = str(value).strip()

        if value:
            values.add(value)

    return sorted(values)


def _extract_entities(
    events: List[Dict[str, Any]],
) -> Dict[str, List[str]]:

    users = _unique_values(
        events,
        "user_id",
    )

    devices = _unique_values(
        events,
        "device_id",
    )

    return {
        "users": users,
        "devices": devices,
    }


# ============================================================
# LIVE FEATURE ENGINE
# ============================================================

def _calculate_live_features(
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:

    if not events:
        return {
            "events": 0,
            "process_execution_frequency": 0,
            "network_connection_frequency": 0,
            "file_access_frequency": 0,
            "login_frequency": 0,
            "system_activity_frequency": 0,
            "unique_processes": 0,
            "unique_destinations": 0,
            "unique_destination_ports": 0,
            "process_burst": 0,
            "network_burst": 0,
            "process_diversity": 0,
            "destination_diversity": 0,
            "process_network_ratio": 0.0,
            "avg_cpu_percent": 0.0,
            "max_cpu_percent": 0.0,
            "avg_memory_percent": 0.0,
            "max_memory_percent": 0.0,
            "process_activity": 0.0,
            "network_activity": 0.0,
            "ioc_matches": 0,
            "ioc_score": 0.0,
        }

    event_types = Counter(
        str(
            event.get(
                "event_type",
                "",
            )
        ).upper()
        for event in events
    )

    process_events = [
        event
        for event in events
        if str(
            event.get(
                "event_type",
                "",
            )
        ).upper()
        == "PROCESS_EXECUTION"
    ]

    network_events = [
        event
        for event in events
        if str(
            event.get(
                "event_type",
                "",
            )
        ).upper()
        == "NETWORK_CONNECTION"
    ]

    file_events = [
        event
        for event in events
        if str(
            event.get(
                "event_type",
                "",
            )
        ).upper()
        == "FILE_ACTIVITY"
    ]

    session_events = [
        event
        for event in events
        if str(
            event.get(
                "event_type",
                "",
            )
        ).upper()
        == "USER_SESSION"
    ]

    system_events = [
        event
        for event in events
        if str(
            event.get(
                "event_type",
                "",
            )
        ).upper()
        == "SYSTEM_ACTIVITY"
    ]

    processes = set()
    destinations = set()
    ports = set()

    for event in process_events:

        process = event.get("process")

        if process:
            processes.add(
                str(process)
            )

    for event in network_events:

        destination = event.get(
            "destination_ip"
        )

        if destination:
            destinations.add(
                str(destination)
            )

        port = event.get(
            "destination_port"
        )

        if port is not None:
            try:
                ports.add(
                    int(port)
                )
            except (TypeError, ValueError):
                pass

    cpu_values = []
    memory_values = []

    for event in events:

        cpu = event.get(
            "cpu_percent"
        )

        memory = event.get(
            "memory_percent"
        )

        if cpu is not None:
            cpu_values.append(
                _safe_number(cpu)
            )

        if memory is not None:
            memory_values.append(
                _safe_number(memory)
            )

    ioc_matches = 0

    for event in events:

        value = event.get(
            "ioc_match",
            False,
        )

        if value is True:
            ioc_matches += 1

        elif str(value).lower() == "true":
            ioc_matches += 1

    total_events = len(events)

    process_count = len(
        process_events
    )

    network_count = len(
        network_events
    )

    # --------------------------------------------------------
    # Activity normalization
    # --------------------------------------------------------

    process_activity = _clamp(
        min(
            100.0,
            process_count / 10.0 * 100.0,
        )
    )

    network_activity = _clamp(
        min(
            100.0,
            network_count / 100.0 * 100.0,
        )
    )

    process_burst = _clamp(
        min(
            100.0,
            process_count / 5.0 * 100.0,
        )
    )

    network_burst = _clamp(
        min(
            100.0,
            network_count / 30.0 * 100.0,
        )
    )

    process_diversity = _clamp(
        min(
            100.0,
            len(processes) / 10.0 * 100.0,
        )
    )

    destination_diversity = _clamp(
        min(
            100.0,
            len(destinations) / 10.0 * 100.0,
        )
    )

    process_network_ratio = 0.0

    if network_count > 0:
        process_network_ratio = round(
            process_count / network_count,
            4,
        )

    ioc_score = _clamp(
        min(
            100.0,
            ioc_matches * 20.0,
        )
    )

    return {
        "events": total_events,

        "process_execution_frequency": process_count,

        "network_connection_frequency": network_count,

        "file_access_frequency": len(
            file_events
        ),

        "login_frequency": len(
            session_events
        ),

        "system_activity_frequency": len(
            system_events
        ),

        "unique_processes": len(
            processes
        ),

        "unique_destinations": len(
            destinations
        ),

        "unique_destination_ports": len(
            ports
        ),

        "process_burst": process_burst,

        "network_burst": network_burst,

        "process_diversity": process_diversity,

        "destination_diversity": destination_diversity,

        "process_network_ratio": process_network_ratio,

        "avg_cpu_percent": round(
            sum(cpu_values) / len(cpu_values),
            2,
        ) if cpu_values else 0.0,

        "max_cpu_percent": round(
            max(cpu_values),
            2,
        ) if cpu_values else 0.0,

        "avg_memory_percent": round(
            sum(memory_values) / len(memory_values),
            2,
        ) if memory_values else 0.0,

        "max_memory_percent": round(
            max(memory_values),
            2,
        ) if memory_values else 0.0,

        "process_activity": process_activity,

        "network_activity": network_activity,

        "ioc_matches": ioc_matches,

        "ioc_score": ioc_score,
    }


# ============================================================
# LIVE THREAT INDICATOR
# ============================================================

def _calculate_live_threat(
    features: Dict[str, Any],
) -> tuple[float, List[str]]:

    score = 0.0
    reasons: List[str] = []

    network_frequency = _safe_number(
        features.get(
            "network_connection_frequency"
        )
    )

    unique_destinations = _safe_number(
        features.get(
            "unique_destinations"
        )
    )

    network_burst = _safe_number(
        features.get(
            "network_burst"
        )
    )

    process_frequency = _safe_number(
        features.get(
            "process_execution_frequency"
        )
    )

    process_diversity = _safe_number(
        features.get(
            "process_diversity"
        )
    )

    ioc_score = _safe_number(
        features.get(
            "ioc_score"
        )
    )

    # Network activity.
    if network_frequency >= 100:
        score += 25
        reasons.append(
            "High live network connection activity observed."
        )
    elif network_frequency >= 50:
        score += 15
        reasons.append(
            "Elevated live network connection activity observed."
        )

    # Destination diversity.
    if unique_destinations >= 10:
        score += 20
        reasons.append(
            "High network destination diversity observed."
        )
    elif unique_destinations >= 5:
        score += 10
        reasons.append(
            "Elevated network destination diversity observed."
        )

    # Burst activity.
    if network_burst >= 80:
        score += 20
        reasons.append(
            "Strong network burst activity detected."
        )
    elif network_burst >= 50:
        score += 10
        reasons.append(
            "Elevated network burst activity detected."
        )

    # Process activity.
    if process_frequency >= 10:
        score += 10
        reasons.append(
            "High process execution activity observed."
        )

    if process_diversity >= 70:
        score += 10
        reasons.append(
            "High process diversity observed."
        )

    # IoC evidence.
    if ioc_score > 0:
        score += min(
            25,
            ioc_score,
        )

        reasons.append(
            "IoC-linked activity was observed in the live window."
        )

    score = _clamp(score)

    if score >= 85:
        severity = "CRITICAL"
    elif score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, reasons


# ============================================================
# STAGE PREDICTION
# ============================================================

def _predict_stage(
    features: Dict[str, Any],
    live_score: float,
) -> tuple[str, float]:

    ioc_matches = _safe_number(
        features.get(
            "ioc_matches"
        )
    )

    network_frequency = _safe_number(
        features.get(
            "network_connection_frequency"
        )
    )

    unique_destinations = _safe_number(
        features.get(
            "unique_destinations"
        )
    )

    process_frequency = _safe_number(
        features.get(
            "process_execution_frequency"
        )
    )

    file_activity = _safe_number(
        features.get(
            "file_access_frequency"
        )
    )

    if ioc_matches >= 5 and network_frequency >= 80:
        return "Lateral Movement", 85.0

    if process_frequency >= 10 and network_frequency >= 60:
        return "Credential Access", 78.0

    if file_activity >= 8:
        return "Collection", 74.0

    if network_frequency >= 50 or unique_destinations >= 8:
        return "Discovery", 70.0

    if live_score >= 40:
        return "Suspicious Activity", 60.0

    return "No Significant Threat", 90.0


# ============================================================
# EXPLAINABILITY
# ============================================================

def _build_explainability(
    features: Dict[str, Any],
    live_score: float,
    fingerprint_score: float,
    graph_score: float,
) -> Dict[str, Any]:

    signals = [
        (
            "network_activity",
            _safe_number(
                features.get(
                    "network_activity"
                )
            ),
        ),
        (
            "destination_diversity",
            _safe_number(
                features.get(
                    "destination_diversity"
                )
            ),
        ),
        (
            "network_burst",
            _safe_number(
                features.get(
                    "network_burst"
                )
            ),
        ),
        (
            "process_activity",
            _safe_number(
                features.get(
                    "process_activity"
                )
            ),
        ),
        (
            "process_diversity",
            _safe_number(
                features.get(
                    "process_diversity"
                )
            ),
        ),
        (
            "ioc_score",
            _safe_number(
                features.get(
                    "ioc_score"
                )
            ),
        ),
    ]

    signals.sort(
        key=lambda item: item[1],
        reverse=True,
    )

    top_signals = [
        {
            "signal": name,
            "score": round(
                score,
                2,
            ),
        }
        for name, score in signals[:5]
    ]

    reasons = [
        "Live telemetry contributed to the security assessment."
    ]

    if live_score >= 40:
        reasons.append(
            "Live behavioral activity exceeded the prototype investigation threshold."
        )

    if fingerprint_score >= 60:
        reasons.append(
            "Current activity shows strong deviation from the established baseline."
        )

    if graph_score > 0:
        reasons.append(
            "Graph evidence contributed to the assessment."
        )
    else:
        reasons.append(
            "The security graph currently provides observed context without confirmed attack evidence."
        )

    return {
        "confidence": "LOW",
        "top_signals": top_signals,
        "reasons": reasons,
        "reason": (
            "Risk is derived from multiple evidence sources "
            "rather than a single security event."
        ),
    }


# ============================================================
# FINGERPRINT
# ============================================================

def _calculate_fingerprint(events):
    """
    Compare the current live window against the saved baseline.

    Only security-relevant categorical telemetry is compared.
    Endpoint metadata such as PID values, connection states and
    synthetic resources are excluded because they create artificial
    baseline drift.
    """

    baseline_path = Path(
        "ai/models/nexus_v25_live_baseline.json"
    )

    if not baseline_path.exists():
        return {
            "available": False,
            "drift_score": 0.0,
            "status": "BASELINE_UNAVAILABLE",
            "categorical_deviation_score": 0.0,
            "numerical_deviation_score": 0.0,
            "new_processes": [],
            "new_destinations": [],
            "new_ports": [],
            "new_resources": []
        }

    try:
        with open(baseline_path, "r") as f:
            baseline = json.load(f)
    except Exception:
        return {
            "available": False,
            "drift_score": 0.0,
            "status": "BASELINE_UNAVAILABLE",
            "categorical_deviation_score": 0.0,
            "numerical_deviation_score": 0.0,
            "new_processes": [],
            "new_destinations": [],
            "new_ports": [],
            "new_resources": []
        }

    def clean_value(value):
        if value is None:
            return None

        value = str(value).strip()

        if not value:
            return None

        return value

    def valid_resource(value):
        value = clean_value(value)

        if not value:
            return False

        upper = value.upper()

        ignored = {
            "ESTABLISHED",
            "CLOSE_WAIT",
            "TIME_WAIT",
            "SYN_SENT",
            "SYN_RECV",
            "FIN_WAIT1",
            "FIN_WAIT2",
            "LAST_ACK",
            "LISTEN",
            "CLOSING",
            "NONE",
            "SYSTEM",
            "ACTIVE_SESSIONS",
            "USER_FILE_METADATA"
        }

        if upper in ignored:
            return False

        if value.lower().startswith("pid:"):
            return False

        return True

    def valid_destination(value):
        value = clean_value(value)

        if not value:
            return False

        # Ignore localhost/link-local telemetry for fingerprint novelty.
        if value in {
            "127.0.0.1",
            "::1"
        }:
            return False

        if value.lower().startswith("fe80:"):
            return False

        return True

    # -------------------------------------------------
    # CURRENT WINDOW
    # -------------------------------------------------

    current_processes = {
        clean_value(e.get("process"))
        for e in events
        if clean_value(e.get("process"))
    }

    current_destinations = {
        clean_value(e.get("destination_ip"))
        for e in events
        if valid_destination(e.get("destination_ip"))
    }

    current_ports = {
        str(e.get("destination_port"))
        for e in events
        if e.get("destination_port") is not None
    }

    current_resources = {
        clean_value(e.get("resource"))
        for e in events
        if valid_resource(e.get("resource"))
    }

    # -------------------------------------------------
    # BASELINE
    # -------------------------------------------------

    baseline_processes = set(
        baseline.get("processes", [])
        or baseline.get("known_processes", [])
        or []
    )

    baseline_destinations = set(
        baseline.get("destinations", [])
        or baseline.get("known_destinations", [])
        or []
    )

    baseline_ports = {
        str(x)
        for x in (
            baseline.get("ports", [])
            or baseline.get("known_ports", [])
            or []
        )
    }

    baseline_resources = set(
        baseline.get("resources", [])
        or baseline.get("known_resources", [])
        or []
    )

    # Clean baseline too because it may contain legacy telemetry.
    baseline_processes = {
        x for x in baseline_processes
        if clean_value(x)
    }

    baseline_destinations = {
        x for x in baseline_destinations
        if valid_destination(x)
    }

    baseline_resources = {
        x for x in baseline_resources
        if valid_resource(x)
    }

    # -------------------------------------------------
    # NOVELTY
    # -------------------------------------------------

    new_processes = sorted(
        current_processes - baseline_processes
    )

    new_destinations = sorted(
        current_destinations - baseline_destinations
    )

    new_ports = sorted(
        current_ports - baseline_ports
    )

    new_resources = sorted(
        current_resources - baseline_resources
    )

    # -------------------------------------------------
    # CATEGORICAL DEVIATION
    # -------------------------------------------------

    process_deviation = (
        len(new_processes) / max(len(current_processes), 1)
    ) * 100

    destination_deviation = (
        len(new_destinations) / max(len(current_destinations), 1)
    ) * 100

    port_deviation = (
        len(new_ports) / max(len(current_ports), 1)
    ) * 100

    resource_deviation = (
        len(new_resources) / max(len(current_resources), 1)
    ) * 100

    categorical_score = (
        process_deviation * 0.30
        + destination_deviation * 0.35
        + port_deviation * 0.20
        + resource_deviation * 0.15
    )

    categorical_score = round(
        min(max(categorical_score, 0.0), 100.0),
        2
    )

    # -------------------------------------------------
    # NUMERICAL DEVIATION
    # -------------------------------------------------

    numerical_score = 0.0

    current_count = len(events)

    baseline_event_count = (
        baseline.get("events")
        or baseline.get("total_events")
        or baseline.get("event_count")
        or 0
    )

    try:
        baseline_event_count = float(baseline_event_count)
    except Exception:
        baseline_event_count = 0.0

    if baseline_event_count > 0:

        event_delta = abs(
            current_count - baseline_event_count
        ) / baseline_event_count * 100

        numerical_score = min(
            event_delta,
            100.0
        )

    numerical_score = round(
        numerical_score,
        2
    )

    # -------------------------------------------------
    # FINAL DRIFT
    # -------------------------------------------------

    drift_score = (
        categorical_score * 0.60
        + numerical_score * 0.40
    )

    drift_score = round(
        min(max(drift_score, 0.0), 100.0),
        2
    )

    if drift_score >= 70:
        status = "STRONG_DEVIATION"
    elif drift_score >= 40:
        status = "MODERATE_DEVIATION"
    elif drift_score >= 15:
        status = "MILD_DEVIATION"
    else:
        status = "BASELINE_CONSISTENT"

    return {
        "available": True,
        "drift_score": drift_score,
        "status": status,
        "categorical_deviation_score": categorical_score,
        "numerical_deviation_score": numerical_score,
        "new_processes": new_processes,
        "new_destinations": new_destinations,
        "new_ports": new_ports,
        "new_resources": new_resources
    }

# ============================================================
# GRAPH
# ============================================================

def _get_graph_evidence() -> Dict[str, Any]:

    try:

        from backend.services.graph_evidence_service import (
            get_graph_evidence,
        )

        result = get_graph_evidence()

        if isinstance(result, dict):
            return result

    except Exception as exc:

        return {
            "available": False,
            "error": str(exc),
            "summary": {},
            "devices": [],
            "graph_evidence_score": 0.0,
            "evidence_status": "UNAVAILABLE",
        }

    return {
        "available": False,
        "summary": {},
        "devices": [],
        "graph_evidence_score": 0.0,
        "evidence_status": "OBSERVED_CONTEXT_ONLY",
    }

# ============================================================
# FUSION
# ============================================================

def _calculate_fused_score(
    live_score: float,
    fingerprint_score: float,
    graph_score: float,
) -> float:

    """
    Prototype multi-source risk indicator.

    This is NOT a probability of compromise.
    """

    score = (
        live_score * 0.60
        + fingerprint_score * 0.30
        + graph_score * 0.10
    )

    return _clamp(score)


def _threat_level(
    score: float,
) -> str:

    if score >= 85:
        return "CRITICAL"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def _response_for_score(
    score: float,
) -> Dict[str, Any]:

    if score >= 85:
        return {
            "action": "ESCALATE",
            "priority": "CRITICAL",
            "human_approval_required": True,
            "automatic_destructive_action": False,
            "operating_mode": "RECOMMENDATION_ONLY",
        }

    if score >= 70:
        return {
            "action": "CONTAIN",
            "priority": "HIGH",
            "human_approval_required": True,
            "automatic_destructive_action": False,
            "operating_mode": "RECOMMENDATION_ONLY",
        }

    if score >= 40:
        return {
            "action": "INVESTIGATE",
            "priority": "MEDIUM",
            "human_approval_required": True,
            "automatic_destructive_action": False,
            "operating_mode": "RECOMMENDATION_ONLY",
        }

    return {
        "action": "MONITOR",
        "priority": "LOW",
        "human_approval_required": True,
        "automatic_destructive_action": False,
        "operating_mode": "RECOMMENDATION_ONLY",
    }


# ============================================================
# MAIN INTELLIGENCE API
# ============================================================

def get_intelligence() -> Dict[str, Any]:

    all_events = _load_events()

    window_seconds = 60

    current_events = _latest_window(
        all_events,
        window_seconds=window_seconds,
    )

    features = _calculate_live_features(
        current_events
    )

    entities = _extract_entities(
        current_events
    )

    live_score, live_reasons = (
        _calculate_live_threat(
            features
        )
    )

    fingerprint = _calculate_fingerprint(
        current_events
    )

    fingerprint_score = _safe_number(
        fingerprint.get(
            "drift_score",
            0.0,
        )
    )

    graph = _get_graph_evidence()

    graph_score = _safe_number(
        graph.get(
            "graph_evidence_score",
            0.0,
        )
    )

    fused_score = _calculate_fused_score(
        live_score=live_score,
        fingerprint_score=fingerprint_score,
        graph_score=graph_score,
    )

    fused_level = _threat_level(
        fused_score
    )

    prediction_stage, prediction_score = (
        _predict_stage(
            features,
            live_score,
        )
    )

    explainability = _build_explainability(
        features=features,
        live_score=live_score,
        fingerprint_score=fingerprint_score,
        graph_score=graph_score,
    )

    explainability["reasons"] = (
        live_reasons
        + explainability["reasons"]
    )

    response = _response_for_score(
        fused_score
    )

    latest_timestamp = None

    if current_events:

        timestamps = [
            event.get("timestamp")
            for event in current_events
            if event.get("timestamp")
        ]

        if timestamps:
            latest_timestamp = max(
                timestamps
            )

    graph_available = bool(
        graph.get(
            "available",
            False,
        )
    )

    graph_summary = graph.get(
        "summary",
        {},
    )

    graph_devices = graph.get(
        "devices",
        [],
    )

    return {

        "available": True,

        "source": "NEXUS_INTELLIGENCE_FUSION",

        "status": "LIVE",

        "interpretation": (
            "Fused security intelligence is calculated from "
            "the current live telemetry window, behavioral "
            "activity, baseline deviation and security graph "
            "context. Scores are prototype risk indicators "
            "and are not confirmed compromise probabilities."
        ),

        "risk": {

            "fused_score": fused_score,

            "threat_level": fused_level,

            "components": {

                "existing_combined_score": live_score,

                "live_anomaly_score": live_score,

                "behavior_score": _safe_number(
                    features.get(
                        "process_activity",
                        0.0,
                    )
                ),

                "fingerprint_drift_score": fingerprint_score,

                "graph_evidence_score": graph_score,
            },
        },

        "telemetry": {

            "live_event_count": len(
                all_events
            ),

            "window_events_analyzed": len(
                current_events
            ),

            "window_seconds": window_seconds,

            "latest_event_timestamp": latest_timestamp,

            "source": "NEXUS_LIVE_SECURITY_AGENT",
        },

        "entity": {

            "users": entities.get(
                "users",
                [],
            ),

            "devices": entities.get(
                "devices",
                [],
            ),
        },

        "live_intelligence": {

            "live_threat_score": live_score,

            "live_severity": _threat_level(
                live_score
            ),

            "reasons": live_reasons,
        },

        "fingerprint": fingerprint,

        "live_features": features,

        "graph": {

            "available": graph_available,

            "summary": graph_summary,

            "devices": graph_devices,

            "evidence_status": graph.get(
                "evidence_status",
                "OBSERVED_CONTEXT_ONLY",
            ),
        },

        "attack_intelligence": {

            "current_stage": (
                "Observed Activity"
            ),

            "predicted_stage": prediction_stage,

            "prediction_score": prediction_score,

            "confidence": explainability.get(
                "confidence",
                "LOW",
            ),
        },

        "explainability": explainability,

        "response": response,

        "historical_pipeline": {

            "v5_23_available": False,

            "previous_combined_score": 0.0,

            "previous_risk_score": 0.0,
        },

        "safety": {

            "mode": "RECOMMENDATION_ONLY",

            "human_approval_required": True,

            "automatic_destructive_action": False,
        },
    }
