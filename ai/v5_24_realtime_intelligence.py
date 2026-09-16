









from ai.activity_fingerprint import (
    build_fingerprint,
    build_baseline,
    compare_fingerprint,
)

import json
import math
import socket
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ============================================================
# NEXUS INTELLIGENCE
# V5.24 REAL-TIME INTELLIGENCE
# ============================================================

VERSION = "V5.24"

ROOT = Path(__file__).resolve().parents[1]

LIVE_EVENTS_FILE = ROOT / "data" / "live" / "live_events.jsonl"

V23_FILE = ROOT / "data" / "v5_23" / "latest_unified_intelligence.json"
FINGERPRINT_BASELINE_FILE = ROOT / "ai" / "models" / "nexus_activity_fingerprint_baseline.json"

OUTPUT_DIR = ROOT / "data" / "v5_24"
OUTPUT_FILE = OUTPUT_DIR / "latest_realtime_intelligence.json"

WINDOW_SECONDS = 60


# ============================================================
# BASIC HELPERS
# ============================================================

def safe_float(value, default=0.0):
    try:
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return default
        return number
    except (TypeError, ValueError):
        return default


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clamp(value, minimum=0.0, maximum=100.0):
    return max(minimum, min(maximum, safe_float(value)))


def load_json(path: Path):
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return {}


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    temporary = path.with_suffix(".tmp")

    with temporary.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, default=str)

    temporary.replace(path)


def parse_timestamp(value):
    if not value:
        return None

    try:
        text = str(value).strip()

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        timestamp = datetime.fromisoformat(text)

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def now_utc():
    return datetime.now(timezone.utc)


# ============================================================
# LOAD LIVE EVENTS
# ============================================================

def load_live_events(path: Path):
    events = []

    if not path.exists():
        return events

    try:
        with path.open("r", encoding="utf-8") as file:

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


# ============================================================
# RECENT WINDOW
# ============================================================

def get_recent_events(events, window_seconds=WINDOW_SECONDS):
    if not events:
        return []

    parsed = []

    for event in events:

        timestamp = parse_timestamp(event.get("timestamp"))

        if timestamp is not None:
            parsed.append((timestamp, event))

    if not parsed:
        return []

    latest_timestamp = max(item[0] for item in parsed)

    cutoff = latest_timestamp - timedelta(seconds=window_seconds)

    return [
        event
        for timestamp, event in parsed
        if timestamp >= cutoff
    ]


# ============================================================
# FEATURE ENGINE
# ============================================================

def extract_live_features(events):

    process_events = []
    network_events = []
    file_events = []
    login_events = []

    processes = set()
    destinations = set()
    destination_ports = set()
    source_ips = set()

    ioc_matches = 0

    timestamps = []

    for event in events:

        event_type = str(
            event.get("event_type", "")
        ).upper()

        process = event.get("process")

        destination = (
            event.get("destination_ip")
            or event.get("destination")
        )

        destination_port = (
            event.get("destination_port")
            or event.get("dest_port")
        )

        source_ip = event.get("source_ip")

        timestamp = parse_timestamp(
            event.get("timestamp")
        )

        if timestamp:
            timestamps.append(timestamp)

        if process:
            processes.add(str(process))

        if destination:
            destinations.add(str(destination))

        if destination_port:
            destination_ports.add(str(destination_port))

        if source_ip:
            source_ips.add(str(source_ip))

        if bool(event.get("ioc_match", False)):
            ioc_matches += 1

        if event_type == "PROCESS_EXECUTION":
            process_events.append(event)

        elif event_type == "NETWORK_CONNECTION":
            network_events.append(event)

        elif event_type in {
            "FILE_ACCESS",
            "FILE_CREATE",
            "FILE_MODIFICATION",
            "FILE_WRITE",
        }:
            file_events.append(event)

        elif event_type in {
            "LOGIN",
            "SESSION_START",
            "USER_LOGIN",
        }:
            login_events.append(event)

    # --------------------------------------------------------
    # Frequency
    # --------------------------------------------------------

    process_frequency = len(process_events)

    network_frequency = len(network_events)

    file_frequency = len(file_events)

    login_frequency = len(login_events)

    # --------------------------------------------------------
    # Burst calculations
    # --------------------------------------------------------

    process_burst = 0.0
    network_burst = 0.0

    if timestamps:
        duration = max(
            1.0,
            (
                max(timestamps) - min(timestamps)
            ).total_seconds()
        )
    else:
        duration = float(WINDOW_SECONDS)

    process_rate = process_frequency / duration
    network_rate = network_frequency / duration

    # Normalize approximately to 0-100.
    process_burst = clamp(
        process_rate * 1000.0,
        0,
        100
    )

    network_burst = clamp(
        network_rate * 1000.0,
        0,
        100
    )

    # --------------------------------------------------------
    # Diversity
    # --------------------------------------------------------

    process_diversity = clamp(
        len(processes) * 4.0,
        0,
        100
    )

    destination_diversity = clamp(
        len(destinations) * 15.0,
        0,
        100
    )

    # --------------------------------------------------------
    # Activity scores
    # --------------------------------------------------------

    process_activity = clamp(
        process_frequency * 5.0,
        0,
        100
    )

    network_activity = clamp(
        network_frequency * 10.0,
        0,
        100
    )

    # --------------------------------------------------------
    # Process/network relationship
    # --------------------------------------------------------

    if network_frequency > 0:
        process_network_ratio = (
            process_frequency / network_frequency
        )
    else:
        process_network_ratio = 0.0

    # --------------------------------------------------------
    # IOC score
    # --------------------------------------------------------

    ioc_score = clamp(
        ioc_matches * 25.0,
        0,
        100
    )

    return {
        "events": len(events),

        "process_execution_frequency":
            process_frequency,

        "network_connection_frequency":
            network_frequency,

        "file_access_frequency":
            file_frequency,

        "login_frequency":
            login_frequency,

        "unique_processes":
            len(processes),

        "unique_destinations":
            len(destinations),

        "unique_destination_ports":
            len(destination_ports),

        "process_burst":
            round(process_burst, 2),

        "network_burst":
            round(network_burst, 2),

        "process_diversity":
            round(process_diversity, 2),

        "destination_diversity":
            round(destination_diversity, 2),

        "process_activity":
            round(process_activity, 2),

        "network_activity":
            round(network_activity, 2),

        "process_network_ratio":
            round(process_network_ratio, 2),

        "ioc_matches":
            ioc_matches,

        "ioc_score":
            round(ioc_score, 2),

        "processes":
            sorted(processes),

        "destinations":
            sorted(destinations),

        "destination_ports":
            sorted(destination_ports),

        "source_ips":
            sorted(source_ips),
    }


# ============================================================
# LIVE THREAT ENGINE
# ============================================================

def calculate_live_threat(features):

    score = 0.0
    reasons = []

    process_frequency = safe_int(
        features.get("process_execution_frequency")
    )

    network_frequency = safe_int(
        features.get("network_connection_frequency")
    )

    file_frequency = safe_int(
        features.get("file_access_frequency")
    )

    unique_processes = safe_int(
        features.get("unique_processes")
    )

    unique_destinations = safe_int(
        features.get("unique_destinations")
    )

    ioc_matches = safe_int(
        features.get("ioc_matches")
    )

    process_burst = safe_float(
        features.get("process_burst")
    )

    network_burst = safe_float(
        features.get("network_burst")
    )

    # --------------------------------------------------------
    # Network activity
    # --------------------------------------------------------

    if network_frequency >= 10:
        score += 25
        reasons.append(
            "High live network connection activity observed."
        )

    elif network_frequency >= 5:
        score += 15
        reasons.append(
            "Elevated live network activity observed."
        )

    elif network_frequency >= 2:
        score += 7

    # --------------------------------------------------------
    # Network diversity
    # --------------------------------------------------------

    if unique_destinations >= 10:
        score += 20
        reasons.append(
            "High network destination diversity observed."
        )

    elif unique_destinations >= 5:
        score += 12

    elif unique_destinations >= 2:
        score += 5

    # --------------------------------------------------------
    # Process activity
    # --------------------------------------------------------

    if process_frequency >= 30:
        score += 20
        reasons.append(
            "Very high process execution activity observed."
        )

    elif process_frequency >= 15:
        score += 12
        reasons.append(
            "Elevated process execution activity observed."
        )

    elif process_frequency >= 5:
        score += 5

    # --------------------------------------------------------
    # Process diversity
    # --------------------------------------------------------

    if unique_processes >= 10:
        score += 12
        reasons.append(
            "High process diversity observed."
        )

    elif unique_processes >= 5:
        score += 6

    # --------------------------------------------------------
    # Burst behaviour
    # --------------------------------------------------------

    if process_burst >= 80:
        score += 8
        reasons.append(
            "Strong process burst activity detected."
        )

    if network_burst >= 80:
        score += 10
        reasons.append(
            "Strong network burst activity detected."
        )

    # --------------------------------------------------------
    # File activity
    # --------------------------------------------------------

    if file_frequency >= 20:
        score += 10
        reasons.append(
            "High file activity observed."
        )

    elif file_frequency >= 10:
        score += 5

    # --------------------------------------------------------
    # IOC matches
    # --------------------------------------------------------

    if ioc_matches >= 1:
        score += 25
        reasons.append(
            "One or more IOC matches detected."
        )

    score = clamp(score)

    if score >= 80:
        severity = "CRITICAL"

    elif score >= 60:
        severity = "HIGH"

    elif score >= 30:
        severity = "MEDIUM"

    elif score >= 10:
        severity = "LOW"

    else:
        severity = "NORMAL"

    if not reasons:
        reasons.append(
            "No strong suspicious live indicators detected."
        )

    return (
        round(score, 2),
        severity,
        reasons
    )


# ============================================================
# HISTORICAL INTELLIGENCE
# ============================================================

def get_historical_intelligence():

    v23 = load_json(V23_FILE)

    if not v23:
        return {
            "available": False,
            "combined_score": 0.0,
            "risk_score": 0.0,
        }

    overall = v23.get(
        "overall_security_assessment",
        {}
    )

    risk = v23.get(
        "risk_intelligence",
        {}
    )

    combined_score = safe_float(
        overall.get(
            "combined_threat_score",
            0
        )
    )

    risk_score = safe_float(
        risk.get(
            "risk_score",
            0
        )
    )

    return {
        "available": True,
        "combined_score": combined_score,
        "risk_score": risk_score,
    }


# ============================================================
# COMBINED THREAT SCORE
# ============================================================

def calculate_combined_score(
    historical,
    live_score
):

    historical_score = safe_float(
        historical.get("combined_score")
    )

    if live_score > 0:

        combined = (
            historical_score * 0.40
            + live_score * 0.60
        )

    else:

        combined = (
            historical_score * 0.70
        )

    return round(
        clamp(combined),
        2
    )


# ============================================================
# ATTACK STAGE
# ============================================================

def determine_current_stage(
    features,
    live_score,
    historical
):

    process = safe_int(
        features.get(
            "process_execution_frequency"
        )
    )

    network = safe_int(
        features.get(
            "network_connection_frequency"
        )
    )

    destinations = safe_int(
        features.get(
            "unique_destinations"
        )
    )

    ioc = safe_int(
        features.get("ioc_matches")
    )

    historical_risk = safe_float(
        historical.get("risk_score")
    )

    if ioc >= 1 and network >= 5:
        return "Command & Control"

    if network >= 10 and destinations >= 5:
        return "Discovery"

    if process >= 15 and live_score >= 30:
        return "Execution"

    if historical_risk >= 70:
        return "Persistence / Continued Activity"

    if live_score >= 30:
        return "Initial Access / Suspicious Activity"

    return "Normal / No Significant Threat"


# ============================================================
# NEXT STAGE PREDICTION
# ============================================================

def predict_next_stage(
    features,
    live_score,
    current_stage,
    historical
):

    process = safe_int(
        features.get(
            "process_execution_frequency"
        )
    )

    network = safe_int(
        features.get(
            "network_connection_frequency"
        )
    )

    destinations = safe_int(
        features.get(
            "unique_destinations"
        )
    )

    ioc = safe_int(
        features.get("ioc_matches")
    )

    risk = max(
        live_score,
        safe_float(
            historical.get("risk_score")
        )
    )

    candidates = []

    # --------------------------------------------------------
    # Lateral movement
    # --------------------------------------------------------

    lateral_score = 0

    if network >= 5:
        lateral_score += 35

    if destinations >= 3:
        lateral_score += 25

    if network >= 10:
        lateral_score += 15

    if ioc >= 1:
        lateral_score += 15

    if risk >= 70:
        lateral_score += 10

    lateral_score = clamp(lateral_score)

    candidates.append({
        "stage": "Lateral Movement",
        "score": round(lateral_score, 2),
        "reason":
            "Elevated network activity and destination diversity may indicate movement between systems."
    })

    # --------------------------------------------------------
    # Command & Control
    # --------------------------------------------------------

    c2_score = 0

    if network >= 5:
        c2_score += 40

    if destinations >= 2:
        c2_score += 20

    if network >= 10:
        c2_score += 20

    if risk >= 60:
        c2_score += 10

    c2_score = clamp(c2_score)

    candidates.append({
        "stage": "Command & Control",
        "score": round(c2_score, 2),
        "reason":
            "Persistent network communication may indicate continued external communication."
    })

    # --------------------------------------------------------
    # Discovery
    # --------------------------------------------------------

    discovery_score = clamp(
        process * 2
        + network * 2
        + destinations * 3
    )

    candidates.append({
        "stage": "Discovery",
        "score": round(discovery_score, 2),
        "reason":
            "Elevated process and network activity may precede discovery behaviour."
    })

    # --------------------------------------------------------
    # Collection
    # --------------------------------------------------------

    file_activity = safe_int(
        features.get(
            "file_access_frequency"
        )
    )

    collection_score = clamp(
        file_activity * 5
        + process * 1
    )

    candidates.append({
        "stage": "Collection",
        "score": round(collection_score, 2),
        "reason":
            "Elevated file activity may indicate collection of valuable resources."
    })

    # --------------------------------------------------------
    # Persistence
    # --------------------------------------------------------

    persistence_score = 0

    if historical.get("available"):
        persistence_score += 30

    if risk >= 60:
        persistence_score += 30

    if current_stage == "Persistence / Continued Activity":
        persistence_score += 30

    candidates.append({
        "stage": "Persistence",
        "score": round(
            clamp(persistence_score),
            2
        ),
        "reason":
            "Repeated suspicious behaviour across time can increase persistence likelihood."
    })

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    candidates.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    best = candidates[0]

    if best["score"] < 20:

        predicted_stage = (
            "Normal / No Significant Threat"
        )

        prediction_score = 10.0

        confidence = "LOW"

        reason = (
            "Current live telemetry does not provide "
            "strong evidence of an imminent attack stage."
        )

    else:

        predicted_stage = best["stage"]

        prediction_score = best["score"]

        if prediction_score >= 75:
            confidence = "HIGH"

        elif prediction_score >= 50:
            confidence = "MEDIUM"

        else:
            confidence = "LOW"

        reason = best["reason"]

    return {
        "predicted_stage": predicted_stage,
        "prediction_score": round(
            prediction_score,
            2
        ),
        "confidence": confidence,
        "reason": reason,
        "candidate_stages": candidates,
    }


# ============================================================
# EXPLAINABILITY
# ============================================================

def build_explanation(
    features,
    live_score,
    combined_score,
    prediction
):

    signals = []

    signals.append({
        "signal": "network_activity",
        "score": clamp(
            features.get(
                "network_activity"
            )
        ),
    })

    signals.append({
        "signal": "destination_diversity",
        "score": clamp(
            features.get(
                "destination_diversity"
            )
        ),
    })

    signals.append({
        "signal": "process_activity",
        "score": clamp(
            features.get(
                "process_activity"
            )
        ),
    })

    signals.append({
        "signal": "process_diversity",
        "score": clamp(
            features.get(
                "process_diversity"
            )
        ),
    })

    signals.append({
        "signal": "network_burst",
        "score": clamp(
            features.get(
                "network_burst"
            )
        ),
    })

    signals.append({
        "signal": "process_burst",
        "score": clamp(
            features.get(
                "process_burst"
            )
        ),
    })

    signals.append({
        "signal": "ioc_score",
        "score": clamp(
            features.get(
                "ioc_score"
            )
        ),
    })

    signals.sort(
        key=lambda item: item["score"],
        reverse=True
    )

    top_signals = signals[:5]

    if combined_score >= 70:
        confidence = "HIGH"

    elif combined_score >= 40:
        confidence = "MEDIUM"

    else:
        confidence = "LOW"

    reasons = []

    if live_score > 0:
        reasons.append(
            "Live telemetry contributed to the security assessment."
        )

    if features.get(
        "network_connection_frequency",
        0
    ) > 0:
        reasons.append(
            "Live network connection telemetry was observed."
        )

    if features.get(
        "process_execution_frequency",
        0
    ) > 0:
        reasons.append(
            "Live process execution telemetry was observed."
        )

    if features.get(
        "ioc_matches",
        0
    ) > 0:
        reasons.append(
            "IOC matches increased the threat assessment."
        )

    if prediction["prediction_score"] >= 50:
        reasons.append(
            "Next-stage analysis indicates elevated likelihood "
            f"of {prediction['predicted_stage']}."
        )

    if not reasons:
        reasons.append(
            "Current telemetry does not contain strong suspicious indicators."
        )

    return {
        "confidence": confidence,
        "top_signals": top_signals,
        "reasons": reasons,
    }


# ============================================================
# RESPONSE ENGINE
# ============================================================

def determine_response(combined_score):

    if combined_score >= 80:

        action = "CONTAIN"
        priority = "CRITICAL"

    elif combined_score >= 60:

        action = "CONTAIN"
        priority = "HIGH"

    elif combined_score >= 30:

        action = "INVESTIGATE"
        priority = "MEDIUM"

    else:

        action = "ALLOW"
        priority = "NORMAL"

    return {
        "action": action,
        "priority": priority,

        "human_approval_required": True,

        "automatic_destructive_action": False,

        "operating_mode": "RECOMMENDATION_ONLY",
    }


# ============================================================
# ENTITY EXTRACTION
# ============================================================

def extract_entities(events):

    users = set()
    devices = set()

    for event in events:

        if event.get("user_id"):
            users.add(
                str(event["user_id"])
            )

        if event.get("device_id"):
            devices.add(
                str(event["device_id"])
            )

    return {
        "users": sorted(users),
        "devices": sorted(devices),
    }


# ============================================================
# LIVE DESTINATIONS
# ============================================================

def extract_destination_data(features):

    return {
        "network_destinations":
            features.get(
                "destinations",
                []
            ),

        "destination_ports":
            features.get(
                "destination_ports",
                []
            ),

        "source_ips":
            features.get(
                "source_ips",
                []
            ),
    }



# ============================================================
# ACTIVITY FINGERPRINT INTELLIGENCE
# ============================================================

def get_activity_fingerprint(events):
    """
    Compare current live behavior against the historical
    NEXUS behavioral activity fingerprint baseline.
    """

    if not events:
        return {
            "available": False,
            "drift_score": 0.0,
            "status": "NO_CURRENT_FINGERPRINT",
            "new_processes": [],
            "new_destinations": [],
            "new_ports": [],
            "new_resources": [],
            "categorical_similarity": {},
            "numeric_deviation": {},
        }

    baseline = load_json(
        FINGERPRINT_BASELINE_FILE
    )

    if not baseline:
        return {
            "available": False,
            "drift_score": 0.0,
            "status": "NO_BASELINE",
            "new_processes": [],
            "new_destinations": [],
            "new_ports": [],
            "new_resources": [],
            "categorical_similarity": {},
            "numeric_deviation": {},
        }

    current = build_fingerprint(
        events,
        WINDOW_SECONDS
    )

    result = compare_fingerprint(
        current,
        baseline
    )

    return result


# ============================================================
# MAIN RESULT
# ============================================================

def build_result():

    # --------------------------------------------------------
    # Load live telemetry
    # --------------------------------------------------------

    events = load_live_events(
        LIVE_EVENTS_FILE
    )

    recent_events = get_recent_events(
        events,
        WINDOW_SECONDS
    )

    features = extract_live_features(
        recent_events
    )

    # --------------------------------------------------------
    # Behavioral activity fingerprint
    # --------------------------------------------------------

    fingerprint = get_activity_fingerprint(
        recent_events
    )

    # --------------------------------------------------------
    # Live threat score
    # --------------------------------------------------------

    live_score, live_severity, live_reasons = (
        calculate_live_threat(features)
    )

    # --------------------------------------------------------
    # Historical V5.23 intelligence
    # --------------------------------------------------------

    historical = (
        get_historical_intelligence()
    )

    # --------------------------------------------------------
    # Combined score
    # --------------------------------------------------------

    combined_score = calculate_combined_score(
        historical,
        live_score
    )

    # --------------------------------------------------------
    # Overall severity
    # --------------------------------------------------------

    if combined_score >= 80:
        threat_level = "CRITICAL"

    elif combined_score >= 60:
        threat_level = "HIGH"

    elif combined_score >= 30:
        threat_level = "MEDIUM"

    elif combined_score >= 10:
        threat_level = "LOW"

    else:
        threat_level = "NORMAL"

    # --------------------------------------------------------
    # Attack intelligence
    # --------------------------------------------------------

    current_stage = determine_current_stage(
        features,
        live_score,
        historical
    )

    prediction = predict_next_stage(
        features,
        live_score,
        current_stage,
        historical
    )

    # --------------------------------------------------------
    # Explainability
    # --------------------------------------------------------

    explanation = build_explanation(
        features,
        live_score,
        combined_score,
        prediction
    )

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    response = determine_response(
        combined_score
    )

    # --------------------------------------------------------
    # Entities
    # --------------------------------------------------------

    entities = extract_entities(
        recent_events
    )

    destinations = extract_destination_data(
        features
    )

    # --------------------------------------------------------
    # Latest timestamp
    # --------------------------------------------------------

    latest_timestamp = None

    if recent_events:

        timestamps = [
            parse_timestamp(
                event.get("timestamp")
            )
            for event in recent_events
        ]

        timestamps = [
            timestamp
            for timestamp in timestamps
            if timestamp is not None
        ]

        if timestamps:
            latest_timestamp = max(
                timestamps
            ).isoformat()

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    result = {

        "version": VERSION,

        "generated_at":
            now_utc().isoformat(),

        "mode": "REAL_TIME",

        "window": {
            "seconds":
                WINDOW_SECONDS,

            "events_analyzed":
                len(recent_events),

            "latest_event_timestamp":
                latest_timestamp,
        },

        "entity": entities,

        "overall_security_assessment": {
            "combined_threat_score":
                combined_score,

            "threat_level":
                threat_level,
        },

        "live_intelligence": {
            "live_threat_score":
                live_score,

            "live_severity":
                live_severity,

            "reasons":
                live_reasons,
        },

        "activity_fingerprint": {
            "available":
                fingerprint.get("available", False),

            "drift_score":
                fingerprint.get("drift_score", 0.0),

            "status":
                fingerprint.get("status", "UNKNOWN"),

            "current_fingerprint_id":
                fingerprint.get(
                    "current_fingerprint_id"
                ),

            "baseline_fingerprint_id":
                fingerprint.get(
                    "baseline_fingerprint_id"
                ),

            "new_processes":
                fingerprint.get(
                    "new_processes",
                    []
                ),

            "new_destinations":
                fingerprint.get(
                    "new_destinations",
                    []
                ),

            "new_ports":
                fingerprint.get(
                    "new_ports",
                    []
                ),

            "new_resources":
                fingerprint.get(
                    "new_resources",
                    []
                ),

            "categorical_deviation_score":
                fingerprint.get(
                    "categorical_deviation_score",
                    0.0
                ),

            "numerical_deviation_score":
                fingerprint.get(
                    "numerical_deviation_score",
                    0.0
                ),
        },

        "live_features": {
            key: value
            for key, value in features.items()
            if key not in {
                "processes",
                "destinations",
                "destination_ports",
                "source_ips",
            }
        },

        "observed_entities": {
            "processes":
                features.get(
                    "processes",
                    []
                ),

            "network_destinations":
                destinations[
                    "network_destinations"
                ],

            "destination_ports":
                destinations[
                    "destination_ports"
                ],

            "source_ips":
                destinations[
                    "source_ips"
                ],
        },

        "attack_intelligence": {

            "current_stage":
                current_stage,

            "predicted_stage":
                prediction[
                    "predicted_stage"
                ],

            "prediction_score":
                prediction[
                    "prediction_score"
                ],
        },

        "explainability":
            explanation,

        "response":
            response,

        "historical_pipeline": {
            "v5_23_available":
                historical["available"],

            "previous_combined_score":
                historical["combined_score"],

            "previous_risk_score":
                historical["risk_score"],
        },

        "safety": {
            "human_approval_required":
                True,

            "automatic_destructive_action":
                False,

            "mode":
                "RECOMMENDATION_ONLY",
        },
    }

    return result


# ============================================================
# TERMINAL DISPLAY
# ============================================================

def print_result(result):

    overall = result[
        "overall_security_assessment"
    ]

    live = result[
        "live_intelligence"
    ]

    fingerprint = result[
        "activity_fingerprint"
    ]

    features = result[
        "live_features"
    ]

    attack = result[
        "attack_intelligence"
    ]

    explanation = result[
        "explainability"
    ]

    response = result[
        "response"
    ]

    print()
    print("=" * 64)
    print(
        "NEXUS INTELLIGENCE – V5.24 REAL-TIME INTELLIGENCE"
    )
    print("=" * 64)

    print()
    print("OPERATING MODE")
    print("-" * 64)
    print("Mode              : REAL_TIME")
    print(
        f"Events analyzed   : "
        f"{result['window']['events_analyzed']}"
    )
    print(
        f"Window            : "
        f"{WINDOW_SECONDS} seconds"
    )

    print()
    print("OVERALL SECURITY ASSESSMENT")
    print("-" * 64)
    print(
        f"Combined Threat Score : "
        f"{overall['combined_threat_score']:.2f}/100"
    )
    print(
        f"Threat Level          : "
        f"{overall['threat_level']}"
    )

    print()
    print("LIVE TELEMETRY")
    print("-" * 64)
    print(
        f"Live Threat Score     : "
        f"{live['live_threat_score']:.2f}/100"
    )
    print(
        f"Live Severity         : "
        f"{live['live_severity']}"
    )
    print(
        f"Process Events        : "
        f"{features.get('process_execution_frequency', 0)}"
    )
    print(
        f"Network Events        : "
        f"{features.get('network_connection_frequency', 0)}"
    )
    print(
        f"Unique Processes      : "
        f"{features.get('unique_processes', 0)}"
    )
    print(
        f"Unique Destinations   : "
        f"{features.get('unique_destinations', 0)}"
    )
    print(
        f"Unique Ports          : "
        f"{features.get('unique_destination_ports', 0)}"
    )
    print(
        f"IOC Matches           : "
        f"{features.get('ioc_matches', 0)}"
    )

    print()
    print("BEHAVIORAL ACTIVITY FINGERPRINT")
    print("-" * 64)

    print(
        f"Fingerprint Available : "
        f"{fingerprint['available']}"
    )

    print(
        f"Fingerprint Drift     : "
        f"{fingerprint['drift_score']:.2f}/100"
    )

    print(
        f"Fingerprint Status    : "
        f"{fingerprint['status']}"
    )

    print(
        f"New Processes         : "
        f"{len(fingerprint['new_processes'])}"
    )

    print(
        f"New Destinations      : "
        f"{len(fingerprint['new_destinations'])}"
    )

    print(
        f"New Ports             : "
        f"{len(fingerprint['new_ports'])}"
    )

    print(
        f"New Resources         : "
        f"{len(fingerprint['new_resources'])}"
    )

    if fingerprint["new_processes"]:
        print("New Processes:")
        for item in fingerprint["new_processes"][:5]:
            print(f"  - {item}")

    if fingerprint["new_destinations"]:
        print("New Destinations:")
        for item in fingerprint["new_destinations"][:5]:
            print(f"  - {item}")

    print()
    print("ATTACK INTELLIGENCE")
    print("-" * 64)
    print(
        f"Current Stage         : "
        f"{attack['current_stage']}"
    )
    print(
        f"Predicted Stage       : "
        f"{attack['predicted_stage']}"
    )
    print(
        f"Prediction Score      : "
        f"{attack['prediction_score']:.2f}/100"
    )

    print()
    print("EXPLAINABILITY")
    print("-" * 64)
    print(
        f"Confidence            : "
        f"{explanation['confidence']}"
    )

    print("Top Signals:")

    for signal in explanation[
        "top_signals"
    ]:

        print(
            f" - {signal['signal']}: "
            f"{signal['score']:.2f}/100"
        )

    print()
    print("RESPONSE")
    print("-" * 64)
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
    print("LIVE DESTINATIONS")
    print("-" * 64)

    destinations = result[
        "observed_entities"
    ][
        "network_destinations"
    ]

    if destinations:

        for destination in destinations[:10]:
            print(f" - {destination}")

    else:
        print(" - None")

    print()
    print("WHY NEXUS REACHED THIS ASSESSMENT")
    print("-" * 64)

    for reason in explanation[
        "reasons"
    ]:

        print(f" - {reason}")

    print()
    print("SAFETY")
    print("-" * 64)
    print(
        "Human approval required : TRUE"
    )
    print(
        "Automatic destructive    : FALSE"
    )
    print(
        "Mode                     : "
        "RECOMMENDATION_ONLY"
    )


# ============================================================
# SAVE
# ============================================================

def save_result(result):

    save_json(
        OUTPUT_FILE,
        result
    )


# ============================================================
# ENTRY POINT
# ============================================================

def main():

    try:

        result = build_result()

        print_result(
            result
        )

        save_result(
            result
        )

        print()
        print("Saved:")
        print(
            OUTPUT_FILE
        )

        print()
        print("=" * 64)
        print(
            "V5.24 REAL-TIME INTELLIGENCE COMPLETE"
        )
        print("=" * 64)

    except KeyboardInterrupt:

        print()
        print(
            "V5.24 stopped by user."
        )

    except Exception as error:

        print()
        print(
            "V5.24 ERROR:"
        )
        print(
            f"{type(error).__name__}: {error}"
        )
        raise


if __name__ == "__main__":
    main()

