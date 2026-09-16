"""
NEXUS INTELLIGENCE
Behavioral Activity Fingerprint Engine

Purpose:
    Build a behavioral fingerprint from authorized telemetry
    and compare current activity against a learned baseline.

Important:
    This fingerprint represents behavior of a device/user context.
    It is NOT an attacker identity fingerprint.

Outputs:
    - behavioral fingerprint
    - deterministic fingerprint ID
    - numerical deviations
    - categorical similarity
    - new behavioral elements
    - overall fingerprint drift score
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set


# ============================================================
# CONFIGURATION
# ============================================================

CATEGORICAL_FIELDS = {
    "processes": (
        "process",
        "process_name",
        "process_path",
    ),
    "destinations": (
        "destination_ip",
        "destination",
        "remote_ip",
        "domain",
        "hostname",
    ),
    "destination_ports": (
        "destination_port",
        "remote_port",
        "port",
    ),
    "resources": (
        "resource",
        "file",
        "file_path",
        "resource_name",
    ),
}


NUMERICAL_FIELDS = (
    "events_per_minute",
    "processes_per_minute",
    "network_per_minute",
    "unique_processes",
    "unique_destinations",
    "unique_ports",
    "ioc_matches",
)


# ============================================================
# SAFE HELPERS
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    try:
        number = float(value)

        if math.isnan(number) or math.isinf(number):
            return default

        return number

    except (TypeError, ValueError):
        return default


def _safe_int(
    value: Any,
    default: int = 0,
) -> int:
    try:
        return int(value)

    except (TypeError, ValueError):
        return default


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    return text


def _clamp(
    value: Any,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:
    value = _safe_float(value)

    return max(
        minimum,
        min(maximum, value),
    )


# ============================================================
# VALUE EXTRACTION
# ============================================================

def _extract_first(
    event: Dict[str, Any],
    fields: Iterable[str],
) -> Optional[str]:
    for field in fields:

        value = _clean(
            event.get(field)
        )

        if value is not None:
            return value

    return None


def _values(
    events: List[Dict[str, Any]],
    fields: Iterable[str],
) -> Set[str]:
    values = set()

    for event in events:

        value = _extract_first(
            event,
            fields,
        )

        if value is not None:
            values.add(value)

    return values


# ============================================================
# TIME HELPERS
# ============================================================

def _parse_timestamp(
    value: Any,
) -> Optional[datetime]:

    if not value:
        return None

    try:

        text = str(value).strip()

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        return datetime.fromisoformat(text)

    except (
        TypeError,
        ValueError,
    ):
        return None


def _hours(
    events: List[Dict[str, Any]],
) -> Counter:
    """
    Count telemetry activity by hour of day.
    """

    hours = []

    for event in events:

        timestamp = _parse_timestamp(
            event.get("timestamp")
        )

        if timestamp is not None:
            hours.append(
                timestamp.hour
            )

    return Counter(hours)


# ============================================================
# EVENT FEATURES
# ============================================================

def _window_features(
    events: List[Dict[str, Any]],
    window_seconds: int = 60,
) -> Dict[str, float]:
    """
    Generate numerical behavioral features
    for one telemetry window.
    """

    window_seconds = max(
        1,
        _safe_int(
            window_seconds,
            60,
        ),
    )

    minutes = max(
        window_seconds / 60.0,
        1.0 / 60.0,
    )

    process_count = sum(
        1
        for event in events
        if str(
            event.get("event_type", "")
        ).upper()
        == "PROCESS_EXECUTION"
    )

    network_count = sum(
        1
        for event in events
        if str(
            event.get("event_type", "")
        ).upper()
        == "NETWORK_CONNECTION"
    )

    processes = _values(
        events,
        CATEGORICAL_FIELDS["processes"],
    )

    destinations = _values(
        events,
        CATEGORICAL_FIELDS["destinations"],
    )

    ports = _values(
        events,
        CATEGORICAL_FIELDS["destination_ports"],
    )

    ioc_matches = sum(
        1
        for event in events
        if bool(
            event.get("ioc_match", False)
        )
    )

    return {
        "events_per_minute": (
            len(events) / minutes
        ),

        "processes_per_minute": (
            process_count / minutes
        ),

        "network_per_minute": (
            network_count / minutes
        ),

        "unique_processes": float(
            len(processes)
        ),

        "unique_destinations": float(
            len(destinations)
        ),

        "unique_ports": float(
            len(ports)
        ),

        "ioc_matches": float(
            ioc_matches
        ),
    }


# ============================================================
# FINGERPRINT HASH
# ============================================================

def _fingerprint_hash(
    processes: Iterable[str],
    destinations: Iterable[str],
    ports: Iterable[str],
    resources: Iterable[str],
    active_hours: Iterable[int],
) -> str:
    """
    Generate a deterministic fingerprint identifier.
    """

    payload = {
        "processes": sorted(
            str(x)
            for x in processes
        ),

        "destinations": sorted(
            str(x)
            for x in destinations
        ),

        "ports": sorted(
            str(x)
            for x in ports
        ),

        "resources": sorted(
            str(x)
            for x in resources
        ),

        "active_hours": sorted(
            int(x)
            for x in active_hours
        ),
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()[:16]


# ============================================================
# BUILD FINGERPRINT
# ============================================================

def build_fingerprint(
    events: List[Dict[str, Any]],
    window_seconds: int = 60,
) -> Dict[str, Any]:
    """
    Create a behavioral activity fingerprint
    from telemetry events.
    """

    events = events or []

    processes = _values(
        events,
        CATEGORICAL_FIELDS["processes"],
    )

    destinations = _values(
        events,
        CATEGORICAL_FIELDS["destinations"],
    )

    ports = _values(
        events,
        CATEGORICAL_FIELDS["destination_ports"],
    )

    resources = _values(
        events,
        CATEGORICAL_FIELDS["resources"],
    )

    hours = _hours(events)

    numerical = _window_features(
        events,
        window_seconds,
    )

    fingerprint_id = _fingerprint_hash(
        processes,
        destinations,
        ports,
        resources,
        hours.keys(),
    )

    return {
        "fingerprint_id": fingerprint_id,

        "event_count": len(events),

        "window_seconds": int(
            window_seconds
        ),

        "processes": sorted(
            processes
        ),

        "destinations": sorted(
            destinations
        ),

        "ports": sorted(
            ports
        ),

        "resources": sorted(
            resources
        ),

        "active_hours": sorted(
            hours.keys()
        ),

        "hour_activity": dict(
            hours
        ),

        "features": {
            key: round(
                _safe_float(value),
                4,
            )
            for key, value
            in numerical.items()
        },

        "created_at": datetime.now(timezone.utc).isoformat()
        + "Z",
    }


# ============================================================
# JACCARD SIMILARITY
# ============================================================

def _jaccard(
    current: Iterable[Any],
    baseline: Iterable[Any],
) -> float:
    """
    Calculate Jaccard similarity.

    1.0 = identical sets
    0.0 = no overlap
    """

    current_set = {
        str(x)
        for x in current
        if x is not None
    }

    baseline_set = {
        str(x)
        for x in baseline
        if x is not None
    }

    # If neither side has information,
    # there is no evidence of deviation.
    if not current_set and not baseline_set:
        return 1.0

    if not current_set:
        return 1.0

    if not baseline_set:
        return 0.0

    intersection = (
        current_set
        & baseline_set
    )

    union = (
        current_set
        | baseline_set
    )

    if not union:
        return 1.0

    return (
        len(intersection)
        / len(union)
    )


# ============================================================
# NUMERICAL DEVIATION
# ============================================================

def _numeric_deviation(
    current: Any,
    stats: Dict[str, Any],
) -> float:
    """
    Convert numerical deviation into 0-1.

    0.0 = close to baseline
    1.0 = strong deviation

    Uses a 3-standard-deviation cap.
    """

    if not stats:
        return 0.0

    current = _safe_float(current)

    mean = _safe_float(
        stats.get("mean", 0.0)
    )

    std = _safe_float(
        stats.get("std", 0.0)
    )

    if std <= 1e-9:

        if abs(
            current - mean
        ) < 1e-9:
            return 0.0

        return 1.0

    return min(
        abs(current - mean)
        / (3.0 * std),
        1.0,
    )


# ============================================================
# BASELINE ACCESS
# ============================================================

def _baseline_values(
    baseline: Dict[str, Any],
    field: str,
) -> List[Any]:

    value = baseline.get(
        field,
        [],
    )

    if isinstance(
        value,
        list,
    ):
        return value

    return []


def _baseline_features(
    baseline: Dict[str, Any],
) -> Dict[str, Any]:

    features = baseline.get(
        "features",
        {},
    )

    if not isinstance(
        features,
        dict,
    ):
        return {}

    return features


# ============================================================
# COMPARE FINGERPRINT
# ============================================================

def compare_fingerprint(
    current: Dict[str, Any],
    baseline: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare current activity with historical behavior.

    IMPORTANT:

    Only dimensions for which telemetry is actually
    present in the current window are evaluated.

    Missing telemetry should NOT automatically become
    suspicious.
    """

    if not current:
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

    # --------------------------------------------------------
    # Current categorical values
    # --------------------------------------------------------

    current_processes = set(
        _baseline_values(
            current,
            "processes",
        )
    )

    current_destinations = set(
        _baseline_values(
            current,
            "destinations",
        )
    )

    current_ports = set(
        _baseline_values(
            current,
            "ports",
        )
    )

    current_resources = set(
        _baseline_values(
            current,
            "resources",
        )
    )

    current_hours = set(
        _baseline_values(
            current,
            "active_hours",
        )
    )

    # --------------------------------------------------------
    # Baseline categorical values
    # --------------------------------------------------------

    baseline_processes = set(
        _baseline_values(
            baseline,
            "processes",
        )
    )

    baseline_destinations = set(
        _baseline_values(
            baseline,
            "destinations",
        )
    )

    baseline_ports = set(
        _baseline_values(
            baseline,
            "ports",
        )
    )

    baseline_resources = set(
        _baseline_values(
            baseline,
            "resources",
        )
    )

    baseline_hours = set(
        _baseline_values(
            baseline,
            "active_hours",
        )
    )

    # --------------------------------------------------------
    # New values
    # --------------------------------------------------------

    new_processes = sorted(
        current_processes
        - baseline_processes
    )

    new_destinations = sorted(
        current_destinations
        - baseline_destinations
    )

    new_ports = sorted(
        current_ports
        - baseline_ports
    )

    new_resources = sorted(
        current_resources
        - baseline_resources
    )

    # --------------------------------------------------------
    # Categorical similarity
    # --------------------------------------------------------

    categorical_similarity = {}

    if current_processes:
        categorical_similarity[
            "processes"
        ] = round(
            _jaccard(
                current_processes,
                baseline_processes,
            ),
            4,
        )

    if current_destinations:
        categorical_similarity[
            "destinations"
        ] = round(
            _jaccard(
                current_destinations,
                baseline_destinations,
            ),
            4,
        )

    if current_ports:
        categorical_similarity[
            "ports"
        ] = round(
            _jaccard(
                current_ports,
                baseline_ports,
            ),
            4,
        )

    if current_resources:
        categorical_similarity[
            "resources"
        ] = round(
            _jaccard(
                current_resources,
                baseline_resources,
            ),
            4,
        )

    if current_hours:
        categorical_similarity[
            "active_hours"
        ] = round(
            _jaccard(
                current_hours,
                baseline_hours,
            ),
            4,
        )

    # --------------------------------------------------------
    # Numerical deviation
    # --------------------------------------------------------

    current_features = current.get(
        "features",
        {},
    )

    baseline_features = _baseline_features(
        baseline
    )

    numeric_deviation = {}

    for field in NUMERICAL_FIELDS:

        if field not in current_features:
            continue

        current_value = current_features.get(
            field
        )

        stats = baseline_features.get(
            field,
            {},
        )

        # Support both:
        #
        # "field": {"mean": ..., "std": ...}
        #
        # and:
        #
        # "field": 123
        #
        if isinstance(
            stats,
            dict,
        ):

            numeric_deviation[field] = round(
                _numeric_deviation(
                    current_value,
                    stats,
                ),
                4,
            )

        else:

            numeric_deviation[field] = 0.0

    # --------------------------------------------------------
    # Convert similarity to deviation
    # --------------------------------------------------------

    categorical_deviations = []

    for similarity in categorical_similarity.values():

        categorical_deviations.append(
            1.0 - _safe_float(
                similarity
            )
        )

    numeric_deviations = list(
        numeric_deviation.values()
    )

    # --------------------------------------------------------
    # Weighted drift
    #
    # Categorical behavior:
    #   60%
    #
    # Numerical behavior:
    #   40%
    # --------------------------------------------------------

    categorical_score = (
        sum(categorical_deviations)
        / len(categorical_deviations)
        if categorical_deviations
        else 0.0
    )

    numerical_score = (
        sum(numeric_deviations)
        / len(numeric_deviations)
        if numeric_deviations
        else 0.0
    )

    drift = (
        categorical_score * 0.60
        + numerical_score * 0.40
    )

    drift_score = round(
        _clamp(
            drift * 100.0
        ),
        2,
    )

    # --------------------------------------------------------
    # Status
    # --------------------------------------------------------

    if drift_score >= 70:
        status = "STRONG_DEVIATION"

    elif drift_score >= 40:
        status = "MODERATE_DEVIATION"

    elif drift_score >= 20:
        status = "MINOR_DEVIATION"

    else:
        status = "WITHIN_BASELINE"

    return {
        "available": True,

        "drift_score": drift_score,

        "status": status,

        "current_fingerprint_id": current.get(
            "fingerprint_id"
        ),

        "baseline_fingerprint_id": baseline.get(
            "fingerprint_id"
        ),

        "new_processes": new_processes,

        "new_destinations": new_destinations,

        "new_ports": new_ports,

        "new_resources": new_resources,

        "categorical_similarity":
            categorical_similarity,

        "numeric_deviation":
            numeric_deviation,

        "categorical_deviation_score":
            round(
                categorical_score * 100.0,
                2,
            ),

        "numerical_deviation_score":
            round(
                numerical_score * 100.0,
                2,
            ),
    }


# ============================================================
# HUMAN-READABLE EVIDENCE
# ============================================================

def fingerprint_reasons(
    comparison: Dict[str, Any],
) -> List[str]:
    """
    Generate human-readable explanations
    for the fingerprint drift.
    """

    if not comparison.get(
        "available",
        False,
    ):
        return []

    reasons = []

    new_processes = comparison.get(
        "new_processes",
        [],
    )

    new_destinations = comparison.get(
        "new_destinations",
        [],
    )

    new_ports = comparison.get(
        "new_ports",
        [],
    )

    new_resources = comparison.get(
        "new_resources",
        [],
    )

    drift = _safe_float(
        comparison.get(
            "drift_score",
            0.0,
        )
    )

    if new_processes:
        reasons.append(
            f"{len(new_processes)} "
            "previously unseen process value(s)"
        )

    if new_destinations:
        reasons.append(
            f"{len(new_destinations)} "
            "previously unseen destination(s)"
        )

    if new_ports:
        reasons.append(
            f"{len(new_ports)} "
            "previously unseen destination port(s)"
        )

    if new_resources:
        reasons.append(
            f"{len(new_resources)} "
            "previously unseen resource value(s)"
        )

    if drift >= 70:
        reasons.append(
            "Strong behavioral fingerprint deviation"
        )

    elif drift >= 40:
        reasons.append(
            "Moderate behavioral fingerprint deviation"
        )

    elif drift >= 20:
        reasons.append(
            "Minor behavioral fingerprint deviation"
        )

    else:
        reasons.append(
            "Current behavior remains close to baseline"
        )

    return reasons


# ============================================================
# BASELINE BUILDER
# ============================================================

def build_baseline(
    fingerprints: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build a baseline from multiple previously observed
    behavioral fingerprints.

    Numerical fields are represented using mean/std.
    Categorical fields are represented using observed
    values across the historical fingerprints.
    """

    fingerprints = [
        fp
        for fp in fingerprints
        if isinstance(fp, dict)
    ]

    if not fingerprints:
        return {}

    processes = set()
    destinations = set()
    ports = set()
    resources = set()
    active_hours = set()

    numerical_values = {
        field: []
        for field in NUMERICAL_FIELDS
    }

    for fingerprint in fingerprints:

        processes.update(
            fingerprint.get(
                "processes",
                [],
            )
        )

        destinations.update(
            fingerprint.get(
                "destinations",
                [],
            )
        )

        ports.update(
            fingerprint.get(
                "ports",
                [],
            )
        )

        resources.update(
            fingerprint.get(
                "resources",
                [],
            )
        )

        active_hours.update(
            fingerprint.get(
                "active_hours",
                [],
            )
        )

        features = fingerprint.get(
            "features",
            {},
        )

        if not isinstance(
            features,
            dict,
        ):
            continue

        for field in NUMERICAL_FIELDS:

            if field in features:

                numerical_values[
                    field
                ].append(
                    _safe_float(
                        features[field]
                    )
                )

    numerical_stats = {}

    for field, values in numerical_values.items():

        if not values:
            continue

        mean = (
            sum(values)
            / len(values)
        )

        variance = (
            sum(
                (value - mean) ** 2
                for value in values
            )
            / len(values)
        )

        std = math.sqrt(
            variance
        )

        numerical_stats[field] = {
            "mean": round(
                mean,
                6,
            ),

            "std": round(
                std,
                6,
            ),

            "samples": len(values),
        }

    baseline_payload = {
        "processes": sorted(
            str(x)
            for x in processes
        ),

        "destinations": sorted(
            str(x)
            for x in destinations
        ),

        "ports": sorted(
            str(x)
            for x in ports
        ),

        "resources": sorted(
            str(x)
            for x in resources
        ),

        "active_hours": sorted(
            int(x)
            for x in active_hours
        ),

        "features": numerical_stats,
    }

    baseline_id = _fingerprint_hash(
        baseline_payload["processes"],
        baseline_payload["destinations"],
        baseline_payload["ports"],
        baseline_payload["resources"],
        baseline_payload["active_hours"],
    )

    baseline_payload[
        "fingerprint_id"
    ] = baseline_id

    baseline_payload[
        "sample_count"
    ] = len(fingerprints)

    baseline_payload[
        "created_at"
    ] = datetime.now(timezone.utc).isoformat() + "Z"

    return baseline_payload


# ============================================================
# SIMPLE FILE HELPERS
# ============================================================

def save_fingerprint(
    path: str,
    fingerprint: Dict[str, Any],
) -> None:

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            fingerprint,
            file,
            indent=2,
            default=str,
        )


def load_fingerprint(
    path: str,
) -> Dict[str, Any]:

    try:

        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        if isinstance(
            data,
            dict,
        ):
            return data

    except (
        OSError,
        json.JSONDecodeError,
    ):
        pass

    return {}


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_events = [
        {
            "timestamp":
                "2026-09-16T10:00:00",
            "event_type":
                "PROCESS_EXECUTION",
            "process":
                "Terminal",
        },

        {
            "timestamp":
                "2026-09-16T10:00:10",
            "event_type":
                "PROCESS_EXECUTION",
            "process":
                "python",
        },

        {
            "timestamp":
                "2026-09-16T10:00:20",
            "event_type":
                "NETWORK_CONNECTION",
            "destination_ip":
                "8.8.8.8",
            "destination_port":
                443,
        },

        {
            "timestamp":
                "2026-09-16T10:00:30",
            "event_type":
                "FILE_ACTIVITY",
            "resource":
                "project",
        },
    ]

    fingerprint = build_fingerprint(
        test_events,
        window_seconds=60,
    )

    print(
        "\nNEXUS ACTIVITY FINGERPRINT"
    )

    print(
        "Fingerprint ID:",
        fingerprint[
            "fingerprint_id"
        ],
    )

    print(
        "Processes:",
        fingerprint[
            "processes"
        ],
    )

    print(
        "Destinations:",
        fingerprint[
            "destinations"
        ],
    )

    print(
        "Resources:",
        fingerprint[
            "resources"
        ],
    )

    print(
        "Features:",
        fingerprint[
            "features"
        ],
    )

    print(
        "\nFingerprint module OK."
    )

