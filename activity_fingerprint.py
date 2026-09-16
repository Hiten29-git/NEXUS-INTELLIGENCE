"""NEXUS Behavioral Activity Fingerprint.

Builds a compact baseline for an authorized user/device from telemetry and
compares a current window against that baseline. The fingerprint describes
behavioral patterns; it is not an identity or attacker fingerprint.
"""

import hashlib
import json
import math
import os
from collections import Counter
from datetime import datetime

BASELINE_FILE = "ai/models/nexus_activity_fingerprint_baseline.json"

CATEGORICAL_FIELDS = {
    "processes": lambda e: e.get("process"),
    "destinations": lambda e: e.get("destination_ip"),
    "destination_ports": lambda e: e.get("destination_port"),
    "resources": lambda e: e.get("resource"),
}

NUMERIC_FEATURES = [
    "events_per_minute",
    "processes_per_minute",
    "network_per_minute",
    "unique_processes",
    "unique_destinations",
    "unique_ports",
    "ioc_matches",
]


def _values(events, extractor):
    return {
        str(value)
        for event in events
        if (value := extractor(event)) not in (None, "")
    }


def _mean(values):
    return sum(values) / len(values) if values else 0.0


def _std(values, mean):
    if len(values) < 2:
        return 0.0
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return math.sqrt(variance)


def _window_features(events, window_seconds=60):
    minutes = max(window_seconds / 60.0, 1 / 60.0)
    process_count = sum(
        e.get("event_type") == "PROCESS_EXECUTION" for e in events
    )
    network_count = sum(
        e.get("event_type") == "NETWORK_CONNECTION" for e in events
    )
    processes = _values(events, CATEGORICAL_FIELDS["processes"])
    destinations = _values(events, CATEGORICAL_FIELDS["destinations"])
    ports = _values(events, CATEGORICAL_FIELDS["destination_ports"])

    return {
        "events_per_minute": len(events) / minutes,
        "processes_per_minute": process_count / minutes,
        "network_per_minute": network_count / minutes,
        "unique_processes": len(processes),
        "unique_destinations": len(destinations),
        "unique_ports": len(ports),
        "ioc_matches": sum(bool(e.get("ioc_match")) for e in events),
    }


def _hours(events):
    hours = []
    for event in events:
        try:
            hours.append(datetime.fromisoformat(event["timestamp"]).hour)
        except (KeyError, TypeError, ValueError):
            continue
    return Counter(hours)


def _fingerprint_hash(processes, destinations, ports, resources, active_hours):
    payload = {
        "processes": sorted(processes),
        "destinations": sorted(destinations),
        "ports": sorted(ports),
        "resources": sorted(resources),
        "active_hours": sorted(active_hours),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def build_fingerprint(events, window_seconds=60):
    """Create a fingerprint from telemetry events."""
    processes = _values(events, CATEGORICAL_FIELDS["processes"])
    destinations = _values(events, CATEGORICAL_FIELDS["destinations"])
    ports = _values(events, CATEGORICAL_FIELDS["destination_ports"])
    resources = _values(events, CATEGORICAL_FIELDS["resources"])
    hour_counts = _hours(events)
    active_hours = sorted(hour_counts)

    return {
        "schema_version": "1.0",
        "processes": sorted(processes),
        "destinations": sorted(destinations),
        "destination_ports": sorted(ports),
        "resources": sorted(resources),
        "active_hours": active_hours,
        "hour_counts": dict(hour_counts),
        "numeric": _window_features(events, window_seconds),
        "fingerprint_hash": _fingerprint_hash(
            processes, destinations, ports, resources, active_hours
        ),
        "event_count": len(events),
    }


def build_baseline(windows):
    """Build a baseline from multiple historical telemetry windows."""
    if not windows:
        raise ValueError("At least one telemetry window is required")

    categorical = {key: set() for key in CATEGORICAL_FIELDS}
    numeric_values = {key: [] for key in NUMERIC_FEATURES}
    hour_counts = Counter()

    for fingerprint in windows:
        for key in categorical:
            categorical[key].update(fingerprint.get(key, []))
        for key in NUMERIC_FEATURES:
            numeric_values[key].append(
                float(fingerprint.get("numeric", {}).get(key, 0))
            )
        hour_counts.update(fingerprint.get("hour_counts", {}))

    numeric = {}
    for key, values in numeric_values.items():
        mean = _mean(values)
        numeric[key] = {
            "mean": round(mean, 4),
            "std": round(_std(values, mean), 4),
            "min": round(min(values), 4),
            "max": round(max(values), 4),
        }

    active_hours = [
        int(hour) for hour, count in hour_counts.items() if count > 0
    ]

    baseline = {
        "schema_version": "1.0",
        "window_count": len(windows),
        "processes": sorted(categorical["processes"]),
        "destinations": sorted(categorical["destinations"]),
        "destination_ports": sorted(categorical["destination_ports"]),
        "resources": sorted(categorical["resources"]),
        "active_hours": sorted(active_hours),
        "numeric": numeric,
    }

    baseline["fingerprint_hash"] = _fingerprint_hash(
        baseline["processes"],
        baseline["destinations"],
        baseline["destination_ports"],
        baseline["resources"],
        baseline["active_hours"],
    )
    return baseline


def _jaccard(current, baseline):
    current, baseline = set(current), set(baseline)
    if not current and not baseline:
        return 1.0
    union = current | baseline
    return len(current & baseline) / len(union) if union else 1.0


def _numeric_deviation(current, stats):
    if not stats:
        return 0.0
    mean = float(stats.get("mean", 0))
    std = float(stats.get("std", 0))
    if std < 1e-9:
        return 0.0 if abs(current - mean) < 1e-9 else 1.0
    return min(abs(current - mean) / (3 * std), 1.0)


def compare_fingerprint(current, baseline):
    """Return explainable fingerprint drift from 0 (normal) to 100 (drift)."""
    categorical_similarity = {
        key: _jaccard(current.get(key, []), baseline.get(key, []))
        for key in CATEGORICAL_FIELDS
    }

    numeric_deviation = {
        key: _numeric_deviation(
            float(current.get("numeric", {}).get(key, 0)),
            baseline.get("numeric", {}).get(key, {}),
        )
        for key in NUMERIC_FEATURES
    }

    hour_similarity = _jaccard(
        current.get("active_hours", []),
        baseline.get("active_hours", []),
    )

    categorical_drift = 1 - _mean(list(categorical_similarity.values()))
    numeric_drift = _mean(list(numeric_deviation.values()))
    time_drift = 1 - hour_similarity

    drift = (
        0.45 * categorical_drift
        + 0.40 * numeric_drift
        + 0.15 * time_drift
    )
    score = round(min(max(drift * 100, 0), 100), 2)

    new_processes = sorted(
        set(current.get("processes", []))
        - set(baseline.get("processes", []))
    )
    new_destinations = sorted(
        set(current.get("destinations", []))
        - set(baseline.get("destinations", []))
    )
    new_resources = sorted(
        set(current.get("resources", []))
        - set(baseline.get("resources", []))
    )

    return {
        "fingerprint_drift_score": score,
        "fingerprint_status": (
            "DRIFT" if score >= 50 else "WITHIN_BASELINE"
        ),
        "current_hash": current.get("fingerprint_hash"),
        "baseline_hash": baseline.get("fingerprint_hash"),
        "new_processes": new_processes,
        "new_destinations": new_destinations,
        "new_resources": new_resources,
        "categorical_similarity": {
            key: round(value, 3)
            for key, value in categorical_similarity.items()
        },
        "numeric_deviation": {
            key: round(value, 3)
            for key, value in numeric_deviation.items()
        },
        "time_similarity": round(hour_similarity, 3),
    }


def save_baseline(baseline, path=BASELINE_FILE):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=2)


def load_baseline(path=BASELINE_FILE):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)
