from backend.services.intelligence_service import load_latest_intelligence


def build_alerts():
    intelligence = load_latest_intelligence()

    if intelligence is None:
        return []

    alerts = []

    assessment = intelligence.get(
        "overall_security_assessment",
        {}
    )

    fingerprint = intelligence.get(
        "activity_fingerprint",
        {}
    )

    live = intelligence.get(
        "live_intelligence",
        {}
    )

    attack = intelligence.get(
        "attack_intelligence",
        {}
    )

    explanation = intelligence.get(
        "explainability",
        {}
    )

    response = intelligence.get(
        "response",
        {}
    )

    entity = intelligence.get(
        "entity",
        {}
    )

    users = entity.get("users", [])
    devices = entity.get("devices", [])

    threat_level = assessment.get(
        "threat_level",
        "UNKNOWN"
    )

    combined_score = assessment.get(
        "combined_threat_score",
        0
    )

    # Create an alert when the live intelligence
    # indicates meaningful activity.
    if combined_score >= 30:
        alerts.append({
            "id": "NEXUS-LIVE-001",
            "title": "Real-Time Behavioral Anomaly",
            "severity": threat_level,
            "target": (
                devices[0]
                if devices
                else "Unknown Device"
            ),
            "source": (
                users[0]
                if users
                else "Unknown User"
            ),
            "timestamp": intelligence.get(
                "generated_at"
            ),
            "mitre": (
                attack.get(
                    "current_stage",
                    "Unknown"
                )
            ),
            "status": "Active",
            "score": combined_score,
            "source_type": "V5.24_REAL_TIME_INTELLIGENCE"
        })

    # Fingerprint deviation becomes a separate
    # evidence alert, not proof of compromise.
    drift = fingerprint.get(
        "drift_score",
        0
    )

    if drift >= 60:
        alerts.append({
            "id": "NEXUS-FP-001",
            "title": "Behavioral Activity Fingerprint Deviation",
            "severity": "MEDIUM",
            "target": (
                devices[0]
                if devices
                else "Unknown Device"
            ),
            "source": (
                users[0]
                if users
                else "Unknown User"
            ),
            "timestamp": intelligence.get(
                "generated_at"
            ),
            "mitre": (
                attack.get(
                    "current_stage",
                    "Unknown"
                )
            ),
            "status": "Investigate",
            "score": drift,
            "source_type": "ACTIVITY_FINGERPRINT"
        })

    # Live telemetry evidence.
    live_score = live.get(
        "live_threat_score",
        0
    )

    if live_score >= 30:
        alerts.append({
            "id": "NEXUS-LIVE-NET-001",
            "title": "Elevated Live Network Activity",
            "severity": live.get(
                "live_severity",
                "MEDIUM"
            ),
            "target": (
                devices[0]
                if devices
                else "Unknown Device"
            ),
            "source": "Live Endpoint Telemetry",
            "timestamp": intelligence.get(
                "generated_at"
            ),
            "mitre": (
                attack.get(
                    "current_stage",
                    "Unknown"
                )
            ),
            "status": "Investigate",
            "score": live_score,
            "source_type": "LIVE_TELEMETRY",
            "reasons": live.get(
                "reasons",
                []
            )
        })

    return alerts
