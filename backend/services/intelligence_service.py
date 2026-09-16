import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

V5_24_FILE = (
    PROJECT_ROOT
    / "data"
    / "v5_24"
    / "latest_realtime_intelligence.json"
)


def load_latest_intelligence():
    """
    Load the latest V5.24 real-time intelligence result.

    Returns None if the file does not exist or cannot be decoded.
    """
    if not V5_24_FILE.exists():
        return None

    try:
        with V5_24_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return None


def get_metrics():
    """
    Convert the internal V5.24 intelligence object into
    the API contract expected by Member 4.
    """

    intelligence = load_latest_intelligence()

    if intelligence is None:
        return {
            "securityPostureScore": 100,
            "activeAttackPaths": 0,
            "compromisedNodes": 0,
            "criticalVulnerabilities": 0,
            "totalAssets": 0,
            "meanTimeToRemediate": "N/A",
            "threatLevel": "UNKNOWN",
            "blockedAttempts24h": 0,
            "dataSource": "UNAVAILABLE",
        }

    assessment = intelligence.get(
        "overall_security_assessment",
        {}
    )

    window = intelligence.get(
        "window",
        {}
    )

    entity = intelligence.get(
        "entity",
        {}
    )

    response = intelligence.get(
        "response",
        {}
    )

    combined_threat = float(
        assessment.get(
            "combined_threat_score",
            0
        )
    )

    threat_level = assessment.get(
        "threat_level",
        "UNKNOWN"
    )

    users = entity.get("users", [])
    devices = entity.get("devices", [])

    events_analyzed = int(
        window.get(
            "events_analyzed",
            0
        )
    )

    # Prototype posture representation:
    # higher threat -> lower posture.
    security_posture = max(
        0,
        min(
            100,
            round(100 - combined_threat, 2)
        )
    )

    return {
        "securityPostureScore": security_posture,

        # Graph integration will populate this later.
        "activeAttackPaths": 0,

        # We do not infer compromise merely from an anomaly.
        "compromisedNodes": 0,

        # Vulnerability inventory will come from Member 3/data integration.
        "criticalVulnerabilities": 0,

        "totalAssets": max(
            len(set(users + devices)),
            1 if events_analyzed > 0 else 0
        ),

        "meanTimeToRemediate": "N/A",

        "threatLevel": threat_level,

        # No blocking is performed by the current
        # recommendation-only architecture.
        "blockedAttempts24h": 0,

        # Additional NEXUS information for future frontend use.
        "nexus": {
            "version": intelligence.get("version"),
            "mode": intelligence.get("mode"),
            "eventsAnalyzed": events_analyzed,
            "combinedThreatScore": combined_threat,
            "liveThreatScore": intelligence.get(
                "live_intelligence",
                {}
            ).get(
                "live_threat_score",
                0
            ),
            "fingerprintDrift": intelligence.get(
                "activity_fingerprint",
                {}
            ).get(
                "drift_score",
                0
            ),
            "fingerprintStatus": intelligence.get(
                "activity_fingerprint",
                {}
            ).get(
                "status",
                "UNAVAILABLE"
            ),
            "currentStage": intelligence.get(
                "attack_intelligence",
                {}
            ).get(
                "current_stage",
                "UNKNOWN"
            ),
            "predictedStage": intelligence.get(
                "attack_intelligence",
                {}
            ).get(
                "predicted_stage",
                "UNKNOWN"
            ),
            "predictionScore": intelligence.get(
                "attack_intelligence",
                {}
            ).get(
                "prediction_score",
                0
            ),
            "recommendedAction": response.get(
                "action",
                "MONITOR"
            ),
            "humanApprovalRequired": response.get(
                "human_approval_required",
                True
            ),
            "automaticDestructiveAction": response.get(
                "automatic_destructive_action",
                False
            ),
        },

        "dataSource": "V5.24_REAL_TIME_INTELLIGENCE",
        "generatedAt": intelligence.get(
            "generated_at"
        ),
    }
