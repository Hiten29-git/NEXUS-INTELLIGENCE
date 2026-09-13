import json
import os
from datetime import datetime, timezone

# ============================================================
# NEXUS INTELLIGENCE - V5.5 ATTACK STAGE INTELLIGENCE
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

INPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "v5_4",
    "latest_temporal_decision.json"
)

OUTPUT_DIR = os.path.join(BASE_DIR, "data", "v5_5")
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "latest_attack_stage.json"
)


# ============================================================
# LOAD V5.4 DECISION
# ============================================================

with open(INPUT_FILE, "r") as f:
    decision = json.load(f)


risk_score = float(
    str(decision.get("risk_score", "0"))
    .replace("/100", "")
    .strip()
)

model_prediction = str(
    decision.get("model_prediction", "")
).lower()

severity = str(
    decision.get("severity", "LOW")
).upper()


# ============================================================
# ATTACK STAGE CLASSIFICATION
# ============================================================

stage = "NO_SIGNIFICANT_THREAT"
confidence = 0.90
reasons = []


# High-risk attack stages
if risk_score >= 80:

    if model_prediction in ["lateral movement", "lateral_movement"]:
        stage = "LATERAL_MOVEMENT"
        confidence = 0.88
        reasons.append("High contextual risk combined with lateral-movement prediction.")

    elif model_prediction in ["credential access", "credential_access"]:
        stage = "CREDENTIAL_ACCESS"
        confidence = 0.86
        reasons.append("High contextual risk combined with credential-access prediction.")

    elif model_prediction == "collection":
        stage = "COLLECTION"
        confidence = 0.84
        reasons.append("High contextual risk combined with collection behavior.")

    elif model_prediction in ["network discovery", "network_discovery"]:
        stage = "DISCOVERY"
        confidence = 0.82
        reasons.append("High contextual risk combined with network-discovery behavior.")

    else:
        stage = "SUSPICIOUS_ACTIVITY"
        confidence = 0.75
        reasons.append("High contextual risk indicates potentially malicious activity.")


# Medium-risk behavior
elif risk_score >= 50:

    if model_prediction in ["network discovery", "network_discovery"]:
        stage = "DISCOVERY"
        confidence = 0.74
        reasons.append("Medium risk with network-discovery behavior.")

    elif model_prediction in ["credential access", "credential_access"]:
        stage = "CREDENTIAL_ACCESS"
        confidence = 0.72
        reasons.append("Medium risk with credential-access indicators.")

    elif model_prediction == "collection":
        stage = "COLLECTION"
        confidence = 0.70
        reasons.append("Medium risk with collection indicators.")

    elif model_prediction in ["lateral movement", "lateral_movement"]:
        stage = "LATERAL_MOVEMENT"
        confidence = 0.76
        reasons.append("Medium risk with lateral-movement indicators.")

    else:
        stage = "SUSPICIOUS_ACTIVITY"
        confidence = 0.65
        reasons.append("Behavior exceeds the normal risk baseline.")


# Lower-risk behavior
elif risk_score >= 25:

    stage = "SUSPICIOUS_ACTIVITY"
    confidence = 0.60
    reasons.append("Behavior shows mild deviation from the normal baseline.")


# Normal behavior
else:

    stage = "NO_SIGNIFICANT_THREAT"
    confidence = 0.90
    reasons.append("Risk remains below the suspicious-activity threshold.")


# ============================================================
# SEVERITY ADJUSTMENT
# ============================================================

if severity == "CRITICAL" and stage == "NO_SIGNIFICANT_THREAT":
    stage = "SUSPICIOUS_ACTIVITY"
    confidence = 0.70
    reasons.append("Critical severity overrides the normal-stage classification.")


# ============================================================
# STAGE INFORMATION
# ============================================================

stage_descriptions = {
    "NO_SIGNIFICANT_THREAT":
        "No meaningful attack-stage behavior detected.",

    "SUSPICIOUS_ACTIVITY":
        "Behavior deviates from the expected baseline and requires monitoring.",

    "DISCOVERY":
        "Activity may indicate reconnaissance or discovery of systems and resources.",

    "CREDENTIAL_ACCESS":
        "Activity may indicate attempts to obtain or use authentication material.",

    "LATERAL_MOVEMENT":
        "Activity may indicate movement from one system or resource toward another.",

    "COLLECTION":
        "Activity may indicate aggregation or access of potentially valuable data.",

    "EXFILTRATION":
        "Activity may indicate possible transfer of collected information."
}


# ============================================================
# BUILD V5.5 RESULT
# ============================================================

result = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "version": "V5.5",

    "source_version": "V5.4",

    "risk_score": f"{risk_score:.2f}/100",
    "severity": severity,

    "attack_stage": stage,
    "confidence": f"{confidence * 100:.1f}%",

    "model_prediction": decision.get(
        "model_prediction",
        "unknown"
    ),

    "description": stage_descriptions.get(
        stage,
        "Unknown attack stage."
    ),

    "reasons": reasons
}


# ============================================================
# SAVE RESULT
# ============================================================

os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(OUTPUT_FILE, "w") as f:
    json.dump(result, f, indent=2)


# ============================================================
# DISPLAY
# ============================================================

print("=" * 72)
print("NEXUS INTELLIGENCE - V5.5 ATTACK STAGE INTELLIGENCE")
print("=" * 72)

print()
print("INPUT")
print("-" * 72)
print("Source Version       :", "V5.4")
print("Risk Score           :", result["risk_score"])
print("Severity             :", severity)
print("Model Prediction     :", result["model_prediction"])

print()
print("ATTACK STAGE")
print("-" * 72)
print("Stage                :", stage)
print("Confidence           :", result["confidence"])

print()
print("DESCRIPTION")
print("-" * 72)
print(result["description"])

print()
print("REASONS")
print("-" * 72)

for reason in reasons:
    print("•", reason)

print()
print("=" * 72)
print("V5.5 ATTACK STAGE INTELLIGENCE COMPLETE")
print("=" * 72)

print()
print("Saved:")
print(OUTPUT_FILE)
