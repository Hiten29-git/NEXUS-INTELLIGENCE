import json
import os
from datetime import datetime, timezone

INPUT_FILE = "data/v5_3/latest_decision.json"
HISTORY_FILE = "data/v5_4/decision_history.json"
OUTPUT_FILE = "data/v5_4/latest_temporal_decision.json"

MAX_HISTORY = 20


def load_json(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------
# LOAD CURRENT V5.3 DECISION
# ---------------------------------------------------------

decision = load_json(INPUT_FILE, None)

if decision is None:
    raise SystemExit("ERROR: V5.3 decision file not found.")


risk_text = str(decision.get("risk_score", "0"))
risk_score = float(risk_text.replace("/100", ""))


# ---------------------------------------------------------
# LOAD HISTORY
# ---------------------------------------------------------

history = load_json(HISTORY_FILE, [])

if not isinstance(history, list):
    history = []


# ---------------------------------------------------------
# CURRENT SIGNAL
# ---------------------------------------------------------

current_anomaly = (
    decision.get("model_prediction") == "-1"
    or decision.get("model_prediction") == -1
)

current_severity = decision.get("severity", "LOW")


# ---------------------------------------------------------
# TEMPORAL SIGNALS
# ---------------------------------------------------------

recent = history[-5:]

recent_risks = []

for item in recent:
    try:
        value = str(item.get("risk_score", "0"))
        value = float(value.replace("/100", ""))
        recent_risks.append(value)
    except Exception:
        pass


if recent_risks:
    average_recent_risk = sum(recent_risks) / len(recent_risks)
else:
    average_recent_risk = risk_score


# Count consecutive anomalous decisions

consecutive_anomalies = 0

for item in reversed(history):
    prediction = item.get("model_prediction")

    if prediction == "-1" or prediction == -1:
        consecutive_anomalies += 1
    else:
        break


if current_anomaly:
    consecutive_anomalies += 1


# ---------------------------------------------------------
# TEMPORAL ESCALATION
# ---------------------------------------------------------

temporal_bonus = 0

if consecutive_anomalies >= 4:
    temporal_bonus = 20

elif consecutive_anomalies == 3:
    temporal_bonus = 15

elif consecutive_anomalies == 2:
    temporal_bonus = 8


# Persistent elevated risk

if average_recent_risk >= 70:
    temporal_bonus += 15

elif average_recent_risk >= 50:
    temporal_bonus += 8


# ---------------------------------------------------------
# FINAL TEMPORAL RISK
# ---------------------------------------------------------

temporal_risk = min(
    100.0,
    max(
        0.0,
        risk_score + temporal_bonus
    )
)


# ---------------------------------------------------------
# SEVERITY
# ---------------------------------------------------------

if temporal_risk >= 80:
    severity = "CRITICAL"

elif temporal_risk >= 65:
    severity = "HIGH"

elif temporal_risk >= 50:
    severity = "MEDIUM"

else:
    severity = "LOW"


# ---------------------------------------------------------
# RESPONSE
# ---------------------------------------------------------

if severity == "CRITICAL":
    response = "ESCALATE_AND_CONTAIN"

elif severity == "HIGH":
    response = "ESCALATE"

elif severity == "MEDIUM":
    response = "MONITOR"

else:
    response = "ALLOW"


# ---------------------------------------------------------
# EXPLANATION
# ---------------------------------------------------------

explanation = []

if current_anomaly:
    explanation.append("current window classified as anomalous")

if consecutive_anomalies >= 2:
    explanation.append(
        f"{consecutive_anomalies} consecutive anomalous windows"
    )

if average_recent_risk >= 50:
    explanation.append(
        f"elevated recent average risk ({average_recent_risk:.2f})"
    )

if temporal_bonus > 0:
    explanation.append(
        f"temporal escalation bonus (+{temporal_bonus:.2f})"
    )

if not explanation:
    explanation.append("no persistent threat pattern detected")


# ---------------------------------------------------------
# CREATE RESULT
# ---------------------------------------------------------

result = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "version": "V5.4",

    "base_risk_score": round(risk_score, 2),

    "average_recent_risk": round(
        average_recent_risk,
        2
    ),

    "consecutive_anomalies": consecutive_anomalies,

    "temporal_bonus": round(
        temporal_bonus,
        2
    ),

    "risk_score": f"{temporal_risk:.2f}/100",

    "severity": severity,

    "response": response,

    "model_prediction": decision.get(
        "model_prediction"
    ),

    "model_score": decision.get(
        "model_score"
    ),

    "explanation": explanation
}


# ---------------------------------------------------------
# UPDATE HISTORY
# ---------------------------------------------------------

history_entry = {
    "timestamp": result["timestamp"],
    "risk_score": result["risk_score"],
    "severity": result["severity"],
    "model_prediction": result["model_prediction"]
}

history.append(history_entry)

history = history[-MAX_HISTORY:]


# ---------------------------------------------------------
# SAVE
# ---------------------------------------------------------

save_json(
    HISTORY_FILE,
    history
)

save_json(
    OUTPUT_FILE,
    result
)


# ---------------------------------------------------------
# REPORT
# ---------------------------------------------------------

print("=" * 72)
print("NEXUS INTELLIGENCE - V5.4 TEMPORAL RISK ENGINE")
print("=" * 72)

print()
print("BASE SIGNAL")
print("-" * 72)

print(f"Base risk score       : {risk_score:.2f}/100")
print(f"Model prediction      : {decision.get('model_prediction')}")
print(f"Current severity      : {current_severity}")

print()
print("TEMPORAL SIGNAL")
print("-" * 72)

print(
    f"Recent average risk   : "
    f"{average_recent_risk:.2f}/100"
)

print(
    f"Consecutive anomalies : "
    f"{consecutive_anomalies}"
)

print(
    f"Temporal bonus        : "
    f"+{temporal_bonus:.2f}"
)

print()
print("FINAL V5.4 DECISION")
print("-" * 72)

print(
    f"Risk score            : "
    f"{temporal_risk:.2f}/100"
)

print(
    f"Severity              : "
    f"{severity}"
)

print(
    f"Response              : "
    f"{response}"
)

print()
print("EXPLANATION")
print("-" * 72)

for reason in explanation:
    print(f"• {reason}")

print()
print("=" * 72)
print("V5.4 TEMPORAL RISK ENGINE COMPLETE")
print("=" * 72)

print()
print("Saved:")
print(OUTPUT_FILE)
print(HISTORY_FILE)
