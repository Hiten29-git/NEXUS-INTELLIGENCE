import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

INFERENCE = BASE_DIR / "ai" / "v5_2_live_inference.py"
OUTPUT_DIR = BASE_DIR / "data" / "v5_3"
RESULT_FILE = OUTPUT_DIR / "latest_decision.json"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 72)
print("NEXUS INTELLIGENCE - V5.3 INTEGRATION ORCHESTRATOR")
print("=" * 72)
print("Architecture:")
print("  V5.2 AI -> Risk -> Explanation -> Integration Layer")
print("=" * 72)
print()

print("[1/3] Running V5.2 live AI inference...")

try:
    result = subprocess.run(
        ["python", str(INFERENCE)],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        timeout=60,
    )
except subprocess.TimeoutExpired:
    print("ERROR: V5.2 inference timed out.")
    raise SystemExit(1)

if result.returncode != 0:
    print("ERROR: V5.2 inference failed.")
    print(result.stderr)
    raise SystemExit(result.returncode)

print("V5.2 inference completed successfully.")
print()

print("[2/3] Capturing AI decision...")

stdout = result.stdout

def extract_value(label):
    for line in stdout.splitlines():
        if label in line:
            return line.split(":", 1)[1].strip()
    return None

decision = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "version": "V5.3",
    "ai_version": "V5.2",
    "risk_score": extract_value("Risk score"),
    "severity": extract_value("Severity"),
    "response": extract_value("Response"),
    "model_prediction": extract_value("Isolation Forest prediction"),
    "model_score": extract_value("Isolation Forest score"),
    "model_component": extract_value("Anomaly component"),
    "behavior_component": extract_value("Behavior component"),
    "ioc_component": extract_value("IoC component"),
}

# Capture explanation lines.
explanation = []
capture = False

for line in stdout.splitlines():
    if line.strip() == "EXPLANATION":
        capture = True
        continue

    if capture:
        line = line.strip()

        if line.startswith("•"):
            explanation.append(line[1:].strip())
        elif line.startswith("-"):
            explanation.append(line[1:].strip())

decision["explanation"] = explanation

print("[3/3] Saving V5.3 decision...")
RESULT_FILE.write_text(
    json.dumps(decision, indent=2),
    encoding="utf-8"
)

print()
print("=" * 72)
print("V5.3 INTEGRATED DECISION")
print("=" * 72)

print(f"Timestamp       : {decision['timestamp']}")
print(f"AI Version      : {decision['ai_version']}")
print(f"Risk Score      : {decision['risk_score']}")
print(f"Severity        : {decision['severity']}")
print(f"Response        : {decision['response']}")
print(f"Model Prediction: {decision['model_prediction']}")
print(f"Model Score     : {decision['model_score']}")

if explanation:
    print()
    print("EXPLANATION")
    for reason in explanation:
        print(f"  • {reason}")

print()
print("=" * 72)
print("V5.3 INTEGRATION COMPLETE")
print("=" * 72)
print()
print(f"Decision saved to:")
print(RESULT_FILE)
