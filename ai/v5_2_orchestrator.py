import time
import subprocess
from datetime import datetime

INTERVAL = 60

print("=" * 70)
print("NEXUS INTELLIGENCE - V5.2 REAL-TIME ORCHESTRATOR")
print("=" * 70)
print("Status : STARTING")
print("Mode   : REAL-TIME")
print("Window : 60 seconds")
print("Press Ctrl+C to stop")
print()

while True:
    start = time.time()

    print("=" * 70)
    print("NEXUS CYCLE")
    print("=" * 70)
    print("Time:", datetime.now().astimezone().isoformat())
    print()

    try:
        print("[1/2] Running V5.1 live inference...")

        result = subprocess.run(
            ["python", "ai/v5_1_live_inference.py"],
            capture_output=True,
            text=True
        )

        if result.stdout:
            print(result.stdout)

        if result.returncode != 0:
            print("ERROR:")
            print(result.stderr)

    except Exception as e:
        print("ORCHESTRATOR ERROR:", e)

    elapsed = time.time() - start
    sleep_time = max(0, INTERVAL - elapsed)

    print("=" * 70)
    print(f"Cycle complete. Next cycle in {sleep_time:.1f} seconds.")
    print("=" * 70)

    try:
        time.sleep(sleep_time)
    except KeyboardInterrupt:
        print("\nNEXUS V5.2 STOPPED")
        break
