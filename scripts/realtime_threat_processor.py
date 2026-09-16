import csv
import time
from pathlib import Path
from datetime import datetime, timezone


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR
    / "data"
    / "normalized"
    / "realtime_security_events.csv"
)

IOC_FILE = (
    BASE_DIR
    / "data"
    / "iocs"
    / "ioc_database.csv"
)

OUTPUT_FILE = (
    BASE_DIR
    / "data"
    / "final"
    / "realtime_threat_events.csv"
)


def load_iocs():

    iocs = []

    if not IOC_FILE.exists():
        print("IoC database not found:")
        print(IOC_FILE)
        return iocs

    with open(IOC_FILE, "r", encoding="utf-8") as f:

        reader = csv.DictReader(f)

        for row in reader:
            iocs.append(row)

    return iocs


def event_to_text(event):

    values = []

    for key, value in event.items():

        if value is not None:

            values.append(
                f"{key}={str(value).lower()}"
            )

    return " ".join(values)


def check_iocs(event, iocs):

    text = event_to_text(event)

    matches = []

    for ioc in iocs:

        value = ioc["ioc_value"].lower()

        if value in text:

            matches.append(ioc)

    return matches


def process_new_events():

    if not INPUT_FILE.exists():

        print("Waiting for normalized telemetry...")
        return 0

    iocs = load_iocs()

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    processed = 0

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        reader = csv.DictReader(f)

        events = list(reader)

    output_exists = OUTPUT_FILE.exists()

    with open(
        OUTPUT_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as output:

        fieldnames = [
            "detected_at",
            "timestamp",
            "user_id",
            "device_id",
            "event_type",
            "process",
            "source_ip",
            "destination_ip",
            "destination_port",
            "resource",
            "ioc_match",
            "ioc_type",
            "ioc_value",
            "threat_name",
            "severity",
            "description"
        ]

        writer = csv.DictWriter(
            output,
            fieldnames=fieldnames
        )

        if not output_exists:

            writer.writeheader()

        for event in events:

            matches = check_iocs(
                event,
                iocs
            )

            if matches:

                for match in matches:

                    result = {
                        "detected_at": datetime.now(
                            timezone.utc
                        ).isoformat(),

                        "timestamp": event.get(
                            "timestamp",
                            ""
                        ),

                        "user_id": event.get(
                            "user_id",
                            event.get("user", "")
                        ),

                        "device_id": event.get(
                            "device_id",
                            ""
                        ),

                        "event_type": event.get(
                            "event_type",
                            ""
                        ),

                        "process": event.get(
                            "process",
                            ""
                        ),

                        "source_ip": event.get(
                            "source_ip",
                            event.get("src", "")
                        ),

                        "destination_ip": event.get(
                            "destination_ip",
                            event.get("dst", "")
                        ),

                        "destination_port": event.get(
                            "destination_port",
                            ""
                        ),

                        "resource": event.get(
                            "resource",
                            ""
                        ),

                        "ioc_match": True,

                        "ioc_type": match[
                            "ioc_type"
                        ],

                        "ioc_value": match[
                            "ioc_value"
                        ],

                        "threat_name": match[
                            "threat_name"
                        ],

                        "severity": match[
                            "severity"
                        ],

                        "description": match[
                            "description"
                        ]
                    }

                    writer.writerow(result)

                    print()
                    print("=" * 70)
                    print("NEXUS REAL-TIME THREAT DETECTED")
                    print("=" * 70)
                    print(
                        f"Time       : {result['detected_at']}"
                    )
                    print(
                        f"Event      : {result['event_type']}"
                    )
                    print(
                        f"Process    : {result['process']}"
                    )
                    print(
                        f"Source IP  : {result['source_ip']}"
                    )
                    print(
                        f"Dest IP    : {result['destination_ip']}"
                    )
                    print(
                        f"IoC        : {result['ioc_value']}"
                    )
                    print(
                        f"Threat     : {result['threat_name']}"
                    )
                    print(
                        f"Severity   : {result['severity']}"
                    )
                    print("=" * 70)

                    processed += 1

    return processed


def main():

    print("=" * 70)
    print("NEXUS INTELLIGENCE")
    print("REAL-TIME THREAT PROCESSOR")
    print("=" * 70)

    print()
    print("Input:")
    print(INPUT_FILE)

    print()
    print("IoC database:")
    print(IOC_FILE)

    print()
    print("Output:")
    print(OUTPUT_FILE)

    print()
    print("Processor running...")
    print("Press Ctrl+C to stop.")
    print()

    last_size = 0

    while True:

        try:

            if INPUT_FILE.exists():

                current_size = INPUT_FILE.stat().st_size

                if current_size != last_size:

                    process_new_events()

                    last_size = current_size

            time.sleep(2)

        except KeyboardInterrupt:

            print()
            print("Stopping real-time processor...")
            break

        except Exception as e:

            print(
                "Processor error:",
                e
            )

            time.sleep(2)


if __name__ == "__main__":
    main()