import csv
import ipaddress
from datetime import datetime
from pathlib import Path

INPUT_FILE = Path("data/normalized/realtime_security_events.csv")

VALID_EVENT_TYPES = {
    "PROCESS_EXECUTION",
    "NETWORK_CONNECTION",
    "LOGIN",
    "RESOURCE_ACCESS",
}

REQUIRED_FIELDS = {
    "event_id",
    "timestamp",
    "user_id",
    "device_id",
    "event_type",
    "ioc_match",
}


def is_valid_ip(value):
    if not value:
        return True

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_timestamp(value):
    if not value:
        return False

    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def is_valid_port(value):
    if value in ("", None):
        return True

    try:
        port = int(value)
        return 1 <= port <= 65535
    except ValueError:
        return False


def validate_event(event, seen_ids):
    errors = []

    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in event:
            errors.append(f"Missing field: {field}")

        elif not event[field]:
            errors.append(f"Empty required field: {field}")

    # Duplicate event ID
    event_id = event.get("event_id", "")

    if event_id in seen_ids:
        errors.append("Duplicate event_id")

    elif event_id:
        seen_ids.add(event_id)

    # Timestamp
    timestamp = event.get("timestamp", "")

    if timestamp and not is_valid_timestamp(timestamp):
        errors.append("Invalid timestamp")

    # Event type
    event_type = event.get("event_type", "")

    if event_type not in VALID_EVENT_TYPES:
        errors.append(f"Invalid event_type: {event_type}")

    # Source IP
    source_ip = event.get("source_ip", "")

    if not is_valid_ip(source_ip):
        errors.append(f"Invalid source_ip: {source_ip}")

    # Destination IP
    destination_ip = event.get("destination_ip", "")

    if not is_valid_ip(destination_ip):
        errors.append(f"Invalid destination_ip: {destination_ip}")

    # Source port
    source_port = event.get("source_port", "")

    if not is_valid_port(source_port):
        errors.append(f"Invalid source_port: {source_port}")

    # Destination port
    destination_port = event.get("destination_port", "")

    if not is_valid_port(destination_port):
        errors.append(f"Invalid destination_port: {destination_port}")

    # IoC field
    ioc_value = event.get("ioc_match", "")

    valid_ioc_values = {
        "True",
        "False",
        "true",
        "false",
        "1",
        "0",
    }

    if ioc_value not in valid_ioc_values:
        errors.append(f"Invalid ioc_match: {ioc_value}")

    return errors


def main():

    print("=" * 90)
    print("NEXUS INTELLIGENCE")
    print("MEMBER 3 - DATA QUALITY VALIDATOR")
    print("=" * 90)

    if not INPUT_FILE.exists():

        print()
        print("[ERROR] File not found:")
        print(f"        {INPUT_FILE}")
        return

    total = 0
    valid = 0
    invalid = 0

    seen_ids = set()

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        print()
        print("Schema columns detected:")
        print()

        for column in (reader.fieldnames or []):
            print(f"  [OK] {column}")

        print()

        for event in reader:

            total += 1

            errors = validate_event(
                event,
                seen_ids
            )

            if errors:

                invalid += 1

                print()
                print(
                    f"[INVALID] "
                    f"{event.get('event_id', 'UNKNOWN')}"
                )

                for error in errors:
                    print(f"   -> {error}")

            else:
                valid += 1

    print()
    print("=" * 90)
    print("DATA QUALITY SUMMARY")
    print("=" * 90)

    print(f"Total events   : {total}")
    print(f"Valid events   : {valid}")
    print(f"Invalid events : {invalid}")

    if total > 0:
        quality = (valid / total) * 100
    else:
        quality = 0

    print(f"Data quality   : {quality:.2f}%")

    print()

    if invalid == 0:

        print("STATUS: PASS")
        print("All events passed validation.")

    else:

        print("STATUS: REVIEW REQUIRED")
        print("One or more events failed validation.")

    print("=" * 90)


if __name__ == "__main__":
    main()