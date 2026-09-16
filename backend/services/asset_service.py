import json
from pathlib import Path
from collections import Counter

LIVE_EVENTS_FILE = Path("data/live/live_events.jsonl")


def _read_live_events():
    if not LIVE_EVENTS_FILE.exists():
        return []

    events = []

    with LIVE_EVENTS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events


def _clean_ip(value):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    # Remove accidental :port notation.
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)

        if port.isdigit():
            value = host

    # Remove IPv4 values incorrectly stored as IP.port.
    parts = value.split(".")

    if len(parts) == 5 and parts[-1].isdigit():
        value = ".".join(parts[:4])

    return value


def _extract_device(event):
    return (
        event.get("device_id")
        or event.get("hostname")
        or event.get("host")
        or event.get("device")
    )


def _extract_user(event):
    return (
        event.get("user_id")
        or event.get("username")
        or event.get("user")
    )


def get_assets():
    events = _read_live_events()

    if not events:
        return []

    devices = {}

    for event in events:
        device_id = _extract_device(event)

        if not device_id:
            continue

        if device_id not in devices:
            devices[device_id] = {
                "device_id": device_id,
                "user_ids": set(),
                "ips": set(),
                "event_types": Counter(),
                "event_count": 0,
            }

        asset = devices[device_id]

        user_id = _extract_user(event)

        if user_id:
            asset["user_ids"].add(str(user_id))

        asset["event_count"] += 1

        event_type = event.get("event_type")

        if event_type:
            asset["event_types"][event_type] += 1

        source_ip = _clean_ip(event.get("source_ip"))

        if source_ip:
            asset["ips"].add(source_ip)

        destination_ip = _clean_ip(
            event.get("destination_ip")
            or event.get("destination")
        )

        if destination_ip:
            asset["ips"].add(destination_ip)

    result = []

    for device_id, asset in devices.items():

        users = sorted(asset["user_ids"])
        observed_ips = sorted(asset["ips"])

        primary_ip = None

        # Prefer a private/local IP as the displayed endpoint IP.
        for ip in observed_ips:
            if (
                ip.startswith("10.")
                or ip.startswith("192.168.")
                or ip.startswith("172.16.")
                or ip.startswith("172.17.")
                or ip.startswith("172.18.")
                or ip.startswith("172.19.")
                or ip.startswith("172.2")
                or ip.startswith("172.3")
            ):
                primary_ip = ip
                break

        if primary_ip is None and observed_ips:
            primary_ip = observed_ips[0]

        result.append(
            {
                "id": f"asset:{device_id}",
                "hostname": device_id,
                "ip": primary_ip,
                "role": "Endpoint",
                "os": "macOS / Live Endpoint",
                "status": "MONITORED",
                "criticality": "MEDIUM",

                # Risk is intentionally not fabricated here.
                # The intelligence engine provides risk separately.
                "riskScore": None,

                "vulnerabilities": [],
                "openPorts": [],

                "blastRadius": 0,

                "observedIps": observed_ips,

                "telemetry": {
                    "eventsObserved": asset["event_count"],
                    "eventTypes": dict(asset["event_types"]),
                },

                "users": users,

                "dataSource": "NEXUS_LIVE_SECURITY_GRAPH",
            }
        )

    return result
