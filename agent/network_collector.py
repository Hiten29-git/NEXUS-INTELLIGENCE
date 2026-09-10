import json
import os
import time
import socket
from datetime import datetime, timezone

import psutil


OUTPUT_FILE = "data/live/live_events.jsonl"
INTERVAL = 2


def get_user():
    return os.getenv("SUDO_USER") or os.getenv("USER") or "unknown"


def get_device():
    return socket.gethostname()


def connection_key(conn):
    """
    Create a stable identifier for a network connection.
    """
    local = conn.laddr if conn.laddr else None
    remote = conn.raddr if conn.raddr else None

    return (
        conn.pid,
        local.ip if local else None,
        local.port if local else None,
        remote.ip if remote else None,
        remote.port if remote else None,
    )


def collect_network_connections():

    current = {}

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as e:
        print(f"Network access denied: {e}")
        return current

    for conn in connections:

        if not conn.raddr:
            continue

        key = connection_key(conn)

        process_name = "unknown"

        if conn.pid:

            try:
                process_name = psutil.Process(conn.pid).name()

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        current[key] = {
            "pid": conn.pid,
            "process": process_name,

            "source_ip": (
                conn.laddr.ip
                if conn.laddr
                else None
            ),

            "source_port": (
                conn.laddr.port
                if conn.laddr
                else None
            ),

            "destination_ip": conn.raddr.ip,

            "destination_port": conn.raddr.port,

            "connection_status": conn.status,
        }

    return current


def write_event(data):

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "user_id": get_user(),

        "device_id": get_device(),

        "event_type": "NETWORK_CONNECTION",

        "source_ip": data["source_ip"],

        "source_port": data["source_port"],

        "destination_ip": data["destination_ip"],

        "destination_port": data["destination_port"],

        "connection_status": data["connection_status"],

        "process": data["process"],

        "pid": data["pid"],

        "resource": (
            f"{data['destination_ip']}:"
            f"{data['destination_port']}"
        ),

        "ioc_match": False,
    }

    with open(OUTPUT_FILE, "a") as f:

        f.write(json.dumps(event) + "\n")

    return event


def main():

    print("=" * 60)
    print("NEXUS INTELLIGENCE – NETWORK COLLECTOR")
    print("=" * 60)

    print(f"User   : {get_user()}")
    print(f"Device : {get_device()}")
    print("Status : NETWORK TELEMETRY ACTIVE")
    print("Mode   : CHANGE DETECTION")
    print("Press Ctrl+C to stop")
    print()

    previous = {}

    while True:

        current = collect_network_connections()

        # Detect NEW connections
        for key, data in current.items():

            if key not in previous:

                event = write_event(data)

                print(
                    f"[NEW NETWORK] "
                    f"{event['process']} → "
                    f"{event['destination_ip']}:"
                    f"{event['destination_port']} "
                    f"({event['connection_status']})"
                )

        # Detect connections whose state changed
        for key, data in current.items():

            if key in previous:

                old_status = previous[key]["connection_status"]

                new_status = data["connection_status"]

                if old_status != new_status:

                    event = write_event(data)

                    print(
                        f"[NETWORK CHANGE] "
                        f"{event['process']} → "
                        f"{event['destination_ip']}:"
                        f"{event['destination_port']} "
                        f"{old_status} → {new_status}"
                    )

        # Detect CLOSED / disappeared connections
        for key, old_data in previous.items():

            if key not in current:

                old_data["connection_status"] = "CLOSED"

                event = write_event(old_data)

                print(
                    f"[NETWORK CLOSED] "
                    f"{event['process']} → "
                    f"{event['destination_ip']}:"
                    f"{event['destination_port']}"
                )

        previous = current

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
