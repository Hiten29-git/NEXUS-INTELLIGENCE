import json
import os
import socket
import time
import getpass
from datetime import datetime, timezone

import psutil


OUTPUT_FILE = "data/live/live_events.jsonl"

DEVICE_ID = socket.gethostname()
USER_ID = getpass.getuser()

seen_pids = set()
seen_connections = set()


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def emit_event(event_type, **kwargs):

    event = {
        "timestamp": timestamp(),
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "event_type": event_type,
        "source_ip": None,
        "destination_ip": None,
        "process": None,
        "parent_process": None,
        "resource": None,
        "ioc_match": False,
        **kwargs
    }

    print(json.dumps(event))

    os.makedirs(
        os.path.dirname(OUTPUT_FILE),
        exist_ok=True
    )

    with open(OUTPUT_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def initialize_baseline():

    global seen_pids
    global seen_connections

    # Existing processes become the baseline.
    # They will NOT be reported as new executions.

    try:

        seen_pids = {
            process.info["pid"]
            for process in psutil.process_iter(["pid"])
            if process.info["pid"] is not None
        }

    except Exception:

        seen_pids = set()

    # Existing network connections become the baseline.

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

        seen_connections = {
            (
                connection.pid,
                connection.laddr.ip
                if connection.laddr else None,
                connection.laddr.port
                if connection.laddr else None,
                connection.raddr.ip
                if connection.raddr else None,
                connection.raddr.port
                if connection.raddr else None
            )
            for connection in connections
            if connection.status == psutil.CONN_ESTABLISHED
            and connection.laddr
            and connection.raddr
        }

    except (
        psutil.AccessDenied,
        PermissionError
    ):

        seen_connections = set()


def get_process_name(pid):

    if not pid:
        return None

    try:

        return psutil.Process(pid).name()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess
    ):

        return None


def collect_process_events():

    global seen_pids

    current_pids = set()

    for process in psutil.process_iter(
        ["pid", "name", "username", "exe", "ppid"]
    ):

        try:

            info = process.info

            pid = info.get("pid")

            if pid is None:
                continue

            current_pids.add(pid)

            if pid not in seen_pids:

                emit_event(
                    "PROCESS_EXECUTION",
                    process=info.get("name"),
                    parent_process=str(
                        info.get("ppid")
                    ),
                    resource=info.get("exe")
                )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            continue

    seen_pids = current_pids


def collect_network_events():

    global seen_connections

    current_connections = set()

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

        for connection in connections:

            if connection.status != psutil.CONN_ESTABLISHED:
                continue

            if not connection.laddr or not connection.raddr:
                continue

            connection_id = (
                connection.pid,
                connection.laddr.ip,
                connection.laddr.port,
                connection.raddr.ip,
                connection.raddr.port
            )

            current_connections.add(
                connection_id
            )

            if connection_id not in seen_connections:

                process_name = get_process_name(
                    connection.pid
                )

                emit_event(
                    "NETWORK_CONNECTION",
                    source_ip=connection.laddr.ip,
                    destination_ip=connection.raddr.ip,
                    process=process_name
                )

    except (
        psutil.AccessDenied,
        PermissionError
    ):

        pass

    seen_connections = current_connections


def main():

    print("=" * 60)
    print("NEXUS INTELLIGENCE - REAL-TIME EVENT COLLECTOR")
    print("=" * 60)

    print(f"User   : {USER_ID}")
    print(f"Device : {DEVICE_ID}")

    print("Status : INITIALIZING BASELINE")

    initialize_baseline()

    print("Status : COLLECTING NEW LIVE EVENTS")
    print("Press Ctrl+C to stop")

    print("=" * 60)

    try:

        while True:

            collect_process_events()
            collect_network_events()

            time.sleep(2)

    except KeyboardInterrupt:

        print("\n")
        print("=" * 60)
        print("NEXUS COLLECTOR STOPPED")
        print("=" * 60)


if __name__ == "__main__":
    main()
