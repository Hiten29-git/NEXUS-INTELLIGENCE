import os
import json
import time
import socket
import subprocess
from datetime import datetime, timezone

import psutil


# ============================================================
# NEXUS INTELLIGENCE — V4 REAL-TIME TELEMETRY COLLECTOR
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data",
    "live"
)

EVENT_FILE = os.path.join(
    DATA_DIR,
    "live_events.jsonl"
)

os.makedirs(
    DATA_DIR,
    exist_ok=True
)


# ============================================================
# CONFIGURATION
# ============================================================

POLL_INTERVAL = 2

HOSTNAME = socket.gethostname()

try:
    CURRENT_USER = psutil.users()[0].name
except Exception:
    CURRENT_USER = os.getenv(
        "USER",
        "unknown"
    )


# ============================================================
# STATE
# ============================================================

known_processes = set()

previous_cpu = None
previous_memory = None


# ============================================================
# HELPERS
# ============================================================

def timestamp():
    return datetime.now(
        timezone.utc
    ).isoformat()


def write_event(event):
    try:
        with open(
            EVENT_FILE,
            "a",
            encoding="utf-8"
        ) as f:

            f.write(
                json.dumps(
                    event,
                    separators=(",", ":")
                )
                + "\n"
            )

    except Exception as e:
        print(
            f"[WRITE ERROR] {e}"
        )


def base_event(event_type):
    return {
        "timestamp": timestamp(),
        "user_id": CURRENT_USER,
        "device_id": HOSTNAME,
        "event_type": event_type,
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "protocol": None,
        "process": None,
        "parent_process": None,
        "resource": None,
        "ioc_match": False
    }


# ============================================================
# PROCESS COLLECTION
# ============================================================

def collect_processes():

    current_pids = set()

    try:
        processes = psutil.process_iter(
            [
                "pid",
                "name",
                "ppid",
                "username",
                "cmdline"
            ]
        )

        for proc in processes:

            try:
                info = proc.info

                pid = info.get(
                    "pid"
                )

                current_pids.add(
                    pid
                )

                if pid in known_processes:
                    continue

                name = (
                    info.get("name")
                    or "unknown"
                )

                parent_pid = (
                    info.get("ppid")
                )

                event = base_event(
                    "PROCESS_EXECUTION"
                )

                event.update({
                    "process": name,
                    "parent_process": str(
                        parent_pid
                    )
                    if parent_pid
                    else None,
                    "resource": (
                        f"pid:{pid}"
                    )
                })

                write_event(event)

                print(
                    f"[PROCESS] "
                    f"{name} "
                    f"(PID {pid})"
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

    except Exception as e:

        print(
            f"[PROCESS ERROR] {e}"
        )

    return current_pids


# ============================================================
# NETWORK COLLECTION
# ============================================================

def collect_network():

    connections = []

    # --------------------------------------------------------
    # Method 1: psutil
    # --------------------------------------------------------

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

    except Exception:
        connections = []

    for conn in connections:

        try:

            if not conn.raddr:
                continue

            destination_ip = (
                conn.raddr.ip
            )

            destination_port = (
                conn.raddr.port
            )

            event = base_event(
                "NETWORK_CONNECTION"
            )

            event.update({
                "source_ip": (
                    conn.laddr.ip
                    if conn.laddr
                    else None
                ),
                "destination_ip":
                    destination_ip,

                "destination_port":
                    destination_port,

                "protocol":
                    "TCP/UDP",

                "process":
                    None,

                "resource":
                    conn.status,

            })

            write_event(event)

            print(
                f"[NETWORK] "
                f"{destination_ip}:"
                f"{destination_port} "
                f"{conn.status}"
            )

        except Exception:
            continue


# ============================================================
# NETWORK FALLBACK
# ============================================================

def collect_network_fallback():

    try:

        result = subprocess.run(
            [
                "netstat",
                "-an"
            ],
            capture_output=True,
            text=True,
            timeout=3
        )

        lines = result.stdout.splitlines()

        count = 0

        for line in lines:

            line = line.strip()

            if not line:
                continue

            if (
                "ESTABLISHED"
                not in line
                and "SYN_SENT"
                not in line
                and "CLOSE_WAIT"
                not in line
            ):
                continue

            parts = line.split()

            if len(parts) < 4:
                continue

            destination = parts[-2]

            event = base_event(
                "NETWORK_CONNECTION"
            )

            event.update({
                "destination_ip":
                    destination,
                "resource":
                    parts[-1]
                    if parts
                    else None
            })

            write_event(event)

            count += 1

        if count:
            print(
                f"[NETWORK-FALLBACK] "
                f"{count} connections"
            )

    except Exception:
        pass


# ============================================================
# SYSTEM TELEMETRY
# ============================================================

def collect_system():

    global previous_cpu
    global previous_memory

    try:

        cpu = psutil.cpu_percent(
            interval=None
        )

        memory = psutil.virtual_memory()

        memory_percent = (
            memory.percent
        )

        event = base_event(
            "SYSTEM_ACTIVITY"
        )

        event.update({

            "resource":
                "system",

            "cpu_percent":
                round(cpu, 2),

            "memory_percent":
                round(
                    memory_percent,
                    2
                ),

            "cpu_delta":
                round(
                    cpu - previous_cpu,
                    2
                )
                if previous_cpu
                is not None
                else 0,

            "memory_delta":
                round(
                    memory_percent
                    - previous_memory,
                    2
                )
                if previous_memory
                is not None
                else 0
        })

        write_event(event)

        previous_cpu = cpu
        previous_memory = memory_percent

    except Exception as e:

        print(
            f"[SYSTEM ERROR] {e}"
        )


# ============================================================
# USER / SESSION TELEMETRY
# ============================================================

def collect_sessions():

    try:

        users = psutil.users()

        event = base_event(
            "USER_SESSION"
        )

        event.update({

            "resource":
                "active_sessions",

            "session_count":
                len(users)

        })

        write_event(event)

    except Exception:
        pass


# ============================================================
# FILESYSTEM METADATA
# ============================================================

def collect_file_activity():

    directories = [
        os.path.expanduser(
            "~/Downloads"
        ),
        os.path.expanduser(
            "~/Desktop"
        )
    ]

    total_files = 0
    total_size = 0

    for directory in directories:

        if not os.path.exists(
            directory
        ):
            continue

        try:

            for name in os.listdir(
                directory
            ):

                path = os.path.join(
                    directory,
                    name
                )

                try:

                    if os.path.isfile(
                        path
                    ):

                        total_files += 1

                        total_size += (
                            os.path.getsize(
                                path
                            )
                        )

                except (
                    OSError,
                    PermissionError
                ):
                    continue

        except (
            OSError,
            PermissionError
        ):
            continue

    event = base_event(
        "FILE_ACTIVITY"
    )

    event.update({

        "resource":
            "user_file_metadata",

        "file_count":
            total_files,

        "total_size_bytes":
            total_size

    })

    write_event(event)


# ============================================================
# INITIAL BASELINE
# ============================================================

def initialize_baseline():

    print(
        "NEXUS INTELLIGENCE — V4 "
        "REAL-TIME COLLECTOR"
    )

    print(
        "=" * 60
    )

    print(
        f"User   : {CURRENT_USER}"
    )

    print(
        f"Device : {HOSTNAME}"
    )

    print(
        f"Output : {EVENT_FILE}"
    )

    print(
        "Status : INITIALIZING BASELINE"
    )

    try:

        for proc in psutil.process_iter(
            ["pid"]
        ):

            try:

                pid = proc.info["pid"]

                known_processes.add(
                    pid
                )

            except Exception:
                continue

    except Exception:
        pass

    print(
        f"Baseline processes: "
        f"{len(known_processes)}"
    )

    print(
        "Status : COLLECTING LIVE EVENTS"
    )

    print(
        "Press Ctrl+C to stop"
    )

    print(
        "=" * 60
    )


# ============================================================
# MAIN LOOP
# ============================================================

def main():

    initialize_baseline()

    cycle = 0

    while True:

        try:

            current_processes = (
                collect_processes()
            )

            # ------------------------------------------------
            # Network
            # ------------------------------------------------

            collect_network()

            # If psutil cannot access network connections,
            # use macOS netstat as fallback.
            if cycle % 5 == 0:

                collect_network_fallback()

            # ------------------------------------------------
            # System
            # ------------------------------------------------

            collect_system()

            # ------------------------------------------------
            # User sessions
            # ------------------------------------------------

            collect_sessions()

            # ------------------------------------------------
            # File metadata
            # ------------------------------------------------

            if cycle % 5 == 0:

                collect_file_activity()

            # ------------------------------------------------
            # Update process baseline
            # ------------------------------------------------

            known_processes.update(
                current_processes
            )

            cycle += 1

            time.sleep(
                POLL_INTERVAL
            )

        except KeyboardInterrupt:

            print()
            print(
                "NEXUS collector stopped."
            )

            break

        except Exception as e:

            print(
                f"[COLLECTOR ERROR] {e}"
            )

            time.sleep(
                POLL_INTERVAL
            )


if __name__ == "__main__":
    main()
