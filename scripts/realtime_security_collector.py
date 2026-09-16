import csv
import json
import socket
import time
import uuid
import getpass
from datetime import datetime, timezone
from pathlib import Path

import psutil


# ============================================================
# FILE PATHS
# ============================================================

RAW_FILE = Path(
    "data/raw/realtime_security_events.jsonl"
)

NORMALIZED_FILE = Path(
    "data/normalized/realtime_security_events.csv"
)


# ============================================================
# CONFIGURATION
# ============================================================

POLL_INTERVAL = 5


# ============================================================
# NORMALIZED CSV SCHEMA
# ============================================================

CSV_FIELDS = [
    "event_id",
    "timestamp",
    "user_id",
    "device_id",
    "event_type",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "process",
    "parent_process",
    "resource",
    "ioc_match",
]


# ============================================================
# SYSTEM INFORMATION
# ============================================================

def get_device_id():
    """
    Return the current computer hostname.
    """

    return socket.gethostname()


def get_local_ip():
    """
    Detect a non-loopback IPv4 address.
    """

    try:

        hostname = socket.gethostname()

        addresses = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_INET
        )

        for address in addresses:

            ip = address[4][0]

            if not ip.startswith("127."):
                return ip

    except Exception:
        pass

    return "127.0.0.1"


def get_parent_process_name(ppid):
    """
    Safely obtain the parent process name.
    """

    if not ppid:
        return ""

    try:

        return psutil.Process(ppid).name()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return ""


# ============================================================
# EVENT CREATION
# ============================================================

def create_event(
    event_type,
    process="",
    parent_process="",
    source_ip="",
    source_port="",
    destination_ip="",
    destination_port="",
    resource="",
    ioc_match=False,
):
    """
    Create a standardized NEXUS security event.
    """

    return {
        "event_id":
            f"RT-{uuid.uuid4().hex[:12]}",

        "timestamp":
            datetime.now(timezone.utc).isoformat(),

        "user_id":
            getpass.getuser(),

        "device_id":
            get_device_id(),

        "event_type":
            event_type,

        "source_ip":
            source_ip,

        "source_port":
            source_port,

        "destination_ip":
            destination_ip,

        "destination_port":
            destination_port,

        "process":
            process,

        "parent_process":
            parent_process,

        "resource":
            resource,

        "ioc_match":
            ioc_match,
    }


# ============================================================
# WRITE EVENT
# ============================================================

def write_event(event):
    """
    Write the same event to:
    1. Raw JSONL
    2. Normalized CSV
    """

    RAW_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    NORMALIZED_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Raw JSONL
    # --------------------------------------------------------

    with RAW_FILE.open(
        "a",
        encoding="utf-8"
    ) as file:

        file.write(
            json.dumps(event) + "\n"
        )

    # --------------------------------------------------------
    # Normalized CSV
    # --------------------------------------------------------

    file_exists = NORMALIZED_FILE.exists()

    with NORMALIZED_FILE.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=CSV_FIELDS
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(event)


# ============================================================
# PROCESS COLLECTION
# ============================================================

def collect_processes(
    previous_processes,
    baseline=False
):
    """
    Collect running processes.

    During the first scan:
        - Build the baseline
        - DO NOT generate events

    During later scans:
        - Detect newly observed PIDs
        - Generate PROCESS_EXECUTION events
    """

    current_processes = {}

    for process in psutil.process_iter(
        ["pid", "ppid", "name"]
    ):

        try:

            info = process.info

            pid = info["pid"]

            name = (
                info["name"]
                or "unknown"
            )

            ppid = info["ppid"]

            current_processes[pid] = name

            # ------------------------------------------------
            # INITIAL BASELINE
            # ------------------------------------------------

            if baseline:
                continue

            # ------------------------------------------------
            # NEW PROCESS DETECTION
            # ------------------------------------------------

            if pid not in previous_processes:

                parent_name = (
                    get_parent_process_name(ppid)
                )

                event = create_event(
                    event_type="PROCESS_EXECUTION",
                    process=name,
                    parent_process=parent_name,
                    source_ip=get_local_ip(),
                    resource=f"PID:{pid}",
                )

                write_event(event)

                print_event(event)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):

            continue

    return current_processes


# ============================================================
# NETWORK COLLECTION
# ============================================================

def collect_network_connections(
    previous_connections,
    baseline=False
):
    """
    Collect active IPv4/IPv6 network connections.

    During the first scan:
        - Build baseline
        - DO NOT generate events

    During later scans:
        - Detect newly observed connections
        - Generate NETWORK_CONNECTION events
    """

    current_connections = set()

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

        for connection in connections:

            # ------------------------------------------------
            # Ignore connections without remote endpoint
            # ------------------------------------------------

            if not connection.raddr:
                continue

            if not connection.laddr:
                continue

            # ------------------------------------------------
            # Endpoint information
            # ------------------------------------------------

            local_ip = connection.laddr.ip

            local_port = connection.laddr.port

            remote_ip = connection.raddr.ip

            remote_port = connection.raddr.port

            # ------------------------------------------------
            # Connection identity
            # ------------------------------------------------

            key = (
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            )

            current_connections.add(key)

            # ------------------------------------------------
            # INITIAL BASELINE
            # ------------------------------------------------

            if baseline:
                continue

            # ------------------------------------------------
            # NEW CONNECTION DETECTION
            # ------------------------------------------------

            if key not in previous_connections:

                process_name = ""

                if connection.pid:

                    try:

                        process_name = (
                            psutil.Process(
                                connection.pid
                            ).name()
                        )

                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        psutil.ZombieProcess,
                    ):

                        pass

                event = create_event(
                    event_type="NETWORK_CONNECTION",
                    process=process_name,
                    source_ip=local_ip,
                    source_port=local_port,
                    destination_ip=remote_ip,
                    destination_port=remote_port,
                    resource="TCP_CONNECTION",
                )

                write_event(event)

                print_event(event)

    except psutil.AccessDenied:

        print(
            "[!] Network access denied."
        )

    return current_connections


# ============================================================
# PRINT EVENT
# ============================================================

def print_event(event):
    """
    Print a compact event representation.
    """

    print(
        f"[{event['timestamp']}] "
        f"{event['event_type']:<22} "
        f"user={event['user_id']:<15} "
        f"process={event['process']:<30} "
        f"src={event['source_ip']:<15} "
        f"src_port={str(event['source_port']):<6} "
        f"dst={event['destination_ip']:<15} "
        f"dst_port={str(event['destination_port']):<6}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    print("=" * 100)

    print(
        "NEXUS INTELLIGENCE"
    )

    print(
        "MEMBER 3 - REAL-TIME SECURITY TELEMETRY"
    )

    print("=" * 100)

    print(
        f"Device : {get_device_id()}"
    )

    print(
        f"User   : {getpass.getuser()}"
    )

    print(
        f"Local IP : {get_local_ip()}"
    )

    print()

    print(
        "Monitoring:"
    )

    print(
        "  [1] Process execution"
    )

    print(
        "  [2] Network connections"
    )

    print()

    print(
        f"Poll interval : {POLL_INTERVAL} seconds"
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print("=" * 100)

    # --------------------------------------------------------
    # INITIAL BASELINE
    # --------------------------------------------------------

    print()

    print(
        "[+] Establishing initial process baseline..."
    )

    previous_processes = (
        collect_processes(
            {},
            baseline=True
        )
    )

    print(
        f"[+] Process baseline: "
        f"{len(previous_processes)} processes"
    )

    print()

    print(
        "[+] Establishing initial network baseline..."
    )

    previous_connections = (
        collect_network_connections(
            set(),
            baseline=True
        )
    )

    print(
        f"[+] Network baseline: "
        f"{len(previous_connections)} connections"
    )

    print()

    print(
        "[+] Initial telemetry baseline established."
    )

    print(
        "[+] Monitoring for NEW process and network activity..."
    )

    print()

    # --------------------------------------------------------
    # CONTINUOUS MONITORING
    # --------------------------------------------------------

    while True:

        try:

            # ------------------------------------------------
            # Process monitoring
            # ------------------------------------------------

            previous_processes = (
                collect_processes(
                    previous_processes,
                    baseline=False
                )
            )

            # ------------------------------------------------
            # Network monitoring
            # ------------------------------------------------

            previous_connections = (
                collect_network_connections(
                    previous_connections,
                    baseline=False
                )
            )

            # ------------------------------------------------
            # Wait before next polling cycle
            # ------------------------------------------------

            time.sleep(
                POLL_INTERVAL
            )

        except KeyboardInterrupt:

            print()

            print(
                "[+] Stopping collector..."
            )

            break

        except Exception as error:

            print(
                f"[ERROR] {error}"
            )

            time.sleep(
                POLL_INTERVAL
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()