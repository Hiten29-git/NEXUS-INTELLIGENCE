import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


# ============================================================
# NEXUS INTELLIGENCE
# Member 3 - Synthetic Security Data Generator
# ============================================================

OUTPUT_FILE = Path("data/raw/security_events.csv")

random.seed(42)


USERS = [
    "user_001",
    "user_002",
    "user_003",
    "user_004",
    "user_005",
]

WORKSTATIONS = [
    "workstation_01",
    "workstation_02",
    "workstation_03",
]

SERVERS = [
    "server_web_01",
    "server_app_01",
    "server_db_01",
    "server_file_01",
]

RESOURCES = [
    "HR_DATA",
    "FINANCE_DATA",
    "CUSTOMER_DATA",
    "SOURCE_CODE",
]


def make_event(
    event_id,
    timestamp,
    event_type,
    user_id,
    source_asset,
    source_ip,
    destination_asset="",
    destination_ip="",
    process_name="",
    resource="",
    action="",
    status="",
    scenario_id="",
    label="BENIGN",
    attack_stage="NORMAL",
    ioc_match=False,
):
    return {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "user_id": user_id,
        "source_asset": source_asset,
        "source_ip": source_ip,
        "destination_asset": destination_asset,
        "destination_ip": destination_ip,
        "process_name": process_name,
        "resource": resource,
        "action": action,
        "status": status,
        "scenario_id": scenario_id,
        "label": label,
        "attack_stage": attack_stage,
        "ioc_match": ioc_match,
    }


# ============================================================
# BENIGN EVENTS
# ============================================================

def generate_benign_events(start_time, count=900):
    events = []

    for i in range(count):

        event_id = f"EVT-{i + 1:06d}"

        timestamp = start_time + timedelta(
            seconds=i * 30
        )

        user = random.choice(USERS)
        workstation = random.choice(WORKSTATIONS)
        server = random.choice(SERVERS)

        source_ip = f"10.10.10.{random.randint(10, 200)}"
        destination_ip = f"10.10.20.{random.randint(10, 100)}"

        event_type = random.choice([
            "LOGIN_SUCCESS",
            "PROCESS_START",
            "DNS_QUERY",
            "NETWORK_CONNECTION",
            "FILE_ACCESS",
        ])

        process = random.choice([
            "chrome.exe",
            "explorer.exe",
            "outlook.exe",
            "teams.exe",
            "python.exe",
        ])

        resource = random.choice(RESOURCES)

        events.append(
            make_event(
                event_id=event_id,
                timestamp=timestamp,
                event_type=event_type,
                user_id=user,
                source_asset=workstation,
                source_ip=source_ip,
                destination_asset=server,
                destination_ip=destination_ip,
                process_name=process,
                resource=resource,
                action="normal_activity",
                status="success",
                scenario_id="SCN-000",
                label="BENIGN",
                attack_stage="NORMAL",
                ioc_match=False,
            )
        )

    return events


# ============================================================
# ATTACK SCENARIO
#
# Abnormal Login
#       ↓
# Suspicious Process
#       ↓
# New Server Connection
#       ↓
# Privilege Change
#       ↓
# Sensitive Resource Access
# ============================================================

def generate_attack_scenario(start_event_number, start_time):

    events = []

    user = "user_003"
    workstation = "workstation_02"

    # Synthetic / reserved documentation IPs
    external_ip = "203.0.113.50"

    # --------------------------------------------------------
    # Stage 1 - Abnormal Login
    # --------------------------------------------------------

    timestamp = start_time

    events.append(
        make_event(
            event_id=f"EVT-{start_event_number:06d}",
            timestamp=timestamp,
            event_type="LOGIN_FAILURE",
            user_id=user,
            source_asset=workstation,
            source_ip=external_ip,
            action="authentication_attempt",
            status="failed",
            scenario_id="SCN-001",
            label="MALICIOUS",
            attack_stage="INITIAL_ACCESS",
            ioc_match=True,
        )
    )

    # --------------------------------------------------------
    # Stage 2 - Successful Login
    # --------------------------------------------------------

    timestamp += timedelta(minutes=1)

    events.append(
        make_event(
            event_id=f"EVT-{start_event_number + 1:06d}",
            timestamp=timestamp,
            event_type="LOGIN_SUCCESS",
            user_id=user,
            source_asset=workstation,
            source_ip=external_ip,
            action="authentication",
            status="success",
            scenario_id="SCN-001",
            label="MALICIOUS",
            attack_stage="INITIAL_ACCESS",
            ioc_match=True,
        )
    )

    # --------------------------------------------------------
    # Stage 3 - Suspicious Process
    # --------------------------------------------------------

    timestamp += timedelta(minutes=2)

    events.append(
        make_event(
            event_id=f"EVT-{start_event_number + 2:06d}",
            timestamp=timestamp,
            event_type="PROCESS_START",
            user_id=user,
            source_asset=workstation,
            source_ip=external_ip,
            process_name="suspicious_loader.exe",
            action="process_execution",
            status="success",
            scenario_id="SCN-001",
            label="MALICIOUS",
            attack_stage="EXECUTION",
            ioc_match=True,
        )
    )

    # --------------------------------------------------------
    # Stage 4 - Network Connection
    # --------------------------------------------------------

    timestamp += timedelta(minutes=2)

    events.append(
        make_event(
            event_id=f"EVT-{start_event_number + 3:06d}",
            timestamp=timestamp,
            event_type="NETWORK_CONNECTION",
            user_id=user,
            source_asset=workstation,
            source_ip="10.10.10.52",
            destination_asset="server_app_01",
            destination_ip="10.10.20.20",
            process_name="suspicious_loader.exe",
            action="new_server_connection",
            status="success",
            scenario_id="SCN-001",
            label="MALICIOUS",
            attack_stage="LATERAL_MOVEMENT",
            ioc_match=True,
        )
    )

    # --------------------------------------------------------
    # Stage 5 - Privilege Change
    # --------------------------------------------------------

    timestamp += timedelta(minutes=2)

    events.append(
        make_event(
            event_id=f"EVT-{start_event_number + 4:06d}",
            timestamp=timestamp,
            event_type="PRIVILEGE_CHANGE",
            user_id=user,
            source_asset="server_app_01",
            source_ip="10.10.10.52",
            process_name="system_service.exe",
            action="privilege_escalation",
            status="success",
            scenario_id="SCN-001",
            label="MALICIOUS",
            attack_stage="PRIVILEGE_ESCALATION",
            ioc_match=True,
        )
    )

    # --------------------------------------------------------
    # Stage 6 - Sensitive Resource Access
    # --------------------------------------------------------

    timestamp += timedelta(minutes=2)

    events.append(
        make_event(
            event_id=f"EVT-{start_event_number + 5:06d}",
            timestamp=timestamp,
            event_type="SENSITIVE_RESOURCE_ACCESS",
            user_id=user,
            source_asset="server_app_01",
            source_ip="10.10.10.52",
            destination_asset="server_db_01",
            destination_ip="10.10.20.30",
            resource="CUSTOMER_DATA",
            action="sensitive_data_access",
            status="success",
            scenario_id="SCN-001",
            label="MALICIOUS",
            attack_stage="COLLECTION",
            ioc_match=True,
        )
    )

    return events


# ============================================================
# MAIN
# ============================================================

def main():

    start_time = datetime(2026, 9, 1, 9, 0, 0)

    benign_events = generate_benign_events(
        start_time=start_time,
        count=900,
    )

    attack_events = generate_attack_scenario(
        start_event_number=901,
        start_time=start_time + timedelta(hours=8),
    )

    all_events = benign_events + attack_events

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = list(all_events[0].keys())

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(all_events)

    print("=" * 60)
    print("NEXUS INTELLIGENCE - DATA GENERATION")
    print("=" * 60)
    print(f"Total events : {len(all_events)}")
    print(f"Benign       : {len(benign_events)}")
    print(f"Attack       : {len(attack_events)}")
    print(f"Output       : {OUTPUT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()