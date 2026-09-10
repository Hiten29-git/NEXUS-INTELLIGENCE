import random
from datetime import datetime, timedelta
import pandas as pd


random.seed(42)

OUTPUT = "datasets/security_events/security_events.csv"

users = []

# 90 normal users
for i in range(1, 91):
    users.append({
        "user_id": f"U{i:03d}",
        "behavior": "normal"
    })

# 10 suspicious users
for i in range(91, 101):
    users.append({
        "user_id": f"U{i:03d}",
        "behavior": "suspicious"
    })


event_types = [
    "LOGIN",
    "FILE_ACCESS",
    "PROCESS_EXECUTION",
    "NETWORK_CONNECTION"
]

normal_processes = [
    "chrome",
    "vscode",
    "python",
    "office"
]

suspicious_processes = [
    "powershell",
    "cmd",
    "wscript"
]

rows = []

start_time = datetime(2026, 9, 1, 9, 0, 0)

for user in users:

    current_time = start_time

    if user["behavior"] == "normal":

        event_count = random.randint(8, 15)

        for _ in range(event_count):

            event_type = random.choice(event_types)

            process = ""
            resource = ""
            ioc_match = False

            if event_type == "PROCESS_EXECUTION":
                process = random.choice(normal_processes)

            elif event_type == "FILE_ACCESS":
                resource = random.choice([
                    "documents",
                    "reports",
                    "projects"
                ])

            rows.append({
                "timestamp": current_time.isoformat(),
                "user_id": user["user_id"],
                "device_id": f"PC{random.randint(1, 100):03d}",
                "source_ip": f"10.0.1.{random.randint(10, 200)}",
                "destination": f"SERVER{random.randint(1, 10):02d}",
                "event_type": event_type,
                "process": process,
                "resource": resource,
                "ioc_match": ioc_match
            })

            current_time += timedelta(minutes=random.randint(5, 30))

    else:

        event_count = random.randint(25, 40)

        for _ in range(event_count):

            event_type = random.choice(event_types)

            process = ""
            resource = ""
            ioc_match = False

            if event_type == "PROCESS_EXECUTION":
                process = random.choice(suspicious_processes)

            elif event_type == "FILE_ACCESS":
                resource = random.choice([
                    "customer_database",
                    "finance_database",
                    "admin_files"
                ])

            elif event_type == "NETWORK_CONNECTION":
                ioc_match = random.random() < 0.6

            elif event_type == "LOGIN":
                ioc_match = random.random() < 0.3

            rows.append({
                "timestamp": current_time.isoformat(),
                "user_id": user["user_id"],
                "device_id": f"PC{random.randint(1, 100):03d}",
                "source_ip": f"10.0.2.{random.randint(1, 250)}",
                "destination": f"SERVER{random.randint(1, 10):02d}",
                "event_type": event_type,
                "process": process,
                "resource": resource,
                "ioc_match": ioc_match
            })

            current_time += timedelta(minutes=random.randint(1, 10))


df = pd.DataFrame(rows)

df.to_csv(OUTPUT, index=False)

print("Dataset generated successfully.")
print(f"Total events: {len(df)}")
print(f"Users: {df['user_id'].nunique()}")
print(f"Output: {OUTPUT}")
print("\nEvents per behavior:")

normal_ids = {u["user_id"] for u in users if u["behavior"] == "normal"}

print(
    "Normal events:",
    len(df[df["user_id"].isin(normal_ids)])
)

print(
    "Suspicious events:",
    len(df[~df["user_id"].isin(normal_ids)])
)
