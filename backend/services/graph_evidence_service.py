from typing import Any

from backend.services.graph_service import driver


def _risk_band(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _is_private_ip(ip: str) -> bool:
    if not ip:
        return False

    ip = str(ip)

    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.20.")
        or ip.startswith("172.21.")
        or ip.startswith("172.22.")
        or ip.startswith("172.23.")
        or ip.startswith("172.24.")
        or ip.startswith("172.25.")
        or ip.startswith("172.26.")
        or ip.startswith("172.27.")
        or ip.startswith("172.28.")
        or ip.startswith("172.29.")
        or ip.startswith("172.30.")
        or ip.startswith("172.31.")
        or ip.startswith("127.")
        or ip.startswith("169.254.")
        or ":" in ip
    )


def get_graph_evidence() -> dict[str, Any]:

    if driver is None:
        return {
            "available": False,
            "reason": "Neo4j driver unavailable"
        }

    query = """
    MATCH (u:User)-[:USES]->(d:Device)

    OPTIONAL MATCH (d)-[:EXECUTES]->(p:Process)

    OPTIONAL MATCH (d)-[:CONNECTS_TO]->(ip:IP)

    OPTIONAL MATCH (d)-[:ACCESSES]->(r:Resource)

    WITH
        u,
        d,
        collect(DISTINCT p.name) AS processes,
        collect(DISTINCT ip.address) AS ips,
        collect(DISTINCT r.name) AS resources

    RETURN
        u.id AS user,
        d.id AS device,
        processes,
        ips,
        resources
    """

    try:

        with driver.session() as session:

            records = list(
                session.run(query)
            )

        devices = []

        total_processes = 0
        total_ips = 0
        total_resources = 0

        for record in records:

            processes = [
                str(x)
                for x in (
                    record["processes"]
                    or []
                )
                if x
            ]

            ips = [
                str(x)
                for x in (
                    record["ips"]
                    or []
                )
                if x
            ]

            resources = [
                str(x)
                for x in (
                    record["resources"]
                    or []
                )
                if x
            ]

            external_ips = [
                ip
                for ip in ips
                if not _is_private_ip(ip)
            ]

            process_count = len(
                processes
            )

            ip_count = len(ips)

            resource_count = len(
                resources
            )

            total_processes += (
                process_count
            )

            total_ips += ip_count

            total_resources += (
                resource_count
            )

            # ------------------------------------------------
            # IMPORTANT:
            # This is GRAPH CONTEXT, not proof of compromise.
            #
            # No threat score is assigned solely because
            # a device has network connections.
            # ------------------------------------------------

            graph_context_score = min(
                100.0,
                (
                    min(process_count * 1.5, 30)
                    + min(ip_count * 1.5, 30)
                    + min(resource_count * 1.0, 20)
                    + min(len(external_ips) * 1.0, 20)
                )
            )

            devices.append(
                {
                    "user": record["user"],
                    "device": record["device"],

                    "process_count":
                        process_count,

                    "ip_count":
                        ip_count,

                    "external_ip_count":
                        len(external_ips),

                    "resource_count":
                        resource_count,

                    "processes":
                        processes,

                    "ips":
                        ips,

                    "resources":
                        resources,

                    "graph_context_score":
                        round(
                            graph_context_score,
                            2
                        ),

                    "graph_evidence_score":
                        0.0,

                    "evidence_status":
                        "OBSERVED_CONTEXT_ONLY",

                    "risk_contribution":
                        0.0,

                    "risk_band":
                        "LOW"
                }
            )

        return {
            "available": True,

            "source":
                "NEXUS_NEO4J_SECURITY_GRAPH",

            "interpretation":
                "Observed graph relationships provide contextual evidence. "
                "They are not treated as confirmed attacks without additional "
                "security evidence.",

            "summary": {
                "devices":
                    len(devices),

                "processes":
                    total_processes,

                "ips":
                    total_ips,

                "resources":
                    total_resources
            },

            "devices":
                devices
        }

    except Exception as exc:

        return {
            "available": False,

            "error":
                str(exc)
        }
