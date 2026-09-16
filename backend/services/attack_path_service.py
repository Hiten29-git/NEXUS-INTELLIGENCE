from typing import Any

from backend.services.graph_service import driver


def get_attack_chains() -> dict[str, Any]:

    with driver.session() as session:

        result = session.run(
            """
            MATCH (u:User)-[:USES]->(d:Device)
            OPTIONAL MATCH path1 =
                (d)-[:EXECUTES]->(p:Process)-[:CONNECTS_TO]->(ip:IP)

            RETURN
                u.id AS user,
                d.id AS device,
                collect(DISTINCT {
                    process: p.name,
                    destination: ip.address,
                    path: [
                        'user:' + u.id,
                        'device:' + d.id,
                        'process:' + p.name,
                        'ip:' + ip.address
                    ],
                    relationships: [
                        'USES',
                        'EXECUTES',
                        'CONNECTS_TO'
                    ]
                }) AS paths
            """
        )

        chains = []

        for record in result:
            for path in record["paths"]:

                if not path["process"] or not path["destination"]:
                    continue

                chains.append({
                    "user": record["user"],
                    "device": record["device"],
                    "path": path["path"],
                    "relationships": path["relationships"]
                })

    return {
        "count": len(chains),
        "chains": chains
    }
