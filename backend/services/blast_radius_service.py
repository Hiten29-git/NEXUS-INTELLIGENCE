from backend.services.graph_service import driver


def _node_id(node):
    """
    Return a stable display identifier regardless of
    whether the Neo4j node uses id or name.
    """
    if node is None:
        return None

    props = dict(node)

    return (
        props.get("id")
        or props.get("name")
        or props.get("hostname")
        or str(props)
    )


def calculate_blast_radius(start_node: str, max_hops: int = 3):
    """
    Read-only What-If Blast Radius analysis.

    Uses the existing NEXUS Neo4j security graph to calculate
    graph reachability.

    No attack, network action, endpoint modification,
    or containment action is performed.
    """

    if driver is None:
        return {
            "available": False,
            "error": "Neo4j driver unavailable"
        }

    if not start_node:
        return {
            "available": False,
            "error": "start_node is required"
        }

    try:
        max_hops = max(1, min(int(max_hops), 5))
    except (TypeError, ValueError):
        max_hops = 3

    query = f"""
    MATCH (start)
    WHERE
        start.id = $start_node
        OR start.name = $start_node
        OR start.hostname = $start_node

    OPTIONAL MATCH path =
        (start)-[*1..{max_hops}]-(target)

    WITH
        start,
        collect(DISTINCT target) AS targets,
        collect(path) AS all_paths

    RETURN
        properties(start) AS start_properties,
        labels(start) AS start_labels,
        targets,
        all_paths
    """

    try:
        with driver.session() as session:

            record = session.run(
                query,
                start_node=start_node
            ).single()

            if not record:
                return {
                    "available": True,
                    "found": False,
                    "mode": "WHAT_IF_SIMULATION",
                    "start_node": start_node,
                    "blast_radius": 0,
                    "reachable_nodes": [],
                    "critical_assets": [],
                    "critical_asset_count": 0,
                    "paths": [],
                    "path_count": 0,
                    "evidence_status": "NO_START_NODE"
                }

            start_properties = record["start_properties"] or {}
            start_labels = record["start_labels"] or []

            targets = record["targets"] or []
            raw_paths = record["all_paths"] or []

            # -----------------------------------------
            # Build reachable node list
            # -----------------------------------------

            reachable_nodes = []
            seen_nodes = set()

            for node in targets:

                if node is None:
                    continue

                node_identifier = _node_id(node)
                node_labels = list(node.labels)
                node_properties = dict(node)

                # Don't count the starting node.
                if (
                    node_identifier == start_node
                    or (
                        node_properties.get("id")
                        == start_properties.get("id")
                        and node_properties.get("id") is not None
                    )
                ):
                    continue

                key = (
                    tuple(sorted(node_labels)),
                    node_identifier
                )

                if key in seen_nodes:
                    continue

                seen_nodes.add(key)

                reachable_nodes.append({
                    "id": node_identifier,
                    "labels": node_labels,
                    "properties": node_properties
                })

            # -----------------------------------------
            # Build readable paths
            # -----------------------------------------

            paths = []
            seen_paths = set()

            for path in raw_paths:

                if path is None:
                    continue

                path_nodes = []

                for node in path.nodes:

                    identifier = _node_id(node)

                    if identifier is None:
                        continue

                    path_nodes.append(identifier)

                if len(path_nodes) < 2:
                    continue

                path_tuple = tuple(path_nodes)

                if path_tuple in seen_paths:
                    continue

                seen_paths.add(path_tuple)

                paths.append(path_nodes)

            # -----------------------------------------
            # Critical asset identification
            # -----------------------------------------

            critical_types = {
                "Server",
                "Database",
                "CriticalAsset"
            }

            critical_assets = []

            for node in reachable_nodes:

                labels = node.get("labels", [])

                if any(
                    label in critical_types
                    for label in labels
                ):
                    critical_assets.append(node)

            return {
                "available": True,
                "found": True,

                "mode": "WHAT_IF_SIMULATION",

                "start_node": start_node,
                "start_labels": start_labels,

                "blast_radius": len(reachable_nodes),

                "reachable_nodes": reachable_nodes,

                "critical_assets": critical_assets,

                "critical_asset_count":
                    len(critical_assets),

                "paths": paths,

                "path_count": len(paths),

                "evidence_status":
                    "OBSERVED_GRAPH_RELATIONSHIPS",

                "interpretation":
                    "Blast radius represents graph "
                    "reachability from the selected "
                    "entity using observed relationships. "
                    "It does not confirm compromise and "
                    "does not perform an attack.",

                "safety": {
                    "read_only": True,
                    "network_action": False,
                    "endpoint_action": False,
                    "automatic_containment": False
                }
            }

    except Exception as exc:

        return {
            "available": False,
            "error": str(exc)
        }
