"""
Attack Surface Explorer — Neo4j persistence.
Infrastructure relationships (Domain/Subdomain/IP/ASN/Country/SSL) are written
here using MERGE so repeated scans never create duplicate nodes/edges.
"""

import logging
from decouple import config
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError, ServiceUnavailable

logger = logging.getLogger(__name__)

NEO4J_URI = config("NEO4J_URI", default="")
NEO4J_USER = config("NEO4J_USER", default="")
NEO4J_PASSWORD = config("NEO4J_PASSWORD", default="")

_driver = None


def get_driver():
    """Return the Neo4j driver, creating the connection on first call."""
    global _driver
    if _driver is not None:
        return _driver
    if not NEO4J_URI:
        raise RuntimeError("NEO4J_URI is not configured")
    try:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        _driver.verify_connectivity()
        logger.info("Neo4j connected — %s", NEO4J_URI)
    except (ServiceUnavailable, Neo4jError) as exc:
        _driver = None
        logger.error("Neo4j connection failed: %s", exc)
        raise
    return _driver


# ── MERGE Cypher per node/relationship type ─────────────────────────────────

_MERGE_STATEMENTS = {
    "domain":    "MERGE (n:Domain {name: $key})",
    "subdomain": "MERGE (n:Subdomain {name: $key})",
    "ip":        "MERGE (n:IP {address: $key})",
    "asn":       "MERGE (n:ASN {asn: $key})",
    "country":   "MERGE (n:Country {code: $key})",
    "ssl":       "MERGE (n:SSL {serial: $key})",
}

_EDGE_LABELS = {
    "HAS_SUBDOMAIN", "RESOLVES_TO", "BELONGS_TO", "LOCATED_IN", "USES_SSL",
}


def _write_graph_tx(tx, nodes: list, edges: list):
    for node in nodes:
        node_type = node["type"]
        stmt = _MERGE_STATEMENTS.get(node_type)
        if not stmt:
            continue
        tx.run(f"{stmt} SET n += $props", key=node["key"], props=node.get("props", {}))

    for edge in edges:
        rel = edge["relationship"]
        if rel not in _EDGE_LABELS:
            continue
        source_type = edge["source_type"]
        target_type = edge["target_type"]
        source_match = _MERGE_STATEMENTS[source_type].replace("MERGE (n:", "MATCH (a:")
        target_match = _MERGE_STATEMENTS[target_type].replace("MERGE (n:", "MATCH (b:")
        query = (
            f"{source_match.replace('$key', '$source_key')} "
            f"{target_match.replace('$key', '$target_key')} "
            f"MERGE (a)-[:{rel}]->(b)"
        )
        tx.run(query, source_key=edge["source_key"], target_key=edge["target_key"])


def write_graph(nodes: list, edges: list) -> bool:
    """Persist nodes/edges into Neo4j. Best-effort — returns False on failure
    instead of raising, so a Neo4j outage never breaks the scan response."""
    try:
        driver = get_driver()
        with driver.session() as session:
            session.execute_write(_write_graph_tx, nodes, edges)
        logger.info("Neo4j graph written: %d nodes, %d edges", len(nodes), len(edges))
        return True
    except Exception as exc:
        logger.error("Neo4j write_graph failed: %s", exc)
        return False
