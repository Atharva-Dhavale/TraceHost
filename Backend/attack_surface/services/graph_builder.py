"""
Attack Surface Explorer — orchestration.
Enumerates subdomains for a root domain, resolves infrastructure (IP/ASN/
Country/SSL) per subdomain, builds a flat nodes/edges graph, persists it to
Neo4j, and returns the graph JSON for the frontend.

Reuses the existing data-collection helpers in checker/views.py rather than
duplicating them — this module only adds graph-shaping + a lightweight risk
heuristic on top.
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

from checker.views import enumerate_subdomains, get_dns_info, get_asn_info

from . import neo4j_service

logger = logging.getLogger(__name__)

MAX_SUBDOMAINS = 30
MAX_WORKERS = 10
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")

_SUSPICIOUS_KEYWORDS = ("login", "secure", "verify", "account", "admin", "wp-", "staging", "test")


def is_valid_domain(domain: str) -> bool:
    return bool(domain) and bool(DOMAIN_RE.match(domain.strip()))


def _get_ssl_certs(domain: str) -> list:
    """crt.sh certificate transparency lookup (root domain, covers subdomains
    via wildcard/SAN entries in name_value)."""
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
        return resp.json() if resp.status_code == 200 else []
    except Exception as exc:
        logger.warning("crt.sh lookup failed for %s: %s", domain, exc)
        return []


def _cert_for_subdomain(subdomain: str, certs: list) -> dict | None:
    for cert in certs:
        names = cert.get("name_value", "")
        if subdomain in names.split("\n"):
            return cert
    return None


def _is_cert_expired(cert: dict) -> bool:
    not_after = cert.get("not_after")
    if not not_after:
        return False
    try:
        expiry = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
        return expiry.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    except Exception:
        return False


def _compute_risk_score(subdomain: str, ip: str | None, cert: dict | None) -> int:
    """Lightweight heuristic — distinct from checker/risk_engine.py, which
    scores full domain analysis. This only estimates attack-surface exposure."""
    score = 10
    if not ip:
        score += 25
    if not cert:
        score += 30
    elif _is_cert_expired(cert):
        score += 20
    lowered = subdomain.lower()
    if any(kw in lowered for kw in _SUSPICIOUS_KEYWORDS):
        score += 15
    return min(score, 100)


def _resolve_subdomain(subdomain: str, certs: list) -> dict:
    dns_result = get_dns_info(subdomain)
    ip = dns_result[0] if isinstance(dns_result, list) and dns_result else None
    asn_info = get_asn_info(ip) if ip else {}
    cert = _cert_for_subdomain(subdomain, certs)
    risk_score = _compute_risk_score(subdomain, ip, cert)
    return {
        "subdomain": subdomain,
        "ip": ip,
        "asn_info": asn_info,
        "cert": cert,
        "risk_score": risk_score,
    }


def _normalize_subdomain(root_domain: str, subdomain: str) -> str | None:
    candidate = (subdomain or "").strip().lower().rstrip(".")
    if not candidate:
        return None
    if candidate.endswith(f".{root_domain}") or candidate == root_domain:
        return candidate
    return f"{candidate}.{root_domain}"


def _node(node_type: str, key: str, label: str, props: dict) -> dict:
    return {"id": f"{node_type}:{key}", "type": node_type, "key": key, "label": label, "data": props}


def _edge(source: dict, target: dict, relationship: str) -> dict:
    return {
        "id": f"{source['id']}__{relationship}__{target['id']}",
        "source": source["id"],
        "target": target["id"],
        "source_type": source["type"],
        "target_type": target["type"],
        "source_key": source["key"],
        "target_key": target["key"],
        "relationship": relationship,
    }


def build_graph(domain: str) -> dict:
    domain = domain.strip().lower()
    if not is_valid_domain(domain):
        return {"error": "Invalid domain"}

    logger.info("Building attack surface graph for %s", domain)

    raw_subdomains = enumerate_subdomains(domain) or []
    seen_subdomains = set()
    subdomains = []
    for subdomain in raw_subdomains:
        normalized = _normalize_subdomain(domain, subdomain)
        if not normalized or normalized in seen_subdomains:
            continue
        seen_subdomains.add(normalized)
        subdomains.append(normalized)
        if len(subdomains) >= MAX_SUBDOMAINS:
            break
    certs = _get_ssl_certs(domain)

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_resolve_subdomain, sub, certs): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                logger.warning("Failed to resolve %s: %s", futures[future], exc)

    nodes_by_id: dict = {}
    edges: list = []

    def add_node(node: dict) -> dict:
        nodes_by_id.setdefault(node["id"], node)
        return nodes_by_id[node["id"]]

    domain_node = add_node(_node("domain", domain, domain, {}))

    for result in results:
        sub = result["subdomain"]
        ip = result["ip"]
        asn_info = result["asn_info"]
        cert = result["cert"]

        sub_node = add_node(_node("subdomain", sub, sub, {"risk_score": result["risk_score"]}))
        edges.append(_edge(domain_node, sub_node, "HAS_SUBDOMAIN"))

        if ip:
            ip_node = add_node(_node("ip", ip, ip, {}))
            edges.append(_edge(sub_node, ip_node, "RESOLVES_TO"))

            asn_id = asn_info.get("asn") if asn_info else None
            if asn_id and asn_id != "Unknown":
                asn_node = add_node(_node("asn", asn_id, asn_id, {"name": asn_id}))
                edges.append(_edge(ip_node, asn_node, "BELONGS_TO"))

            country_code = asn_info.get("country_code") if asn_info else None
            country_name = asn_info.get("country") if asn_info else None
            if country_code:
                country_node = add_node(
                    _node("country", country_code, country_name or country_code, {"name": country_name})
                )
                edges.append(_edge(ip_node, country_node, "LOCATED_IN"))

        if cert:
            serial = cert.get("serial_number") or cert.get("id")
            if serial:
                ssl_node = add_node(_node("ssl", str(serial), cert.get("issuer_name", "SSL Cert"), {
                    "issuer": cert.get("issuer_name"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                    "expired": _is_cert_expired(cert),
                }))
                edges.append(_edge(sub_node, ssl_node, "USES_SSL"))

    nodes = list(nodes_by_id.values())
    neo4j_nodes = [{"type": n["type"], "key": n["key"], "props": {"label": n["label"], **n["data"]}} for n in nodes]
    persisted = neo4j_service.write_graph(neo4j_nodes, edges)

    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "subdomain_count": len(results),
        "neo4j_persisted": persisted,
        "nodes": nodes,
        "edges": edges,
    }
