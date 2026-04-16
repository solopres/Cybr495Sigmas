# +-----------------------------------------------------------+
# | decisionengine.py                                         |
# +-----------------------------------------------------------+
# | Purpose:                                                  |
# |  - Translate recon results into a test plan               |
# |  - Choose relevant tests and prioritize execution         |
# |                                                           |
# | Responsibilities:                                         |
# |  - Service -> applicable test mapping                     |
# |  - Compatibility checks (skip irrelevant modules)         |
# |  - Prioritization/risk ordering (optional)                |
# |                                                           |
# | Key Data Models:                                          |
# |  + TestPlan                                                |
# |     - service: Service                                    |
# |     - tests: list[TestModule]                             |
# |                                                           |
# |  + RiskScore (optional)                                   |
# |     - severity: str                                       |
# |     - confidence: float                                   |
# |                                                           |
# | Key Components:                                           |
# |  + DecisionEngine                                         |
# |     + build_plan(services: list[Service]) -> list[TestPlan] |
# |     + prioritize(plans: list[TestPlan]) -> list[TestPlan] |
# |                                                           |
# | Inputs:                                                   |
# |  - list[Service] from reconnaissance                       |
# |                                                           |
# | Outputs:                                                  |
# |  - list[TestPlan] (what tests to run on what service)     |
# +-----------------------------------------------------------+



# decisionengine.py

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

from reconnaissance import ReconResult, Service


@dataclass
class AttackRecommendation:
    host: str
    port: int
    service_name: str
    module: str
    priority: float
    rationale: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)


@dataclass
class HostPlan:
    host: str
    host_risk: float
    recommendations: List[AttackRecommendation] = field(default_factory=list)


# Map service families to allowed test modules
SERVICE_TEST_MAP: Dict[str, List[str]] = {
    "http": [
        "http_security_headers_check",
        "http_auth_surface_check",
        "http_admin_panel_discovery",
        "http_content_discovery",
        "http_method_check",
    ],
    "http-alt": [
        "http_security_headers_check",
        "http_auth_surface_check",
        "http_admin_panel_discovery",
        "http_content_discovery",
        "http_method_check",
    ],
    "https": [
        "tls_configuration_check",
        "https_security_headers_check",
        "https_auth_surface_check",
        "https_admin_panel_discovery",
        "https_content_discovery",
    ],
    "https-alt": [
        "tls_configuration_check",
        "https_security_headers_check",
        "https_auth_surface_check",
        "https_admin_panel_discovery",
        "https_content_discovery",
    ],
    "ssh": [
        "ssh_banner_review",
        "ssh_auth_policy_check",
        "ssh_version_review",
    ],
    "ftp": [
        "ftp_anonymous_access_check",
        "ftp_plaintext_risk_check",
        "ftp_version_review",
    ],
    "telnet": [
        "telnet_plaintext_risk_check",
        "telnet_auth_exposure_check",
    ],
    "smtp": [
        "smtp_open_relay_check",
        "smtp_banner_review",
        "smtp_user_enum_check",
    ],
    "imap": [
        "imap_plaintext_risk_check",
        "imap_auth_surface_check",
    ],
    "pop3": [
        "pop3_plaintext_risk_check",
        "pop3_auth_surface_check",
    ],
    "smb": [
        "smb_null_session_check",
        "smb_share_enum_check",
        "smb_config_review",
    ],
    "netbios-ssn": [
        "netbios_enum_check",
        "smb_null_session_check",
    ],
    "msrpc": [
        "rpc_enum_check",
        "rpc_exposure_review",
    ],
    "mysql": [
        "mysql_auth_exposure_check",
        "mysql_version_review",
    ],
    "postgres": [
        "postgres_auth_exposure_check",
        "postgres_version_review",
    ],
    "redis": [
        "redis_unauth_access_check",
        "redis_config_review",
    ],
    "rdp": [
        "rdp_exposure_review",
        "rdp_auth_policy_check",
    ],
    "vnc": [
        "vnc_auth_exposure_check",
        "vnc_version_review",
    ],
    "nfs": [
        "nfs_export_enum_check",
        "nfs_authz_review",
    ],
    "rpcbind": [
        "rpcbind_service_enum_check",
    ],
    "ajp13": [
        "ajp_exposure_check",
    ],
}


RISKY_PORT_BONUS = {
    23: 2.5,
    21: 1.5,
    445: 2.0,
    139: 1.5,
    3389: 2.0,
    5900: 2.0,
    2049: 1.5,
    111: 1.5,
    3632: 2.5,
    8009: 2.0,
    6379: 2.0,
}


def normalize_service_name(service: Service) -> str:
    if service.name:
        return service.name.lower()

    # fallback guesses based on port
    fallback = {
        80: "http",
        443: "https",
        8080: "http-alt",
        8180: "http-alt",
        8443: "https-alt",
        22: "ssh",
        21: "ftp",
        23: "telnet",
        25: "smtp",
        445: "smb",
        139: "netbios-ssn",
        135: "msrpc",
        3306: "mysql",
        5432: "postgres",
        6379: "redis",
        3389: "rdp",
        5900: "vnc",
        2049: "nfs",
        111: "rpcbind",
        8009: "ajp13",
    }
    return fallback.get(service.port, "unknown")


def score_attack_priority(service: Service, module: str, host_risk: float) -> Tuple[float, List[str]]:
    reasons: List[str] = []
    priority = 0.0

    service_risk = service.risk_score or 0.0
    priority += service_risk
    reasons.append(f"Service recon risk score: {service_risk:.1f}")

    priority += host_risk * 0.35
    reasons.append(f"Host recon risk contribution: {host_risk:.1f} x 0.35")

    if service.port in RISKY_PORT_BONUS:
        bonus = RISKY_PORT_BONUS[service.port]
        priority += bonus
        reasons.append(f"Risky exposed port {service.port} (+{bonus:.1f})")

    if service.banner:
        priority += 0.5
        reasons.append("Banner present, gives fingerprinting value (+0.5)")

    if service.version:
        priority += 0.75
        reasons.append("Version identified, targeted review is more useful (+0.75)")

    if module == "tls_configuration_check":
        if service.tls_version in {"TLSv1", "TLSv1.1"}:
            priority += 2.0
            reasons.append(f"Legacy TLS version seen: {service.tls_version} (+2.0)")
        elif service.tls_version is None:
            priority += 0.5
            reasons.append("TLS service with incomplete TLS details (+0.5)")

    if "admin_panel" in module:
        title = (service.http_title or service.https_title or "").lower()
        server = (service.http_server or service.https_server or "").lower()
        if any(x in title for x in ["admin", "login", "panel", "dashboard"]):
            priority += 1.5
            reasons.append("Page title suggests admin/auth surface (+1.5)")
        if any(x in server for x in ["apache", "nginx", "tomcat"]):
            priority += 0.5
            reasons.append("Common web stack identified (+0.5)")

    if "auth" in module:
        priority += 0.75
        reasons.append("Authentication surface is usually high value (+0.75)")

    if "anonymous" in module or "unauth" in module or "null_session" in module:
        priority += 1.25
        reasons.append("Possible unauthenticated access path (+1.25)")

    return round(priority, 2), reasons


def build_service_recommendations(service: Service, host_risk: float) -> List[AttackRecommendation]:
    service_name = normalize_service_name(service)
    modules = SERVICE_TEST_MAP.get(service_name, [])

    recs: List[AttackRecommendation] = []

    for module in modules:
        priority, rationale = score_attack_priority(service, module, host_risk)
        recs.append(
            AttackRecommendation(
                host=service.host,
                port=service.port,
                service_name=service_name,
                module=module,
                priority=priority,
                rationale=rationale,
                prerequisites=[],
            )
        )

    return recs


def build_attack_plan(recon: ReconResult, min_priority: float = 3.0) -> List[HostPlan]:
    plans_by_host: Dict[str, HostPlan] = {}

    for service in recon.services:
        host_risk = recon.host_risk_score.get(service.host, 0.0)

        if service.host not in plans_by_host:
            plans_by_host[service.host] = HostPlan(
                host=service.host,
                host_risk=host_risk,
                recommendations=[],
            )

        recs = build_service_recommendations(service, host_risk)
        plans_by_host[service.host].recommendations.extend(recs)

    # Filter and sort
    for host, plan in plans_by_host.items():
        deduped: Dict[Tuple[str, int, str], AttackRecommendation] = {}

        for rec in plan.recommendations:
            key = (rec.host, rec.port, rec.module)
            if key not in deduped or rec.priority > deduped[key].priority:
                deduped[key] = rec

        filtered = [r for r in deduped.values() if r.priority >= min_priority]
        filtered.sort(key=lambda r: r.priority, reverse=True)
        plan.recommendations = filtered

    # Return hosts sorted by host risk
    return sorted(plans_by_host.values(), key=lambda p: p.host_risk, reverse=True)