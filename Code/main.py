# +-----------------------------------------------------------+
# | main.py                                                   |
# +-----------------------------------------------------------+
# | Purpose:                                                  |
# |  - Program entry point                                    |
# |  - Load config/args                                       |
# |  - Orchestrate Recon -> Decision -> Tests -> Reporting     |
# |                                                           |
# | Responsibilities:                                         |
# |  - Parse CLI arguments / config profile                   |
# |  - Call reconnaissance to discover services               |
# |  - Call decision engine to select tests                   |
# |  - Execute tests and collect findings                     |
# |  - Trigger reporting + export                             |
# |                                                           |
# | Key Components:                                           |
# |  + main() -> int                                          |
# |  + parse_args() -> ScanConfig                             |
# |  + run_pipeline(cfg: ScanConfig) -> ReportBundle          |
# |                                                           |
# | Inputs:                                                   |
# |  - target(s): host/IP/range                               |
# |  - scan profile / port ranges / timeouts                  |
# |                                                           |
# | Outputs:                                                  |
# |  - terminal output                                        |
# |  - exported JSON/CSV/PDF (optional)                       |
# +-----------------------------------------------------------+

# main.py

import asyncio
from typing import List, Dict, Any

from reconnaissance import recon_services


# ---------------------------
# Data Types (minimal)
# ---------------------------

class ScanConfig:
    def __init__(self, targets: List[str], profile: str = "default", ports: str = "1-2000"):
        self.targets = targets
        self.profile = profile
        self.ports = ports


class ReportBundle:
    def __init__(self, inventory, selected_tests, findings):
        self.inventory = inventory
        self.selected_tests = selected_tests
        self.findings = findings


# ---------------------------
# CLI Parsing
# ---------------------------

def parse_args() -> ScanConfig:
    """
    Parse command line arguments.
    Return ScanConfig object.
    """
    # Placeholder logic (edit later)
    targets = ["45.33.32.156"]
    ports = "1-2000"
    return ScanConfig(targets, ports=ports)


# ---------------------------
# Pipeline Steps
# ---------------------------

def run_recon(cfg: ScanConfig) -> Dict[str, Any]:
    """
    Discover services on targets using reconnaissance.py
    """
    services = asyncio.run(recon_services(cfg.targets, ports=cfg.ports))

    # Convert Service objects to simple dicts for the rest of the pipeline
    services_out = []
    for s in services:
        services_out.append({
            "host": s.host,
            "port": s.port,
            "protocol": s.protocol,
            "name": s.name,
            "version": s.version,
            "banner": s.banner,
            "http_status": getattr(s, "http_status", None),
            "http_server": getattr(s, "http_server", None),
            "tls_version": getattr(s, "tls_version", None),
            "tls_cipher": getattr(s, "tls_cipher", None),
            "tls_cert_subject": getattr(s, "tls_cert_subject", None),
            "tls_cert_issuer": getattr(s, "tls_cert_issuer", None),
            "tls_cert_sans": getattr(s, "tls_cert_sans", None),
        })

    return {
        "targets": cfg.targets,
        "services": services_out
    }


def run_decision_engine(inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Select which tests to run based on recon results.
    """
    return []


def run_tests(selected_tests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Execute selected tests.
    """
    return []


def export_report(bundle: ReportBundle) -> None:
    """
    Output results (console / file).
    """
    print("Report complete")

    # Quick view for now
    for svc in bundle.inventory.get("services", []):
        print(svc["host"], svc["port"], svc.get("name"), svc.get("version"))


# ---------------------------
# Orchestration
# ---------------------------

def run_pipeline(cfg: ScanConfig) -> ReportBundle:
    inventory = run_recon(cfg)
    selected_tests = run_decision_engine(inventory)
    findings = run_tests(selected_tests)

    bundle = ReportBundle(inventory, selected_tests, findings)
    export_report(bundle)

    return bundle


def main() -> int:
    cfg = parse_args()
    run_pipeline(cfg)
    return 0


if __name__ == "__main__":
    main()

