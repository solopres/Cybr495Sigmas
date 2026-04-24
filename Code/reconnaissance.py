# reconnaissance.py
from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
import socket
from dataclasses import dataclass
from html import unescape
from typing import Dict, List, Optional, Union, Tuple, Any


# ---------------------------
# Data Models
# ---------------------------

@dataclass
class Host:
    address: str
    is_alive: bool = False


@dataclass
class Service:
    host: str
    port: int
    protocol: str = "tcp"
    name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

    # Extra fingerprint fields
    http_server: Optional[str] = None
    http_status: Optional[int] = None
    http_title: Optional[str] = None

    https_server: Optional[str] = None
    https_status: Optional[int] = None
    https_title: Optional[str] = None

    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_cert_subject: Optional[str] = None
    tls_cert_issuer: Optional[str] = None
    tls_cert_sans: Optional[List[str]] = None

    # Risk scoring (0-10)
    risk_score: Optional[float] = None
    risk_reasons: Optional[List[str]] = None


@dataclass
class TargetInfo:
    target: str                      # what user typed (ip/hostname/CIDR element)
    resolved_ips: List[str]          # hostname->IPs, or [ip]
    reverse_dns: Optional[str] = None
    is_private_or_loopback: Optional[bool] = None

    # lightweight web intel (best-effort)
    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_title: Optional[str] = None
    https_status: Optional[int] = None
    https_server: Optional[str] = None
    https_title: Optional[str] = None


@dataclass
class ReconResult:
    targets: List[str]
    target_info: List[TargetInfo]
    services: List[Service]
    host_risk_score: Dict[str, float]
    host_risk_reasons: Dict[str, List[str]]


# ---------------------------
# Config / Defaults
# ---------------------------

COMMON_PORT_GUESSES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    512: "exec",
    513: "login",
    514: "shell",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1099: "rmiregistry",
    1524: "ingreslock",   # common in metasploitable labs
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    3632: "distccd",
    5432: "postgres",
    5900: "vnc",
    6000: "x11",
    6379: "redis",
    6667: "irc",
    8009: "ajp13",
    8080: "http-alt",
    8180: "http-alt",
    8443: "https-alt",
}

TLS_PORTS = {443, 8443, 993, 995, 465, 636, 990}


def _is_private_or_loopback(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def _expand_targets(target: Union[str, List[str]]) -> List[str]:
    if isinstance(target, str):
        target_list = [target]
    else:
        target_list = list(target)

    expanded: List[str] = []
    for t in target_list:
        t = t.strip()
        if not t:
            continue
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            expanded.extend([str(ip) for ip in net.hosts()])
        else:
            expanded.append(t)
    return expanded


def _parse_ports(ports: Union[str, List[int]]) -> List[int]:
    if isinstance(ports, list):
        return sorted(set(int(p) for p in ports))

    s = ports.strip()
    out: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a_i, b_i = int(a), int(b)
            lo, hi = min(a_i, b_i), max(a_i, b_i)
            out.extend(range(lo, hi + 1))
        else:
            out.append(int(part))
    return sorted(set(out))


# ---------------------------
# Target Enrichment (DNS / Web titles)
# ---------------------------

def _extract_html_title(html: str) -> Optional[str]:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    if not m:
        return None
    title = unescape(m.group(1)).strip()
    title = re.sub(r"\s+", " ", title)
    return title[:200] if title else None


async def _resolve_target_to_ips(target: str) -> List[str]:
    # If it's an IP already, return it.
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass

    def _blocking_resolve() -> List[str]:
        ips: List[str] = []
        try:
            infos = socket.getaddrinfo(target, None)
            for fam, _, _, _, sockaddr in infos:
                if fam in (socket.AF_INET, socket.AF_INET6):
                    ip = sockaddr[0]
                    ips.append(ip)
        except Exception:
            return []
        # de-dupe preserve order
        seen = set()
        out: List[str] = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        return out

    return await asyncio.to_thread(_blocking_resolve)


async def _reverse_dns(ip: str) -> Optional[str]:
    def _blocking_ptr() -> Optional[str]:
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return name
        except Exception:
            return None

    return await asyncio.to_thread(_blocking_ptr)


async def _probe_http_like(
    host: str,
    port: int,
    timeout: float,
    use_tls: bool,
    grab_title: bool = True,
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    HTTP/HTTPS probe:
    - HEAD / to get status + Server
    - optional GET / to extract <title>
    Returns (status, server_header, title)
    """
    ctx = None
    server_hostname = None
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        server_hostname = host  # ok for hostname; for IP still works often

    async def _send(req_bytes: bytes) -> str:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=server_hostname),
            timeout=timeout,
        )
        try:
            writer.write(req_bytes)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(16384), timeout=timeout)
            return raw.decode(errors="replace")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    head_req = (
        "HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: recon/1.0\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    text = await _send(head_req)

    m = re.search(r"HTTP/\d\.\d\s+(\d+)", text)
    status = int(m.group(1)) if m else None

    m2 = re.search(r"(?im)^Server:\s*(.+)$", text)
    server = m2.group(1).strip() if m2 else None

    title: Optional[str] = None
    if grab_title:
        get_req = (
            "GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: recon/1.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        body = await _send(get_req)
        title = _extract_html_title(body)

    return status, server, title


async def gather_target_info(
    targets: Union[str, List[str]],
    timeout: float = 1.5,
    concurrency: int = 100,
) -> List[TargetInfo]:
    expanded = _expand_targets(targets)
    sem = asyncio.Semaphore(concurrency)

    async def one(t: str) -> TargetInfo:
        async with sem:
            ips = await _resolve_target_to_ips(t)
            info = TargetInfo(
                target=t,
                resolved_ips=ips,
                is_private_or_loopback=_is_private_or_loopback(ips[0]) if ips else None,
            )
            # Reverse DNS only if we have at least one IP
            if ips:
                info.reverse_dns = await _reverse_dns(ips[0])

            # Best-effort HTTP/HTTPS intel against first resolved IP (or hostname if no IP)
            probe_host = ips[0] if ips else t
            try:
                st, sv, title = await _probe_http_like(probe_host, 80, timeout, use_tls=False, grab_title=True)
                info.http_status, info.http_server, info.http_title = st, sv, title
            except Exception:
                pass

            try:
                st, sv, title = await _probe_http_like(probe_host, 443, timeout, use_tls=True, grab_title=True)
                info.https_status, info.https_server, info.https_title = st, sv, title
            except Exception:
                pass

            return info

    tasks = [asyncio.create_task(one(t)) for t in expanded]
    return await asyncio.gather(*tasks)


# ---------------------------
# Host Discovery
# ---------------------------

async def _tcp_ping(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def discover_hosts(
    target: Union[str, List[str]],
    timeout: float = 1.0,
    concurrency: int = 200,
    allow_non_private: bool = True,
) -> List[Host]:
    candidates = _expand_targets(target)

    if not allow_non_private:
        candidates = [h for h in candidates if _is_private_or_loopback(h)]

    probe_ports = [22, 80, 443, 445, 21, 25, 3389]
    sem = asyncio.Semaphore(concurrency)

    async def probe(addr: str) -> Host:
        async with sem:
            for p in probe_ports:
                if await _tcp_ping(addr, p, timeout):
                    return Host(addr, True)
            return Host(addr, False)

    tasks = [asyncio.create_task(probe(h)) for h in candidates]
    hosts = await asyncio.gather(*tasks)
    return hosts


# ---------------------------
# Port Scanning (TCP connect scan)
# ---------------------------

async def _check_port_open(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def scan_ports(
    host: Host,
    ports: Union[str, List[int]],
    timeout: float = 1.0,
    concurrency: int = 500,
) -> List[Service]:
    port_list = _parse_ports(ports)
    sem = asyncio.Semaphore(concurrency)

    async def one(port: int) -> Optional[Service]:
        async with sem:
            if await _check_port_open(host.address, port, timeout):
                guess = COMMON_PORT_GUESSES.get(port)
                return Service(host=host.address, port=port, protocol="tcp", name=guess)
            return None

    tasks = [asyncio.create_task(one(p)) for p in port_list]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


# ---------------------------
# Service Detection / Fingerprinting
# ---------------------------

async def _read_banner_plain(host: str, port: int, timeout: float, max_bytes: int = 2048) -> str:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    try:
        data = await asyncio.wait_for(reader.read(max_bytes), timeout=timeout)
        return data.decode(errors="replace").strip()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _extract_version_from_banner(name: Optional[str], banner: Optional[str]) -> Optional[str]:
    if not banner:
        return None

    patterns = [
        (r"OpenSSH[_/ -]([\w\.p]+)", "OpenSSH"),
        (r"vsftpd\s+([\w\.]+)", "vsftpd"),
        (r"ProFTPD\s+([\w\.]+)", "ProFTPD"),
        (r"Apache/?\s*([\w\.]+)", "Apache"),
        (r"nginx/?\s*([\w\.]+)", "nginx"),
        (r"Postfix", "Postfix"),
        (r"Exim\s+([\w\.]+)", "Exim"),
        (r"MySQL\s+([\w\.]+)", "MySQL"),
        (r"Redis\s+([\w\.]+)", "Redis"),
        (r"VNC\s+([\w\.]+)", "VNC"),
    ]
    for pat, label in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            if m.groups():
                return f"{label} {m.group(1)}"
            return label
    return None


async def _probe_tls(host: str, port: int, timeout: float) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
        timeout=timeout,
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        info: Dict[str, Any] = {}

        if sslobj:
            info["tls_version"] = sslobj.version()
            c = sslobj.cipher()
            info["tls_cipher"] = c[0] if c else None

            cert = sslobj.getpeercert()
            if cert:
                subj = cert.get("subject", ())
                iss = cert.get("issuer", ())
                info["tls_cert_subject"] = " / ".join("=".join(x) for r in subj for x in r) if subj else None
                info["tls_cert_issuer"] = " / ".join("=".join(x) for r in iss for x in r) if iss else None
                sans = cert.get("subjectAltName", ())
                info["tls_cert_sans"] = [v for (t, v) in sans if t.lower() == "dns"] if sans else None

        return info
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def detect_service(service: Service, timeout: float = 1.5) -> Service:
    host, port = service.host, service.port

    # TLS details
    if port in TLS_PORTS or (service.name and service.name.lower() in {"https", "https-alt", "ldaps", "imaps", "pop3s", "smtps"}):
        try:
            tls = await _probe_tls(host, port, timeout)
            service.tls_version = tls.get("tls_version")
            service.tls_cipher = tls.get("tls_cipher")
            service.tls_cert_subject = tls.get("tls_cert_subject")
            service.tls_cert_issuer = tls.get("tls_cert_issuer")
            service.tls_cert_sans = tls.get("tls_cert_sans")
        except Exception:
            pass

    # HTTP / HTTPS probes + title
    if port in (80, 8080, 8180, 8000, 8888) or (service.name and service.name.lower() in {"http", "http-alt"}):
        try:
            status, server, title = await _probe_http_like(host, port, timeout, use_tls=False, grab_title=True)
            service.http_status = status
            service.http_server = server
            service.http_title = title
            service.banner = None  # avoid storing large headers; keep server/title/status
            if server and not service.version:
                service.version = server
            if not service.name:
                service.name = "http"
        except Exception:
            pass
        return service

    if port in (443, 8443) or (service.name and service.name.lower() in {"https", "https-alt"}):
        try:
            status, server, title = await _probe_http_like(host, port, timeout, use_tls=True, grab_title=True)
            service.https_status = status
            service.https_server = server
            service.https_title = title
            if server and not service.version:
                service.version = server
            if not service.name:
                service.name = "https"
        except Exception:
            pass
        return service

    # Plain banners
    try:
        banner = await _read_banner_plain(host, port, timeout)
        if banner:
            service.banner = banner
            if not service.name:
                low = banner.lower()
                if "ssh" in low:
                    service.name = "ssh"
                elif "ftp" in low:
                    service.name = "ftp"
                elif "smtp" in low:
                    service.name = "smtp"
                elif "imap" in low:
                    service.name = "imap"
                elif "pop" in low:
                    service.name = "pop3"
            service.version = _extract_version_from_banner(service.name, banner) or service.version
    except Exception:
        pass

    return service


# ---------------------------
# Risk scoring (0–10, heuristic)
# ---------------------------

_RISKY_PORT_WEIGHTS: Dict[int, float] = {
    23: 3.0,    # telnet
    21: 2.0,    # ftp
    445: 3.0,   # smb
    139: 2.5,   # netbios
    3389: 3.0,  # rdp
    5900: 3.0,  # vnc
    2049: 2.5,  # nfs
    111: 2.0,   # rpcbind
    512: 4.0,   # exec
    513: 4.0,   # login
    514: 4.0,   # shell
    3632: 4.0,  # distccd
    8009: 3.0,  # ajp
    3306: 2.0,  # mysql
    5432: 2.0,  # postgres
    6379: 3.0,  # redis (often exposed w/out auth in labs/misconfigs)
    6000: 3.0,  # x11
}

_PLAINTEXT_SERVICE_NAMES = {"telnet", "ftp", "http", "pop3", "imap", "smtp"}
_ADMIN_LIKE_PORTS = {8080, 8443, 8000, 8888}


def score_service_risk(svc: Service) -> Tuple[float, List[str]]:
    """
    Heuristic triage score (NOT a confirmed vulnerability score).
    Produces a 0–10 score plus reasons.
    """
    score = 0.0
    reasons: List[str] = []

    # Any exposed service adds baseline surface area
    score += 1.0
    reasons.append("Exposed service increases attack surface (+1.0)")

    # Risky ports
    if svc.port in _RISKY_PORT_WEIGHTS:
        w = _RISKY_PORT_WEIGHTS[svc.port]
        score += w
        reasons.append(f"High-risk port {svc.port} (+{w:.1f})")

    # Service name based heuristics
    if svc.name and svc.name.lower() in _PLAINTEXT_SERVICE_NAMES:
        score += 1.5
        reasons.append(f"Likely plaintext protocol ({svc.name}) (+1.5)")

    if svc.port in _ADMIN_LIKE_PORTS:
        score += 1.0
        reasons.append(f"Common admin/alt web port {svc.port} (+1.0)")

    # Banner/version disclosure (helps attackers target CVEs)
    if svc.banner:
        score += 0.5
        reasons.append("Banner present (version disclosure) (+0.5)")
    if svc.http_server or svc.https_server:
        score += 0.5
        reasons.append("Server header present (version disclosure) (+0.5)")
    if svc.version and re.search(r"\d+\.\d+", svc.version):
        score += 0.5
        reasons.append("Version string detected (+0.5)")

    # TLS weakness heuristics (only based on negotiated version, not full cipher audit)
    if svc.port in TLS_PORTS or (svc.name and "https" in svc.name.lower()):
        if svc.tls_version in {"TLSv1", "TLSv1.1"}:
            score += 2.0
            reasons.append(f"Weak/legacy TLS negotiated ({svc.tls_version}) (+2.0)")
        elif svc.tls_version is None:
            score += 0.5
            reasons.append("TLS port but no TLS details captured (+0.5)")

    # Cap and normalize
    score = max(0.0, min(10.0, score))
    return score, reasons


def score_hosts(services: List[Service]) -> Tuple[Dict[str, float], Dict[str, List[str]]]:
    """
    Aggregate host risk from service scores.
    Strategy: host score = min(10, max(service scores) + small bump for many services)
    """
    by_host: Dict[str, List[Service]] = {}
    for s in services:
        by_host.setdefault(s.host, []).append(s)

    host_scores: Dict[str, float] = {}
    host_reasons: Dict[str, List[str]] = {}

    for host, svcs in by_host.items():
        if not svcs:
            host_scores[host] = 0.0
            host_reasons[host] = ["No services discovered"]
            continue

        max_svc = max((s.risk_score or 0.0) for s in svcs)
        count = len(svcs)
        bump = 0.0
        if count >= 10:
            bump = 1.5
        elif count >= 5:
            bump = 1.0
        elif count >= 3:
            bump = 0.5

        score = min(10.0, max_svc + bump)

        reasons = [f"Max service risk on host: {max_svc:.1f}"]
        if bump > 0:
            reasons.append(f"Multiple exposed services ({count}) (+{bump:.1f})")

        host_scores[host] = score
        host_reasons[host] = reasons

    return host_scores, host_reasons


# ---------------------------
# High-level convenience
# ---------------------------

async def recon_services(
    targets: Union[str, List[str]],
    ports: Union[str, List[int]] = "1-1024",
    timeout: float = 1.0,
    scan_concurrency: int = 500,
    detect_concurrency: int = 200,
    allow_non_private: bool = True,
    enrich: bool = True,
    score_risk: bool = True,
) -> ReconResult:
    """
    Full recon:
    - (optional) target enrichment
    - discover hosts
    - scan ports
    - fingerprint discovered services
    - (optional) risk scoring (0-10) per service and per host
    """
    expanded_targets = _expand_targets(targets)

    target_info: List[TargetInfo] = []
    if enrich:
        try:
            target_info = await gather_target_info(expanded_targets, timeout=max(1.0, timeout))
        except Exception:
            target_info = []

    hosts = await discover_hosts(expanded_targets, timeout=timeout, allow_non_private=allow_non_private)
    live = [h for h in hosts if h.is_alive]

    all_services: List[Service] = []
    for h in live:
        svcs = await scan_ports(h, ports=ports, timeout=timeout, concurrency=scan_concurrency)
        all_services.extend(svcs)

    # Fingerprint services concurrently (bounded)
    sem = asyncio.Semaphore(detect_concurrency)

    async def fp(svc: Service) -> Service:
        async with sem:
            return await detect_service(svc, timeout=max(1.0, timeout))

    tasks = [asyncio.create_task(fp(s)) for s in all_services]
    services = await asyncio.gather(*tasks)

    # Risk scoring
    host_risk_score: Dict[str, float] = {}
    host_risk_reasons: Dict[str, List[str]] = {}
    if score_risk:
        for s in services:
            sc, rs = score_service_risk(s)
            s.risk_score = sc
            s.risk_reasons = rs
        host_risk_score, host_risk_reasons = score_hosts(services)

    return ReconResult(
        targets=expanded_targets,
        target_info=target_info,
        services=services,
        host_risk_score=host_risk_score,
        host_risk_reasons=host_risk_reasons,
    )
