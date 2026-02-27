# +-----------------------------------------------------------+
# | reconnaissance.py                                         |
# +-----------------------------------------------------------+
# | Purpose:                                                  |
# |  - Discover live hosts and exposed services               |
# |  - Perform safe fingerprinting / version hints            |
# |                                                           |
# | Responsibilities:                                         |
# |  - Host discovery (optional)                              |
# |  - Port scanning (TCP/UDP optional)                       |
# |  - Service detection (banner/protocol hints)              |
# |                                                           |
# | Key Data Models:                                          |
# |  + Host                                                   |
# |     - address: str                                        |
# |     - is_alive: bool                                      |
# |                                                           |
# |  + Service                                                |
# |     - host: str                                           |
# |     - port: int                                           |
# |     - protocol: str                                       |
# |     - name: str?                                          |
# |     - version: str?                                       |
# |     - banner: str?                                        |
# |                                                           |
# | Key Functions:                                            |
# |  + discover_hosts(target: str|list) -> list[Host]         |
# |  + scan_ports(host: Host, ports: list[int]) -> list[Service] |
# |  + detect_service(service: Service) -> Service            |
# |                                                           |
# | Inputs:                                                   |
# |  - target scope + ports + timeouts                        |
# |                                                           |
# | Outputs:                                                  |
# |  - list[Service] (discovered + fingerprinted)             |
# +-----------------------------------------------------------+
#



# reconnaissance.py

# reconnaissance.py
from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Tuple


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

    # Extra fingerprint fields (optional, but useful)
    http_server: Optional[str] = None
    http_status: Optional[int] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    tls_cert_subject: Optional[str] = None
    tls_cert_issuer: Optional[str] = None
    tls_cert_sans: Optional[List[str]] = None


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
    512: "exec",
    513: "login",
    514: "shell",
    1099: "rmiregistry",
    1524: "ingreslock",  # common in metasploitable labs
    2049: "nfs",
    3306: "mysql",
    3632: "distccd",
    5432: "postgres",
    5900: "vnc",
    6000: "x11",
    6667: "irc",
    8009: "ajp13",
    8180: "http-alt",
}

TLS_PORTS = {443, 8443, 993, 995, 465, 636, 990}


def _is_private_or_loopback(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback
    except ValueError:
        # hostname: treat as NOT allowed by default (safer)
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
# Host Discovery (non-invasive)
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
    """
    Non-invasive discovery: attempts a TCP connect to a few common ports.
    (Avoids ICMP/raw sockets requirements.)
    """
    candidates = _expand_targets(target)

    # Safety: default restrict to private/loopback IPs only
    if not allow_non_private:
        candidates = [h for h in candidates if _is_private_or_loopback(h)]

    probe_ports = [22, 80, 443, 445, 21, 25]
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
    """
    TCP connect scan on the specified ports.
    """
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


async def _probe_http(host: str, port: int, timeout: float) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Very light HTTP probe: send HEAD / then parse status + Server header.
    Returns (status, server_header, raw_head)
    """
    req = (
        "HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: recon/1.0\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    try:
        writer.write(req)
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        text = raw.decode(errors="replace")

        m = re.search(r"HTTP/\d\.\d\s+(\d+)", text)
        status = int(m.group(1)) if m else None

        m2 = re.search(r"(?im)^Server:\s*(.+)$", text)
        server = m2.group(1).strip() if m2 else None

        return status, server, text.strip()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _extract_version_from_banner(name: Optional[str], banner: Optional[str]) -> Optional[str]:
    if not banner:
        return None

    # crude but helpful patterns
    patterns = [
        (r"OpenSSH[_/ -]([\w\.p]+)", "OpenSSH"),
        (r"vsftpd\s+([\w\.]+)", "vsftpd"),
        (r"ProFTPD\s+([\w\.]+)", "ProFTPD"),
        (r"Apache/?\s*([\w\.]+)", "Apache"),
        (r"nginx/?\s*([\w\.]+)", "nginx"),
        (r"Postfix", "Postfix"),
        (r"Exim\s+([\w\.]+)", "Exim"),
        (r"MySQL\s+([\w\.]+)", "MySQL"),
        (r"VNC\s+([\w\.]+)", "VNC"),
    ]
    for pat, label in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            if m.groups():
                return f"{label} {m.group(1)}"
            return label
    return None


async def _probe_tls(host: str, port: int, timeout: float) -> Dict[str, object]:
    """
    TLS handshake to gather:
    - negotiated TLS version and cipher
    - certificate subject/issuer/SANs (if available)
    """
    ctx = ssl.create_default_context()
    # In a lab, certs may be self-signed. We still want to read them.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
        timeout=timeout,
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        info: Dict[str, object] = {}

        if sslobj:
            info["tls_version"] = sslobj.version()
            c = sslobj.cipher()
            info["tls_cipher"] = c[0] if c else None

            cert = sslobj.getpeercert()
            # getpeercert() may be empty depending on python/ssl settings; handle gracefully
            if cert:
                # Subject / Issuer are tuples-of-tuples; flatten to readable strings
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
    """
    Non-invasive fingerprinting based on port/protocol guesses:
    - plain banner read when the service speaks first (ssh/ftp/smtp/etc.)
    - HTTP HEAD probe for web
    - TLS handshake + cert for likely TLS ports
    """
    host, port = service.host, service.port

    # TLS first if the port is commonly TLS
    if port in TLS_PORTS or (service.name and service.name.lower() in {"https"}):
        tls = await _probe_tls(host, port, timeout)
        service.tls_version = tls.get("tls_version")  # type: ignore
        service.tls_cipher = tls.get("tls_cipher")    # type: ignore
        service.tls_cert_subject = tls.get("tls_cert_subject")  # type: ignore
        service.tls_cert_issuer = tls.get("tls_cert_issuer")    # type: ignore
        service.tls_cert_sans = tls.get("tls_cert_sans")        # type: ignore

    # HTTP probe
    if port in (80, 8080, 8180, 8000, 8888) or (service.name and service.name.lower() in {"http", "http-alt"}):
        status, server, raw = await _probe_http(host, port, timeout)
        service.http_status = status
        service.http_server = server
        service.banner = raw
        if server:
            service.version = server

        if not service.name:
            service.name = "http"
        return service

    # Plain banners (services that greet first)
    try:
        banner = await _read_banner_plain(host, port, timeout)
        if banner:
            service.banner = banner
            if not service.name:
                # heuristic name if unknown
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
        # some services won't speak until you send data; that's fine.
        pass

    return service


# ---------------------------
# High-level convenience
# ---------------------------

async def recon_services(
    targets: Union[str, List[str]],
    ports: Union[str, List[int]] = "1-1024",
    timeout: float = 1.0,
    scan_concurrency: int = 500,
    detect_concurrency: int = 200,
    allow_non_private: bool = True,   # CHANGE: allow scanning public IPs like 45.33.32.156
) -> List[Service]:

    """
    Full recon:
    - discover hosts
    - scan ports
    - fingerprint discovered services
    """
    hosts = await discover_hosts(targets, timeout=timeout, allow_non_private=allow_non_private)
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
    return await asyncio.gather(*tasks)


