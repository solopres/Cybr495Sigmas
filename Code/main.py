# main.py (GUI + CLI-friendly) - updated for ReconResult + risk scoring
import asyncio
import threading
import queue
import json
import paramiko
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

import tkinter as tk
from tkinter import ttk, messagebox

# recon_services now returns ReconResult (not List[Service])
from reconnaissance import recon_services, ReconResult


# ---------------------------
# Data Types
# ---------------------------

@dataclass
class ScanConfig:
    targets: List[str]
    profile: str = "default"
    ports: str = "1-2000"

    # Optional toggles (wired to recon module features)
    enrich: bool = True
    score_risk: bool = True
    allow_non_private: bool = True


@dataclass
class ReportBundle:
    inventory: Dict[str, Any]
    selected_tests: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]


# ---------------------------
# Pipeline Steps
# ---------------------------

def export_simple(inventory, filename="open_ports.json"):
    result = {}

    for svc in inventory.get("services", []):
        host = svc["host"]
        port = svc["port"]

        if host not in result:
            result[host] = []

        if port not in result[host]:
            result[host].append(port)

    # sort ports
    for host in result:
        result[host].sort()

    with open(filename, "w") as f:
        json.dump(result, f, indent=2)



def run_recon(cfg: ScanConfig) -> Dict[str, Any]:
    """
    Discover services on targets using reconnaissance.py
    Returns inventory dict used by decision engine.
    """
    # Run async recon from sync code
    result: ReconResult = asyncio.run(
        recon_services(
            cfg.targets,
            ports=cfg.ports,
            enrich=cfg.enrich,
            score_risk=cfg.score_risk,
            allow_non_private=cfg.allow_non_private,
        )
    )

    # Convert Service objects to simple dicts for the rest of the pipeline
    services_out: List[Dict[str, Any]] = []
    for s in result.services:
        services_out.append({
            "host": s.host,
            "port": s.port,
            "protocol": s.protocol,
            "name": getattr(s, "name", None),
            "version": getattr(s, "version", None),
            "banner": getattr(s, "banner", None),

            "http_status": getattr(s, "http_status", None),
            "http_server": getattr(s, "http_server", None),
            "http_title": getattr(s, "http_title", None),

            "https_status": getattr(s, "https_status", None),
            "https_server": getattr(s, "https_server", None),
            "https_title": getattr(s, "https_title", None),

            "tls_version": getattr(s, "tls_version", None),
            "tls_cipher": getattr(s, "tls_cipher", None),
            "tls_cert_subject": getattr(s, "tls_cert_subject", None),
            "tls_cert_issuer": getattr(s, "tls_cert_issuer", None),
            "tls_cert_sans": getattr(s, "tls_cert_sans", None),

            # NEW: risk scoring
            "risk_score": getattr(s, "risk_score", None),
            "risk_reasons": getattr(s, "risk_reasons", None),
        })

    # Convert target_info objects (if enabled)
    targets_out: List[Dict[str, Any]] = []
    for t in result.target_info:
        targets_out.append({
            "target": t.target,
            "resolved_ips": t.resolved_ips,
            "reverse_dns": t.reverse_dns,
            "is_private_or_loopback": t.is_private_or_loopback,

            "http_status": t.http_status,
            "http_server": t.http_server,
            "http_title": t.http_title,
            "https_status": t.https_status,
            "https_server": t.https_server,
            "https_title": t.https_title,
        })

    # Inventory includes everything the decision engine might want:
    # - services with per-service risk_score
    # - per-host risk summary maps
    # - target enrichment
    inventory = {
        "targets": result.targets,
        "target_info": targets_out,
        "services": services_out,
        "host_risk_score": result.host_risk_score,
        "host_risk_reasons": result.host_risk_reasons,
    }
    return inventory


def run_decision_engine(inventory: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Select which tests to run based on recon results.
    Your separate decision engine can now use:
      - inventory["host_risk_score"][host]
      - each svc["risk_score"]
    """
    findings = []
    try:
        for service in inventory["services"]:
            if service["name"] == "ssh":
                findings.append({
                    "traversal": run_remote_python(service["host"],"msfadmin",
                                  "msfadmin","dist/directoryTraverse")
                })
            elif service["name"] == "proftpd":
                pass

    except Exception as e:
        print(e)
    return findings


def run_remote_python(host, user, password, script_path):
    # Initialize the SSH client
    ssh = paramiko.SSHClient()
    # Automatically add the remote server's host key
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the server
        ssh.connect(hostname=host, username=user, password=password)

        sftp = ssh.open_sftp()
        remote_path = script_path.split("/")[-1]
        print(remote_path)
        sftp.put(script_path, remote_path)

        # --- CLOSE SFTP ---
        sftp.close()
        # Execute the command to run remote script
        # --- MAKE EXECUTABLE ---
        ssh.exec_command(f"chmod +x {remote_path}")

        # --- RUN IT ---
        stdin, stdout, stderr = ssh.exec_command(f"./{remote_path}")

        # Read and decode the results
        output = stdout.read().decode()
        error = stderr.read().decode()

        if error:
            print(f"Error: {error}")
        return json.loads(output)

    finally:
        ssh.close()


def run_pipeline(cfg: ScanConfig) -> ReportBundle:
    inventory = run_recon(cfg)
    selected_tests = run_decision_engine(inventory)
    findings = run_decision_engine(inventory)
    return ReportBundle(inventory=inventory, selected_tests=selected_tests, findings=findings)


# ---------------------------
# GUI
# ---------------------------

class ScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Recon Scanner (GUI)")
        self.root.geometry("900x650")

        self.log_q: "queue.Queue[str]" = queue.Queue()
        self.worker_thread: Optional[threading.Thread] = None

        # --- Inputs frame
        frm = ttk.Frame(root, padding=12)
        frm.pack(fill="x")

        ttk.Label(frm, text="Targets (comma or newline separated):").grid(row=0, column=0, sticky="w")
        self.targets_txt = tk.Text(frm, height=4, width=70)
        self.targets_txt.grid(row=1, column=0, columnspan=4, sticky="we", pady=(4, 10))
        self.targets_txt.insert("1.0", "45.33.32.156")

        ttk.Label(frm, text="Ports:").grid(row=2, column=0, sticky="w")
        self.ports_var = tk.StringVar(value="1-2000")
        ttk.Entry(frm, textvariable=self.ports_var, width=20).grid(row=2, column=1, sticky="w", padx=(8, 0))

        ttk.Label(frm, text="Profile:").grid(row=2, column=2, sticky="e")
        self.profile_var = tk.StringVar(value="default")
        ttk.Entry(frm, textvariable=self.profile_var, width=20).grid(row=2, column=3, sticky="w", padx=(8, 0))

        # --- Feature toggles
        opts = ttk.Frame(root, padding=(12, 0, 12, 8))
        opts.pack(fill="x")

        self.enrich_var = tk.BooleanVar(value=True)
        self.score_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(opts, text="Enrich targets (DNS / titles)", variable=self.enrich_var).pack(side="left")
        ttk.Checkbutton(opts, text="Risk scoring (0–10)", variable=self.score_var).pack(side="left", padx=12)

        frm.columnconfigure(0, weight=1)

        # --- Buttons
        btns = ttk.Frame(root, padding=(12, 0, 12, 12))
        btns.pack(fill="x")

        self.run_btn = ttk.Button(btns, text="Run Recon", command=self.on_run)
        self.run_btn.pack(side="left")

        self.clear_btn = ttk.Button(btns, text="Clear Log", command=self.clear_log)
        self.clear_btn.pack(side="left", padx=8)

        # --- Log output
        out = ttk.Frame(root, padding=(12, 0, 12, 12))
        out.pack(fill="both", expand=True)

        ttk.Label(out, text="Output:").pack(anchor="w")

        self.log_box = tk.Text(out, wrap="word")
        self.log_box.pack(side="left", fill="both", expand=True, pady=(6, 0))

        scroll = ttk.Scrollbar(out, orient="vertical", command=self.log_box.yview)
        scroll.pack(side="right", fill="y", pady=(6, 0))
        self.log_box.configure(yscrollcommand=scroll.set)

        # Poll the log queue so worker thread can safely write output
        self.root.after(100, self._drain_log_queue)

    def clear_log(self):
        self.log_box.delete("1.0", "end")

    def log(self, msg: str):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def _drain_log_queue(self):
        try:
            while True:
                msg = self.log_q.get_nowait()
                self.log(msg)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_log_queue)

    def _parse_targets(self) -> List[str]:
        raw = self.targets_txt.get("1.0", "end").strip()
        if not raw:
            return []
        parts: List[str] = []
        for line in raw.splitlines():
            parts.extend([p.strip() for p in line.split(",") if p.strip()])
        seen = set()
        out: List[str] = []
        for t in parts:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def on_run(self):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("Running", "A scan is already running.")
            return

        targets = self._parse_targets()
        ports = self.ports_var.get().strip()
        profile = self.profile_var.get().strip() or "default"

        if not targets:
            messagebox.showerror("Input error", "Please enter at least one target.")
            return
        if not ports:
            messagebox.showerror("Input error", "Please enter a port range/list (e.g., 1-2000).")
            return

        cfg = ScanConfig(
            targets=targets,
            ports=ports,
            profile=profile,
            enrich=bool(self.enrich_var.get()),
            score_risk=bool(self.score_var.get()),
            allow_non_private=True,
        )

        self.run_btn.config(state="disabled")
        self.log_q.put(
            "Starting recon...\n"
            f"Targets: {cfg.targets}\n"
            f"Ports: {cfg.ports}\n"
            f"Profile: {cfg.profile}\n"
            f"Enrich: {cfg.enrich}\n"
            f"Risk scoring: {cfg.score_risk}\n"
        )

        self.worker_thread = threading.Thread(
            target=self._worker_run_pipeline,
            args=(cfg,),
            daemon=True
        )
        self.worker_thread.start()

    def _worker_run_pipeline(self, cfg: ScanConfig):
        try:
            bundle = run_pipeline(cfg)
            inv = bundle.inventory
            services = inv.get("services", [])
            target_info = inv.get("target_info", [])
            host_scores = inv.get("host_risk_score", {}) or {}
            findings = bundle.findings
            traversal = []
            for i in findings:
                if "traversal" in i:
                    traversal = i["traversal"]

            # Show target enrichment first (if any)
            if target_info:
                self.log_q.put("\nTarget enrichment:")
                for t in target_info:
                    tgt = t.get("target")
                    ips = t.get("resolved_ips") or []
                    ptr = t.get("reverse_dns")
                    http = t.get("http_status")
                    https = t.get("https_status")
                    title = t.get("http_title") or t.get("https_title")
                    line = f"  - {tgt} -> {', '.join(ips) if ips else '(no DNS)'}"
                    if ptr:
                        line += f" | PTR: {ptr}"
                    if http or https:
                        line += f" | HTTP:{http or '-'} HTTPS:{https or '-'}"
                    if title:
                        line += f" | Title: {title}"
                    self.log_q.put(line)

            # Host risk summary
            if host_scores:
                self.log_q.put("\nHost risk (0–10):")
                # print sorted by risk desc
                for host, score in sorted(host_scores.items(), key=lambda kv: kv[1], reverse=True):
                    self.log_q.put(f"  - {host}: {score:.1f}/10")

            # Services list
            self.log_q.put("\nDiscovered services:")
            # sort services by risk then host/port
            def svc_key(s: Dict[str, Any]):
                rs = s.get("risk_score")
                return (-(rs if isinstance(rs, (int, float)) else -1), s.get("host", ""), s.get("port", 0))

            for svc in sorted(services, key=svc_key):
                host = svc.get("host")
                port = svc.get("port")
                name = svc.get("name") or ""
                ver = svc.get("version") or ""
                proto = svc.get("protocol") or "tcp"
                risk = svc.get("risk_score")
                risk_str = f"{risk:.1f}/10" if isinstance(risk, (int, float)) else "n/a"
                line = f"  - {host}:{port}/{proto}  {name} {ver}".strip()
                line += f"  | Risk: {risk_str}"
                self.log_q.put(line)

            # Directory Traversal Results
            lines = []
            for file in traversal:
                lines.append(f"[{file['risk']}] {file['file']}")
                lines.append(f"  Score: {file['score']}")
                lines.append(f"  Reasons: {', '.join(file['reasons'])}")
                lines.append("")  # spacing

            self.log_q.put("\n".join(lines))
            self.log_q.put("\nDone.")
        except Exception as e:
            self.log_q.put(f"\nERROR: {type(e).__name__}: {e}")
        finally:
            self.root.after(0, lambda: self.run_btn.config(state="normal"))


def launch_gui():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    ScannerGUI(root)
    root.mainloop()


def main() -> int:
    launch_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
