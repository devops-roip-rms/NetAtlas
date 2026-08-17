from __future__ import annotations

import argparse
import base64
import csv
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
from xml.etree import ElementTree

try:
    import paramiko
except ImportError:  # Optional for direct, package-free local operation.
    paramiko = None


APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
DATA_DIR = Path(os.environ.get("NETATLAS_DATA_DIR", APP_DIR / "data")).resolve()
DATA_DIR.mkdir(exist_ok=True)
HOSTS_DB = DATA_DIR / "hosts.db"
APP_VERSION = "1.2.3"
SENSITIVE_CONFIG_KEYS = {"ssh_password", "linux_ssh_password", "windows_ssh_password", "password"}

PRIMARY_PORTS = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}
AUXILIARY_PORTS = {445: "SMB", 5985: "WinRM", 5986: "WinRM/HTTPS"}
ALL_PORTS = {**PRIMARY_PORTS, **AUXILIARY_PORTS}
TERMINAL_DEFAULTS = (
    "MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%"
    "xterm%-1%0%_Std_Colors_0_%80%24%0%0%-1%<none>%%0%0%-1%-1"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(value: object, limit: int = 240) -> str:
    text = str("" if value is None else value).replace("\x00", "").strip()
    return re.sub(r"[\r\n\t]+", " ", text)[:limit]


def safe_name(value: str) -> str:
    value = clean_text(value, 80).replace("=", "-").replace("#", "-").replace("%", "-")
    return value or "Unnamed"


def normalize_hostname(value: object) -> str:
    """Return a display-safe hostname without the internal DNS suffix."""
    hostname = clean_text(value, 180).rstrip(".")
    return re.sub(r"(?i)\.tng\.topsecret$", "", hostname).rstrip(".")


def infer_host_role(host: dict) -> str:
    """Infer a useful role label without claiming more precision than the evidence supports."""
    hostname = normalize_hostname(host.get("hostname")).lower()
    short = hostname.split(".", 1)[0]
    services = set(host.get("services", []))
    open_ports = set(host.get("open_ports", []))
    patterns = (
        (r"(^|[-_])(dc|adc)\d*($|[-_])", "Domain Controller"),
        (r"(^|[-_])(db|sql|ora|oracle|postgres|pgsql|mysql)\d*($|[-_])", "Database Server"),
        (r"(^|[-_])(web|www|nginx|apache)\d*($|[-_])", "Web Server"),
        (r"(^|[-_])(app|api|middleware|mw)\d*($|[-_])", "Application Server"),
        (r"(^|[-_])(fs|file|nas)\d*($|[-_])", "File Server"),
        (r"(^|[-_])(vcenter|esx|esxi|hyperv|hv)\d*($|[-_])", "Virtualization Host"),
        (r"(^|[-_])(backup|veeam)\d*($|[-_])", "Backup Server"),
        (r"(^|[-_])(monitor|monitoring|zabbix|nagios|prometheus)\d*($|[-_])", "Monitoring Server"),
        (r"(^|[-_])(jump|bastion)\d*($|[-_])", "Jump Host"),
        (r"(^|[-_])(print|printer)\d*($|[-_])", "Print Server"),
    )
    for pattern, role in patterns:
        if re.search(pattern, short):
            return role
    if 445 in open_ports:
        return "File / Windows Server"
    if {"HTTP", "HTTPS"} & services:
        return "Web Service"
    if host.get("os_family") == "Windows" or "RDP" in services:
        return "Windows Server"
    if host.get("os_family") == "Linux":
        return "Linux Server"
    if "SSH" in services:
        return "SSH Host"
    return "Network Endpoint"


def normalize_host_record(host: dict) -> dict:
    host["hostname"] = normalize_hostname(host.get("hostname"))
    if not host.get("role"):
        host["role"] = infer_host_role(host)
    return host


@dataclass
class ScanJob:
    id: str
    config: dict
    secrets: dict = field(default_factory=dict, repr=False)
    status: str = "queued"
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    total: int = 0
    completed: int = 0
    results: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cancelled: bool = False
    current_phase: str = "Preparing address plan"

    def public(self) -> dict:
        payload = asdict(self)
        payload["config"] = {key: value for key, value in payload.get("config", {}).items() if key not in SENSITIVE_CONFIG_KEYS}
        payload["progress"] = round((self.completed / self.total * 100), 1) if self.total else 0
        payload["summary"] = summarize(self.results)
        payload.pop("cancelled", None)
        payload.pop("secrets", None)
        return payload


JOBS: dict[str, ScanJob] = {}
JOBS_LOCK = threading.Lock()


def summarize(results: list[dict]) -> dict:
    return {
        "hosts": len(results),
        "ssh": sum("SSH" in r.get("services", []) for r in results),
        "rdp": sum("RDP" in r.get("services", []) for r in results),
        "web": sum(bool({"HTTP", "HTTPS"} & set(r.get("services", []))) for r in results),
        "windows": sum(r.get("os_family") == "Windows" for r in results),
        "linux": sum(r.get("os_family") == "Linux" for r in results),
        "unknown": sum(r.get("os_family") not in {"Windows", "Linux"} for r in results),
    }


def build_address_plan(config: dict) -> list[dict]:
    plan: list[dict] = []
    seen: set[tuple[str, str]] = set()
    max_addresses = int(config.get("max_addresses", 65536))
    for site in config.get("sites", []):
        site_name = clean_text(site.get("name"), 60) or "Site"
        for vlan in site.get("vlans", []):
            cidr = clean_text(vlan.get("cidr"), 64)
            if not cidr:
                continue
            network = ipaddress.ip_network(cidr, strict=False)
            if network.version != 4:
                raise ValueError(f"IPv6 is not supported yet: {cidr}")
            if network.num_addresses > 4096:
                raise ValueError(f"{cidr} is too large; use networks /20 or smaller")
            vlan_name = clean_text(vlan.get("name"), 60) or cidr
            for address in network.hosts():
                key = (site_name, str(address))
                if key in seen:
                    continue
                seen.add(key)
                plan.append({"site": site_name, "vlan": vlan_name, "cidr": str(network), "ip": str(address)})
                if len(plan) > max_addresses:
                    raise ValueError(f"Address plan exceeds the safety limit of {max_addresses:,} addresses")
    if not plan:
        raise ValueError("Add at least one valid IPv4 subnet")
    return plan


def tcp_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def ssh_banner(ip: str, timeout: float) -> str:
    try:
        with socket.create_connection((ip, 22), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return clean_text(sock.recv(512).decode("utf-8", "replace"))
    except OSError:
        return ""


def http_probe(ip: str, port: int, timeout: float) -> dict:
    secure = port == 443
    result = {"title": "", "server": "", "status": "", "url": f"{'https' if secure else 'http'}://{ip}"}
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        sock = raw
        if secure:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw, server_hostname=ip)
        with sock:
            sock.settimeout(max(timeout, 1.0))
            request = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetAtlas/{APP_VERSION}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode("ascii"))
            chunks = []
            size = 0
            while size < 32768:
                block = sock.recv(min(8192, 32768 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
            text = b"".join(chunks).decode("utf-8", "replace")
            head, _, body = text.partition("\r\n\r\n")
            lines = head.splitlines()
            result["status"] = clean_text(lines[0] if lines else "")
            for line in lines[1:]:
                if line.lower().startswith("server:"):
                    result["server"] = clean_text(line.split(":", 1)[1])
            match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if match:
                result["title"] = clean_text(re.sub(r"<[^>]+>", "", match.group(1)), 120)
    except (OSError, ssl.SSLError):
        pass
    return result


def reverse_dns(ip: str) -> str:
    try:
        return normalize_hostname(socket.gethostbyaddr(ip)[0])
    except (OSError, socket.herror):
        return ""


def infer_os(open_ports: list[int], banner: str, web: list[dict]) -> tuple[str, str, int, str]:
    joined = " ".join([banner, *(x.get("server", "") for x in web)]).lower()
    version = ""
    evidence = "Service fingerprint"
    if any(port in open_ports for port in (3389, 445, 5985, 5986)) or "microsoft-iis" in joined:
        family, confidence = "Windows", 82
        match = re.search(r"microsoft-iis/([\w.]+)", joined)
        if match:
            version = f"Windows / IIS {match.group(1)}"
    elif any(token in joined for token in ("ubuntu", "debian", "openssh_for_windows")):
        if "openssh_for_windows" in joined:
            family, confidence = "Windows", 90
            match = re.search(r"openssh_for_windows[_/-]([\w.]+)", joined)
            version = f"Windows OpenSSH {match.group(1)}" if match else "Windows"
        else:
            family, confidence = "Linux", 88
            match = re.search(r"(ubuntu|debian)[_ -]?([\w.]+)?", joined)
            version = " ".join(x for x in (match.group(1).title(), match.group(2) or "") if x) if match else "Linux"
    elif 22 in open_ports and any(token in joined for token in ("openssh", "dropbear", "nginx", "apache")):
        family, confidence = "Linux", 62
    else:
        family, confidence, evidence = "Unknown", 0, "Insufficient fingerprint"
    return family, version, confidence, evidence


def scan_host(item: dict, timeout: float, auxiliary: bool) -> dict | None:
    ip = item["ip"]
    ports = list(PRIMARY_PORTS) + (list(AUXILIARY_PORTS) if auxiliary else [])
    opened = [port for port in ports if tcp_open(ip, port, timeout)]
    if not set(opened) & set(PRIMARY_PORTS):
        return None
    banner = ssh_banner(ip, max(timeout, 0.75)) if 22 in opened else ""
    web = [http_probe(ip, port, max(timeout, 0.8)) for port in (80, 443) if port in opened]
    family, version, confidence, evidence = infer_os(opened, banner, web)
    services = [PRIMARY_PORTS[p] for p in PRIMARY_PORTS if p in opened]
    hostname = reverse_dns(ip)
    host = {
        **item,
        "hostname": hostname,
        "hostname_source": "Reverse DNS" if hostname else "Unresolved",
        "services": services,
        "open_ports": opened,
        "ssh_banner": banner,
        "web": web,
        "os_family": family,
        "os_version": version,
        "os_confidence": confidence,
        "os_evidence": evidence,
        "resources": {},
        "resource_status": "Credentials not supplied",
        "discovered_at": utc_now(),
    }
    host["role"] = infer_host_role(host)
    return host


def windows_version_from_build(version: str) -> str:
    version = clean_text(version, 80)
    builds = {
        "10.0.26100": "Windows Server 2025",
        "10.0.20348": "Windows Server 2022",
        "10.0.17763": "Windows Server 2019",
        "10.0.14393": "Windows Server 2016",
        "6.3.9600": "Windows Server 2012 R2",
        "6.2.9200": "Windows Server 2012",
        "6.1.7601": "Windows Server 2008 R2",
    }
    for prefix, name in builds.items():
        if version.startswith(prefix):
            return f"{name} (build {version})"
    return f"Windows (build {version})" if version else "Windows"


def script_field(output: str, name: str) -> str:
    match = re.search(rf"(?:^|\n)\s*{re.escape(name)}:\s*([^\r\n]+)", output, re.I)
    return clean_text(match.group(1), 180) if match else ""


def enrich_nmap(host: dict) -> None:
    if not shutil.which("nmap"):
        return
    ports = ",".join(str(x) for x in host["open_ports"])
    command = ["nmap", "-Pn", "-sV", "--version-light", "-O", "--osscan-guess", "--host-timeout", "45s"]
    if {3389, 445} & set(host["open_ports"]):
        command += ["--script", "rdp-ntlm-info,smb-os-discovery"]
    command += ["-p", ports, "-oX", "-", host["ip"]]
    try:
        proc = subprocess.run(command, capture_output=True, timeout=55, check=False)
        if not proc.stdout:
            return
        root = ElementTree.fromstring(proc.stdout)
        osmatch = root.find(".//osmatch")
        if osmatch is not None:
            host["os_version"] = clean_text(osmatch.attrib.get("name"), 160)
            host["os_confidence"] = int(osmatch.attrib.get("accuracy", "0"))
            host["os_evidence"] = "Nmap OS fingerprint"
            name = host["os_version"].lower()
            host["os_family"] = "Windows" if "windows" in name else "Linux" if any(x in name for x in ("linux", "unix", "ubuntu", "debian")) else "Other"
        products = []
        for service in root.findall(".//port/service"):
            label = " ".join(filter(None, [service.attrib.get("product"), service.attrib.get("version"), service.attrib.get("extrainfo")]))
            if label:
                products.append(clean_text(label, 120))
        host["service_fingerprints"] = products
        for script in root.findall(".//script"):
            output = script.attrib.get("output", "")
            script_id = script.attrib.get("id", "")
            if script_id == "rdp-ntlm-info":
                hostname = script_field(output, "DNS_Computer_Name") or script_field(output, "NetBIOS_Computer_Name")
                version = script_field(output, "Product_Version")
                if hostname:
                    host["hostname"] = normalize_hostname(hostname)
                    host["hostname_source"] = "RDP identity"
                if version:
                    host["os_family"] = "Windows"
                    host["os_version"] = windows_version_from_build(version)
                    host["os_confidence"] = 94
                    host["os_evidence"] = "RDP NTLM product version"
            elif script_id == "smb-os-discovery":
                hostname = script_field(output, "Computer name") or script_field(output, "FQDN")
                os_name = script_field(output, "OS")
                if hostname:
                    host["hostname"] = normalize_hostname(hostname)
                    host["hostname_source"] = "SMB identity"
                if os_name:
                    host["os_family"] = "Windows"
                    host["os_version"] = os_name
                    host["os_confidence"] = 96
                    host["os_evidence"] = "SMB OS discovery"
    except (OSError, subprocess.TimeoutExpired, ElementTree.ParseError, ValueError):
        return


def ssh_output(client: object, command: str, timeout: int = 15) -> str:
    _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
    return stdout.read(1_000_000).decode("utf-8", "replace")


def apply_linux_ssh(host: dict, client: object) -> bool:
    command = (
        "printf 'NETATLAS_LINUX\\n'; "
        "(hostname -f 2>/dev/null || hostname 2>/dev/null); "
        "uname -srmo 2>/dev/null; "
        "(. /etc/os-release 2>/dev/null; printf '%s\\n' \"$PRETTY_NAME\"); "
        "getconf _NPROCESSORS_ONLN 2>/dev/null; "
        "awk '/MemTotal/{printf \"%.1f\\n\",$2/1048576}' /proc/meminfo 2>/dev/null; "
        "df -Pk / 2>/dev/null | awk 'NR==2{printf \"%.1f/%.1f\\n\",($2-$4)/1048576,$2/1048576}'"
    )
    lines = [clean_text(line) for line in ssh_output(client, command).splitlines()]
    if "NETATLAS_LINUX" not in lines:
        return False
    pos = lines.index("NETATLAS_LINUX")
    values = (lines[pos + 1 :] + [""] * 6)[:6]
    hostname, kernel, release, cores, ram, disk = values
    if hostname:
        host["hostname"] = normalize_hostname(hostname)
        host["hostname_source"] = "Authenticated SSH"
    host["os_family"] = "Linux"
    host["os_version"] = release or kernel or "Linux"
    host["os_confidence"] = 100
    host["os_evidence"] = "Authenticated /etc/os-release"
    host["resources"] = {"cpu_cores": cores, "ram_gb": ram, "disk_root_gb": disk}
    host["resource_status"] = "Collected via password-authenticated SSH"
    return True


def apply_windows_ssh(host: dict, client: object) -> bool:
    script = (
        "$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;"
        "$c=Get-CimInstance Win32_ComputerSystem;$d=Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\";"
        "$fqdn=try{[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName}catch{$env:COMPUTERNAME};"
        "[pscustomobject]@{netatlas='windows';hostname=$fqdn;caption=$o.Caption;version=$o.Version;"
        "cores=$c.NumberOfLogicalProcessors;ram=[math]::Round($c.TotalPhysicalMemory/1GB,1);"
        "disk=[math]::Round($d.Size/1GB,1);free=[math]::Round($d.FreeSpace/1GB,1)}|ConvertTo-Json -Compress"
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    output = ssh_output(client, f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}")
    match = re.search(r"\{.*\}", output, re.S)
    if not match:
        return False
    data = json.loads(match.group(0))
    if data.get("netatlas") != "windows":
        return False
    if data.get("hostname"):
        host["hostname"] = normalize_hostname(data["hostname"])
        host["hostname_source"] = "Authenticated Windows OpenSSH"
    host["os_family"] = "Windows"
    host["os_version"] = clean_text(f"{data.get('caption', '')} {data.get('version', '')}")
    host["os_confidence"] = 100
    host["os_evidence"] = "Authenticated Windows OpenSSH"
    host["resources"] = {
        "cpu_cores": data.get("cores"), "ram_gb": data.get("ram"),
        "disk_c_gb": data.get("disk"), "disk_free_gb": data.get("free"),
    }
    host["resource_status"] = "Collected via password-authenticated SSH"
    return True


def try_ssh_profile(host: dict, username: str, password: str, profile: str) -> tuple[bool, str]:
    if not username or not password:
        return False, "not configured"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host["ip"], port=22, username=username, password=password,
            timeout=8, banner_timeout=8, auth_timeout=8,
            allow_agent=False, look_for_keys=False,
        )
        windows_first = profile == "Windows" or host.get("os_family") == "Windows" or "windows" in host.get("ssh_banner", "").lower()
        if windows_first:
            enriched = apply_windows_ssh(host, client) or apply_linux_ssh(host, client)
        else:
            enriched = apply_linux_ssh(host, client) or apply_windows_ssh(host, client)
        if enriched:
            host["credential_profile"] = f"{profile} SSH profile"
            return True, ""
        return False, "authenticated, but OS commands were unavailable"
    except Exception as exc:
        return False, clean_text(exc, 100)
    finally:
        client.close()


def enrich_ssh_resources(host: dict, linux_user: str, linux_password: str, windows_user: str, windows_password: str) -> None:
    if paramiko is None or 22 not in host["open_ports"]:
        return
    profiles = [
        ("Linux", linux_user, linux_password),
        ("Windows", windows_user, windows_password),
    ]
    if host.get("os_family") == "Windows":
        profiles.reverse()
    unique: set[tuple[str, str]] = set()
    errors = []
    for profile, username, password in profiles:
        signature = (username, password)
        if not username or not password or signature in unique:
            continue
        unique.add(signature)
        success, error = try_ssh_profile(host, username, password, profile)
        if success:
            return
        errors.append(f"{profile} profile: {error}")
    if errors:
        host["resource_status"] = "SSH enrichment failed — " + "; ".join(errors)


def enrich_windows_resources(host: dict, use_ssl: bool) -> None:
    if host["os_family"] != "Windows" or not ({5985, 5986} & set(host["open_ports"])):
        return
    script = (
        "$ErrorActionPreference='Stop';$o=Get-CimInstance Win32_OperatingSystem;"
        "$c=Get-CimInstance Win32_ComputerSystem;$d=Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\";"
        "[pscustomobject]@{hostname=$env:COMPUTERNAME;caption=$o.Caption;version=$o.Version;cores=$c.NumberOfLogicalProcessors;"
        "ram=[math]::Round($c.TotalPhysicalMemory/1GB,1);disk=[math]::Round($d.Size/1GB,1);"
        "free=[math]::Round($d.FreeSpace/1GB,1)}|ConvertTo-Json -Compress"
    )
    command = ["Invoke-Command", "-ComputerName", host["ip"], "-ScriptBlock", f"{{{script}}}"]
    if use_ssl:
        command.append("-UseSSL")
    encoded = " ".join(command)
    try:
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", encoded], capture_output=True, text=True, timeout=18, check=False)
        data = json.loads(proc.stdout.strip())
        if data.get("hostname"):
            host["hostname"] = normalize_hostname(data["hostname"])
            host["hostname_source"] = "Authenticated WinRM"
        host["os_version"] = clean_text(f"{data.get('caption', '')} {data.get('version', '')}")
        host["os_confidence"] = 100
        host["os_evidence"] = "Authenticated WinRM"
        host["resources"] = {"cpu_cores": data.get("cores"), "ram_gb": data.get("ram"), "disk_c_gb": data.get("disk"), "disk_free_gb": data.get("free")}
        host["resource_status"] = "Collected via WinRM"
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return


def hosts_db_connection() -> sqlite3.Connection:
    HOSTS_DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(HOSTS_DB, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=15000")
    return connection


def init_hosts_db() -> None:
    connection = hosts_db_connection()
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS remembered_hosts (
                site TEXT NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                role TEXT NOT NULL,
                role_locked INTEGER NOT NULL DEFAULT 0,
                vlan TEXT NOT NULL DEFAULT '',
                cidr TEXT NOT NULL DEFAULT '',
                services_json TEXT NOT NULL DEFAULT '[]',
                open_ports_json TEXT NOT NULL DEFAULT '[]',
                web_json TEXT NOT NULL DEFAULT '[]',
                os_family TEXT NOT NULL DEFAULT '',
                os_version TEXT NOT NULL DEFAULT '',
                os_confidence INTEGER NOT NULL DEFAULT 0,
                os_evidence TEXT NOT NULL DEFAULT '',
                resources_json TEXT NOT NULL DEFAULT '{}',
                resource_status TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_scan_id TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (site, ip)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS remembered_hosts_hostname ON remembered_hosts(hostname)")
        connection.execute("CREATE INDEX IF NOT EXISTS remembered_hosts_last_seen ON remembered_hosts(last_seen DESC)")
        connection.commit()
    finally:
        connection.close()


def remember_job_hosts(job: ScanJob) -> int:
    """Merge resolved scan results into the durable host inventory."""
    init_hosts_db()
    remembered = 0
    connection = hosts_db_connection()
    try:
        for host in job.results:
            normalize_host_record(host)
            if not host.get("hostname"):
                continue
            observed = host.get("discovered_at") or job.finished_at or utc_now()
            role = clean_text(host.get("role") or infer_host_role(host), 80)
            connection.execute(
                """
                INSERT INTO remembered_hosts (
                    site, ip, hostname, role, vlan, cidr, services_json, open_ports_json,
                    web_json, os_family, os_version, os_confidence, os_evidence,
                    resources_json, resource_status, first_seen, last_seen, last_scan_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(site, ip) DO UPDATE SET
                    hostname=excluded.hostname,
                    role=CASE WHEN remembered_hosts.role_locked=1 THEN remembered_hosts.role ELSE excluded.role END,
                    vlan=excluded.vlan,
                    cidr=excluded.cidr,
                    services_json=excluded.services_json,
                    open_ports_json=excluded.open_ports_json,
                    web_json=excluded.web_json,
                    os_family=excluded.os_family,
                    os_version=excluded.os_version,
                    os_confidence=excluded.os_confidence,
                    os_evidence=excluded.os_evidence,
                    resources_json=excluded.resources_json,
                    resource_status=excluded.resource_status,
                    last_seen=excluded.last_seen,
                    last_scan_id=excluded.last_scan_id,
                    seen_count=remembered_hosts.seen_count+1
                """,
                (
                    clean_text(host.get("site"), 60), clean_text(host.get("ip"), 64), host["hostname"], role,
                    clean_text(host.get("vlan"), 60), clean_text(host.get("cidr"), 64),
                    json.dumps(host.get("services", [])), json.dumps(host.get("open_ports", [])),
                    json.dumps(host.get("web", [])), clean_text(host.get("os_family"), 40),
                    clean_text(host.get("os_version"), 180), int(host.get("os_confidence") or 0),
                    clean_text(host.get("os_evidence"), 180), json.dumps(host.get("resources", {})),
                    clean_text(host.get("resource_status"), 240), observed, observed, job.id,
                ),
            )
            remembered += 1
        connection.commit()
    finally:
        connection.close()
    return remembered


def decode_json_field(value: str, fallback: object) -> object:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def list_remembered_hosts() -> list[dict]:
    init_hosts_db()
    connection = hosts_db_connection()
    try:
        rows = connection.execute("SELECT * FROM remembered_hosts ORDER BY last_seen DESC").fetchall()
    finally:
        connection.close()
    hosts = []
    for row in rows:
        host = dict(row)
        host["services"] = decode_json_field(host.pop("services_json"), [])
        host["open_ports"] = decode_json_field(host.pop("open_ports_json"), [])
        host["web"] = decode_json_field(host.pop("web_json"), [])
        host["resources"] = decode_json_field(host.pop("resources_json"), {})
        host["role_locked"] = bool(host.get("role_locked"))
        normalize_host_record(host)
        hosts.append(host)
    return hosts


def update_remembered_role(site: object, ip: object, role: object) -> dict:
    site_name = clean_text(site, 60)
    address = clean_text(ip, 64)
    role_name = clean_text(role, 80)
    if not site_name or not address or not role_name:
        raise ValueError("Site, IP address and role are required")
    ipaddress.ip_address(address)
    init_hosts_db()
    connection = hosts_db_connection()
    try:
        cursor = connection.execute(
            "UPDATE remembered_hosts SET role=?, role_locked=1 WHERE site=? AND ip=?",
            (role_name, site_name, address),
        )
        if cursor.rowcount != 1:
            raise ValueError("Remembered host was not found")
        connection.commit()
    finally:
        connection.close()
    return {"site": site_name, "ip": address, "role": role_name, "role_locked": True}


def save_job(job: ScanJob) -> None:
    path = DATA_DIR / f"scan-{job.id}.json"
    path.write_text(json.dumps(job.public(), indent=2), encoding="utf-8")


def run_scan(job: ScanJob) -> None:
    try:
        plan = build_address_plan(job.config)
        job.total = len(plan)
        job.status = "running"
        job.started_at = utc_now()
        job.current_phase = "Checking SSH, RDP and web services"
        timeout = min(max(float(job.config.get("timeout", 0.45)), 0.15), 3.0)
        workers = min(max(int(job.config.get("concurrency", 128)), 8), 256)
        auxiliary = bool(job.config.get("auxiliary_ports", True))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netatlas") as pool:
            futures = {pool.submit(scan_host, item, timeout, auxiliary): item for item in plan}
            for future in as_completed(futures):
                if job.cancelled:
                    for pending in futures:
                        pending.cancel()
                    break
                job.completed += 1
                try:
                    result = future.result()
                    if result:
                        job.results.append(result)
                except Exception as exc:  # keep the wider scan alive
                    if len(job.errors) < 20:
                        job.errors.append(f"{futures[future]['ip']}: {clean_text(exc)}")

        if not job.cancelled and job.config.get("deep_scan") and shutil.which("nmap"):
            job.current_phase = "Enriching OS and service fingerprints"
            with ThreadPoolExecutor(max_workers=min(6, workers)) as pool:
                list(pool.map(enrich_nmap, job.results))

        if not job.cancelled and job.config.get("ssh_resources"):
            job.current_phase = "Collecting Linux and Windows resources over SSH"
            linux_user = clean_text(job.config.get("linux_ssh_username"), 100)
            linux_password = str(job.secrets.get("linux_ssh_password", ""))
            windows_user = clean_text(job.config.get("windows_ssh_username"), 100)
            windows_password = str(job.secrets.get("windows_ssh_password", ""))
            with ThreadPoolExecutor(max_workers=min(12, workers)) as pool:
                list(pool.map(lambda h: enrich_ssh_resources(h, linux_user, linux_password, windows_user, windows_password), job.results))

        if not job.cancelled and job.config.get("windows_resources"):
            job.current_phase = "Collecting Windows resources over WinRM"
            with ThreadPoolExecutor(max_workers=min(8, workers)) as pool:
                list(pool.map(lambda h: enrich_windows_resources(h, bool(job.config.get("winrm_ssl"))), job.results))

        for host in job.results:
            host["hostname"] = normalize_hostname(host.get("hostname"))
            host["role"] = infer_host_role(host)
        job.results.sort(key=lambda r: (r["site"].lower(), ipaddress.ip_address(r["ip"])))
        if job.results:
            job.current_phase = "Updating remembered hosts"
            try:
                remember_job_hosts(job)
            except (OSError, sqlite3.Error) as exc:
                if len(job.errors) < 20:
                    job.errors.append(f"Remembered hosts database: {clean_text(exc)}")
        job.status = "cancelled" if job.cancelled else "complete"
        job.current_phase = "Cancelled" if job.cancelled else "Complete"
    except Exception as exc:
        job.status = "failed"
        job.errors.append(clean_text(exc, 500))
        job.current_phase = "Failed"
    finally:
        job.secrets.clear()
        job.finished_at = utc_now()
        save_job(job)


def moba_line(icon: int, fields: list[object], comment: str = "") -> str:
    first = "%".join(clean_text(x, 500).replace("#", "__DIEZE__").replace("%", "-") for x in fields)
    comment = clean_text(comment, 220).replace("#", "__DIEZE__").replace("%", "-")
    return f"#{icon}#{first}#{TERMINAL_DEFAULTS}#0#{comment}#-1"


def ssh_session(host: dict, username: str) -> str:
    fields = [0, host["ip"], 22, username, "", -1, -1, "", "", "", "", 0, 0 if username else -1, 0, "", "", -1, 0, 0, 0, "", 1080, "", 0, 0, 1, "", 0, "", "", "", 0, -1, -1, 0]
    return moba_line(109, fields, f"{host['site']} | {host['vlan']} | {host.get('role')} | {host.get('os_version') or host.get('os_family')}")


def rdp_session(host: dict, username: str) -> str:
    fields = [4, host["ip"], 3389, username, 0, 0, 0, 0, -1, 0, 0, -1, "", "", "", "", 0, 0, "", -1, "", -1, -1, 0, -1, 0, -1, 0, 0, 0, 0, ""]
    return moba_line(91, fields, f"{host['site']} | {host['vlan']} | {host.get('role')} | {host.get('os_version') or 'Windows host'}")


def browser_session(host: dict, url: str) -> str:
    fields = [11, url, -1, -1, -1, -1, -1, -1, -1, 0, 0, 3, -1, -1, 0, -1, 0, -1, 0, "", ""]
    return moba_line(313, fields, f"{host['site']} | {host['vlan']} | Web console")


def export_mobaxterm(job: ScanJob, linux_ssh_user: str = "", rdp_user: str = "", windows_ssh_user: str = "") -> bytes:
    sections: dict[str, list[tuple[str, str]]] = {}
    for host in job.results:
        family = host.get("os_family")
        block = family if family in {"Windows", "Linux"} else "Unclassified"
        folder = f"{block}\\{safe_name(host['site'])}\\{safe_name(host['vlan'])}"
        sessions: list[tuple[str, str]] = []
        base = safe_name(host.get("hostname") or host["ip"])
        if family == "Windows":
            sessions.append((f"{base} - SSH", ssh_session(host, windows_ssh_user or linux_ssh_user)))
            sessions.append((f"{base} - RDP", rdp_session(host, rdp_user)))
        elif family == "Linux":
            sessions.append((f"{base} - SSH", ssh_session(host, linux_ssh_user)))
        else:
            if "SSH" in host["services"]:
                sessions.append((f"{base} - SSH", ssh_session(host, linux_ssh_user or windows_ssh_user)))
            if "RDP" in host["services"]:
                sessions.append((f"{base} - RDP", rdp_session(host, rdp_user)))
        if sessions:
            sections.setdefault(folder, []).extend(sessions)
    lines = ["[Bookmarks]", "SubRep=NetAtlas", "ImgNum=41", ""]
    for index, folder in enumerate(sorted(sections, key=str.lower), 1):
        lines += [f"[Bookmarks_{index}]", f"SubRep={folder}", "ImgNum=41"]
        used: dict[str, int] = {}
        for name, value in sections[folder]:
            used[name] = used.get(name, 0) + 1
            unique = name if used[name] == 1 else f"{name} ({used[name]})"
            lines.append(f"{unique}={value}")
        lines.append("")
    return "\r\n".join(lines).encode("cp1252", "replace")


def export_csv(job: ScanJob, linux_ssh_user: str = "", rdp_user: str = "", windows_ssh_user: str = "") -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["name", "protocol", "host", "port", "username", "folder", "url"])
    for host in job.results:
        family = host.get("os_family")
        block = family if family in {"Windows", "Linux"} else "Unclassified"
        folder = f"NetAtlas\\{block}\\{host['site']}\\{host['vlan']}"
        name = host.get("hostname") or host["ip"]
        if family == "Windows":
            writer.writerow([f"{name} - SSH", "SSH", host["ip"], 22, windows_ssh_user or linux_ssh_user, folder, ""])
            writer.writerow([f"{name} - RDP", "RDP", host["ip"], 3389, rdp_user, folder, ""])
        elif family == "Linux":
            writer.writerow([f"{name} - SSH", "SSH", host["ip"], 22, linux_ssh_user, folder, ""])
        else:
            if "SSH" in host["services"]:
                writer.writerow([f"{name} - SSH", "SSH", host["ip"], 22, linux_ssh_user or windows_ssh_user, folder, ""])
            if "RDP" in host["services"]:
                writer.writerow([f"{name} - RDP", "RDP", host["ip"], 3389, rdp_user, folder, ""])
    return buffer.getvalue().encode("utf-8-sig")


def export_inventory_csv(job: ScanJob) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow([
        "site", "vlan", "cidr", "hostname", "hostname_source", "role", "ip", "services", "open_ports",
        "os_family", "os_version", "os_confidence", "os_evidence", "resource_status",
        "cpu_cores", "ram_gb", "disk_root_gb", "disk_c_gb", "disk_free_gb", "web_urls",
    ])
    for host in job.results:
        resources = host.get("resources", {})
        writer.writerow([
            host.get("site", ""), host.get("vlan", ""), host.get("cidr", ""),
            host.get("hostname", ""), host.get("hostname_source", ""), host.get("role", ""), host.get("ip", ""),
            ",".join(host.get("services", [])), ",".join(str(p) for p in host.get("open_ports", [])),
            host.get("os_family", ""), host.get("os_version", ""), host.get("os_confidence", ""),
            host.get("os_evidence", ""), host.get("resource_status", ""),
            resources.get("cpu_cores", ""), resources.get("ram_gb", ""), resources.get("disk_root_gb", ""),
            resources.get("disk_c_gb", ""), resources.get("disk_free_gb", ""),
            ",".join(web.get("url", "") for web in host.get("web", [])),
        ])
    return buffer.getvalue().encode("utf-8-sig")


class Handler(BaseHTTPRequestHandler):
    server_version = f"NetAtlas/{APP_VERSION}"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8765")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store" if self.path.startswith("/api/") else "no-cache")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000:
            raise ValueError("Request is too large")
        return json.loads(self.rfile.read(length) or b"{}")

    def send_json(self, payload: object, status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        try:
            path = urlparse(self.path).path
            if path == "/api/remembered-hosts/role":
                payload = self.json_body()
                self.send_json(update_remembered_role(payload.get("site"), payload.get("ip"), payload.get("role")))
                return
            if path == "/api/scans":
                config = self.json_body()
                legacy_user = clean_text(config.pop("ssh_username", ""), 100)
                legacy_password = str(config.pop("ssh_password", ""))
                linux_password = str(config.pop("linux_ssh_password", legacy_password))
                windows_password = str(config.pop("windows_ssh_password", legacy_password))
                config["linux_ssh_username"] = clean_text(config.get("linux_ssh_username") or legacy_user, 100)
                config["windows_ssh_username"] = clean_text(config.get("windows_ssh_username") or legacy_user, 100)
                if max(len(linux_password), len(windows_password)) > 1024:
                    raise ValueError("SSH password is too long")
                if config.get("ssh_resources") and not paramiko:
                    raise ValueError("Password-based SSH support is not installed in this runtime")
                linux_partial = bool(config["linux_ssh_username"]) != bool(linux_password)
                windows_partial = bool(config["windows_ssh_username"]) != bool(windows_password)
                profile_ready = (config["linux_ssh_username"] and linux_password) or (config["windows_ssh_username"] and windows_password)
                if config.get("ssh_resources") and (linux_partial or windows_partial):
                    raise ValueError("Each SSH profile needs both a username and password")
                if config.get("ssh_resources") and not profile_ready:
                    raise ValueError("Configure at least one complete Linux or Windows SSH profile")
                build_address_plan(config)  # validate before creating a job
                job = ScanJob(
                    id=uuid.uuid4().hex[:12], config=config,
                    secrets={"linux_ssh_password": linux_password, "windows_ssh_password": windows_password},
                )
                with JOBS_LOCK:
                    JOBS[job.id] = job
                threading.Thread(target=run_scan, args=(job,), daemon=True, name=f"scan-{job.id}").start()
                self.send_json(job.public(), HTTPStatus.ACCEPTED)
                return
            match = re.fullmatch(r"/api/scans/([a-f0-9]+)/cancel", path)
            if match and match.group(1) in JOBS:
                JOBS[match.group(1)].cancelled = True
                self.send_json({"ok": True})
                return
            self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_json({"error": clean_text(exc, 500)}, HTTPStatus.BAD_REQUEST)

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path == "/api/health":
            self.send_json({
                "ok": True,
                "version": APP_VERSION,
                "runtime": "container" if Path("/.dockerenv").exists() else "local",
                "nmap": bool(shutil.which("nmap")),
                "ssh": bool(shutil.which("ssh")),
                "password_ssh": paramiko is not None,
                "winrm": os.name == "nt" and bool(shutil.which("powershell.exe")),
                "data_dir": str(DATA_DIR),
            })
            return
        if path == "/api/scans":
            with JOBS_LOCK:
                jobs = [job.public() for job in JOBS.values()]
            self.send_json(jobs)
            return
        if path == "/api/remembered-hosts":
            self.send_json(list_remembered_hosts())
            return
        match = re.fullmatch(r"/api/scans/([a-f0-9]+)", path)
        if match:
            job = JOBS.get(match.group(1))
            self.send_json(job.public() if job else {"error": "Scan not found"}, 200 if job else 404)
            return
        inventory = re.fullmatch(r"/api/scans/([a-f0-9]+)/inventory\.csv", path)
        if inventory:
            job = JOBS.get(inventory.group(1))
            if not job:
                self.send_json({"error": "Scan not found"}, 404)
                return
            data = export_inventory_csv(job)
            filename = f"NetAtlas-inventory-{datetime.now().strftime('%Y%m%d-%H%M')}.csv"
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        export = re.fullmatch(r"/api/scans/([a-f0-9]+)/export\.(mxtsessions|csv)", path)
        if export:
            job = JOBS.get(export.group(1))
            if not job:
                self.send_json({"error": "Scan not found"}, 404)
                return
            params = parse_qs(urlparse(self.path).query)
            legacy_ssh_user = params.get("ssh_user", [""])[0]
            linux_ssh_user = params.get("linux_ssh_user", [legacy_ssh_user])[0]
            windows_ssh_user = params.get("windows_ssh_user", [legacy_ssh_user])[0]
            rdp_user = params.get("rdp_user", [""])[0]
            data = export_mobaxterm(job, linux_ssh_user, rdp_user, windows_ssh_user) if export.group(2) == "mxtsessions" else export_csv(job, linux_ssh_user, rdp_user, windows_ssh_user)
            filename = f"NetAtlas-{datetime.now().strftime('%Y%m%d-%H%M')}.{export.group(2)}"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.serve_static(path)

    def serve_static(self, path: str) -> None:
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        target = (WEB_DIR / relative).resolve()
        if WEB_DIR.resolve() not in target.parents and target != WEB_DIR.resolve():
            self.send_error(404)
            return
        if not target.is_file():
            target = WEB_DIR / "index.html"
        mime = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json"}.get(target.suffix, "application/octet-stream")
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def load_saved_jobs() -> None:
    for path in sorted(DATA_DIR.glob("scan-*.json"))[-20:]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            job = ScanJob(id=data["id"], config=data.get("config", {}))
            for key in ("status", "created_at", "started_at", "finished_at", "total", "completed", "results", "errors", "current_phase"):
                if key in data:
                    setattr(job, key, data[key])
            for host in job.results:
                normalize_host_record(host)
            JOBS[job.id] = job
        except (OSError, json.JSONDecodeError, KeyError):
            continue


def main() -> None:
    parser = argparse.ArgumentParser(description="NetAtlas local network inventory")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    init_hosts_db()
    load_saved_jobs()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"NetAtlas is running at {url}")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nNetAtlas stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
