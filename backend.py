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
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    Fernet = None
    class InvalidToken(Exception):
        pass
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing
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
APP_VERSION = "1.2.10"
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
    """Use the resolved hostname as the default role, with a service fallback."""
    hostname = normalize_hostname(host.get("hostname"))
    if hostname:
        return hostname
    services = set(host.get("services", []))
    open_ports = set(host.get("open_ports", []))
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
    host.setdefault("ssh_username", "")
    host.setdefault("ssh_auth_status", "Not attempted" if 22 in host.get("open_ports", []) else "")
    host.setdefault("ssh_auth_method", "")
    host.setdefault("ssh_auth_error", "")
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
        checked = round((self.completed / self.total * 100), 1) if self.total else 0
        payload["progress"] = 100 if self.status == "complete" and self.finished_at else min(checked, 99)
        payload["summary"] = summarize(self.results)
        payload["breakdown"] = inventory_breakdown(self.results)
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


def inventory_breakdown(results: list[dict]) -> dict:
    sites: dict[str, dict[str, float | int]] = {}
    operating_systems: dict[str, int] = {}
    vlans: dict[tuple[str, str], int] = {}
    for host in results:
        site = clean_text(host.get("site"), 60) or "Unassigned"
        vlan = clean_text(host.get("vlan"), 60) or "No VLAN"
        os_name = clean_text(host.get("os_version") or host.get("os_family"), 180) or "Unknown"
        operating_systems[os_name] = operating_systems.get(os_name, 0) + 1
        vlans[(site, vlan)] = vlans.get((site, vlan), 0) + 1
        totals = sites.setdefault(site, {"servers": 0, "cpu_cores": 0.0, "ram_gb": 0.0, "disk_gb": 0.0, "resource_hosts": 0})
        totals["servers"] += 1
        resources = host.get("resources") or {}

        def number(value: object) -> float:
            match = re.search(r"-?\d+(?:\.\d+)?", str(value or ""))
            return float(match.group(0)) if match else 0.0

        cpu = number(resources.get("cpu_cores"))
        ram = number(resources.get("ram_gb"))
        disk_value = resources.get("disk_c_gb") or resources.get("disk_root_gb")
        disk_text = str(disk_value or "")
        disk = number(disk_text.split("/", 1)[-1] if "/" in disk_text else disk_text)
        if cpu or ram or disk:
            totals["resource_hosts"] += 1
        totals["cpu_cores"] += cpu
        totals["ram_gb"] += ram
        totals["disk_gb"] += disk
    return {
        "sites": [{"site": site, **values} for site, values in sorted(sites.items(), key=lambda item: item[0].lower())],
        "operating_systems": [{"name": name, "servers": count} for name, count in sorted(operating_systems.items(), key=lambda item: (-item[1], item[0].lower()))],
        "vlans": [{"site": site, "vlan": vlan, "servers": count} for (site, vlan), count in sorted(vlans.items(), key=lambda item: (item[0][0].lower(), item[0][1].lower()))],
    }


def build_address_plan(config: dict) -> list[dict]:
    plan: list[dict] = []
    seen: set[tuple[str, str]] = set()
    max_addresses = int(config.get("max_addresses", 65536))
    scan_mode = clean_text(config.get("scan_mode"), 24).lower() or "combined"
    if scan_mode not in {"combined", "direct_only"}:
        raise ValueError("Scan mode must be combined or direct_only")
    sites = [] if scan_mode == "direct_only" else config.get("sites", [])
    for site in sites:
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
    direct_group = clean_text(config.get("direct_target_group"), 60) or "Direct targets"
    direct_targets = config.get("direct_targets", [])
    if direct_targets and not isinstance(direct_targets, list):
        raise ValueError("Direct targets must be a list")
    for index, target in enumerate(direct_targets):
        if not isinstance(target, dict):
            raise ValueError("Each direct target must contain an IPv4 address")
        raw_ip = clean_text(target.get("ip") or target.get("cidr"), 64)
        try:
            network = ipaddress.ip_network(raw_ip, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid direct target IPv4 address or scope: {raw_ip or 'empty line'}") from exc
        if network.version != 4:
            raise ValueError(f"IPv6 is not supported yet: {raw_ip}")
        if network.num_addresses > 4096:
            raise ValueError(f"{raw_ip} is too large; use networks /20 or smaller")
        target_name = clean_text(target.get("name"), 60)
        for address in network.hosts():
            text_address = str(address)
            key = (direct_group, text_address)
            if key in seen:
                continue
            seen.add(key)
            plan.append({"site": direct_group, "vlan": "", "cidr": str(network), "ip": text_address,
                         "direct_target": True, "target_label": target_name})
            if len(plan) > max_addresses:
                raise ValueError(f"Address plan exceeds the safety limit of {max_addresses:,} addresses")
    if not plan:
        raise ValueError("Add at least one valid IPv4 subnet or direct server target")
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
        "ssh_username": "",
        "ssh_auth_status": "Not attempted" if 22 in opened else "",
        "ssh_auth_method": "",
        "ssh_auth_error": "",
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
                if hostname and not host.get("hostname"):
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
                if hostname and not host.get("hostname"):
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


def ssh_exception_text(exc: Exception) -> str:
    if paramiko is not None and isinstance(exc, paramiko.AuthenticationException):
        return "credentials rejected by both password and keyboard-interactive authentication"
    if paramiko is not None and isinstance(exc, paramiko.ssh_exception.NoValidConnectionsError):
        return "connection failed before authentication"
    if paramiko is not None and isinstance(exc, paramiko.ssh_exception.IncompatiblePeer):
        return "SSH algorithms are incompatible with this server"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "SSH handshake or authentication timed out"
    detail = clean_text(exc, 140)
    return detail or exc.__class__.__name__


def transient_ssh_error(exc: Exception) -> bool:
    """Return True only for failures where one fresh connection retry can help."""
    if isinstance(exc, (socket.timeout, TimeoutError, ConnectionError)):
        return True
    if paramiko is None:
        return False
    if isinstance(exc, (paramiko.AuthenticationException, paramiko.ssh_exception.IncompatiblePeer)):
        return False
    return isinstance(exc, (paramiko.SSHException, paramiko.ssh_exception.NoValidConnectionsError))


def connect_ssh_password(client: object, ip: str, username: str, password: str) -> str:
    """Connect with password auth, then retry keyboard-interactive password prompts."""
    try:
        client.connect(
            hostname=ip, port=22, username=username, password=password,
            timeout=8, banner_timeout=10, auth_timeout=10,
            allow_agent=False, look_for_keys=False,
        )
        return "password"
    except paramiko.AuthenticationException as password_error:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise password_error

        def password_handler(_title: str, _instructions: str, prompts: list[tuple[str, bool]]) -> list[str]:
            responses = []
            for prompt, echo in prompts:
                prompt_text = prompt.lower()
                responses.append(password if (not echo or "password" in prompt_text or "passcode" in prompt_text) else "")
            return responses

        try:
            transport.auth_interactive(username, password_handler)
        except paramiko.AuthenticationException as interactive_error:
            raise interactive_error from password_error
        if not transport.is_authenticated():
            raise password_error
        return "keyboard-interactive"


def try_ssh_profile(host: dict, username: str, password: str, profile: str) -> tuple[bool, str]:
    if not username or not password:
        return False, "not configured"
    for attempt in range(2):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            auth_method = connect_ssh_password(client, host["ip"], username, password)
            host["ssh_username"] = username
            host["ssh_auth_status"] = "Authenticated"
            host["ssh_auth_method"] = auth_method
            host["ssh_auth_error"] = ""
            windows_first = profile == "Windows" or host.get("os_family") == "Windows" or "windows" in host.get("ssh_banner", "").lower()
            if windows_first:
                enriched = apply_windows_ssh(host, client) or apply_linux_ssh(host, client)
            else:
                enriched = apply_linux_ssh(host, client) or apply_windows_ssh(host, client)
            if enriched:
                host["credential_profile"] = f"{profile} SSH profile"
                return True, ""
            host["resource_status"] = "SSH authenticated, but inventory commands were unavailable or restricted"
            host["ssh_auth_status"] = "Authenticated; inventory commands unavailable"
            return True, ""
        except Exception as exc:
            if attempt == 0 and transient_ssh_error(exc):
                time.sleep(0.2)
                continue
            suffix = " after 2 attempts" if attempt else ""
            return False, ssh_exception_text(exc) + suffix
        finally:
            client.close()
    return False, "SSH connection failed after 2 attempts"


def enrich_ssh_resources(host: dict, linux_user: str, linux_password: str, windows_user: str, windows_password: str) -> None:
    if paramiko is None or 22 not in host["open_ports"]:
        return
    profiles = [
        ("Linux", linux_user, linux_password),
        ("Windows", windows_user, windows_password),
    ]
    if host.get("os_family") == "Windows":
        profiles.reverse()
    preferred = next((username for _profile, username, _password in profiles if username), "")
    if preferred:
        host["ssh_username"] = preferred
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
        host["ssh_auth_status"] = "Authentication or SSH negotiation failed"
        host["ssh_auth_error"] = "; ".join(errors)


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
                site_locked INTEGER NOT NULL DEFAULT 0,
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
                ssh_username TEXT NOT NULL DEFAULT '',
                ssh_auth_status TEXT NOT NULL DEFAULT '',
                ssh_auth_method TEXT NOT NULL DEFAULT '',
                ssh_auth_error TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_scan_id TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (site, ip)
            )
            """
        )
        existing_columns = {row["name"] for row in connection.execute("PRAGMA table_info(remembered_hosts)")}
        migrations = {
            "ssh_username": "TEXT NOT NULL DEFAULT ''",
            "ssh_auth_status": "TEXT NOT NULL DEFAULT ''",
            "ssh_auth_method": "TEXT NOT NULL DEFAULT ''",
            "ssh_auth_error": "TEXT NOT NULL DEFAULT ''",
            "site_locked": "INTEGER NOT NULL DEFAULT 0",
            "system_id": "TEXT NOT NULL DEFAULT ''",
            "system_position": "INTEGER NOT NULL DEFAULT 0",
            "reachable": "INTEGER",
            "last_checked": "TEXT NOT NULL DEFAULT ''",
            "added_at": "TEXT NOT NULL DEFAULT ''",
            "direct_target": "INTEGER NOT NULL DEFAULT 0",
            "target_label": "TEXT NOT NULL DEFAULT ''",
            "deletion_candidate": "INTEGER NOT NULL DEFAULT 0",
            "flagged_at": "TEXT NOT NULL DEFAULT ''",
        }
        for column, declaration in migrations.items():
            if column not in existing_columns:
                connection.execute(f"ALTER TABLE remembered_hosts ADD COLUMN {column} {declaration}")
        connection.execute("CREATE INDEX IF NOT EXISTS remembered_hosts_hostname ON remembered_hosts(hostname)")
        connection.execute("CREATE INDEX IF NOT EXISTS remembered_hosts_last_seen ON remembered_hosts(last_seen DESC)")
        connection.execute("UPDATE remembered_hosts SET added_at=first_seen WHERE added_at=''")
        connection.execute("UPDATE remembered_hosts SET direct_target=1 WHERE cidr LIKE '%/32'")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS systems (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, position INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS discoveries (site TEXT NOT NULL, ip TEXT NOT NULL, host_json TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, dismissed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(site, ip));
            CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
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
            site = clean_text(host.get("site"), 60)
            cidr = clean_text(host.get("cidr"), 64)
            if host.get("direct_target") or cidr.endswith("/32"):
                locked = connection.execute(
                    "SELECT site FROM remembered_hosts WHERE ip=? AND site_locked=1 AND direct_target=1 ORDER BY last_seen DESC LIMIT 1",
                    (clean_text(host.get("ip"), 64),),
                ).fetchone()
                if locked:
                    site = locked["site"]
            connection.execute(
                """
                INSERT INTO remembered_hosts (
                    site, ip, hostname, role, vlan, cidr, services_json, open_ports_json,
                    web_json, os_family, os_version, os_confidence, os_evidence,
                    resources_json, resource_status, ssh_username, ssh_auth_status,
                    ssh_auth_method, ssh_auth_error, first_seen, last_seen, last_scan_id, direct_target, target_label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(site, ip) DO UPDATE SET
                    hostname=excluded.hostname,
                    role=CASE WHEN remembered_hosts.role_locked=1 THEN remembered_hosts.role ELSE excluded.role END,
                    vlan=excluded.vlan,
                    cidr=excluded.cidr,
                    direct_target=excluded.direct_target,
                    target_label=excluded.target_label,
                    services_json=excluded.services_json,
                    open_ports_json=excluded.open_ports_json,
                    web_json=excluded.web_json,
                    os_family=CASE WHEN excluded.os_family IN ('', 'Unknown') OR (excluded.os_confidence < remembered_hosts.os_confidence AND remembered_hosts.os_version<>'') THEN remembered_hosts.os_family ELSE excluded.os_family END,
                    os_version=CASE WHEN excluded.os_confidence < remembered_hosts.os_confidence AND remembered_hosts.os_version<>'' THEN remembered_hosts.os_version ELSE excluded.os_version END,
                    os_confidence=MAX(remembered_hosts.os_confidence, excluded.os_confidence),
                    os_evidence=CASE WHEN excluded.os_confidence < remembered_hosts.os_confidence THEN remembered_hosts.os_evidence ELSE excluded.os_evidence END,
                    resources_json=CASE WHEN excluded.resources_json='{}' THEN remembered_hosts.resources_json ELSE excluded.resources_json END,
                    resource_status=CASE WHEN excluded.resources_json='{}' AND remembered_hosts.resources_json<>'{}' THEN remembered_hosts.resource_status ELSE excluded.resource_status END,
                    ssh_username=excluded.ssh_username,
                    ssh_auth_status=excluded.ssh_auth_status,
                    ssh_auth_method=excluded.ssh_auth_method,
                    ssh_auth_error=excluded.ssh_auth_error,
                    last_seen=excluded.last_seen,
                    last_scan_id=excluded.last_scan_id,
                    seen_count=remembered_hosts.seen_count+1,
                    reachable=1, last_checked=excluded.last_seen
                """,
                (
                    site, clean_text(host.get("ip"), 64), host["hostname"], role,
                    clean_text(host.get("vlan"), 60), cidr,
                    json.dumps(host.get("services", [])), json.dumps(host.get("open_ports", [])),
                    json.dumps(host.get("web", [])), clean_text(host.get("os_family"), 40),
                    clean_text(host.get("os_version"), 180), int(host.get("os_confidence") or 0),
                    clean_text(host.get("os_evidence"), 180), json.dumps(host.get("resources", {})),
                    clean_text(host.get("resource_status"), 240), clean_text(host.get("ssh_username"), 100),
                    clean_text(host.get("ssh_auth_status"), 160), clean_text(host.get("ssh_auth_method"), 80),
                    clean_text(host.get("ssh_auth_error"), 300), observed, observed, job.id,
                    int(bool(host.get("direct_target") or cidr.endswith("/32"))), clean_text(host.get("target_label"), 60),
                ),
            )
            connection.execute("UPDATE remembered_hosts SET reachable=1, last_checked=?, added_at=CASE WHEN added_at='' THEN ? ELSE added_at END WHERE site=? AND ip=?", (observed, utc_now(), site, clean_text(host.get("ip"), 64)))
            connection.execute("DELETE FROM discoveries WHERE site=? AND ip=?", (site, clean_text(host.get("ip"), 64)))
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
        host["site_locked"] = bool(host.get("site_locked"))
        host["direct_target"] = bool(host.get("direct_target"))
        host["deletion_candidate"] = bool(host.get("deletion_candidate"))
        normalize_host_record(host)
        hosts.append(host)
    system_map = {system["id"]: system for system in list_systems()}
    for host in hosts:
        system = system_map.get(host.get("system_id"), {})
        host["system_name"] = system.get("name", "")
        host["system_order"] = system.get("position", 2147483647)
        # Use the entire system catalog so selected-only exports retain their paths.
        host["system_folder"] = system_folder(host["system_name"], [s["name"] for s in system_map.values()])
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


def update_remembered_site(site: object, ip: object, new_site: object) -> dict:
    old_site = clean_text(site, 60)
    address = clean_text(ip, 64)
    site_name = clean_text(new_site, 60)
    if not old_site or not address or not site_name:
        raise ValueError("Current site, IP address and new site are required")
    ipaddress.ip_address(address)
    init_hosts_db()
    connection = hosts_db_connection()
    try:
        row = connection.execute("SELECT cidr, direct_target FROM remembered_hosts WHERE site=? AND ip=?", (old_site, address)).fetchone()
        if not row:
            raise ValueError("Remembered host was not found")
        if not row["direct_target"] and not clean_text(row["cidr"], 64).endswith("/32"):
            raise ValueError("Only direct server targets can be moved to another site")
        try:
            connection.execute(
                "UPDATE remembered_hosts SET site=?, site_locked=1 WHERE site=? AND ip=?",
                (site_name, old_site, address),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("That site already contains this IP address") from exc
        connection.commit()
    finally:
        connection.close()
    return {"old_site": old_site, "site": site_name, "ip": address, "site_locked": True}


def flag_remembered_host(payload: dict) -> dict:
    site, ip = clean_text(payload.get("site"), 60), clean_text(payload.get("ip"), 64)
    if not site or not ip or not isinstance(payload.get("flagged"), bool):
        raise ValueError("Site, IP and a boolean flagged value are required")
    flagged = payload["flagged"]
    init_hosts_db()
    with closing(hosts_db_connection()) as connection, connection:
        if connection.execute("UPDATE remembered_hosts SET deletion_candidate=?, flagged_at=? WHERE site=? AND ip=?",
                              (int(flagged), utc_now() if flagged else "", site, ip)).rowcount != 1:
            raise ValueError("Remembered host was not found")
    return {"ok": True}


def delete_remembered_host(site: object, ip: object) -> dict:
    site_name = clean_text(site, 60)
    address = clean_text(ip, 64)
    if not site_name or not address:
        raise ValueError("Site and IP address are required")
    ipaddress.ip_address(address)
    init_hosts_db()
    connection = hosts_db_connection()
    try:
        cursor = connection.execute("DELETE FROM remembered_hosts WHERE site=? AND ip=?", (site_name, address))
        if cursor.rowcount != 1:
            raise ValueError("Remembered host was not found")
        connection.commit()
    finally:
        connection.close()
    return {"ok": True, "site": site_name, "ip": address}


def list_systems() -> list[dict]:
    init_hosts_db()
    with closing(hosts_db_connection()) as connection:
        return sorted([dict(row) for row in connection.execute("SELECT * FROM systems")], key=lambda system: system_name_key(system["name"]))


def edit_system(payload: dict) -> dict:
    init_hosts_db()
    action = payload.get("action", "create")
    system_id = clean_text(payload.get("id"), 40)
    with closing(hosts_db_connection()) as connection, connection:
        if action in {"create", "rename"}:
            name = clean_text(payload.get("name"), 80)
            if not name or any(c in name for c in "\\/#%=\r\n"):
                raise ValueError("Use a system name without slashes, #, %, or =")
            try:
                if action == "create":
                    system_id = uuid.uuid4().hex[:12]
                    connection.execute("INSERT INTO systems VALUES (?, ?, (SELECT COALESCE(MAX(position), -1)+1 FROM systems))", (system_id, name))
                elif connection.execute("UPDATE systems SET name=? WHERE id=?", (name, system_id)).rowcount != 1:
                    raise ValueError("System not found")
            except sqlite3.IntegrityError as exc:
                raise ValueError("A system with that name already exists") from exc
        elif action == "delete":
            connection.execute("UPDATE remembered_hosts SET system_id='', system_position=0 WHERE system_id=?", (system_id,))
            connection.execute("DELETE FROM systems WHERE id=?", (system_id,))
        elif action == "reorder":
            ids = payload.get("ids")
            current = {row[0] for row in connection.execute("SELECT id FROM systems")}
            if not isinstance(ids, list) or len(ids) != len(current) or set(ids) != current:
                raise ValueError("Include every system exactly once")
            for position, identifier in enumerate(ids):
                connection.execute("UPDATE systems SET position=? WHERE id=?", (position, identifier))
        else:
            raise ValueError("Unknown system action")
    return {"ok": True, "id": system_id}


def move_system_hosts(payload: dict) -> dict:
    system_id = clean_text(payload.get("system_id"), 40)
    hosts = ordered_export_hosts(selected_hosts_from_list(list_remembered_hosts(), payload.get("hosts"), "remembered inventory"))
    keys = {(host["site"], host["ip"]) for host in hosts}
    with closing(hosts_db_connection()) as connection, connection:
        if system_id and not connection.execute("SELECT id FROM systems WHERE id=?", (system_id,)).fetchone():
            raise ValueError("System not found")
        ordered = [(row["site"], row["ip"]) for row in connection.execute(
            "SELECT site, ip FROM remembered_hosts WHERE system_id=? ORDER BY system_position, hostname, ip", (system_id,)
        ) if (row["site"], row["ip"]) not in keys]
        position = int(payload.get("position", len(ordered)))
        position = min(max(0, position), len(ordered))
        ordered[position:position] = [(host["site"], host["ip"]) for host in hosts]
        for index, (site, ip) in enumerate(ordered):
            connection.execute("UPDATE remembered_hosts SET system_id=?, system_position=? WHERE site=? AND ip=?", (system_id, index, site, ip))
    return {"ok": True}


def remembered_overview() -> dict:
    hosts = list_remembered_hosts()
    reachable = [host for host in hosts if host.get("reachable") == 1]
    summary = summarize(hosts)
    summary.update({"reachable": len(reachable), "unreachable": sum(host.get("reachable") == 0 for host in hosts),
                    "unchecked": sum(host.get("reachable") is None for host in hosts)})
    services = summarize(reachable)
    return {"summary": summary, "reachable_services": services, "breakdown": inventory_breakdown(hosts),
            "latest_added": sorted(hosts, key=lambda h: (h["added_at"], h["site"], h["ip"]), reverse=True)[:10],
            "last_checked": max((host.get("last_checked", "") for host in hosts), default="")}


def inventory_key(host: dict, known: list[dict]) -> tuple[str, str]:
    if host.get("direct_target") or str(host.get("cidr", "")).endswith("/32"):
        locked = next((row for row in known if row["ip"] == host["ip"] and row.get("site_locked") and row.get("direct_target")), None)
        if locked:
            return locked["site"], host["ip"]
    return host["site"], host["ip"]


def record_scan_inventory(job: ScanJob, plan: list[dict]) -> None:
    known = list_remembered_hosts()
    known_keys = {(host["site"], host["ip"]) for host in known}
    # Only a complete, error-free scan can mark a previously known host offline.
    if not job.cancelled and not job.errors and job.completed == len(plan):
        answered = {inventory_key(host, known) for host in job.results}
        with closing(hosts_db_connection()) as connection, connection:
            for item in plan:
                key = inventory_key(item, known)
                if key in known_keys:
                    connection.execute("UPDATE remembered_hosts SET reachable=?, last_checked=? WHERE site=? AND ip=?", (int(key in answered), utc_now(), *key))
    if job.config.get("background_scan"):
        existing, new = [], []
        for host in job.results:
            normalize_host_record(host)
            key = inventory_key(host, known)
            if key in known_keys:
                old = next(row for row in known if (row["site"], row["ip"]) == key)
                if not host["hostname"]:
                    host["hostname"] = old["hostname"]
                    host["role"] = infer_host_role(host)
                existing.append(host)
            else:
                new.append(host)
        remember_job_hosts(ScanJob(id=job.id, config={}, results=existing))
        with closing(hosts_db_connection()) as connection, connection:
            for host in new:
                if not host.get("hostname"):
                    continue
                observed = host.get("discovered_at") or utc_now()
                connection.execute("""INSERT INTO discoveries(site, ip, host_json, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(site, ip) DO UPDATE SET host_json=excluded.host_json, last_seen=excluded.last_seen""",
                    (host["site"], host["ip"], json.dumps(host), observed, observed))
    else:
        for host in job.results:
            key = inventory_key(host, known)
            if key in known_keys and not normalize_hostname(host.get("hostname")):
                host["hostname"] = next(row["hostname"] for row in known if (row["site"], row["ip"]) == key)
                host["role"] = infer_host_role(host)
        remember_job_hosts(job)


def list_discoveries() -> list[dict]:
    init_hosts_db()
    with closing(hosts_db_connection()) as connection:
        rows = connection.execute("""SELECT d.* FROM discoveries d WHERE dismissed=0 AND NOT EXISTS
            (SELECT 1 FROM remembered_hosts h WHERE h.site=d.site AND h.ip=d.ip) ORDER BY first_seen DESC""").fetchall()
    return [{**json.loads(row["host_json"]), "first_seen": row["first_seen"], "last_seen": row["last_seen"]} for row in rows]


def review_discoveries(payload: dict) -> dict:
    hosts = selected_hosts_from_list(list_discoveries(), payload.get("hosts"), "new discoveries")
    action = payload.get("action")
    if action == "approve":
        # Preserve the original discovery date as the inventory's first-seen date.
        for host in hosts:
            host["discovered_at"] = host["first_seen"]
        remember_job_hosts(ScanJob(id="approved-" + uuid.uuid4().hex[:8], config={}, results=hosts))
        with closing(hosts_db_connection()) as connection, connection:
            for host in hosts:
                connection.execute("UPDATE remembered_hosts SET last_seen=?, last_checked=? WHERE site=? AND ip=?", (host["last_seen"], host["last_seen"], host["site"], host["ip"]))
    elif action == "dismiss":
        with closing(hosts_db_connection()) as connection, connection:
            for host in hosts:
                connection.execute("UPDATE discoveries SET dismissed=1 WHERE site=? AND ip=?", (host["site"], host["ip"]))
    else:
        raise ValueError("Choose approve or dismiss")
    return {"ok": True, "count": len(hosts)}


def prepare_scan(config: dict) -> tuple[dict, dict]:
    config = dict(config)
    config.pop("background_scan", None)
    legacy_user = clean_text(config.pop("ssh_username", ""), 100)
    legacy_password = str(config.pop("ssh_password", ""))
    secrets = {key: str(config.pop(key, legacy_password)) for key in ("linux_ssh_password", "windows_ssh_password")}
    config = {key: value for key, value in config.items() if key not in SENSITIVE_CONFIG_KEYS}
    for family in ("linux", "windows"):
        config[f"{family}_ssh_username"] = clean_text(config.get(f"{family}_ssh_username") or legacy_user, 100)
    if any(len(value) > 1024 for value in secrets.values()):
        raise ValueError("SSH password is too long")
    if config.get("ssh_resources"):
        if not paramiko:
            raise ValueError("Password-based SSH support is not installed")
        pairs = [(config[f"{family}_ssh_username"], secrets[f"{family}_ssh_password"]) for family in ("linux", "windows")]
        if any(bool(user) != bool(password) for user, password in pairs):
            raise ValueError("Each SSH profile needs both a username and password")
        if not any(user and password for user, password in pairs):
            raise ValueError("Configure at least one complete Linux or Windows SSH profile")
    build_address_plan(config)
    float(config.get("timeout", 0.5))
    int(config.get("concurrency", 128))
    return config, secrets


SCHEDULE_LOCK = threading.RLock()
SCHEDULE: dict = {"enabled": False, "interval_minutes": 60, "config": {}, "next_run": None, "active_job": None, "last_run": None, "error": ""}
SCHEDULE_SECRETS: dict = {}


def schedule_cipher() -> Fernet:
    if Fernet is None:
        raise ValueError("Install requirements.txt to save encrypted schedule credentials")
    path = HOSTS_DB.parent / "schedule.key"
    try:
        with path.open("xb") as stream:
            stream.write(Fernet.generate_key())
        path.chmod(0o600)
    except FileExistsError:
        pass
    return Fernet(path.read_bytes())


def save_schedule() -> None:
    stored = {key: SCHEDULE[key] for key in ("enabled", "interval_minutes", "config", "next_run", "last_run")}
    stored["credentials"] = schedule_cipher().encrypt(json.dumps(SCHEDULE_SECRETS).encode()).decode() if SCHEDULE_SECRETS else ""
    with closing(hosts_db_connection()) as connection, connection:
        connection.execute("INSERT OR REPLACE INTO settings VALUES ('background_schedule', ?)", (json.dumps(stored),))


def load_schedule() -> None:
    with SCHEDULE_LOCK, closing(hosts_db_connection()) as connection:
        row = connection.execute("SELECT value FROM settings WHERE name='background_schedule'").fetchone()
        if not row:
            return
        try:
            stored = json.loads(row[0])
            encrypted = stored.pop("credentials")
            credentials = json.loads(schedule_cipher().decrypt(encrypted.encode())) if encrypted else {}
            SCHEDULE.update(stored)
            SCHEDULE_SECRETS.clear()
            SCHEDULE_SECRETS.update(credentials)
        except (InvalidToken, ValueError, KeyError, OSError):
            SCHEDULE.update(enabled=False, error="Saved schedule credentials could not be opened. Re-enter them to enable scheduling.")


def schedule_public() -> dict:
    with SCHEDULE_LOCK:
        result = dict(SCHEDULE)
        result["config"] = {key: value for key, value in result["config"].items() if key not in SENSITIVE_CONFIG_KEYS}
        job = JOBS.get(result.get("active_job"))
        result["running"] = bool(job and job.status in {"queued", "running"})
        result["job"] = {"id": job.id, "status": job.status, "progress": job.public()["progress"], "phase": job.current_phase} if job else None
        return result


def configure_schedule(payload: dict) -> dict:
    with SCHEDULE_LOCK:
        old_schedule, old_secrets = dict(SCHEDULE), dict(SCHEDULE_SECRETS)
        if payload.get("action") == "stop":
            SCHEDULE.update(enabled=False, next_run=None)
            job = JOBS.get(SCHEDULE.get("active_job"))
            if job and job.status in {"queued", "running"}:
                job.cancelled = True
            SCHEDULE_SECRETS.clear()
        else:
            interval = int(payload.get("interval_minutes", 60))
            if not 1 <= interval <= 10080:
                raise ValueError("Interval must be between 1 and 10080 minutes")
            config, secrets = prepare_scan(payload.get("config", {}))
            if not config.get("ssh_resources"):
                secrets = {}
            SCHEDULE_SECRETS.clear()
            SCHEDULE_SECRETS.update(secrets)
            SCHEDULE.update(enabled=True, interval_minutes=interval, config=config, next_run=time.time(), error="")
        try:
            save_schedule()
        except Exception:
            SCHEDULE.clear()
            SCHEDULE.update(old_schedule)
            SCHEDULE_SECRETS.clear()
            SCHEDULE_SECRETS.update(old_secrets)
            raise
        return schedule_public()


def scheduler_tick() -> None:
    with SCHEDULE_LOCK, JOBS_LOCK:
        active = JOBS.get(SCHEDULE.get("active_job"))
        if active and active.status not in {"queued", "running"}:
            SCHEDULE.update(active_job=None, last_run=active.finished_at, error="; ".join(active.errors),
                            next_run=time.time() + SCHEDULE["interval_minutes"] * 60 if SCHEDULE["enabled"] else None)
            save_schedule()
        if not SCHEDULE["enabled"] or SCHEDULE["next_run"] is None or time.time() < SCHEDULE["next_run"]:
            return
        # Do not overlap scans or overload authentication services.
        if any(job.status in {"queued", "running"} for job in JOBS.values()):
            return
        job = ScanJob(id=uuid.uuid4().hex[:12], config={**SCHEDULE["config"], "background_scan": True}, secrets=dict(SCHEDULE_SECRETS))
        JOBS[job.id] = job
        SCHEDULE.update(active_job=job.id, next_run=None)
        threading.Thread(target=run_scan, args=(job,), daemon=True, name=f"background-{job.id}").start()


def scheduler_loop() -> None:
    while True:
        try:
            scheduler_tick()
        except Exception as exc:
            with SCHEDULE_LOCK:
                SCHEDULE["error"] = clean_text(exc)
        time.sleep(2)


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
            with ThreadPoolExecutor(max_workers=min(2, workers)) as pool:
                list(pool.map(enrich_nmap, job.results))

        linux_user = clean_text(job.config.get("linux_ssh_username"), 100)
        windows_user = clean_text(job.config.get("windows_ssh_username"), 100)
        for host in job.results:
            if 22 not in host.get("open_ports", []):
                continue
            if host.get("os_family") == "Windows":
                host["ssh_username"] = windows_user or linux_user
            else:
                host["ssh_username"] = linux_user or windows_user

        if not job.cancelled and job.config.get("ssh_resources"):
            job.current_phase = "Collecting Linux and Windows resources over SSH"
            linux_password = str(job.secrets.get("linux_ssh_password", ""))
            windows_password = str(job.secrets.get("windows_ssh_password", ""))
            with ThreadPoolExecutor(max_workers=min(4, workers)) as pool:
                list(pool.map(lambda h: enrich_ssh_resources(h, linux_user, linux_password, windows_user, windows_password), job.results))

        if not job.cancelled and job.config.get("windows_resources"):
            job.current_phase = "Collecting Windows resources over WinRM"
            with ThreadPoolExecutor(max_workers=min(4, workers)) as pool:
                list(pool.map(lambda h: enrich_windows_resources(h, bool(job.config.get("winrm_ssl"))), job.results))

        for host in job.results:
            host["hostname"] = normalize_hostname(host.get("hostname"))
            host["role"] = infer_host_role(host)
        job.results.sort(key=lambda r: (r["site"].lower(), ipaddress.ip_address(r["ip"])))
        if not job.cancelled:
            job.current_phase = "Updating remembered hosts"
            try:
                record_scan_inventory(job, plan)
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


def selected_export_hosts(job: ScanJob, selection: object) -> list[dict]:
    return selected_hosts_from_list(job.results, selection, "this scan")


def selected_hosts_from_list(source: list[dict], selection: object, source_name: str) -> list[dict]:
    if not isinstance(selection, list) or not selection:
        raise ValueError("Select at least one host to export")
    keys: set[tuple[str, str]] = set()
    for item in selection:
        if not isinstance(item, dict):
            raise ValueError("Invalid host selection")
        site, ip = clean_text(item.get("site"), 120), clean_text(item.get("ip"), 64)
        if not site or not ip:
            raise ValueError("Each selected host needs a site and IP address")
        keys.add((site, ip))
    hosts = [host for host in source if (clean_text(host.get("site"), 120), clean_text(host.get("ip"), 64)) in keys]
    if not hosts:
        raise ValueError(f"None of the selected hosts belong to {source_name}")
    return hosts


def system_name_key(name: str) -> tuple:
    """Case-insensitive natural ordering: RMS-2 precedes RMS-10."""
    return tuple(int(part) if part.isdigit() else part.casefold() for part in re.split(r"(\d+)", name))


def system_folder(name: str, system_names: list[str]) -> str:
    name = name or "Unassigned"
    if re.fullmatch(r"\d+-\d+", name):
        return f"RAFAEL\\{safe_name(name)}"
    parts = name.split("-")
    catalog = sorted({item for item in system_names if item}, key=lambda item: (system_name_key(item), item))
    parents = []
    # Shared hyphen prefixes become parents, while the full name stays the leaf.
    for depth in range(1, len(parts)):
        prefix = "-".join(parts[:depth]).casefold() + "-"
        matches = [item for item in catalog if item.casefold().startswith(prefix)]
        if len(matches) < 2:
            break
        # Mixed-case system names must share a single parent, not RMS and rms.
        parents.append(safe_name(matches[0].split("-")[depth - 1]))
    return "\\".join([*parents, safe_name(name)])


def session_folder(host: dict, system_names: list[str] | None = None) -> str:
    if "system_id" in host:
        return host.get("system_folder") or system_folder(host.get("system_name"), system_names or [])
    folder = safe_name(host["site"])
    return f"{folder}\\{safe_name(host['vlan'])}" if host.get("vlan") else folder


def ordered_export_hosts(hosts: list[dict]) -> list[dict]:
    return sorted(hosts, key=lambda host: (system_name_key(host.get("system_name") or "Unassigned"),
                  int(host.get("system_position", 0)), str(host.get("hostname", "")).lower(), host["site"], host["ip"]))


def export_mobaxterm(job: ScanJob, linux_ssh_user: str = "", rdp_user: str = "", windows_ssh_user: str = "", hosts: list[dict] | None = None) -> bytes:
    sections: dict[str, list[tuple[str, str]]] = {}
    system_names = [host.get("system_name", "") for host in job.results]
    for host in ordered_export_hosts(job.results if hosts is None else hosts):
        family = host.get("os_family")
        folder = session_folder(host, system_names)
        sessions: list[tuple[str, str]] = []
        base = safe_name(host.get("role") or host.get("hostname") or host["ip"])
        observed_ssh_user = clean_text(host.get("ssh_username"), 100)
        if family == "Windows":
            sessions.append((base, ssh_session(host, windows_ssh_user or observed_ssh_user or linux_ssh_user)))
            sessions.append((base, rdp_session(host, rdp_user)))
        elif family == "Linux":
            sessions.append((base, ssh_session(host, linux_ssh_user or observed_ssh_user)))
        else:
            if "SSH" in host["services"]:
                sessions.append((base, ssh_session(host, observed_ssh_user or linux_ssh_user or windows_ssh_user)))
            if "RDP" in host["services"]:
                sessions.append((base, rdp_session(host, rdp_user)))
        if sessions:
            parts = folder.split("\\")
            for depth in range(1, len(parts)):
                sections.setdefault("\\".join(parts[:depth]), [])
            sections.setdefault(folder, []).extend(sessions)
    lines = ["[Bookmarks]", "SubRep=NetAtlas", "ImgNum=41", ""]
    for index, folder in enumerate(sections, 1):
        lines += [f"[Bookmarks_{index}]", f"SubRep={folder}", "ImgNum=41"]
        used: set[str] = set()
        for name, value in sections[folder]:
            unique, duplicate = name, 1
            while unique.casefold() in used:
                duplicate += 1
                unique = f"{name} ({duplicate})"
            used.add(unique.casefold())
            lines.append(f"{unique}={value}")
        lines.append("")
    return "\r\n".join(lines).encode("cp1252", "replace")


def export_csv(job: ScanJob, linux_ssh_user: str = "", rdp_user: str = "", windows_ssh_user: str = "", hosts: list[dict] | None = None) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["name", "protocol", "host", "port", "username", "folder", "url", "role", "system"])
    system_names = [host.get("system_name", "") for host in job.results]
    for host in ordered_export_hosts(job.results if hosts is None else hosts):
        family = host.get("os_family")
        folder = f"NetAtlas\\{session_folder(host, system_names)}"
        system = host.get("system_name") or ("Unassigned" if "system_id" in host else "")
        name = host.get("hostname") or host["ip"]
        role = host.get("role") or infer_host_role(host)
        observed_ssh_user = clean_text(host.get("ssh_username"), 100)
        if family == "Windows":
            writer.writerow([f"{name} - SSH", "SSH", host["ip"], 22, windows_ssh_user or observed_ssh_user or linux_ssh_user, folder, "", role, system])
            writer.writerow([f"{name} - RDP", "RDP", host["ip"], 3389, rdp_user, folder, "", role, system])
        elif family == "Linux":
            writer.writerow([f"{name} - SSH", "SSH", host["ip"], 22, linux_ssh_user or observed_ssh_user, folder, "", role, system])
        else:
            if "SSH" in host["services"]:
                writer.writerow([f"{name} - SSH", "SSH", host["ip"], 22, observed_ssh_user or linux_ssh_user or windows_ssh_user, folder, "", role, system])
            if "RDP" in host["services"]:
                writer.writerow([f"{name} - RDP", "RDP", host["ip"], 3389, rdp_user, folder, "", role, system])
    return buffer.getvalue().encode("utf-8-sig")


def export_inventory_csv(job: ScanJob, hosts: list[dict] | None = None) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow([
        "site", "vlan", "cidr", "hostname", "hostname_source", "role", "ip", "services", "open_ports",
        "os_family", "os_version", "os_confidence", "os_evidence", "resource_status",
        "ssh_username", "ssh_auth_status", "ssh_auth_method", "ssh_auth_error",
        "cpu_cores", "ram_gb", "disk_root_gb", "disk_c_gb", "disk_free_gb", "web_urls", "system",
    ])
    for host in job.results if hosts is None else hosts:
        resources = host.get("resources", {})
        writer.writerow([
            host.get("site", ""), host.get("vlan", ""), host.get("cidr", ""),
            host.get("hostname", ""), host.get("hostname_source", ""), host.get("role", ""), host.get("ip", ""),
            ",".join(host.get("services", [])), ",".join(str(p) for p in host.get("open_ports", [])),
            host.get("os_family", ""), host.get("os_version", ""), host.get("os_confidence", ""),
            host.get("os_evidence", ""), host.get("resource_status", ""),
            host.get("ssh_username", ""), host.get("ssh_auth_status", ""),
            host.get("ssh_auth_method", ""), host.get("ssh_auth_error", ""),
            resources.get("cpu_cores", ""), resources.get("ram_gb", ""), resources.get("disk_root_gb", ""),
            resources.get("disk_c_gb", ""), resources.get("disk_free_gb", ""),
            ",".join(web.get("url", "") for web in host.get("web", [])),
            host.get("system_name") or ("Unassigned" if "system_id" in host else ""),
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

    def send_download(self, data: bytes, filename: str, content_type: str = "application/octet-stream") -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        try:
            path = urlparse(self.path).path
            if path == "/api/remembered-hosts/flag":
                self.send_json(flag_remembered_host(self.json_body()))
                return
            if path == "/api/systems":
                self.send_json(edit_system(self.json_body()))
                return
            if path == "/api/systems/move":
                self.send_json(move_system_hosts(self.json_body()))
                return
            if path == "/api/discoveries/review":
                self.send_json(review_discoveries(self.json_body()))
                return
            if path == "/api/schedule":
                self.send_json(configure_schedule(self.json_body()))
                return
            if path == "/api/remembered-hosts/role":
                payload = self.json_body()
                self.send_json(update_remembered_role(payload.get("site"), payload.get("ip"), payload.get("role")))
                return
            if path == "/api/remembered-hosts/site":
                payload = self.json_body()
                self.send_json(update_remembered_site(payload.get("site"), payload.get("ip"), payload.get("new_site")))
                return
            if path == "/api/remembered-hosts/delete":
                payload = self.json_body()
                self.send_json(delete_remembered_host(payload.get("site"), payload.get("ip")))
                return
            if path == "/api/remembered-hosts/export":
                payload = self.json_body()
                hosts = selected_hosts_from_list(list_remembered_hosts(), payload.get("hosts"), "remembered inventory")
                export_format = clean_text(payload.get("format"), 20).lower()
                linux_ssh_user = clean_text(payload.get("linux_ssh_user"), 100)
                windows_ssh_user = clean_text(payload.get("windows_ssh_user"), 100)
                rdp_user = clean_text(payload.get("rdp_user"), 100)
                remembered_job = ScanJob(id="remembered", config={}, results=hosts, status="complete")
                timestamp = datetime.now().strftime('%Y%m%d-%H%M')
                if export_format == "mxtsessions":
                    data = export_mobaxterm(remembered_job, linux_ssh_user, rdp_user, windows_ssh_user, hosts)
                    self.send_download(data, f"NetAtlas-remembered-{timestamp}.mxtsessions")
                elif export_format == "csv":
                    data = export_csv(remembered_job, linux_ssh_user, rdp_user, windows_ssh_user, hosts)
                    self.send_download(data, f"NetAtlas-remembered-{timestamp}.csv", "text/csv; charset=utf-8")
                else:
                    raise ValueError("Remembered export format must be mxtsessions or csv")
                return
            export_match = re.fullmatch(r"/api/scans/([a-f0-9]+)/export", path)
            if export_match:
                job = JOBS.get(export_match.group(1))
                if not job:
                    self.send_json({"error": "Scan not found"}, HTTPStatus.NOT_FOUND)
                    return
                payload = self.json_body()
                hosts = selected_export_hosts(job, payload.get("hosts"))
                export_format = clean_text(payload.get("format"), 20).lower()
                linux_ssh_user = clean_text(payload.get("linux_ssh_user"), 100)
                windows_ssh_user = clean_text(payload.get("windows_ssh_user"), 100)
                rdp_user = clean_text(payload.get("rdp_user"), 100)
                timestamp = datetime.now().strftime('%Y%m%d-%H%M')
                if export_format == "mxtsessions":
                    data = export_mobaxterm(job, linux_ssh_user, rdp_user, windows_ssh_user, hosts)
                    self.send_download(data, f"NetAtlas-selected-{timestamp}.mxtsessions")
                elif export_format == "csv":
                    data = export_csv(job, linux_ssh_user, rdp_user, windows_ssh_user, hosts)
                    self.send_download(data, f"NetAtlas-selected-{timestamp}.csv", "text/csv; charset=utf-8")
                elif export_format == "inventory":
                    data = export_inventory_csv(job, hosts)
                    self.send_download(data, f"NetAtlas-inventory-selected-{timestamp}.csv", "text/csv; charset=utf-8")
                else:
                    raise ValueError("Export format must be mxtsessions, csv, or inventory")
                return
            if path == "/api/scans":
                config, secrets = prepare_scan(self.json_body())
                job = ScanJob(
                    id=uuid.uuid4().hex[:12], config=config,
                    secrets=secrets,
                )
                with JOBS_LOCK:
                    if any(current.status in {"queued", "running"} for current in JOBS.values()):
                        raise ValueError("Another scan is running. Wait for it or stop it before starting a new scan.")
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
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.send_json({"error": clean_text(exc, 500)}, HTTPStatus.BAD_REQUEST)
        except (OSError, sqlite3.Error) as exc:
            self.send_json({"error": clean_text(exc, 500)}, HTTPStatus.INTERNAL_SERVER_ERROR)

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
        if path == "/api/overview":
            self.send_json(remembered_overview())
            return
        if path == "/api/systems":
            self.send_json(list_systems())
            return
        if path == "/api/discoveries":
            self.send_json(list_discoveries())
            return
        if path == "/api/schedule":
            self.send_json(schedule_public())
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
            if job.status in {"running", "queued"}:
                job.status = "cancelled"
                job.current_phase = "Interrupted by restart"
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
    load_schedule()
    threading.Thread(target=scheduler_loop, daemon=True, name="background-scheduler").start()
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
