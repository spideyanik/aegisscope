from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any


WEB_TLS_SCRIPTS = (
    "http-headers",
    "http-security-headers",
    "ssl-cert",
)
SAFE_SERVICE_SCRIPTS = (
    "banner",
    "dns-recursion",
    *WEB_TLS_SCRIPTS,
    "rdp-enum-encryption",
    "smb-protocols",
    "smb2-security-mode",
    "smtp-commands",
    "ssh-hostkey",
)


@dataclass(frozen=True, slots=True)
class NmapProfile:
    description: str
    scripts: tuple[str, ...] = ()


NMAP_PROFILES = {
    "inventory": NmapProfile("TCP services and light version detection"),
    "web-tls": NmapProfile(
        "Web headers and TLS configuration evidence", WEB_TLS_SCRIPTS
    ),
    "safe-services": NmapProfile(
        "Allowlisted, non-destructive service checks", SAFE_SERVICE_SCRIPTS
    ),
}


def build_nmap_command(
    executable: str,
    hostname: str,
    ports: list[int],
    profile_name: str,
    timeout_seconds: int,
    max_rate: int,
) -> list[str]:
    if profile_name not in NMAP_PROFILES:
        raise ValueError(f"unknown Nmap profile: {profile_name}")
    if not hostname or hostname.startswith("-") or any(char.isspace() for char in hostname):
        raise ValueError("invalid Nmap target hostname")
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Nmap ports must be between 1 and 65535")

    profile = NMAP_PROFILES[profile_name]
    command = [
        executable,
        "-sT",
        "-sV",
        "--version-light",
        "-Pn",
        "-n",
        "--open",
        "--reason",
        "--noninteractive",
        "-T3",
        "--max-retries",
        "2",
        "--max-rate",
        str(max_rate),
        "--host-timeout",
        f"{timeout_seconds}s",
        "-p",
        ",".join(str(port) for port in sorted(set(ports))),
    ]
    if profile.scripts:
        command.extend(
            [
                "--script",
                ",".join(profile.scripts),
                "--script-timeout",
                f"{min(timeout_seconds, 30)}s",
            ]
        )
    command.extend(["-oX", "-", "--", hostname])
    return command


def _script_result(element: ET.Element) -> dict[str, str]:
    return {
        "id": element.get("id", "unknown")[:120],
        "output": element.get("output", "").replace("\x00", "")[:2_000],
    }


def parse_nmap_xml(xml_output: str, hostname: str, ports: list[int]) -> dict[str, Any]:
    root = ET.fromstring(xml_output)
    host = root.find("host")
    result: dict[str, Any] = {
        "hostname": hostname,
        "transport": "tcp",
        "scanned_ports": sorted(set(ports)),
        "host_status": "unknown",
        "addresses": [],
        "open_ports": [],
        "host_scripts": [],
    }
    if host is None:
        return result

    status = host.find("status")
    if status is not None:
        result["host_status"] = status.get("state", "unknown")
        result["status_reason"] = status.get("reason", "unknown")
    result["addresses"] = sorted(
        {
            address
            for element in host.findall("address")
            if (address := element.get("addr"))
        }
    )
    for port_element in host.findall("./ports/port"):
        state = port_element.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port_element.find("service")
        product = service.get("product", "") if service is not None else ""
        version = service.get("version", "") if service is not None else ""
        extra = service.get("extrainfo", "") if service is not None else ""
        item = {
            "port": int(port_element.get("portid", "0")),
            "protocol": port_element.get("protocol", "tcp"),
            "service": service.get("name", "unknown") if service is not None else "unknown",
            "version": " ".join(part for part in (product, version, extra) if part),
            "reason": state.get("reason", "unknown"),
            "scripts": [
                _script_result(script) for script in port_element.findall("script")
            ],
        }
        result["open_ports"].append(item)
    result["open_ports"].sort(key=lambda item: item["port"])
    result["host_scripts"] = [
        _script_result(script) for script in host.findall("./hostscript/script")
    ]
    return result


def run_nmap_scan(
    hostname: str,
    ports: list[int],
    profile_name: str,
    timeout_seconds: int,
    max_rate: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "engine": "nmap",
        "profile": profile_name,
        "hostname": hostname,
        "transport": "tcp",
        "scanned_ports": sorted(set(ports)),
        "open_ports": [],
        "error": None,
        "note": "Nmap evidence confirms observed exposure and service hints, not exploitability.",
    }
    executable = shutil.which("nmap")
    if not executable:
        result["error"] = "nmap executable was not found"
        return result

    command = build_nmap_command(
        executable, hostname, ports, profile_name, timeout_seconds, max_rate
    )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds + 10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result["error"] = "Nmap process exceeded the configured timeout"
        return result
    if completed.returncode != 0:
        detail = completed.stderr.strip().replace("\x00", "")[:500]
        result["error"] = f"Nmap exited with status {completed.returncode}: {detail}"
        return result
    try:
        parsed = parse_nmap_xml(completed.stdout, hostname, ports)
    except (ET.ParseError, ValueError) as error:
        result["error"] = f"Nmap XML could not be parsed: {type(error).__name__}"
        return result
    result.update(parsed)
    return result
