"""Shared utilities."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

from chat_geoip.config import (
    DB_CANDIDATES,
    ASN_DB_CANDIDATES,
    SCRIPT_DIR,
    TSHARK_CANDIDATES,
    VIRTUAL_IFACE_PATTERNS,
)

ENDPOINTS_LINE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s*\|\s*(\d+)\s*\|")


def find_tshark(explicit: Optional[str] = None) -> str:
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        found = shutil.which(explicit)
        if found:
            return found
        sys.exit(f"tshark tidak ditemukan: {explicit}")

    env = os.environ.get("TSHARK_PATH") or os.environ.get("TSHARK")
    if env and Path(env).is_file():
        return env

    for candidate in TSHARK_CANDIDATES:
        if candidate == "tshark":
            found = shutil.which("tshark")
            if found:
                return found
        elif Path(candidate).is_file():
            return candidate

    hint = (
        "Windows: install Wireshark → https://www.wireshark.org/download.html\n"
        "Linux: sudo apt install tshark"
    )
    sys.exit(f"tshark tidak ditemukan di PATH.\n{hint}")


def resolve_db_path(explicit: Optional[str], candidates: tuple[str, ...] = DB_CANDIDATES) -> Path:
    if explicit:
        for base in (Path.cwd(), SCRIPT_DIR):
            p = (base / explicit).resolve() if not Path(explicit).is_absolute() else Path(explicit)
            if p.is_file():
                return p
        p = Path(os.path.expanduser(explicit))
        if p.is_file():
            return p
        sys.exit(f"Database GeoLite2 tidak ditemukan: {explicit}")

    env_key = candidates[0]
    env = os.environ.get(env_key)
    if env:
        p = Path(os.path.expanduser(env))
        if p.is_file():
            return p

    for candidate in candidates[1:]:
        for base in (SCRIPT_DIR, Path.cwd()):
            p = base / candidate if not candidate.startswith("~") else Path(os.path.expanduser(candidate))
            if p.is_file():
                return p.resolve()

    sys.exit(
        "GeoLite2-City.mmdb tidak ditemukan.\n"
        "Letakkan di folder script atau: set GEOLITE2_CITY_DB=C:\\path\\GeoLite2-City.mmdb"
    )


def resolve_asn_db_path(explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        for base in (Path.cwd(), SCRIPT_DIR):
            p = (base / explicit).resolve() if not Path(explicit).is_absolute() else Path(explicit)
            if p.is_file():
                return p
        p = Path(os.path.expanduser(explicit))
        if p.is_file():
            return p
        return None

    env = os.environ.get("GEOLITE2_ASN_DB")
    if env:
        p = Path(os.path.expanduser(env))
        if p.is_file():
            return p

    for candidate in ASN_DB_CANDIDATES[1:]:
        for base in (SCRIPT_DIR, Path.cwd()):
            p = base / candidate if not candidate.startswith("~") else Path(os.path.expanduser(candidate))
            if p.is_file():
                return p.resolve()
    return None


def is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def get_local_public_ips() -> set[str]:
    """UDP connect trick to discover local public IP."""
    ips: set[str] = set()
    for target in (("8.8.8.8", 80), ("1.1.1.1", 80)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(target)
            ip = s.getsockname()[0]
            s.close()
            if is_public_ip(ip):
                ips.add(ip)
        except OSError:
            pass
    return ips


def run_tshark(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        sys.exit(f"tshark timeout setelah {timeout}s: {' '.join(cmd[:6])}...")


def is_virtual_interface(dev: str, desc: str) -> bool:
    combined = f"{dev} {desc}".lower()
    return any(pat in combined for pat in VIRTUAL_IFACE_PATTERNS)


def redact_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    return ip
