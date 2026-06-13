"""Configuration, presets, and data models."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

SCRIPT_DIR = Path(__file__).resolve().parent.parent

_VERSION_FILE = SCRIPT_DIR / "VERSION"
VERSION = _VERSION_FILE.read_text(encoding="utf-8").strip() if _VERSION_FILE.is_file() else "0.0.0"

FILTER_PRESETS: dict[str, str] = {
    "video-chat": (
        "stun or rtp or rtcp or rtsp or sip or h323 or "
        'tls.handshake.extensions_server_name contains "zoom" or '
        'tls.handshake.extensions_server_name contains "teams" or '
        'tls.handshake.extensions_server_name contains "discord" or '
        'tls.handshake.extensions_server_name contains "meet.google" or '
        'tls.handshake.extensions_server_name contains "webex" or '
        'tls.handshake.extensions_server_name contains "whatsapp" or '
        "quic or (udp.port >= 10000 and udp.port <= 65535 and frame.len > 200)"
    ),
    "webrtc": "stun or turn or dtls or sctp or rtp or rtcp or udp.port == 3478",
    "omegle-ometv": (
        "stun or turn or dtls or sctp or rtp or rtcp or "
        'tls.handshake.extensions_server_name contains "omegle" or '
        'tls.handshake.extensions_server_name contains "ometv" or '
        'tls.handshake.extensions_server_name contains "ome.tv" or '
        "udp.port == 3478 or tcp.port == 3478"
    ),
    "voip": "sip or rtp or rtcp or h323 or mgcp or iax2",
    "all": "",
}

BPF_PRESETS: dict[str, str] = {
    "default": "udp or tcp port 443 or tcp port 80 or tcp port 3478 or udp port 3478",
    "omegle-ometv": "udp or tcp port 3478 or udp portrange 10000-65535",
}

TSHARK_CANDIDATES = (
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
)

DB_CANDIDATES = (
    "GEOLITE2_CITY_DB",
    "GeoLite2-City.mmdb",
    "~/GeoIP/GeoLite2-City.mmdb",
    "~/geoip/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
)

ASN_DB_CANDIDATES = (
    "GEOLITE2_ASN_DB",
    "GeoLite2-ASN.mmdb",
    "~/GeoIP/GeoLite2-ASN.mmdb",
)

VIRTUAL_IFACE_PATTERNS = (
    "loopback",
    "usbpcap",
    "ciscodump",
    "etwdump",
    "randpkt",
    "sshdump",
    "udpdump",
    "wifidump",
)


@dataclass
class GeoResult:
    ip: str
    country: str = ""
    country_code: str = ""
    subdivision: str = ""
    city: str = ""
    postal_code: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_radius_km: Optional[int] = None
    packet_hits: int = 0
    bytes_total: int = 0
    asn: str = ""
    org: str = ""
    error: str = ""


@dataclass
class IceCandidate:
    ip: str
    port: Optional[int] = None
    typ: str = "unknown"  # host | srflx | relay | unknown
    source: str = "passive"  # passive_stun | passive_rtp | browser_hook
    packet_hits: int = 0
    udp_hits: int = 0
    rtp_ssrc: str = ""
    sni: str = ""


@dataclass
class PeerCandidate:
    ip: str
    port: Optional[int] = None
    typ: str = "unknown"
    role: str = "unknown"  # self | peer_candidate | cdn | turn_relay | signaling | unknown
    confidence: int = 0
    source: str = "passive"
    packet_hits: int = 0
    udp_hits: int = 0
    geo: Optional[GeoResult] = None
    is_new: bool = False
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.geo:
            d["geo"] = asdict(self.geo)
        return d


@dataclass
class PcapInfo:
    path: str
    exists: bool = True
    file_size_bytes: int = 0
    packet_count: int = 0
    duration_seconds: float = 0.0
    first_packet: str = ""
    last_packet: str = ""
    filtered_packets: int = 0
    error: str = ""


@dataclass
class CaptureMeta:
    mode: str = ""
    pcap_path: str = ""
    interface: str = ""
    capture_seconds: int = 0
    display_filter: str = ""
    filter_preset: str = ""
    tshark: str = ""
    database: str = ""
    timestamp_utc: str = ""
    ip_count: int = 0
    version: str = VERSION
    platform: str = ""


@dataclass
class RunConfig:
    pcap: Optional[str] = None
    interface: Optional[str] = None
    capture_seconds: int = 60
    write_pcap: Optional[str] = None
    display_filter: str = ""
    filter_preset: str = "video-chat"
    db_path: Optional[str] = None
    asn_db_path: Optional[str] = None
    include_private: bool = False
    output: str = "table"
    out_file: Optional[str] = None
    tshark_path: Optional[str] = None
    extra_ips: list[str] = field(default_factory=list)
    pcap_info_only: bool = False
    bpf_filter: str = BPF_PRESETS["default"]
    live: bool = False
    live_refresh: float = 1.0
    exclude_self: bool = True
    auto_interface: bool = False
    hybrid: bool = False
    browser_only: bool = False
    platform: str = ""
    platform_url: str = ""
    min_confidence: int = 0
    redact: bool = False
    alert_sound: bool = False
    webhook: str = ""
    session_dir: str = ""


def effective_filter(cfg: RunConfig) -> str:
    if cfg.display_filter:
        return cfg.display_filter
    return FILTER_PRESETS.get(cfg.filter_preset, FILTER_PRESETS["video-chat"])


def effective_bpf(cfg: RunConfig) -> str:
    if cfg.filter_preset == "omegle-ometv":
        return BPF_PRESETS["omegle-ometv"]
    return cfg.bpf_filter
