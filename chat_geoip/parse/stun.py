"""STUN packet parsing helpers."""

from __future__ import annotations

from typing import Optional

from chat_geoip.config import IceCandidate
from chat_geoip.utils import is_public_ip


def parse_stun_fields(tokens: list[str]) -> list[IceCandidate]:
    """Parse tshark tab-separated STUN fields into ICE candidates."""
    candidates: list[IceCandidate] = []
    field_map = _token_map(tokens)

    xor_ip = field_map.get("stun.xor-mapped-address.ip", "")
    xor_port = field_map.get("stun.xor-mapped-address.port", "")
    stun_type = field_map.get("stun.type", "")

    src_ip = field_map.get("ip.src", "")
    dst_ip = field_map.get("ip.dst", "")

    if xor_ip and is_public_ip(xor_ip):
        port = _safe_int(xor_port)
        candidates.append(
            IceCandidate(
                ip=xor_ip,
                port=port,
                typ="srflx",
                source="passive_stun",
                packet_hits=1,
            )
        )

    # Binding response may carry peer reflexive in src/dst
    for ip in (src_ip, dst_ip):
        if ip and is_public_ip(ip) and ip != xor_ip:
            typ = "relay" if "turn" in stun_type.lower() else "unknown"
            candidates.append(
                IceCandidate(ip=ip, typ=typ, source="passive_stun", packet_hits=1)
            )

    return candidates


def _token_map(tokens: list[str]) -> dict[str, str]:
    """Map positional tokens to field names based on known order from passive capture."""
    names = [
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "stun.type",
        "stun.xor-mapped-address.ip",
        "stun.xor-mapped-address.port",
        "rtp.ssrc",
        "tls.handshake.extensions_server_name",
    ]
    result: dict[str, str] = {}
    for i, token in enumerate(tokens):
        if i < len(names) and token and token != "<no value>":
            result[names[i]] = token.strip()
    return result


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None
