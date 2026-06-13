"""STUN packet parsing helpers."""

from __future__ import annotations

from typing import Optional, Sequence

from chat_geoip.config import TSHARK_LIVE_FIELDS_APT, IceCandidate
from chat_geoip.utils import is_public_ip


def parse_stun_fields(tokens: list[str], field_names: Sequence[str] = TSHARK_LIVE_FIELDS_APT) -> list[IceCandidate]:
    """Parse tshark tab-separated STUN fields into ICE candidates."""
    candidates: list[IceCandidate] = []
    field_map = _token_map(tokens, field_names)

    xor_ip = (
        field_map.get("classicstun.att.ipv4-xord", "")
        or field_map.get("stun.att.ipv4-xord", "")
    )
    xor_port = (
        field_map.get("classicstun.att.port-xord", "")
        or field_map.get("stun.att.port-xord", "")
    )
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


def _token_map(tokens: list[str], field_names: Sequence[str]) -> dict[str, str]:
    """Map positional tokens to field names based on tshark -e order."""
    result: dict[str, str] = {}
    for i, token in enumerate(tokens):
        if i < len(field_names) and token and token != "<no value>":
            result[field_names[i]] = token.strip()
    return result


def _safe_int(val: str) -> Optional[int]:
    try:
        return int(val)
    except (ValueError, TypeError):
        return None
