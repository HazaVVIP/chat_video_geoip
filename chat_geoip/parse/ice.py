"""ICE candidate parsing and normalization."""

from __future__ import annotations

import re
from typing import Optional

from chat_geoip.config import IceCandidate
from chat_geoip.utils import is_public_ip

CANDIDATE_LINE = re.compile(
    r"candidate:\S+\s+\d+\s+(?:udp|tcp)\s+\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+typ\s+(host|srflx|relay|prflx)",
    re.I,
)

IP_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+typ\s+(host|srflx|relay|prflx)", re.I)


def parse_browser_candidate(candidate_str: str) -> Optional[IceCandidate]:
    """Parse SDP ICE candidate string from browser hook."""
    if not candidate_str:
        return None

    m = CANDIDATE_LINE.search(candidate_str)
    if not m:
        m2 = IP_PORT_RE.search(candidate_str)
        if not m2:
            return None
        ip, port_s, typ = m2.group(1), m2.group(2), m2.group(3)
    else:
        ip, port_s, typ = m.group(1), m.group(2), m.group(3)

    if not is_public_ip(ip) and typ != "host":
        return None

    return IceCandidate(
        ip=ip,
        port=int(port_s),
        typ=typ.lower(),
        source="browser_hook",
        packet_hits=1,
    )


def parse_passive_line(tokens: list[str], include_private: bool = False) -> list[IceCandidate]:
    """Parse a tshark output line into ICE candidates."""
    from chat_geoip.parse.stun import parse_stun_fields

    candidates: list[IceCandidate] = []

    # Basic IP extraction
    for i, token in enumerate(tokens):
        token = token.strip()
        if not token or token == "<no value>":
            continue
        if _looks_like_ip(token):
            if include_private or is_public_ip(token):
                typ = "unknown"
                port = None
                udp_hits = 0
                # Check adjacent port fields
                if i + 1 < len(tokens) and tokens[i + 1].strip().isdigit():
                    port = int(tokens[i + 1].strip())
                    udp_hits = 1
                candidates.append(
                    IceCandidate(
                        ip=token,
                        port=port,
                        typ=typ,
                        source="passive_rtp",
                        packet_hits=1,
                        udp_hits=udp_hits,
                    )
                )

    candidates.extend(parse_stun_fields(tokens))
    return _dedupe_candidates(candidates)


def merge_candidates(existing: dict[str, IceCandidate], new: list[IceCandidate]) -> list[str]:
    """Merge candidates into dict keyed by ip; return list of newly seen IPs."""
    new_ips: list[str] = []
    for c in new:
        key = c.ip
        if key in existing:
            prev = existing[key]
            prev.packet_hits += c.packet_hits
            prev.udp_hits += c.udp_hits
            if c.typ != "unknown":
                prev.typ = c.typ
            if c.port and not prev.port:
                prev.port = c.port
            if c.source and c.source not in ("passive",):
                prev.source = c.source
            if c.rtp_ssrc:
                prev.rtp_ssrc = c.rtp_ssrc
            if c.sni:
                prev.sni = c.sni
        else:
            existing[key] = c
            new_ips.append(key)
    return new_ips


def _dedupe_candidates(candidates: list[IceCandidate]) -> list[IceCandidate]:
    seen: dict[str, IceCandidate] = {}
    merge_candidates(seen, candidates)
    return list(seen.values())


def _looks_like_ip(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
