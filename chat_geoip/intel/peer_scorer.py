"""Peer candidate scoring and classification."""

from __future__ import annotations

from chat_geoip.config import IceCandidate, PeerCandidate
from chat_geoip.intel.geoip import enrich_geo, format_location, lookup_geo
from chat_geoip.intel.vpn_proxy import classify_cdn, is_likely_vpn_proxy
from chat_geoip.utils import get_local_public_ips, is_public_ip

TURN_PORTS = {3478, 5349}


def score_candidates(
    ice_map: dict[str, IceCandidate],
    geo_reader=None,
    asn_reader=None,
    exclude_self: bool = True,
    self_ips: set[str] | None = None,
    browser_ips: set[str] | None = None,
    min_confidence: int = 0,
) -> list[PeerCandidate]:
    if self_ips is None:
        self_ips = get_local_public_ips() if exclude_self else set()
    if browser_ips is None:
        browser_ips = set()

    peers: list[PeerCandidate] = []
    for ip, ice in ice_map.items():
        if not is_public_ip(ip):
            continue

        role = _classify_role(ip, ice, self_ips)
        confidence = _compute_confidence(ip, ice, role, browser_ips)
        sources = _collect_sources(ice, browser_ips)

        geo = None
        if geo_reader:
            geo = lookup_geo(geo_reader, ip, ice.packet_hits)
            if asn_reader:
                enrich_geo(geo, asn_reader)

        peer = PeerCandidate(
            ip=ip,
            port=ice.port,
            typ=ice.typ,
            role=role,
            confidence=confidence,
            source=ice.source,
            packet_hits=ice.packet_hits,
            udp_hits=ice.udp_hits,
            geo=geo,
            sources=sources,
        )
        if confidence >= min_confidence:
            peers.append(peer)

    peers.sort(key=lambda p: (-p.confidence, -p.packet_hits, p.ip))
    return peers


def _classify_role(ip: str, ice: IceCandidate, self_ips: set[str]) -> str:
    if ip in self_ips:
        return "self"

    cdn = classify_cdn(ip)
    if cdn:
        return "cdn"

    if ice.typ == "relay" or (ice.port in TURN_PORTS) or (ice.udp_hits and 3478 in (ice.port or 0,)):
        if ice.port in TURN_PORTS or ice.typ == "relay":
            return "turn_relay"

    if ice.sni and any(k in ice.sni.lower() for k in ("omegle", "ometv", "ome.tv")):
        return "signaling"

    if ice.typ in ("host", "srflx") or ice.udp_hits > 0:
        return "peer_candidate"

    return "unknown"


def _compute_confidence(ip: str, ice: IceCandidate, role: str, browser_ips: set[str]) -> int:
    if role == "self":
        return 0
    if role == "cdn":
        return 5
    if role == "turn_relay":
        return 10
    if role == "signaling":
        return 15

    score = 30
    typ_base = {"srflx": 35, "host": 25, "prflx": 30, "relay": 5, "unknown": 10}
    score += typ_base.get(ice.typ, 10)
    score += min(ice.packet_hits * 2, 20)
    score += min(ice.udp_hits * 3, 15)
    if ip in browser_ips:
        score += 25
    if ice.source == "browser_hook":
        score += 15
    if classify_cdn(ip):
        score -= 40
    return max(0, min(100, score))


def _collect_sources(ice: IceCandidate, browser_ips: set[str]) -> list[str]:
    sources = []
    if ice.source:
        sources.append(ice.source)
    if ice.ip in browser_ips and "browser_hook" not in sources:
        sources.append("browser_hook")
    return sources


def is_turn_only_session(peers: list[PeerCandidate]) -> bool:
    peer_hits = [p for p in peers if p.role == "peer_candidate" and p.confidence >= 50]
    if peer_hits:
        return False
    turn_hits = [p for p in peers if p.role == "turn_relay"]
    return len(turn_hits) > 0


def sources_agree(passive_best: str, browser_best: str) -> bool:
    return bool(passive_best and browser_best and passive_best == browser_best)


def best_peer(peers: list[PeerCandidate], min_confidence: int = 50) -> PeerCandidate | None:
    candidates = [p for p in peers if p.role == "peer_candidate" and p.confidence >= min_confidence]
    return candidates[0] if candidates else None
