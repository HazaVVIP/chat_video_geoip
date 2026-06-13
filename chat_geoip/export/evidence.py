"""Evidence export and reporting."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from chat_geoip.config import VERSION, CaptureMeta, GeoResult, PcapInfo, PeerCandidate
from chat_geoip.intel.peer_scorer import best_peer
from chat_geoip.utils import redact_ip


def build_report(
    rows: list[GeoResult],
    meta: CaptureMeta,
    pcap_info: Optional[PcapInfo] = None,
    peer_candidates: Optional[list[PeerCandidate]] = None,
    excluded: Optional[list[PeerCandidate]] = None,
) -> dict:
    return {
        "meta": asdict(meta),
        "pcap": asdict(pcap_info) if pcap_info else None,
        "results": [asdict(r) for r in rows],
        "peer_candidates": [p.to_dict() for p in (peer_candidates or [])],
        "excluded": [p.to_dict() for p in (excluded or [])],
        "version": VERSION,
    }


def write_live_report(
    out_file: str,
    peers: list[PeerCandidate],
    meta: CaptureMeta,
    total_packets: int,
    duration_seconds: int,
    redact: bool = False,
) -> None:
    peer_candidates = [p for p in peers if p.role == "peer_candidate"]
    excluded = [p for p in peers if p.role != "peer_candidate"]
    bp = best_peer(peers)

    payload = {
        "version": VERSION,
        "meta": {**asdict(meta), "total_packets": total_packets, "duration_seconds": duration_seconds},
        "peer_candidates": [_maybe_redact_dict(p.to_dict(), redact) for p in peer_candidates],
        "excluded": [_maybe_redact_dict(p.to_dict(), redact) for p in excluded],
        "peer_best": _maybe_redact_dict(bp.to_dict(), redact) if bp else None,
    }
    Path(out_file).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_output(
    rows: list[GeoResult],
    cfg,
    meta: CaptureMeta,
    pcap_info: Optional[PcapInfo] = None,
    peers: Optional[list[PeerCandidate]] = None,
) -> None:
    from chat_geoip.ui.dashboard import format_table

    if cfg.output == "json":
        peer_candidates = [p for p in (peers or []) if p.role == "peer_candidate"]
        excluded = [p for p in (peers or []) if p.role != "peer_candidate"]
        text = json.dumps(
            build_report(rows, meta, pcap_info, peer_candidates, excluded),
            indent=2,
            ensure_ascii=False,
        )
    else:
        parts = []
        if pcap_info and pcap_info.exists:
            parts.append(
                f"PCAP: {pcap_info.path} | {pcap_info.packet_count} pkts | "
                f"{pcap_info.duration_seconds:.1f}s | filter-match: {pcap_info.filtered_packets}"
            )
        parts.append(format_table(rows))
        text = "\n".join(parts)

    if cfg.out_file:
        Path(cfg.out_file).write_text(text + "\n", encoding="utf-8")
        print(f"Disimpan ke {cfg.out_file}", file=__import__("sys").stderr)
    else:
        print(text)


def _maybe_redact_dict(d: dict, redact: bool) -> dict:
    if not redact:
        return d
    out = dict(d)
    if "ip" in out:
        out["ip"] = redact_ip(out["ip"])
    if "geo" in out and out["geo"]:
        out["geo"] = dict(out["geo"])
        out["geo"]["ip"] = redact_ip(out["geo"]["ip"])
    return out
