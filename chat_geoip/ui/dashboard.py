"""Live APT dashboard rendering."""

from __future__ import annotations

import os
import platform
import sys
import time
from pathlib import Path
from typing import Iterable, Optional

from chat_geoip.config import GeoResult, PeerCandidate, RunConfig, VERSION
from chat_geoip.intel.geoip import format_location


def clear_screen() -> None:
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def format_table(rows: Iterable[GeoResult]) -> str:
    headers = ("IP", "Pkt", "Negara", "Provinsi", "Kota", "Kode Pos", "Lat", "Lon")
    col_widths = [len(h) for h in headers]
    str_rows: list[tuple[str, ...]] = []

    for r in rows:
        row = (
            r.ip,
            str(r.packet_hits),
            r.country or r.error or "-",
            r.subdivision or "-",
            r.city or "-",
            r.postal_code or "-",
            f"{r.latitude:.4f}" if r.latitude is not None else "-",
            f"{r.longitude:.4f}" if r.longitude is not None else "-",
        )
        str_rows.append(row)
        col_widths = [max(w, len(c)) for w, c in zip(col_widths, row)]

    def fmt_row(values: tuple[str, ...]) -> str:
        return "  ".join(v.ljust(col_widths[i]) for i, v in enumerate(values))

    lines = [fmt_row(headers), "  ".join("-" * w for w in col_widths)]
    lines.extend(fmt_row(row) for row in str_rows)
    return "\n".join(lines)


def format_peer_table(peers: list[PeerCandidate], min_confidence: int = 70) -> str:
    headers = ("IP", "Typ", "Role", "Conf%", "Pkt", "Lokasi", "ASN/Org")
    col_widths = [len(h) for h in headers]
    str_rows: list[tuple[str, ...]] = []

    for p in peers:
        loc = format_location(p.geo) if p.geo else "-"
        asn_org = ""
        if p.geo:
            asn_org = f"{p.geo.asn} {p.geo.org}".strip() or "-"
        tag = " [NEW]" if p.is_new else ""
        row = (
            p.ip + tag,
            p.typ,
            p.role,
            str(p.confidence),
            str(p.packet_hits),
            loc,
            asn_org,
        )
        str_rows.append(row)
        col_widths = [max(w, len(c)) for w, c in zip(col_widths, row)]

    def fmt_row(values: tuple[str, ...]) -> str:
        return "  ".join(v.ljust(col_widths[i]) for i, v in enumerate(values))

    lines = [fmt_row(headers), "  ".join("-" * w for w in col_widths)]
    lines.extend(fmt_row(row) for row in str_rows)
    return "\n".join(lines) if str_rows else "  (kosong)"


def render_live_screen(
    cfg: RunConfig,
    tshark: str,
    db_path: Path,
    filt: str,
    rows: list[GeoResult],
    total_packets: int,
    started: float,
    last_event: float,
) -> None:
    uptime = _uptime_str(started)
    idle = time.time() - last_event

    clear_screen()
    print("=" * 72)
    print(f"  LIVE GEOLOCATE v{VERSION} — video/chat traffic")
    print("=" * 72)
    print(f"  Interface : {cfg.interface}")
    print(f"  tshark    : {tshark}")
    print(f"  Database  : {db_path.name}")
    print(f"  Filter    : {filt or '(semua IP publik)'}")
    print(f"  Uptime    : {uptime}  |  Paket: {total_packets:,}  |  IP: {len(rows)}")
    if cfg.write_pcap:
        print(f"  Simpan    : {cfg.write_pcap}")
    print(f"  Refresh   : {cfg.live_refresh:.1f}s  |  Ctrl+C untuk berhenti")
    if idle > 5 and total_packets == 0:
        print("  [!] Belum ada paket — pastikan CMD Run as Administrator & interface benar")
    elif idle > 15:
        print(f"  [!] Tidak ada paket baru {idle:.0f}s — coba --filter-preset all")
    print("-" * 72)

    if not rows:
        print("  Menunggu lalu lintas video/chat ...")
    else:
        print(format_table(rows))
    print("-" * 72)
    sys.stdout.flush()


def render_apt_dashboard(
    cfg: RunConfig,
    tshark: str,
    db_path: Path,
    filt: str,
    peers: list[PeerCandidate],
    total_packets: int,
    started: float,
    last_event: float,
    turn_only: bool = False,
    mode: str = "live",
    browser_active: bool = False,
) -> None:
    uptime = _uptime_str(started)
    idle = time.time() - last_event
    min_conf = cfg.min_confidence or 70

    peer_candidates = [p for p in peers if p.role == "peer_candidate" and p.confidence >= min_conf]
    infra = [p for p in peers if p.role not in ("peer_candidate",) or p.confidence < min_conf]

    clear_screen()
    print("=" * 72)
    print(f"  APT GEO INTEL v{VERSION} — {mode.upper()} — {cfg.platform or cfg.filter_preset}")
    print("=" * 72)
    print(f"  Interface : {cfg.interface or '(browser-only)'}")
    print(f"  tshark    : {tshark if tshark else 'n/a'}")
    print(f"  Database  : {db_path.name}")
    print(f"  Mode      : {mode}{' + browser' if browser_active else ''}")
    print(f"  Uptime    : {uptime}  |  Paket: {total_packets:,}  |  Peers: {len(peer_candidates)}")
    if turn_only:
        print("  [!] TURN_ONLY_SESSION — peer IP mungkin tersembunyi di relay")
    if cfg.write_pcap:
        print(f"  Simpan    : {cfg.write_pcap}")
    print(f"  Refresh   : {cfg.live_refresh:.1f}s  |  Ctrl+C untuk berhenti")
    if idle > 15 and total_packets == 0 and not browser_active:
        print(f"  [!] Tidak ada paket baru {idle:.0f}s")
    print("-" * 72)
    print(f"  === PEER CANDIDATES (confidence >= {min_conf}) ===")
    print(format_peer_table(peer_candidates, min_conf))
    print("-" * 72)
    print("  === INFRASTRUCTURE ===")
    print(format_peer_table(infra[:10], 0))
    print("-" * 72)
    sys.stdout.flush()


def render_summary(peers: list[PeerCandidate], turn_only: bool = False) -> None:
    clear_screen()
    print("=" * 72)
    print("  RINGKASAN LIVE (selesai)")
    print("=" * 72)
    if turn_only:
        print("  [!] TURN_ONLY_SESSION terdeteksi")
    peer_candidates = [p for p in peers if p.role == "peer_candidate"]
    print(format_peer_table(peer_candidates))


def _uptime_str(started: float) -> str:
    uptime = int(time.time() - started)
    mm, ss = divmod(uptime, 60)
    hh, mm = divmod(mm, 60)
    return f"{hh:02d}:{mm:02d}:{ss:02d}"
