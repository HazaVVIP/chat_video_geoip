"""Passive tshark capture and IP/ICE extraction."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

import geoip2.database

from chat_geoip.config import (
    CaptureMeta,
    GeoResult,
    IceCandidate,
    PcapInfo,
    PeerCandidate,
    RunConfig,
    effective_bpf,
    effective_filter,
)
from chat_geoip.intel.geoip import geolocate_ips, lookup_geo
from chat_geoip.intel.peer_scorer import best_peer, is_turn_only_session, score_candidates
from chat_geoip.parse.ice import merge_candidates, parse_passive_line
from chat_geoip.ui.dashboard import render_apt_dashboard, render_live_screen, render_summary
from chat_geoip.utils import ENDPOINTS_LINE, find_tshark, is_public_ip, run_tshark

TSHARK_LIVE_FIELDS = [
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


def list_interfaces(tshark: str, include_virtual: bool = False) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    from chat_geoip.utils import is_virtual_interface

    proc = run_tshark([tshark, "-D"], timeout=30)
    if proc.returncode != 0:
        sys.exit(f"Gagal list interface:\n{proc.stderr[:1000]}")

    ready: list[tuple[str, str]] = []
    skipped: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        m = re.match(r"^\d+\.\s+(.+?)(?:\s+\((.+)\))?$", line)
        if not m:
            continue
        dev, desc = m.group(1).strip(), (m.group(2) or "").strip()
        if is_virtual_interface(dev, desc) and not include_virtual:
            skipped.append((dev, desc))
        else:
            ready.append((dev, desc))
    return ready, skipped


def resolve_interface(tshark: str, iface_arg: str) -> str:
    """Resolve numeric index or description to device path."""
    if not iface_arg:
        return iface_arg

    ready, skipped = list_interfaces(tshark, include_virtual=True)
    all_ifaces = ready + skipped

    if iface_arg.isdigit():
        idx = int(iface_arg)
        if 1 <= idx <= len(all_ifaces):
            return all_ifaces[idx - 1][0]
        sys.exit(f"Interface index {idx} tidak valid (1-{len(all_ifaces)})")

    for dev, desc in all_ifaces:
        if iface_arg == dev or iface_arg.lower() in (dev.lower(), desc.lower()):
            return dev
    return iface_arg


def auto_select_interface(tshark: str) -> str:
    ready, _ = list_interfaces(tshark)
    for dev, desc in ready:
        combined = f"{dev} {desc}".lower()
        if any(k in combined for k in ("wi-fi", "wifi", "wireless", "ethernet", "eth")):
            return dev
    if ready:
        return ready[0][0]
    sys.exit("Tidak ada interface capture-ready ditemukan.")


def count_filtered_packets(tshark: str, cfg: RunConfig, filt: str) -> int:
    if not cfg.pcap and not cfg.interface:
        return 0
    cmd = _tshark_base(tshark, cfg) + ["-Y", filt or "frame"]
    proc = run_tshark(cmd + ["-T", "fields", "-e", "frame.number"], timeout=120)
    if proc.returncode not in (0, 1):
        return 0
    return sum(1 for ln in proc.stdout.splitlines() if ln.strip())


def get_pcap_info(tshark: str, pcap_path: str, display_filter: str = "") -> PcapInfo:
    path = Path(pcap_path)
    info = PcapInfo(path=str(path.resolve()))
    if not path.is_file():
        info.exists = False
        info.error = "file_not_found"
        return info

    info.file_size_bytes = path.stat().st_size
    proc = run_tshark([tshark, "-n", "-r", str(path), "-q", "-z", "io,stat,0"])
    if proc.returncode in (0, 1) and proc.stdout:
        m = re.search(r"(\d+)\s+frames", proc.stdout, re.I)
        if m:
            info.packet_count = int(m.group(1))
        dur = re.search(r"Duration:\s*([\d.]+)\s*sec", proc.stdout, re.I)
        if dur:
            info.duration_seconds = float(dur.group(1))

    cap = run_tshark([tshark, "-n", "-r", str(path), "-T", "fields", "-e", "frame.time", "-c", "1"])
    if cap.stdout.strip():
        info.first_packet = cap.stdout.strip().splitlines()[0]

    cap_end = run_tshark(
        [tshark, "-n", "-r", str(path), "-T", "fields", "-e", "frame.time"],
        timeout=300,
    )
    lines = [ln.strip() for ln in cap_end.stdout.splitlines() if ln.strip()]
    if lines:
        info.last_packet = lines[-1]

    if display_filter:
        info.filtered_packets = count_filtered_packets(
            tshark,
            RunConfig(pcap=str(path), display_filter=display_filter, filter_preset=""),
            display_filter,
        )
    return info


def extract_ips_fields(tshark: str, cfg: RunConfig, filt: str) -> dict[str, int]:
    hits: dict[str, int] = defaultdict(int)
    cmd = _tshark_base(tshark, cfg) + [
        "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
        "-e", "ip.src", "-e", "ip.dst",
    ]
    if filt:
        cmd += ["-Y", filt]

    timeout = max(cfg.capture_seconds + 60, 120) if cfg.interface else 600
    proc = run_tshark(cmd, timeout=timeout)
    if proc.returncode not in (0, 1):
        err = (proc.stderr or proc.stdout or "").strip()
        sys.exit(f"tshark ekstraksi gagal (exit {proc.returncode}):\n{err[:2000]}")

    for line in proc.stdout.splitlines():
        for token in line.split("\t"):
            token = token.strip()
            if not token or token == "<no value>":
                continue
            if cfg.include_private or is_public_ip(token):
                hits[token] += 1
    return dict(hits)


def extract_ice_fields(tshark: str, cfg: RunConfig, filt: str) -> dict[str, IceCandidate]:
    ice_map: dict[str, IceCandidate] = {}
    cmd = _tshark_base(tshark, cfg) + [
        "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
    ]
    for field in TSHARK_LIVE_FIELDS:
        cmd += ["-e", field]
    if filt:
        cmd += ["-Y", filt]

    timeout = max(cfg.capture_seconds + 60, 120) if cfg.interface else 600
    proc = run_tshark(cmd, timeout=timeout)
    if proc.returncode not in (0, 1):
        return ice_map

    for line in proc.stdout.splitlines():
        tokens = line.split("\t")
        new_cands = parse_passive_line(tokens, cfg.include_private)
        merge_candidates(ice_map, new_cands)

    if not cfg.include_private:
        ice_map = {ip: c for ip, c in ice_map.items() if is_public_ip(ip)}
    return ice_map


def extract_ips_endpoints(tshark: str, pcap: str) -> dict[str, int]:
    hits: dict[str, int] = {}
    proc = run_tshark([tshark, "-n", "-r", pcap, "-q", "-z", "endpoints,ip"], timeout=600)
    if proc.returncode not in (0, 1):
        return hits
    for line in proc.stdout.splitlines():
        m = ENDPOINTS_LINE.match(line)
        if m:
            hits[m.group(1)] = int(m.group(2))
    return hits


def extract_ips(cfg: RunConfig, tshark: str) -> tuple[dict[str, int], str]:
    filt = effective_filter(cfg)
    hits: dict[str, int] = {}

    if cfg.pcap:
        pcap_path = Path(cfg.pcap)
        if not pcap_path.is_file():
            sys.exit(f"File pcap tidak ditemukan: {pcap_path}")
    elif cfg.interface:
        print(f"[*] Capture live {cfg.capture_seconds}s pada {cfg.interface!r} ...", file=sys.stderr)

    if cfg.filter_preset == "all" and cfg.pcap and not cfg.display_filter:
        hits = extract_ips_endpoints(tshark, cfg.pcap)
        if not cfg.include_private:
            hits = {ip: n for ip, n in hits.items() if is_public_ip(ip)}
        return hits, ""

    ice_map = extract_ice_fields(tshark, cfg, filt)
    hits = {ip: c.packet_hits for ip, c in ice_map.items()}

    if not hits and filt:
        hits = extract_ips_fields(tshark, cfg, filt)

    if not hits and cfg.pcap and filt:
        print("[!] Filter tidak match paket — fallback ke semua endpoint IP di pcap.", file=sys.stderr)
        hits = extract_ips_endpoints(tshark, cfg.pcap)

    if not cfg.include_private:
        hits = {ip: n for ip, n in hits.items() if is_public_ip(ip)}

    for ip in cfg.extra_ips:
        hits.setdefault(ip, 0)

    return hits, filt


def _tshark_base(tshark: str, cfg: RunConfig) -> list[str]:
    cmd = [tshark, "-n"]
    if cfg.pcap:
        cmd += ["-r", cfg.pcap]
    elif cfg.interface:
        cmd += ["-i", cfg.interface, "-a", f"duration:{cfg.capture_seconds}"]
        bpf = effective_bpf(cfg)
        if bpf:
            cmd += ["-f", bpf]
        if cfg.write_pcap and not cfg.live:
            cmd += ["-w", cfg.write_pcap]
    return cmd


def _find_dumpcap(tshark: str) -> Optional[str]:
    tshark_path = Path(tshark)
    for name in ("dumpcap", "dumpcap.exe"):
        candidate = tshark_path.parent / name
        if candidate.is_file():
            return str(candidate)
    import shutil
    found = shutil.which("dumpcap")
    return found


def build_live_tshark_cmd(tshark: str, cfg: RunConfig, filt: str, write_pcap: bool = False) -> list[str]:
    cmd = [tshark, "-n", "-i", cfg.interface or "", "-l", "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f"]
    for field in TSHARK_LIVE_FIELDS:
        cmd += ["-e", field]

    bpf = effective_bpf(cfg)
    if cfg.filter_preset == "all" and not cfg.display_filter:
        bpf = "udp or tcp"
    if bpf:
        cmd += ["-f", bpf]
    if filt:
        cmd += ["-Y", filt]
    if write_pcap:
        cmd += ["-w", cfg.write_pcap]
    return cmd


def build_dumpcap_cmd(tshark: str, cfg: RunConfig) -> list[str]:
    dumpcap = _find_dumpcap(tshark)
    if not dumpcap:
        return []
    bpf = effective_bpf(cfg)
    cmd = [dumpcap, "-i", cfg.interface or "", "-w", cfg.write_pcap or ""]
    if bpf:
        cmd += ["-f", bpf]
    return cmd


def ingest_line(
    line: str,
    ice_map: dict[str, IceCandidate],
    hits: dict[str, int],
    cfg: RunConfig,
    new_ips: set[str],
) -> int:
    tokens = line.split("\t")
    new_list = parse_passive_line(tokens, cfg.include_private)
    added = merge_candidates(ice_map, new_list)
    counted = 0
    for ip in added:
        new_ips.add(ip)
        hits[ip] = ice_map[ip].packet_hits
        counted += 1
    for ip in new_list:
        if ip.ip in hits:
            hits[ip.ip] += 1
            if ip.ip not in added:
                counted += 1
    return counted


def run_live_monitor(cfg: RunConfig, tshark: str, db_path: Path, asn_path: Optional[Path] = None) -> int:
    if not cfg.interface:
        sys.exit("--live butuh -i/--interface")

    filt = effective_filter(cfg)
    if cfg.filter_preset == "all" and not cfg.display_filter:
        filt = ""

    dumpcap_proc = None
    use_dual = bool(cfg.write_pcap)
    if use_dual:
        dumpcap_cmd = build_dumpcap_cmd(tshark, cfg)
        if dumpcap_cmd:
            print(f"[*] dumpcap writer: {' '.join(dumpcap_cmd)}", file=sys.stderr)
            dumpcap_proc = subprocess.Popen(dumpcap_cmd, stderr=subprocess.DEVNULL)

    cmd = build_live_tshark_cmd(tshark, cfg, filt, write_pcap=not use_dual and bool(cfg.write_pcap))
    print(f"[*] LIVE mode — Ctrl+C untuk stop", file=sys.stderr)
    print(f"[*] tshark: {' '.join(cmd)}", file=sys.stderr)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

    ice_map: dict[str, IceCandidate] = {}
    hits: dict[str, int] = defaultdict(int)
    geo_cache: dict[str, GeoResult] = {}
    new_ips: set[str] = set()
    total_packets = 0
    started = time.time()
    last_render = 0.0
    last_event = started
    dirty = True
    use_apt_ui = cfg.filter_preset in ("omegle-ometv",) or cfg.platform

    try:
        with geoip2.database.Reader(str(db_path)) as reader:
            asn_reader = geoip2.database.Reader(str(asn_path)) if asn_path and asn_path.is_file() else None
            try:
                while proc.poll() is None:
                    line = proc.stdout.readline() if proc.stdout else ""
                    if line:
                        line = line.rstrip("\n")
                        if line.strip():
                            n = ingest_line(line, ice_map, hits, cfg, new_ips)
                            if n:
                                total_packets += 1
                                last_event = time.time()
                                dirty = True

                    for ip in list(new_ips):
                        geo_cache[ip] = lookup_geo(reader, ip, hits[ip])
                    if new_ips:
                        dirty = True
                    new_ips.clear()

                    now = time.time()
                    if now - last_render >= cfg.live_refresh:
                        dirty = True

                    if dirty:
                        if use_apt_ui:
                            peers = score_candidates(
                                ice_map, reader, asn_reader,
                                exclude_self=cfg.exclude_self,
                                min_confidence=0,
                            )
                            render_apt_dashboard(
                                cfg, tshark, db_path, filt, peers,
                                total_packets, started, last_event,
                                turn_only=is_turn_only_session(peers),
                            )
                        else:
                            rows = []
                            for ip in sorted(hits, key=lambda x: (-hits[x], x)):
                                row = geo_cache.get(ip)
                                if row:
                                    row.packet_hits = hits[ip]
                                    rows.append(row)
                            render_live_screen(
                                cfg, tshark, db_path, filt, rows,
                                total_packets, started, last_event,
                            )
                        last_render = now
                        dirty = False
                    elif not line:
                        time.sleep(0.05)
            finally:
                if asn_reader:
                    asn_reader.close()
    except KeyboardInterrupt:
        print("\n[*] Dihentikan operator.", file=sys.stderr)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if dumpcap_proc and dumpcap_proc.poll() is None:
            dumpcap_proc.terminate()
            try:
                dumpcap_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dumpcap_proc.kill()
        if total_packets == 0:
            print(
                "Tidak ada paket tertangkap. Coba: CMD Run as Administrator, "
                "periksa interface (--list-interfaces), atau --filter-preset all",
                file=sys.stderr,
            )

    if not hits:
        print("Tidak ada IP publik tertangkap.", file=sys.stderr)
        return 1

    peers = score_candidates(ice_map, exclude_self=cfg.exclude_self, min_confidence=cfg.min_confidence)
    render_summary(peers, turn_only=is_turn_only_session(peers))

    if cfg.out_file:
        from chat_geoip.export.evidence import write_live_report
        meta = CaptureMeta(
            mode="live-stream",
            interface=cfg.interface or "",
            display_filter=filt,
            filter_preset=cfg.filter_preset,
            tshark=tshark,
            database=str(db_path),
            timestamp_utc=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            ip_count=len(hits),
            platform=cfg.platform,
        )
        write_live_report(cfg.out_file, peers, meta, total_packets, int(time.time() - started))

    return 0


def live_capture_to_pcap(cfg: RunConfig, tshark: str) -> RunConfig:
    if not cfg.write_pcap:
        return cfg

    print(f"[*] Capture live: interface={cfg.interface!r} durasi={cfg.capture_seconds}s", file=sys.stderr)
    print(f"[*] Menyimpan ke: {cfg.write_pcap}", file=sys.stderr)

    cmd = _tshark_base(tshark, cfg)
    timeout = cfg.capture_seconds + 90
    proc = run_tshark(cmd, timeout=timeout)
    if proc.returncode not in (0, 1):
        err = (proc.stderr or proc.stdout or "").strip()
        sys.exit(f"Capture live gagal:\n{err[:2000]}")

    out = Path(cfg.write_pcap)
    if not out.is_file():
        sys.exit(f"File pcap tidak terbuat setelah capture: {out}")
    print(f"[OK] Capture selesai: {out} ({out.stat().st_size:,} bytes)", file=sys.stderr)

    return RunConfig(
        pcap=str(out),
        interface=None,
        capture_seconds=cfg.capture_seconds,
        write_pcap=cfg.write_pcap,
        display_filter=cfg.display_filter,
        filter_preset=cfg.filter_preset,
        db_path=cfg.db_path,
        include_private=cfg.include_private,
        output=cfg.output,
        out_file=cfg.out_file,
        tshark_path=cfg.tshark_path,
        extra_ips=cfg.extra_ips,
        bpf_filter=cfg.bpf_filter,
        platform=cfg.platform,
    )
