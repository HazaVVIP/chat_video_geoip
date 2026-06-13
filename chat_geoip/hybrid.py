"""Hybrid mode — passive tshark + browser hook in parallel."""

from __future__ import annotations

import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional

import geoip2.database

from chat_geoip.capture.browser_hook import BrowserHook
from chat_geoip.capture.passive import (
    build_live_tshark_cmd,
    build_dumpcap_cmd,
    ingest_line,
    resolve_interface,
)
from chat_geoip.config import CaptureMeta, IceCandidate, RunConfig, effective_filter
from chat_geoip.intel.peer_scorer import best_peer, is_turn_only_session, score_candidates
from chat_geoip.platforms.omegle_ometv import get_platform_url
from chat_geoip.session.store import SessionStore
from chat_geoip.ui.dashboard import render_apt_dashboard, render_summary
from chat_geoip.utils import resolve_asn_db_path


def run_hybrid(cfg: RunConfig, tshark: str, db_path: Path) -> int:
    if not cfg.interface:
        sys.exit("--hybrid butuh -i/--interface")

    filt = effective_filter(cfg)
    if cfg.filter_preset == "all" and not cfg.display_filter:
        filt = ""

    platform_url = cfg.platform_url or get_platform_url(cfg.platform)
    hook = BrowserHook(platform=cfg.platform, url=platform_url)
    hook.start()

    dumpcap_proc = None
    if cfg.write_pcap:
        dumpcap_cmd = build_dumpcap_cmd(tshark, cfg)
        if dumpcap_cmd:
            dumpcap_proc = subprocess.Popen(dumpcap_cmd, stderr=subprocess.DEVNULL)

    cmd = build_live_tshark_cmd(tshark, cfg, filt, write_pcap=not bool(dumpcap_proc) and bool(cfg.write_pcap))
    print(f"[*] HYBRID mode — passive + browser hook", file=sys.stderr)
    print(f"[*] tshark: {' '.join(cmd)}", file=sys.stderr)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

    ice_map: dict[str, IceCandidate] = {}
    hits: dict[str, int] = defaultdict(int)
    new_ips: set[str] = set()
    total_packets = 0
    started = time.time()
    last_render = 0.0
    last_event = started
    last_skip_update = started
    dirty = True

    asn_path = resolve_asn_db_path(cfg.asn_db_path)
    store = SessionStore(session_dir=cfg.session_dir, platform=cfg.platform, mode="hybrid")
    store.new_skip()

    try:
        with geoip2.database.Reader(str(db_path)) as reader:
            asn_reader = geoip2.database.Reader(str(asn_path)) if asn_path and asn_path.is_file() else None
            try:
                while proc.poll() is None:
                    line = proc.stdout.readline() if proc.stdout else ""
                    if line and line.strip():
                        n = ingest_line(line.rstrip("\n"), ice_map, hits, cfg, new_ips)
                        if n:
                            total_packets += 1
                            last_event = time.time()
                            dirty = True

                    browser_new = hook.poll_candidates()
                    browser_map = hook.get_ice_map()
                    from chat_geoip.parse.ice import merge_candidates
                    if browser_new:
                        merge_candidates(ice_map, list(browser_map.values()))
                        dirty = True
                        last_event = time.time()

                    now = time.time()
                    if now - last_render >= cfg.live_refresh:
                        dirty = True

                    if dirty:
                        browser_ips = set(browser_map.keys())
                        peers = score_candidates(
                            ice_map, reader, asn_reader,
                            exclude_self=cfg.exclude_self,
                            browser_ips=browser_ips,
                            min_confidence=0,
                        )
                        for p in peers:
                            if p.ip in new_ips or p.ip in browser_new:
                                p.is_new = True

                        render_apt_dashboard(
                            cfg, tshark, db_path, filt, peers,
                            total_packets, started, last_event,
                            turn_only=is_turn_only_session(peers) or hook.relay_only,
                            mode="hybrid",
                            browser_active=True,
                        )

                        if now - last_skip_update >= 30:
                            store.update_skip(
                                peers,
                                passive_ips=list(hits.keys()),
                                browser_ips=list(browser_ips),
                                min_confidence=cfg.min_confidence or 50,
                                redact=cfg.redact,
                            )
                            last_skip_update = now

                        last_render = now
                        dirty = False
                        new_ips.clear()
                    elif not line:
                        time.sleep(0.05)
            finally:
                if asn_reader:
                    asn_reader.close()
    except KeyboardInterrupt:
        print("\n[*] Hybrid session dihentikan.", file=sys.stderr)
    finally:
        hook.stop()
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if dumpcap_proc and dumpcap_proc.poll() is None:
            dumpcap_proc.terminate()

    browser_ips = set(hook.get_ice_map().keys())
    peers = score_candidates(
        ice_map,
        exclude_self=cfg.exclude_self,
        browser_ips=browser_ips,
        min_confidence=cfg.min_confidence,
    )
    store.update_skip(peers, passive_ips=list(hits.keys()), browser_ips=list(browser_ips), redact=cfg.redact)
    render_summary(peers, turn_only=is_turn_only_session(peers))

    report_path = store.save_apt_report(
        extra_meta={
            "tshark": tshark,
            "interface": cfg.interface,
            "total_packets": total_packets,
            "duration_seconds": int(time.time() - started),
        },
        redact=cfg.redact,
    )
    print(f"\n[OK] Evidence: {report_path}", file=sys.stderr)

    if cfg.out_file:
        from chat_geoip.export.evidence import write_live_report
        meta = CaptureMeta(
            mode="hybrid",
            interface=cfg.interface or "",
            display_filter=filt,
            filter_preset=cfg.filter_preset,
            tshark=tshark,
            database=str(db_path),
            timestamp_utc=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            ip_count=len(hits),
            platform=cfg.platform,
        )
        write_live_report(cfg.out_file, peers, meta, total_packets, int(time.time() - started), cfg.redact)

    bp = best_peer(peers, cfg.min_confidence or 50)
    if cfg.alert_sound and bp:
        _beep()

    return 0 if peers else 1


def _beep() -> None:
    try:
        import platform
        if platform.system() == "Windows":
            import winsound
            winsound.Beep(1000, 300)
        else:
            print("\a", end="", flush=True)
    except Exception:
        pass
