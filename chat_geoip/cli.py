"""CLI entry point and orchestration."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from chat_geoip.capture.browser_hook import BrowserHook, run_browser_only
from chat_geoip.capture.passive import (
    auto_select_interface,
    extract_ips,
    get_pcap_info,
    list_interfaces,
    live_capture_to_pcap,
    resolve_interface,
    run_live_monitor,
)
from chat_geoip.check import run_self_check
from chat_geoip.config import (
    FILTER_PRESETS,
    VERSION,
    BPF_PRESETS,
    CaptureMeta,
    RunConfig,
    effective_filter,
)
from chat_geoip.export.evidence import write_output
from chat_geoip.hybrid import run_hybrid
from chat_geoip.intel.geoip import geolocate_ips
from chat_geoip.intel.peer_scorer import score_candidates
from chat_geoip.platforms.omegle_ometv import apply_platform_config, get_platform_url
from chat_geoip.utils import find_tshark, is_public_ip, resolve_asn_db_path, resolve_db_path


def print_interfaces_list(tshark: str) -> None:
    ready, skipped = list_interfaces(tshark)
    if not ready and not skipped:
        print("Tidak ada interface capture.")
        return
    print(f"tshark: {tshark}\n")
    print("Capture-ready:")
    for idx, (dev, desc) in enumerate(ready, 1):
        label = f" ({desc})" if desc else ""
        print(f"  {idx}. {dev}{label}")
    if skipped:
        print("\nSkipped (virtual):")
        for idx, (dev, desc) in enumerate(skipped, len(ready) + 1):
            label = f" ({desc})" if desc else ""
            print(f"  {idx}. {dev}{label}")
    print('\nPakai: --live -i "NAMA_INTERFACE" atau --live -i 4')
    print("      --auto-interface untuk pilih Wi-Fi/Ethernet otomatis")


def print_pcap_info(info, filt: str = "") -> None:
    if not info.exists:
        print(f"File tidak ditemukan: {info.path}")
        return
    print(f"File       : {info.path}")
    print(f"Ukuran     : {info.file_size_bytes:,} bytes")
    print(f"Paket      : {info.packet_count}")
    print(f"Durasi     : {info.duration_seconds:.2f} detik")
    if info.first_packet:
        print(f"Pertama    : {info.first_packet}")
    if info.last_packet:
        print(f"Terakhir   : {info.last_packet}")
    if filt:
        print(f"Filter     : {filt}")
        print(f"Match pkt  : {info.filtered_packets}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="APT-grade hybrid WebRTC peer intelligence (tshark + GeoLite2 + browser hook).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("-r", "--pcap", help="Analisis file .pcap / .pcapng")
    src.add_argument("-i", "--interface", help="Capture live dari interface (butuh admin/root)")

    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--check", action="store_true", help="Smoke test: tshark, mmdb, deps")
    p.add_argument("--live", action="store_true", help="Mode live sampai Ctrl+C (butuh -i)")
    p.add_argument("--hybrid", action="store_true", help="Hybrid: passive tshark + browser hook")
    p.add_argument("--browser-only", action="store_true", help="Browser hook saja (tanpa tshark)")
    p.add_argument("--platform", choices=("ometv", "omegle"), default="", help="Platform target")
    p.add_argument("--url", dest="platform_url", default="", help="Override platform URL")
    p.add_argument("--live-refresh", type=float, default=1.0, metavar="SEC")
    p.add_argument("-c", "--capture-seconds", type=int, default=60)
    p.add_argument("-w", "--write-pcap", metavar="FILE")
    p.add_argument("--filter-preset", choices=tuple(FILTER_PRESETS), default="video-chat")
    p.add_argument("-f", "--display-filter", default="")
    p.add_argument("--bpf-filter", default=BPF_PRESETS["default"])
    p.add_argument("--db", dest="db_path")
    p.add_argument("--asn-db", dest="asn_db_path")
    p.add_argument("--include-private", action="store_true")
    p.add_argument("--no-exclude-self", action="store_true", help="Jangan exclude IP sendiri")
    p.add_argument("--auto-interface", action="store_true", help="Pilih Wi-Fi/Ethernet otomatis")
    p.add_argument("--ip", action="append", default=[], dest="extra_ips")
    p.add_argument("-o", "--output", choices=("table", "json"), default="table")
    p.add_argument("--out-file")
    p.add_argument("--tshark", dest="tshark_path")
    p.add_argument("--list-interfaces", action="store_true")
    p.add_argument("--list-filters", action="store_true")
    p.add_argument("--pcap-info", action="store_true")
    p.add_argument("--min-confidence", type=int, default=70)
    p.add_argument("--redact", action="store_true", help="Mask octet terakhir di export")
    p.add_argument("--alert-sound", action="store_true")
    p.add_argument("--webhook", default="")
    p.add_argument("--session-dir", default="")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.check:
        return run_self_check(args.tshark_path)

    tshark = find_tshark(args.tshark_path) if not args.browser_only else ""

    if args.list_interfaces:
        print_interfaces_list(tshark)
        return 0

    if args.list_filters:
        for name, filt in FILTER_PRESETS.items():
            print(f"[{name}]")
            print(filt or "(semua IP via endpoints)")
            print()
        return 0

    if args.browser_only:
        return _run_browser_only_mode(args)

    if not args.pcap and not args.interface and not args.extra_ips:
        parser.error("Butuh -r/--pcap, -i/--interface, --ip, --hybrid, atau --browser-only")

    if args.hybrid and not args.interface:
        parser.error("--hybrid butuh -i/--interface")
    if args.live and not args.interface:
        parser.error("--live butuh -i/--interface")
    if args.live and args.pcap:
        parser.error("--live tidak bisa digabung dengan -r/--pcap")
    if args.hybrid and args.pcap:
        parser.error("--hybrid tidak bisa digabung dengan -r/--pcap")

    iface = args.interface
    if iface and tshark:
        iface = resolve_interface(tshark, iface)
    if args.auto_interface and tshark:
        iface = auto_select_interface(tshark)
        print(f"[*] Auto-interface: {iface!r}", file=sys.stderr)

    cfg = RunConfig(
        pcap=args.pcap,
        interface=iface,
        capture_seconds=args.capture_seconds,
        write_pcap=args.write_pcap,
        display_filter=args.display_filter,
        filter_preset=args.filter_preset,
        db_path=args.db_path,
        asn_db_path=args.asn_db_path,
        include_private=args.include_private,
        output=args.output,
        out_file=args.out_file,
        tshark_path=tshark,
        extra_ips=args.extra_ips,
        bpf_filter=args.bpf_filter,
        live=args.live,
        live_refresh=max(0.2, args.live_refresh),
        exclude_self=not args.no_exclude_self,
        auto_interface=args.auto_interface,
        hybrid=args.hybrid,
        browser_only=args.browser_only,
        platform=args.platform,
        platform_url=args.platform_url,
        min_confidence=args.min_confidence,
        redact=args.redact,
        alert_sound=args.alert_sound,
        webhook=args.webhook,
        session_dir=args.session_dir,
    )

    if cfg.platform:
        apply_platform_config(cfg.platform, cfg)

    db_path = resolve_db_path(cfg.db_path)
    asn_path = resolve_asn_db_path(cfg.asn_db_path)

    if cfg.hybrid:
        return run_hybrid(cfg, tshark, db_path)

    if cfg.live:
        return run_live_monitor(cfg, tshark, db_path, asn_path)

    filt = effective_filter(cfg)

    if args.pcap_info:
        if not cfg.pcap:
            parser.error("--pcap-info butuh -r/--pcap")
        info = get_pcap_info(tshark, cfg.pcap, filt)
        print_pcap_info(info, filt)
        if not args.extra_ips and cfg.filter_preset != "all":
            return 0

    pcap_info = None
    if cfg.interface and cfg.write_pcap:
        cfg = live_capture_to_pcap(cfg, tshark)

    ips: dict[str, int] = {}
    if cfg.pcap or cfg.interface:
        ips, filt = extract_ips(cfg, tshark)
        if cfg.pcap:
            pcap_info = get_pcap_info(tshark, cfg.pcap, filt)
    elif cfg.extra_ips:
        for ip in cfg.extra_ips:
            if cfg.include_private or is_public_ip(ip):
                ips[ip] = 0

    if not ips:
        print("Tidak ada IP publik ditemukan.", file=sys.stderr)
        if cfg.pcap and pcap_info:
            print(f"Tip: coba --filter-preset all atau --pcap-info -r {cfg.pcap}", file=sys.stderr)
        return 1

    meta = CaptureMeta(
        mode="live" if args.interface else ("pcap" if cfg.pcap else "ip-only"),
        pcap_path=cfg.pcap or (cfg.write_pcap or ""),
        interface=args.interface or "",
        capture_seconds=cfg.capture_seconds,
        display_filter=filt,
        filter_preset=cfg.filter_preset,
        tshark=tshark,
        database=str(db_path),
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        ip_count=len(ips),
        platform=cfg.platform,
    )

    print(f"tshark   : {tshark}", file=sys.stderr)
    print(f"Database : {db_path}", file=sys.stderr)
    if cfg.pcap:
        print(f"PCAP     : {cfg.pcap}", file=sys.stderr)
    if cfg.extra_ips and not cfg.pcap and not cfg.interface:
        print("Mode     : manual lookup", file=sys.stderr)
    else:
        print(f"Filter   : {filt or '(all endpoints)'}", file=sys.stderr)
    print(f"IP unik  : {len(ips)}", file=sys.stderr)

    rows = geolocate_ips(ips, db_path, asn_path)
    write_output(rows, cfg, meta, pcap_info)
    return 0


def _run_browser_only_mode(args) -> int:
    from chat_geoip.config import IceCandidate
    from chat_geoip.intel.peer_scorer import score_candidates
    from chat_geoip.session.store import SessionStore
    from chat_geoip.ui.dashboard import render_apt_dashboard
    import time

    platform = args.platform or "ometv"
    url = args.platform_url or get_platform_url(platform)
    hook = BrowserHook(platform=platform, url=url)
    hook.start()

    store = SessionStore(session_dir=args.session_dir, platform=platform, mode="browser-only")
    store.new_skip()
    started = time.time()
    last_render = 0.0

    db_path = resolve_db_path(args.db_path)
    asn_path = resolve_asn_db_path(args.asn_db_path)

    try:
        import geoip2.database
        with geoip2.database.Reader(str(db_path)) as reader:
            asn_reader = geoip2.database.Reader(str(asn_path)) if asn_path and asn_path.is_file() else None
            try:
                while True:
                    hook.poll_candidates()
                    now = time.time()
                    if now - last_render >= max(0.2, args.live_refresh):
                        ice_map = hook.get_ice_map()
                        peers = score_candidates(
                            ice_map, reader, asn_reader,
                            browser_ips=set(ice_map.keys()),
                            min_confidence=0,
                        )
                        cfg = RunConfig(
                            platform=platform,
                            filter_preset="omegle-ometv",
                            live_refresh=args.live_refresh,
                            min_confidence=args.min_confidence,
                        )
                        render_apt_dashboard(
                            cfg, "", db_path, "", peers, 0, started, now,
                            turn_only=hook.relay_only,
                            mode="browser-only",
                            browser_active=True,
                        )
                        store.update_skip(peers, browser_ips=list(ice_map.keys()), redact=args.redact)
                        last_render = now
                    time.sleep(0.1)
            finally:
                if asn_reader:
                    asn_reader.close()
    except KeyboardInterrupt:
        print("\n[*] Browser-only dihentikan.", file=sys.stderr)
    finally:
        hook.stop()

    ice_map = hook.get_ice_map()
    peers = score_candidates(ice_map, browser_ips=set(ice_map.keys()), min_confidence=args.min_confidence)
    report = store.save_apt_report({"mode": "browser-only"}, redact=args.redact)
    print(f"[OK] Evidence: {report}", file=sys.stderr)
    return 0
