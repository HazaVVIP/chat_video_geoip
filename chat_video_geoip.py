#!/usr/bin/env python3
"""
Ekstrak IP dari lalu lintas video/chat (tshark/pcap) + geolokasi GeoLite2.

Contoh:
  python chat_video_geoip.py --live -i "Wi-Fi"
  python chat_video_geoip.py --live -i "Wi-Fi" -w session.pcap
  python chat_video_geoip.py -r meeting.pcap
  python chat_video_geoip.py --list-interfaces

GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    print(
        "Modul geoip2 belum terpasang. Jalankan: pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


SCRIPT_DIR = Path(__file__).resolve().parent

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
    "voip": "sip or rtp or rtcp or h323 or mgcp or iax2",
    "all": "",  # tanpa display filter — pakai stat endpoints
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
    "GeoLite2-City.mmdb",  # relatif ke cwd / script dir
    "~/GeoIP/GeoLite2-City.mmdb",
    "~/geoip/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
)

ENDPOINTS_LINE = re.compile(
    r"^\s*(\d+\.\d+\.\d+\.\d+)\s*\|\s*(\d+)\s*\|"
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
    error: str = ""


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
    mode: str = ""  # pcap | live | ip-only
    pcap_path: str = ""
    interface: str = ""
    capture_seconds: int = 0
    display_filter: str = ""
    filter_preset: str = ""
    tshark: str = ""
    database: str = ""
    timestamp_utc: str = ""
    ip_count: int = 0


@dataclass
class RunConfig:
    pcap: Optional[str] = None
    interface: Optional[str] = None
    capture_seconds: int = 60
    write_pcap: Optional[str] = None
    display_filter: str = ""
    filter_preset: str = "video-chat"
    db_path: Optional[str] = None
    include_private: bool = False
    output: str = "table"
    out_file: Optional[str] = None
    tshark_path: Optional[str] = None
    extra_ips: list[str] = field(default_factory=list)
    pcap_info_only: bool = False
    bpf_filter: str = "udp or tcp port 443 or tcp port 80 or tcp port 3478 or udp port 3478"
    live: bool = False
    live_refresh: float = 1.0


def find_tshark(explicit: Optional[str] = None) -> str:
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        found = shutil.which(explicit)
        if found:
            return found
        sys.exit(f"tshark tidak ditemukan: {explicit}")

    env = os.environ.get("TSHARK_PATH") or os.environ.get("TSHARK")
    if env and Path(env).is_file():
        return env

    for candidate in TSHARK_CANDIDATES:
        if candidate == "tshark":
            found = shutil.which("tshark")
            if found:
                return found
        elif Path(candidate).is_file():
            return candidate

    hint = (
        "Windows: install Wireshark → https://www.wireshark.org/download.html\n"
        "Linux: sudo apt install tshark"
    )
    sys.exit(f"tshark tidak ditemukan di PATH.\n{hint}")


def resolve_db_path(explicit: Optional[str]) -> Path:
    if explicit:
        for base in (Path.cwd(), SCRIPT_DIR):
            p = (base / explicit).resolve() if not Path(explicit).is_absolute() else Path(explicit)
            if p.is_file():
                return p
        p = Path(os.path.expanduser(explicit))
        if p.is_file():
            return p
        sys.exit(f"Database GeoLite2 tidak ditemukan: {explicit}")

    env = os.environ.get("GEOLITE2_CITY_DB")
    if env:
        p = Path(os.path.expanduser(env))
        if p.is_file():
            return p

    for candidate in DB_CANDIDATES[1:]:
        for base in (SCRIPT_DIR, Path.cwd()):
            p = base / candidate if not candidate.startswith("~") else Path(os.path.expanduser(candidate))
            if p.is_file():
                return p.resolve()

    sys.exit(
        "GeoLite2-City.mmdb tidak ditemukan.\n"
        "Letakkan di folder script atau: set GEOLITE2_CITY_DB=C:\\path\\GeoLite2-City.mmdb"
    )


def is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def run_tshark(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        sys.exit(f"tshark timeout setelah {timeout}s: {' '.join(cmd[:6])}...")


def effective_filter(cfg: RunConfig) -> str:
    if cfg.display_filter:
        return cfg.display_filter
    return FILTER_PRESETS.get(cfg.filter_preset, FILTER_PRESETS["video-chat"])


def tshark_base(tshark: str, cfg: RunConfig) -> list[str]:
    cmd = [tshark, "-n"]
    if cfg.pcap:
        cmd += ["-r", cfg.pcap]
    elif cfg.interface:
        cmd += ["-i", cfg.interface, "-a", f"duration:{cfg.capture_seconds}"]
        if cfg.bpf_filter:
            cmd += ["-f", cfg.bpf_filter]
        if cfg.write_pcap:
            cmd += ["-w", cfg.write_pcap]
    return cmd


def count_filtered_packets(tshark: str, cfg: RunConfig, filt: str) -> int:
    if not cfg.pcap and not cfg.interface:
        return 0
    cmd = tshark_base(tshark, cfg) + ["-Y", filt or "frame"]
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

    cap = run_tshark(
        [tshark, "-n", "-r", str(path), "-T", "fields", "-e", "frame.time", "-c", "1"]
    )
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


def list_interfaces(tshark: str) -> list[tuple[str, str]]:
    proc = run_tshark([tshark, "-D"], timeout=30)
    if proc.returncode != 0:
        sys.exit(f"Gagal list interface:\n{proc.stderr[:1000]}")
    result: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        # "1. \Device\NPF_{...} (Ethernet)"
        m = re.match(r"^\d+\.\s+(.+?)(?:\s+\((.+)\))?$", line)
        if m:
            result.append((m.group(1).strip(), (m.group(2) or "").strip()))
    return result


def extract_ips_fields(tshark: str, cfg: RunConfig, filt: str) -> dict[str, int]:
    """Ekstrak IP dari ip.src + ip.dst pada paket terfilter."""
    hits: dict[str, int] = defaultdict(int)
    cmd = tshark_base(tshark, cfg) + [
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
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


def extract_ips_endpoints(tshark: str, pcap: str) -> dict[str, int]:
    """Fallback: semua IPv4 endpoint + jumlah paket (tanpa display filter)."""
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
        print(
            f"[*] Capture live {cfg.capture_seconds}s pada {cfg.interface!r} ...",
            file=sys.stderr,
        )

    if cfg.filter_preset == "all" and cfg.pcap and not cfg.display_filter:
        hits = extract_ips_endpoints(tshark, cfg.pcap)
        if cfg.include_private:
            return hits, ""
        return {ip: n for ip, n in hits.items() if is_public_ip(ip)}, ""

    if filt:
        hits = extract_ips_fields(tshark, cfg, filt)
    elif cfg.pcap:
        hits = extract_ips_endpoints(tshark, cfg.pcap)
    else:
        hits = extract_ips_fields(tshark, cfg, "")

    if not hits and cfg.pcap and filt:
        print(
            "[!] Filter tidak match paket — fallback ke semua endpoint IP di pcap.",
            file=sys.stderr,
        )
        hits = extract_ips_endpoints(tshark, cfg.pcap)

    if not cfg.include_private:
        hits = {ip: n for ip, n in hits.items() if is_public_ip(ip)}

    for ip in cfg.extra_ips:
        hits.setdefault(ip, 0)

    return hits, filt


def live_capture_to_pcap(cfg: RunConfig, tshark: str) -> RunConfig:
    """Capture live ke file pcap, lalu alihkan analisis ke file tersebut."""
    if not cfg.write_pcap:
        return cfg

    print(f"[*] Capture live: interface={cfg.interface!r} durasi={cfg.capture_seconds}s", file=sys.stderr)
    print(f"[*] Menyimpan ke: {cfg.write_pcap}", file=sys.stderr)

    cmd = tshark_base(tshark, cfg)
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
    )


def clear_screen() -> None:
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")


def ingest_ip_line(
    line: str,
    hits: dict[str, int],
    cfg: RunConfig,
    new_ips: set[str],
) -> int:
    """Parse baris tshark; kembalikan jumlah IP yang dihitung."""
    counted = 0
    for token in line.split("\t"):
        token = token.strip()
        if not token or token == "<no value>":
            continue
        if not cfg.include_private and not is_public_ip(token):
            continue
        if token not in hits:
            new_ips.add(token)
        hits[token] += 1
        counted += 1
    return counted


def build_live_tshark_cmd(tshark: str, cfg: RunConfig, filt: str) -> list[str]:
    cmd = [
        tshark,
        "-n",
        "-i",
        cfg.interface or "",
        "-l",  # flush tiap paket — output real-time
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
    ]
    bpf = cfg.bpf_filter
    if cfg.filter_preset == "all" and not cfg.display_filter:
        bpf = "udp or tcp"
    if bpf:
        cmd += ["-f", bpf]
    if filt:
        cmd += ["-Y", filt]
    if cfg.write_pcap:
        cmd += ["-w", cfg.write_pcap]
    return cmd


def render_live_screen(
    cfg: RunConfig,
    tshark: str,
    db_path: Path,
    filt: str,
    hits: dict[str, int],
    geo_cache: dict[str, GeoResult],
    total_packets: int,
    started: float,
    last_event: float,
) -> None:
    rows: list[GeoResult] = []
    for ip in sorted(hits, key=lambda x: (-hits[x], x)):
        row = geo_cache.get(ip)
        if row is None:
            continue
        row.packet_hits = hits[ip]
        rows.append(row)

    uptime = int(time.time() - started)
    mm, ss = divmod(uptime, 60)
    hh, mm = divmod(mm, 60)
    idle = time.time() - last_event

    clear_screen()
    print("=" * 72)
    print("  LIVE GEOLOCATE — video/chat traffic")
    print("=" * 72)
    print(f"  Interface : {cfg.interface}")
    print(f"  tshark    : {tshark}")
    print(f"  Database  : {db_path.name}")
    print(f"  Filter    : {filt or '(semua IP publik)'}")
    print(f"  Uptime    : {hh:02d}:{mm:02d}:{ss:02d}  |  Paket: {total_packets:,}  |  IP: {len(hits)}")
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


def run_live_monitor(cfg: RunConfig, tshark: str, db_path: Path) -> int:
    if not cfg.interface:
        sys.exit("--live butuh -i/--interface")

    filt = effective_filter(cfg)
    if cfg.filter_preset == "all" and not cfg.display_filter:
        filt = ""

    cmd = build_live_tshark_cmd(tshark, cfg, filt)
    print(f"[*] LIVE mode — Ctrl+C untuk stop", file=sys.stderr)
    print(f"[*] tshark: {' '.join(cmd)}", file=sys.stderr)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )

    hits: dict[str, int] = defaultdict(int)
    geo_cache: dict[str, GeoResult] = {}
    new_ips: set[str] = set()
    total_packets = 0
    started = time.time()
    last_render = 0.0
    last_event = started
    dirty = True

    try:
        with geoip2.database.Reader(str(db_path)) as reader:
            while proc.poll() is None:
                line = proc.stdout.readline() if proc.stdout else ""
                if line:
                    line = line.rstrip("\n")
                    if line.strip():
                        n = ingest_ip_line(line, hits, cfg, new_ips)
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
                    render_live_screen(
                        cfg, tshark, db_path, filt, hits, geo_cache,
                        total_packets, started, last_event,
                    )
                    last_render = now
                    dirty = False
                elif not line:
                    time.sleep(0.05)

            # baca sisa stdout
            if proc.stdout:
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if line.strip():
                        ingest_ip_line(line, hits, cfg, new_ips)
                        total_packets += 1
                for ip in new_ips:
                    geo_cache[ip] = lookup_geo(reader, ip, hits.get(ip, 0))

    except KeyboardInterrupt:
        print("\n[*] Dihentikan operator.", file=sys.stderr)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if total_packets == 0:
            print(
                "Tidak ada paket tertangkap. Coba: CMD Run as Administrator, "
                "periksa interface (--list-interfaces), atau --filter-preset all",
                file=sys.stderr,
            )

    if not hits:
        print("Tidak ada IP publik tertangkap.", file=sys.stderr)
        return 1

    rows = []
    for ip in sorted(hits, key=lambda x: (-hits[x], x)):
        row = geo_cache.get(ip)
        if not row:
            continue
        row.packet_hits = hits[ip]
        rows.append(row)

    clear_screen()
    print("=" * 72)
    print("  RINGKASAN LIVE (selesai)")
    print("=" * 72)
    print(format_table(rows))

    meta = CaptureMeta(
        mode="live-stream",
        interface=cfg.interface or "",
        display_filter=filt,
        filter_preset=cfg.filter_preset,
        tshark=tshark,
        database=str(db_path),
        timestamp_utc=datetime.now(timezone.utc).isoformat(),
        ip_count=len(hits),
        pcap_path=cfg.write_pcap or "",
    )

    if cfg.out_file:
        payload = build_report(rows, meta, None)
        payload["meta"]["total_packets"] = total_packets
        payload["meta"]["duration_seconds"] = int(time.time() - started)
        Path(cfg.out_file).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"\nDisimpan ke {cfg.out_file}", file=sys.stderr)

    return 0


def lookup_geo(reader: geoip2.database.Reader, ip: str, packet_hits: int) -> GeoResult:
    result = GeoResult(ip=ip, packet_hits=packet_hits)
    try:
        rec = reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        result.error = "not_in_database"
        return result
    except ValueError as exc:
        result.error = str(exc)
        return result

    result.country = rec.country.name or ""
    result.country_code = rec.country.iso_code or ""
    if rec.subdivisions:
        result.subdivision = rec.subdivisions.most_specific.name or ""
    result.city = rec.city.name or ""
    result.postal_code = rec.postal.code or ""
    result.latitude = rec.location.latitude
    result.longitude = rec.location.longitude
    result.accuracy_radius_km = rec.location.accuracy_radius
    return result


def geolocate_ips(ips: dict[str, int], db_path: Path) -> list[GeoResult]:
    results: list[GeoResult] = []
    with geoip2.database.Reader(str(db_path)) as reader:
        for ip in sorted(ips, key=lambda x: (-ips[x], x)):
            results.append(lookup_geo(reader, ip, ips[ip]))
    return results


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


def build_report(
    rows: list[GeoResult],
    meta: CaptureMeta,
    pcap_info: Optional[PcapInfo] = None,
) -> dict:
    return {
        "meta": asdict(meta),
        "pcap": asdict(pcap_info) if pcap_info else None,
        "results": [asdict(r) for r in rows],
    }


def write_output(
    rows: list[GeoResult],
    cfg: RunConfig,
    meta: CaptureMeta,
    pcap_info: Optional[PcapInfo] = None,
) -> None:
    if cfg.output == "json":
        text = json.dumps(build_report(rows, meta, pcap_info), indent=2, ensure_ascii=False)
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
        print(f"Disimpan ke {cfg.out_file}", file=sys.stderr)
    else:
        print(text)


def print_pcap_info(info: PcapInfo, filt: str = "") -> None:
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


def print_interfaces(tshark: str) -> None:
    ifaces = list_interfaces(tshark)
    if not ifaces:
        print("Tidak ada interface capture.")
        return
    print(f"tshark: {tshark}\n")
    for idx, (dev, desc) in enumerate(ifaces, 1):
        label = f" ({desc})" if desc else ""
        print(f"  {idx}. {dev}{label}")
    print("\nPakai: --live -i \"NAMA_INTERFACE\"  (contoh: --live -i \"Wi-Fi\")")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Integrasi tshark/pcap + GeoLite2 untuk geolokasi IP video/chat.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("-r", "--pcap", help="Analisis file .pcap / .pcapng")
    src.add_argument("-i", "--interface", help="Capture live dari interface (butuh admin/root)")

    p.add_argument(
        "--live",
        action="store_true",
        help="Mode live: tampilkan geolokasi terus-menerus sampai Ctrl+C (butuh -i)",
    )
    p.add_argument(
        "--live-refresh",
        type=float,
        default=1.0,
        metavar="SEC",
        help="Interval refresh layar live dalam detik (default: 1.0)",
    )
    p.add_argument("-c", "--capture-seconds", type=int, default=60, help="Durasi capture live terbatas (bukan --live)")
    p.add_argument(
        "-w",
        "--write-pcap",
        metavar="FILE",
        help="Simpan capture live ke file pcap lalu analisis otomatis",
    )
    p.add_argument(
        "--filter-preset",
        choices=tuple(FILTER_PRESETS),
        default="video-chat",
        help="Preset filter video/chat (default: video-chat)",
    )
    p.add_argument(
        "-f",
        "--display-filter",
        default="",
        help="Display filter Wireshark custom (override preset)",
    )
    p.add_argument(
        "--bpf-filter",
        default="udp or tcp port 443 or tcp port 80 or tcp port 3478 or udp port 3478",
        help="BPF capture filter untuk live capture",
    )
    p.add_argument("--db", dest="db_path", help="Path GeoLite2-City.mmdb")
    p.add_argument("--include-private", action="store_true", help="Sertakan IP private/loopback")
    p.add_argument("--ip", action="append", default=[], dest="extra_ips", help="IP manual untuk lookup")
    p.add_argument("-o", "--output", choices=("table", "json"), default="table")
    p.add_argument("--out-file", help="Simpan hasil ke file")
    p.add_argument("--tshark", dest="tshark_path", help="Path tshark (auto-detect jika kosong)")
    p.add_argument("--list-interfaces", action="store_true", help="Daftar interface capture")
    p.add_argument("--list-filters", action="store_true", help="Tampilkan preset filter")
    p.add_argument("--pcap-info", action="store_true", help="Info file pcap (butuh -r)")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    tshark = find_tshark(args.tshark_path)

    if args.list_interfaces:
        print_interfaces(tshark)
        return 0

    if args.list_filters:
        for name, filt in FILTER_PRESETS.items():
            print(f"[{name}]")
            print(filt or "(semua IP via endpoints)")
            print()
        return 0

    if not args.pcap and not args.interface and not args.extra_ips:
        parser.error("Butuh -r/--pcap, -i/--interface, atau --ip")

    if args.live and not args.interface:
        parser.error("--live butuh -i/--interface")
    if args.live and args.pcap:
        parser.error("--live tidak bisa digabung dengan -r/--pcap")

    cfg = RunConfig(
        pcap=args.pcap,
        interface=args.interface,
        capture_seconds=args.capture_seconds,
        write_pcap=args.write_pcap,
        display_filter=args.display_filter,
        filter_preset=args.filter_preset,
        db_path=args.db_path,
        include_private=args.include_private,
        output=args.output,
        out_file=args.out_file,
        tshark_path=tshark,
        extra_ips=args.extra_ips,
        bpf_filter=args.bpf_filter,
        live=args.live,
        live_refresh=max(0.2, args.live_refresh),
    )

    db_path = resolve_db_path(cfg.db_path)

    if cfg.live:
        return run_live_monitor(cfg, tshark, db_path)

    filt = effective_filter(cfg)

    if args.pcap_info:
        if not cfg.pcap:
            parser.error("--pcap-info butuh -r/--pcap")
        info = get_pcap_info(tshark, cfg.pcap, filt)
        print_pcap_info(info, filt)
        if args.pcap_info and not args.extra_ips and cfg.filter_preset != "all":
            return 0

    pcap_info: Optional[PcapInfo] = None

    if cfg.interface and cfg.write_pcap:
        cfg = live_capture_to_pcap(cfg, tshark)

    ips: dict[str, int] = {}
    if cfg.pcap or cfg.interface:
        ips, filt = extract_ips(cfg, tshark)
        if cfg.pcap:
            pcap_info = get_pcap_info(tshark, cfg.pcap, filt)
    elif cfg.extra_ips:
        ips = {}
        for ip in cfg.extra_ips:
            if cfg.include_private or is_public_ip(ip):
                ips[ip] = 0

    if not ips and cfg.extra_ips:
        for ip in cfg.extra_ips:
            if cfg.include_private or is_public_ip(ip):
                ips.setdefault(ip, 0)

    if not ips:
        print("Tidak ada IP publik ditemukan.", file=sys.stderr)
        if cfg.pcap and pcap_info:
            print(
                f"Tip: coba --filter-preset all atau --pcap-info -r {cfg.pcap}",
                file=sys.stderr,
            )
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
    )

    print(f"tshark   : {tshark}", file=sys.stderr)
    print(f"Database : {db_path}", file=sys.stderr)
    if cfg.pcap:
        print(f"PCAP     : {cfg.pcap}", file=sys.stderr)
    print(f"Filter   : {filt or '(all endpoints)'}", file=sys.stderr)
    print(f"IP unik  : {len(ips)}", file=sys.stderr)

    rows = geolocate_ips(ips, db_path)
    write_output(rows, cfg, meta, pcap_info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
