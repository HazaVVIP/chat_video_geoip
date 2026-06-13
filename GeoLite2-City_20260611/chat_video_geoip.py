#!/usr/bin/env python3
"""
Ekstrak IP dari lalu lintas video/chat (tshark) lalu geolokasi via GeoLite2.

Contoh:
  python3 chat_video_geoip.py -r capture.pcap
  python3 chat_video_geoip.py -i eth0 -c 60
  python3 chat_video_geoip.py -r zoom.pcap --db ~/GeoIP/GeoLite2-City.mmdb -o json

GeoLite2 (gratis, akun MaxMind diperlukan):
  https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
  Unduh GeoLite2-City.mmdb dan arahkan dengan --db atau env GEOLITE2_CITY_DB.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Optional

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    print(
        "Modul geoip2 belum terpasang. Jalankan: pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


# Display filter Wireshark: signaling + media umum video/chat (WebRTC, VoIP, conferencing)
DEFAULT_DISPLAY_FILTER = (
    "stun or rtp or rtcp or rtsp or sip or h323 or "
    "tls.handshake.extensions_server_name contains \"zoom\" or "
    "tls.handshake.extensions_server_name contains \"teams\" or "
    "tls.handshake.extensions_server_name contains \"discord\" or "
    "tls.handshake.extensions_server_name contains \"meet.google\" or "
    "tls.handshake.extensions_server_name contains \"webex\" or "
    "quic or (udp.port >= 10000 and udp.port <= 65535 and frame.len > 200)"
)

DEFAULT_DB_CANDIDATES = (
    "GEOLITE2_CITY_DB",
    "~/GeoIP/GeoLite2-City.mmdb",
    "~/geoip/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
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
    error: str = ""


@dataclass
class RunConfig:
    pcap: Optional[str] = None
    interface: Optional[str] = None
    capture_seconds: int = 30
    display_filter: str = DEFAULT_DISPLAY_FILTER
    db_path: Optional[str] = None
    include_private: bool = False
    output: str = "table"
    out_file: Optional[str] = None
    tshark_path: str = "tshark"
    extra_ips: list[str] = field(default_factory=list)


def find_tshark(explicit: str) -> str:
    path = shutil.which(explicit)
    if not path:
        sys.exit(f"tshark tidak ditemukan ({explicit}). Pasang: sudo apt install tshark")
    return path


def resolve_db_path(explicit: Optional[str]) -> Path:
    if explicit:
        p = Path(os.path.expanduser(explicit))
        if not p.is_file():
            sys.exit(f"Database GeoLite2 tidak ditemukan: {p}")
        return p

    env = os.environ.get("GEOLITE2_CITY_DB")
    if env:
        p = Path(os.path.expanduser(env))
        if p.is_file():
            return p

    for candidate in DEFAULT_DB_CANDIDATES[1:]:
        p = Path(os.path.expanduser(candidate))
        if p.is_file():
            return p

    sys.exit(
        "GeoLite2-City.mmdb tidak ditemukan.\n"
        "Unduh dari https://dev.maxmind.com/geoip/geolite2-free-geolocation-data\n"
        "Lalu: export GEOLITE2_CITY_DB=/path/to/GeoLite2-City.mmdb"
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


def run_tshark_ips(cfg: RunConfig) -> tuple[dict[str, int], str]:
    """Jalankan tshark; kembalikan {ip: jumlah kemunculan} dan stderr ringkas."""
    tshark = find_tshark(cfg.tshark_path)
    hits: dict[str, int] = defaultdict(int)

    base_cmd = [tshark, "-n", "-Y", cfg.display_filter, "-T", "fields", "-e", "ip.addr"]

    if cfg.pcap:
        cmd = base_cmd + ["-r", cfg.pcap]
    elif cfg.interface:
        cmd = base_cmd + ["-i", cfg.interface, "-a", f"duration:{cfg.capture_seconds}"]
    else:
        sys.exit("Berikan --pcap FILE atau --interface IFACE untuk capture live.")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(cfg.capture_seconds + 30, 120) if cfg.interface else 600,
        )
    except subprocess.TimeoutExpired:
        sys.exit("tshark timeout — periksa filter atau durasi capture.")

    if proc.returncode not in (0, 1):
        err = (proc.stderr or proc.stdout or "").strip()
        sys.exit(f"tshark gagal (exit {proc.returncode}):\n{err[:2000]}")

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        for token in line.replace(",", "\t").split("\t"):
            token = token.strip()
            if not token or token == "<no value>":
                continue
            for part in token.split(","):
                part = part.strip()
                if not part:
                    continue
                if cfg.include_private or is_public_ip(part):
                    hits[part] += 1

    for ip in cfg.extra_ips:
        if cfg.include_private or is_public_ip(ip):
            hits[ip] += 0

    return dict(hits), proc.stderr.strip()


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
    lines = []
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

    lines.append(fmt_row(headers))
    lines.append("  ".join("-" * w for w in col_widths))
    for row in str_rows:
        lines.append(fmt_row(row))
    return "\n".join(lines)


def write_output(rows: list[GeoResult], cfg: RunConfig) -> None:
    if cfg.output == "json":
        payload = [asdict(r) for r in rows]
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        text = format_table(rows)

    if cfg.out_file:
        Path(cfg.out_file).write_text(text + "\n", encoding="utf-8")
        print(f"Disimpan ke {cfg.out_file}", file=sys.stderr)
    else:
        print(text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Ekstrak IP video/chat via tshark + geolokasi GeoLite2.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument("-r", "--pcap", help="File capture Wireshark (.pcap/.pcapng)")
    src.add_argument("-i", "--interface", help="Interface untuk capture live (mis. eth0, wlan0)")

    p.add_argument("-c", "--capture-seconds", type=int, default=30, help="Durasi capture live (default: 30)")
    p.add_argument(
        "-f",
        "--display-filter",
        default=DEFAULT_DISPLAY_FILTER,
        help="Display filter Wireshark (default: filter video/chat umum)",
    )
    p.add_argument(
        "--db",
        dest="db_path",
        help="Path GeoLite2-City.mmdb (default: GEOLITE2_CITY_DB atau lokasi umum)",
    )
    p.add_argument("--include-private", action="store_true", help="Sertakan IP private/loopback")
    p.add_argument("--ip", action="append", default=[], dest="extra_ips", help="IP tambahan untuk lookup")
    p.add_argument("-o", "--output", choices=("table", "json"), default="table")
    p.add_argument("--out-file", help="Tulis hasil ke file")
    p.add_argument("--tshark", default="tshark", help="Path binary tshark")
    p.add_argument(
        "--list-filters",
        action="store_true",
        help="Tampilkan display filter bawaan lalu keluar",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_filters:
        print("Display filter bawaan:\n")
        print(DEFAULT_DISPLAY_FILTER)
        return 0

    if not args.pcap and not args.interface and not args.extra_ips:
        parser.error("Butuh --pcap, --interface, atau minimal --ip")

    cfg = RunConfig(
        pcap=args.pcap,
        interface=args.interface,
        capture_seconds=args.capture_seconds,
        display_filter=args.display_filter,
        db_path=args.db_path,
        include_private=args.include_private,
        output=args.output,
        out_file=args.out_file,
        tshark_path=args.tshark,
        extra_ips=args.extra_ips,
    )

    db_path = resolve_db_path(cfg.db_path)

    if cfg.pcap or cfg.interface:
        ips, tshark_err = run_tshark_ips(cfg)
        if tshark_err:
            print(f"[tshark] {tshark_err[:500]}", file=sys.stderr)
    else:
        ips = {}

    for ip in cfg.extra_ips:
        if cfg.include_private or is_public_ip(ip):
            ips.setdefault(ip, 0)

    if not ips:
        print("Tidak ada IP publik ditemukan pada lalu lintas yang difilter.", file=sys.stderr)
        return 1

    print(f"Database: {db_path}", file=sys.stderr)
    print(f"IP unik: {len(ips)}", file=sys.stderr)

    rows = geolocate_ips(ips, db_path)
    write_output(rows, cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
