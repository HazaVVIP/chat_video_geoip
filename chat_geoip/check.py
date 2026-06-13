"""Self-check / smoke test."""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

from chat_geoip.config import SCRIPT_DIR, VERSION
from chat_geoip.utils import find_tshark, resolve_db_path, resolve_asn_db_path


def run_self_check(tshark_path: str | None = None) -> int:
    ok = True
    print(f"Chat Video GeoIP v{VERSION} — self check\n")

    # [1] VERSION
    vf = SCRIPT_DIR / "VERSION"
    if vf.is_file():
        print(f"[OK] VERSION file: {vf.read_text(encoding='utf-8').strip()}")
    else:
        print("[X] VERSION file missing")
        ok = False

    # [2] Python deps
    try:
        import geoip2  # noqa: F401
        print("[OK] geoip2 module")
    except ImportError:
        print("[X] geoip2 not installed")
        ok = False

    try:
        import playwright  # noqa: F401
        print("[OK] playwright module (hybrid mode)")
    except ImportError:
        print("[!] playwright not installed (optional for hybrid)")

    # [3] tshark
    try:
        tshark = find_tshark(tshark_path)
        proc = subprocess.run([tshark, "-v"], capture_output=True, text=True, timeout=10)
        ver_line = (proc.stderr or proc.stdout or "").splitlines()[0] if proc.returncode == 0 else "unknown"
        print(f"[OK] tshark: {tshark}")
        print(f"     {ver_line[:80]}")
    except SystemExit:
        print("[X] tshark not found")
        ok = False

    # [4] GeoLite2 City
    try:
        db = resolve_db_path(None)
        print(f"[OK] GeoLite2-City: {db} ({db.stat().st_size:,} bytes)")
    except SystemExit:
        print("[X] GeoLite2-City.mmdb not found")
        ok = False

    # [5] GeoLite2 ASN (optional)
    asn = resolve_asn_db_path(None)
    if asn:
        print(f"[OK] GeoLite2-ASN: {asn}")
    else:
        print("[!] GeoLite2-ASN.mmdb not found (optional)")

    # [6] Hook script
    hook = SCRIPT_DIR / "inject" / "webrtc_hook.js"
    if hook.is_file():
        print(f"[OK] webrtc_hook.js ({hook.stat().st_size} bytes)")
    else:
        print("[X] inject/webrtc_hook.js missing")
        ok = False

    # [7] Admin/Npcap hint (Windows)
    if platform.system() == "Windows":
        print("[!] Windows: jalankan CMD sebagai Administrator untuk live capture")
        try:
            tshark = find_tshark(tshark_path)
            ifaces_proc = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=10)
            if ifaces_proc.returncode == 0 and ifaces_proc.stdout.strip():
                print(f"[OK] Npcap interfaces detected ({ifaces_proc.stdout.count(chr(10))} entries)")
            else:
                print("[!] No capture interfaces — install Npcap with Wireshark")
        except SystemExit:
            pass

    print()
    if ok:
        print("[OK] Self check passed")
        return 0
    print("[X] Self check failed — perbaiki item di atas")
    return 1
