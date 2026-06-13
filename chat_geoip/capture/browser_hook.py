"""Playwright browser hook for WebRTC ICE candidates."""

from __future__ import annotations

import queue
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from chat_geoip.config import IceCandidate, SCRIPT_DIR
from chat_geoip.parse.ice import merge_candidates, parse_browser_candidate
from chat_geoip.platforms.omegle_ometv import get_platform_url

HOOK_SCRIPT = SCRIPT_DIR / "inject" / "webrtc_hook.js"


class BrowserHook:
    """Capture ICE candidates from browser via Playwright."""

    def __init__(self, platform: str = "ometv", url: str = "", headless: bool = False):
        self.platform = platform
        self.url = url or get_platform_url(platform)
        self.headless = headless
        self.ice_map: dict[str, IceCandidate] = {}
        self._queue: queue.Queue = queue.Queue()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._relay_only = False
        self._playwright = None
        self._context = None
        self._page = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_browser, daemon=True)
        self._thread.start()
        # Wait briefly for browser init
        time.sleep(2)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        if self._context:
            try:
                self._context.close()
            except Exception:
                pass
        if self._playwright:
            try:
                self._playwright.stop()
            except Exception:
                pass

    def poll_candidates(self) -> list[str]:
        """Drain queue and merge into ice_map; return new IPs."""
        new_ips: list[str] = []
        while True:
            try:
                data = self._queue.get_nowait()
            except queue.Empty:
                break
            if data.get("warning") == "relay_only_policy":
                self._relay_only = True
                continue
            candidate_str = data.get("candidate", "")
            cand = parse_browser_candidate(candidate_str)
            if not cand:
                ip = data.get("ip", "")
                if ip:
                    cand = IceCandidate(
                        ip=ip,
                        port=data.get("port"),
                        typ=data.get("typ", "unknown"),
                        source="browser_hook",
                        packet_hits=1,
                    )
            if cand:
                added = merge_candidates(self.ice_map, [cand])
                new_ips.extend(added)
        return new_ips

    @property
    def relay_only(self) -> bool:
        return self._relay_only

    def get_ice_map(self) -> dict[str, IceCandidate]:
        return dict(self.ice_map)

    def _run_browser(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            print(
                "[!] Playwright belum terpasang. Jalankan: pip install playwright && playwright install chromium",
                file=sys.stderr,
            )
            return

        hook_js = HOOK_SCRIPT.read_text(encoding="utf-8") if HOOK_SCRIPT.is_file() else ""

        try:
            self._playwright = sync_playwright().start()
            profile_dir = SCRIPT_DIR / "sessions" / "browser_profile"
            profile_dir.mkdir(parents=True, exist_ok=True)

            self._context = self._playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                headless=self.headless,
                args=["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream"],
            )

            def on_candidate(source, data):
                self._queue.put(data)

            self._page = self._context.pages[0] if self._context.pages else self._context.new_page()
            self._page.expose_binding("reportIceCandidate", lambda source, data: on_candidate(source, data))
            if hook_js:
                self._page.add_init_script(hook_js)

            print(f"[*] Browser hook: membuka {self.url}", file=sys.stderr)
            self._page.goto(self.url, wait_until="domcontentloaded", timeout=60000)

            while not self._stop.is_set():
                time.sleep(0.5)

        except Exception as exc:
            print(f"[!] Browser hook error: {exc}", file=sys.stderr)


def run_browser_only(
    platform: str,
    url: str,
    on_update: Optional[Callable[[dict[str, IceCandidate]], None]] = None,
    refresh: float = 1.0,
) -> dict[str, IceCandidate]:
    """Run browser-only mode until KeyboardInterrupt."""
    hook = BrowserHook(platform=platform, url=url)
    hook.start()
    try:
        while True:
            hook.poll_candidates()
            if on_update:
                on_update(hook.get_ice_map())
            time.sleep(refresh)
    except KeyboardInterrupt:
        print("\n[*] Browser hook dihentikan.", file=sys.stderr)
    finally:
        hook.stop()
    return hook.get_ice_map()
