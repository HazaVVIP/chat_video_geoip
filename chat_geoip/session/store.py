"""Session store — per-skip correlation for APT engagements."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from chat_geoip.config import SCRIPT_DIR, VERSION, PeerCandidate
from chat_geoip.intel.peer_scorer import best_peer, is_turn_only_session, sources_agree
from chat_geoip.utils import redact_ip


@dataclass
class SkipRecord:
    skip_id: int
    started_at: str
    ended_at: str = ""
    candidates: list[dict] = field(default_factory=list)
    peer_best: Optional[dict] = None
    turn_only: bool = False
    passive_ips: list[str] = field(default_factory=list)
    browser_ips: list[str] = field(default_factory=list)
    sources_agree: bool = False


class SessionStore:
    def __init__(self, session_dir: str = "", platform: str = "", mode: str = "hybrid"):
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = Path(session_dir) if session_dir else SCRIPT_DIR / "sessions" / ts
        base.mkdir(parents=True, exist_ok=True)
        self.base = base
        self.evidence_dir = SCRIPT_DIR / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.platform = platform
        self.mode = mode
        self.skips: list[SkipRecord] = []
        self._current: Optional[SkipRecord] = None
        self._skip_counter = 0
        self.meta: dict = {
            "version": VERSION,
            "platform": platform,
            "mode": mode,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "session_dir": str(base),
        }

    def new_skip(self) -> SkipRecord:
        if self._current:
            self.end_skip()
        self._skip_counter += 1
        self._current = SkipRecord(
            skip_id=self._skip_counter,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        return self._current

    def end_skip(self) -> None:
        if not self._current:
            return
        self._current.ended_at = datetime.now(timezone.utc).isoformat()
        self.skips.append(self._current)
        self._append_jsonl(self._current)
        self._current = None

    def update_skip(
        self,
        peers: list[PeerCandidate],
        passive_ips: list[str] | None = None,
        browser_ips: list[str] | None = None,
        min_confidence: int = 50,
        redact: bool = False,
    ) -> None:
        if not self._current:
            self.new_skip()

        skip = self._current
        skip.candidates = [_redact_peer(p, redact) for p in peers]
        skip.passive_ips = [_maybe_redact(ip, redact) for ip in (passive_ips or [])]
        skip.browser_ips = [_maybe_redact(ip, redact) for ip in (browser_ips or [])]
        skip.turn_only = is_turn_only_session(peers)

        bp = best_peer(peers, min_confidence)
        if bp:
            skip.peer_best = _redact_peer(bp, redact)

        passive_best = ""
        browser_best = ""
        for p in peers:
            if p.role == "peer_candidate":
                if "passive" in p.source or "passive_stun" in p.source or "passive_rtp" in p.source:
                    if not passive_best:
                        passive_best = p.ip
                if "browser_hook" in p.sources or p.source == "browser_hook":
                    if not browser_best:
                        browser_best = p.ip
        skip.sources_agree = sources_agree(passive_best, browser_best)

    def _append_jsonl(self, skip: SkipRecord) -> None:
        path = self.base / "session.jsonl"
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(skip), ensure_ascii=False) + "\n")

    def save_apt_report(self, extra_meta: dict | None = None, redact: bool = False) -> Path:
        if self._current:
            self.end_skip()

        report = {
            "version": VERSION,
            "platform": self.platform,
            "mode": self.mode,
            "skips": [asdict(s) for s in self.skips],
            "meta": {**self.meta, **(extra_meta or {})},
        }
        out = self.evidence_dir / "APT_REPORT.json"
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return out


def _redact_peer(p: PeerCandidate, redact: bool) -> dict:
    d = p.to_dict()
    if redact:
        d["ip"] = redact_ip(d["ip"])
        if d.get("geo"):
            d["geo"]["ip"] = redact_ip(d["geo"]["ip"])
    return d


def _maybe_redact(ip: str, redact: bool) -> str:
    return redact_ip(ip) if redact else ip
