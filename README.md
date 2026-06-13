# Chat Video GeoIP — APT-Grade

Hybrid WebRTC peer intelligence: passive tshark capture + browser ICE hook + GeoLite2 geolocation. Optimized for **OmeTV / Omegle** on Windows.

## Features

- **Passive capture** — tshark live/pcap with STUN/ICE/RTP field extraction
- **Browser hook** — Playwright injects `webrtc_hook.js` to capture ICE candidates from `RTCPeerConnection`
- **Hybrid mode** — merges passive + browser sources with confidence scoring
- **Peer scoring** — classifies `peer_candidate` vs `cdn` / `turn_relay` / `self`
- **APT dashboard** — live terminal UI with peer vs infrastructure sections
- **Evidence export** — `evidence/APT_REPORT.json` + `sessions/*/session.jsonl`

## Quick start (Windows)

```cmd
cd C:\tools\chat_video_geoip
setup.bat
run.bat --check
run.bat --version
```

### Hybrid OmeTV (recommended)

```cmd
REM Run CMD as Administrator
run.bat omegle
REM dengan interface spesifik:
run.bat omegle 4
run.bat omegle "Wi-Fi 2"
REM atau manual:
run.bat --hybrid --auto-interface --platform ometv
```

### Passive live only

```cmd
live.bat
REM or:
run.bat --live --auto-interface --filter-preset omegle-ometv -i "Wi-Fi 2"
```

### Browser hook only

```cmd
run.bat --browser-only --platform ometv
```

### Analyze pcap

```cmd
run.bat -r session.pcap --filter-preset omegle-ometv -o json --out-file result.json
```

## Deploy Windows

1. Copy entire folder to `C:\tools\chat_video_geoip`
2. Run `setup.bat` (Python + pip + Playwright Chromium)
3. Verify with `update.bat` and `run.bat --check`
4. Place `GeoLite2-City.mmdb` in folder (included in repo) or set `GEOLITE2_CITY_DB`

Optional: `GeoLite2-ASN.mmdb` for ASN/Org column.

## CLI reference

| Flag | Description |
|------|-------------|
| `--hybrid` | Passive tshark + browser hook parallel |
| `--browser-only` | Browser ICE hook without Wireshark |
| `--platform ometv\|omegle` | Platform preset (filter + URL) |
| `--filter-preset omegle-ometv` | WebRTC filter for OmeTV/Omegle |
| `--auto-interface` | Pick first Wi-Fi/Ethernet |
| `--min-confidence 70` | Peer alert threshold |
| `--redact` | Mask last IP octet in exports |
| `--check` | Smoke test all dependencies |

## Output example

```
=== PEER CANDIDATES (confidence >= 70) ===
103.169.238.160  srflx  peer_candidate  89  71  Jakarta/ID

=== INFRASTRUCTURE ===
172.253.118.94   unknown  cdn  5  12  -  google
```

## Legal / privacy

Use only on networks and sessions you are authorized to monitor. Capturing third-party traffic without authorization may violate local law. This tool is for authorized security research and education.

## Version

See `VERSION` file. Current: **1.0.0**
