#!/usr/bin/env python3
"""
Ekstrak IP dari lalu lintas video/chat (tshark/pcap) + geolokasi GeoLite2.
APT-grade: hybrid passive + browser WebRTC hook untuk OmeTV/Omegle.

Contoh:
  python chat_video_geoip.py --live -i "Wi-Fi"
  python chat_video_geoip.py --hybrid -i "Wi-Fi" --platform ometv
  python chat_video_geoip.py --browser-only --platform ometv
  python chat_video_geoip.py -r meeting.pcap --filter-preset omegle-ometv
  python chat_video_geoip.py --check

GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""

from chat_geoip.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
