"""Unit tests for chat_video_geoip APT modules."""

from __future__ import annotations

import pytest

from chat_geoip.config import IceCandidate
from chat_geoip.intel.peer_scorer import score_candidates, is_turn_only_session, sources_agree
from chat_geoip.intel.vpn_proxy import classify_cdn
from chat_geoip.parse.ice import merge_candidates, parse_browser_candidate, parse_passive_line
from chat_geoip.parse.stun import parse_stun_fields
from chat_geoip.utils import is_public_ip, is_virtual_interface


class TestIsPublicIp:
    def test_private_rejected(self):
        assert not is_public_ip("192.168.1.1")
        assert not is_public_ip("10.0.0.1")
        assert not is_public_ip("127.0.0.1")

    def test_public_accepted(self):
        assert is_public_ip("8.8.8.8")
        assert is_public_ip("103.169.238.160")

    def test_invalid(self):
        assert not is_public_ip("not-an-ip")


class TestVirtualInterface:
    def test_usbpcap_skipped(self):
        assert is_virtual_interface(r"\Device\NPF_{USB}", "USBPcap")

    def test_loopback_skipped(self):
        assert is_virtual_interface("lo", "Loopback")

    def test_wifi_not_virtual(self):
        assert not is_virtual_interface(r"\Device\NPF_{abc}", "Wi-Fi 2")


class TestCdnClassifier:
    def test_google_prefix(self):
        assert classify_cdn("74.125.130.95") == "google"
        assert classify_cdn("172.253.118.94") == "google"

    def test_non_cdn(self):
        assert classify_cdn("103.169.238.160") == ""


class TestIceParsing:
    def test_browser_candidate_srflx(self):
        cand = "candidate:1 1 udp 2130706431 82.64.1.2 54321 typ srflx"
        result = parse_browser_candidate(cand)
        assert result is not None
        assert result.ip == "82.64.1.2"
        assert result.typ == "srflx"
        assert result.source == "browser_hook"

    def test_stun_xor_mapped(self):
        tokens = ["", "", "", "", "", "103.169.238.160", "12345"]
        cands = parse_stun_fields(tokens)
        assert any(c.ip == "103.169.238.160" and c.typ == "srflx" for c in cands)

    def test_passive_line_ips(self):
        tokens = ["103.169.238.160", "8.8.8.8"]
        cands = parse_passive_line(tokens)
        ips = {c.ip for c in cands}
        assert "103.169.238.160" in ips
        assert "8.8.8.8" in ips

    def test_merge_candidates(self):
        existing: dict[str, IceCandidate] = {}
        merge_candidates(existing, [IceCandidate(ip="1.2.3.4", packet_hits=1)])
        merge_candidates(existing, [IceCandidate(ip="1.2.3.4", packet_hits=2, typ="srflx")])
        assert existing["1.2.3.4"].packet_hits == 3
        assert existing["1.2.3.4"].typ == "srflx"


class TestPeerScorer:
    def test_cdn_low_confidence(self):
        ice_map = {"74.125.130.95": IceCandidate(ip="74.125.130.95", packet_hits=50)}
        peers = score_candidates(ice_map, exclude_self=False)
        assert peers[0].role == "cdn"
        assert peers[0].confidence < 20

    def test_peer_candidate_high(self):
        ice_map = {
            "103.169.238.160": IceCandidate(
                ip="103.169.238.160", typ="srflx", source="passive_stun",
                packet_hits=30, udp_hits=10,
            )
        }
        peers = score_candidates(ice_map, exclude_self=False, browser_ips={"103.169.238.160"})
        assert peers[0].role == "peer_candidate"
        assert peers[0].confidence >= 70

    def test_turn_only_session(self):
        ice_map = {
            "74.125.130.95": IceCandidate(ip="74.125.130.95", typ="relay", packet_hits=5),
        }
        peers = score_candidates(ice_map, exclude_self=False)
        assert is_turn_only_session(peers) or peers[0].role == "cdn"

    def test_sources_agree(self):
        assert sources_agree("1.2.3.4", "1.2.3.4")
        assert not sources_agree("1.2.3.4", "5.6.7.8")
        assert not sources_agree("", "1.2.3.4")


class TestResolveInterface:
    def test_resolve_numeric_index(self):
        from chat_geoip.capture.passive import resolve_interface

        def mock_list(_tshark, include_virtual=False):
            return [("dev_wifi", "Wi-Fi 2"), ("dev_eth", "Ethernet")], []

        import chat_geoip.capture.passive as passive_mod
        orig = passive_mod.list_interfaces
        passive_mod.list_interfaces = mock_list
        try:
            assert resolve_interface("tshark", "1") == "dev_wifi"
            assert resolve_interface("tshark", "2") == "dev_eth"
        finally:
            passive_mod.list_interfaces = orig


class TestEffectiveFilter:
    def test_omegle_preset_exists(self):
        from chat_geoip.config import FILTER_PRESETS
        assert "omegle-ometv" in FILTER_PRESETS
        assert "omegle" in FILTER_PRESETS["omegle-ometv"].lower()
