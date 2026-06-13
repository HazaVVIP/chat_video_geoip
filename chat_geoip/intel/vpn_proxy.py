"""VPN/proxy/datacenter heuristics."""

from __future__ import annotations

DATACENTER_ORG_KEYWORDS = (
    "hetzner",
    "digitalocean",
    "amazon",
    "google cloud",
    "microsoft",
    "m247",
    "ovh",
    "linode",
    "vultr",
    "contabo",
    "choopa",
    "leaseweb",
    "psychz",
    "hosting",
    "vpn",
    "proxy",
    "datacenter",
    "data center",
    "cloudflare",
    "akamai",
    "fastly",
)

CDN_PREFIXES: list[tuple[str, str]] = [
    ("74.125.", "google"),
    ("172.253.", "google"),
    ("142.250.", "google"),
    ("216.58.", "google"),
    ("104.16.", "cloudflare"),
    ("104.17.", "cloudflare"),
    ("104.18.", "cloudflare"),
    ("104.19.", "cloudflare"),
    ("104.20.", "cloudflare"),
    ("104.21.", "cloudflare"),
    ("104.22.", "cloudflare"),
    ("104.23.", "cloudflare"),
    ("104.24.", "cloudflare"),
    ("104.25.", "cloudflare"),
    ("104.26.", "cloudflare"),
    ("104.27.", "cloudflare"),
    ("23.", "akamai"),
    ("95.100.", "akamai"),
    ("151.101.", "fastly"),
]


def classify_cdn(ip: str) -> str:
    for prefix, name in CDN_PREFIXES:
        if ip.startswith(prefix):
            return name
    return ""


def is_datacenter_org(org: str) -> bool:
    org_l = org.lower()
    return any(kw in org_l for kw in DATACENTER_ORG_KEYWORDS)


def is_likely_vpn_proxy(org: str, asn: str = "") -> bool:
    if is_datacenter_org(org):
        return True
    return False
