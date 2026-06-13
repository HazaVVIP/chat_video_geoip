"""GeoIP and ASN enrichment."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
except ImportError:
    geoip2 = None  # type: ignore

from chat_geoip.config import GeoResult


def lookup_geo(reader, ip: str, packet_hits: int = 0) -> GeoResult:
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


def lookup_asn(reader, ip: str) -> tuple[str, str]:
    try:
        rec = reader.asn(ip)
        return str(rec.autonomous_system_number), rec.autonomous_system_organization or ""
    except Exception:
        return "", ""


def enrich_geo(geo: GeoResult, asn_reader=None) -> GeoResult:
    if asn_reader:
        asn, org = lookup_asn(asn_reader, geo.ip)
        geo.asn = asn
        geo.org = org
    return geo


def geolocate_ips(ips: dict[str, int], db_path: Path, asn_path: Optional[Path] = None) -> list[GeoResult]:
    results: list[GeoResult] = []
    with geoip2.database.Reader(str(db_path)) as reader:
        asn_reader = geoip2.database.Reader(str(asn_path)) if asn_path and asn_path.is_file() else None
        try:
            for ip in sorted(ips, key=lambda x: (-ips[x], x)):
                geo = lookup_geo(reader, ip, ips[ip])
                if asn_reader:
                    enrich_geo(geo, asn_reader)
                results.append(geo)
        finally:
            if asn_reader:
                asn_reader.close()
    return results


def format_location(geo: GeoResult) -> str:
    if geo.city:
        parts = [geo.city]
        if geo.subdivision:
            parts.append(geo.subdivision)
        if geo.country_code:
            parts.append(geo.country_code)
        return "/".join(parts)
    if geo.latitude is not None and geo.longitude is not None:
        radius = geo.accuracy_radius_km or 0
        return f"~{geo.latitude:.3f},{geo.longitude:.3f} (±{radius} km)"
    if geo.country:
        return geo.country
    return geo.error or "-"
