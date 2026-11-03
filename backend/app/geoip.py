"""
IP Geolocation Enrichment Module.
Provides IP geolocation lookups with local in-memory caching and safe offline fallback
for lab / RFC 1918 / loopback IP addresses.
Includes proper data source attribution.
"""
import ipaddress
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger("honeypot.geoip")

# In-memory LRU-like cache for IP lookups
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}

# Simulated realistic lab threat origins for local/private IPs in testing environments
_MOCK_LAB_ORIGINS = [
    {"country": "United States", "country_code": "US", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874, "org": "DigitalOcean Lab VPS"},
    {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "org": "Hetzner Cloud"},
    {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "org": "Leaseweb B.V."},
    {"country": "Russia", "country_code": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "org": "Selectel Network"},
    {"country": "China", "country_code": "CN", "city": "Hangzhou", "lat": 30.2741, "lon": 120.1551, "org": "Alibaba Cloud"},
    {"country": "Brazil", "country_code": "BR", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "org": "Claro Telecom"},
    {"country": "India", "country_code": "IN", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946, "org": "Reliance Jio Infocomm"},
    {"country": "United Kingdom", "country_code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278, "org": "OVH Hosting Ltd"},
]

def is_private_or_local(ip_str: str) -> bool:
    """Check if an IP is private, loopback, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False

def resolve_ip_geo(ip_str: str) -> Dict[str, Any]:
    """
    Resolve IP address to Geolocation metadata.
    Returns: {country, country_code, city, lat, lon, org, source_attribution}
    """
    if not ip_str:
        return {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "lat": None,
            "lon": None,
            "org": "Unknown",
            "attribution": "N/A"
        }

    # Check cache
    if ip_str in _GEO_CACHE:
        return _GEO_CACHE[ip_str]

    # For private/local lab testing, assign a deterministic simulated origin
    # to provide realistic visual intelligence in lab dashboards
    if is_private_or_local(ip_str):
        # Generate a deterministic index from the IP string
        idx = sum(ord(c) for c in ip_str) % len(_MOCK_LAB_ORIGINS)
        origin = _MOCK_LAB_ORIGINS[idx].copy()
        origin["attribution"] = "Local Lab Simulated Origin (RFC 1918 / Loopback)"
        _GEO_CACHE[ip_str] = origin
        return origin

    # Attempt live query from ip-api.com (free tier, 45 req/min)
    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,city,lat,lon,org,isp"
        resp = requests.get(url, timeout=2.5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                geo_info = {
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "XX"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "org": data.get("org") or data.get("isp") or "Unknown ISP",
                    "attribution": "IP Geolocation by ip-api.com"
                }
                _GEO_CACHE[ip_str] = geo_info
                return geo_info
    except Exception as exc:
        logger.debug(f"Live GeoIP lookup failed for {ip_str}: {exc}")

    # Fallback default
    fallback = {
        "country": "External Attacker",
        "country_code": "XX",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "org": "External IP",
        "attribution": "Fallback"
    }
    _GEO_CACHE[ip_str] = fallback
    return fallback
