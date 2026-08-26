from __future__ import annotations

import ipaddress
import json
from urllib.request import Request, urlopen

API_BASE = "https://ipapi.co"


def lookup(ip: str) -> dict:
    address = ipaddress.ip_address(ip.strip())
    if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast:
        return {
            "ip": str(address),
            "scope": "private/local",
            "geolocation": None,
            "message": "Private IP addresses do not have public Internet geolocation data."
        }

    url = f"{API_BASE}/{address}/json/"
    request = Request(url, headers={"User-Agent": "Nexis-Security/0.4"})
    with urlopen(request, timeout=10) as response:
        data = json.loads(response.read().decode("utf-8"))

    return {
        "ip": data.get("ip", str(address)),
        "scope": "public",
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country_name") or data.get("country_code"),
        "postal": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": data.get("timezone"),
        "asn": data.get("asn"),
        "organization": data.get("org"),
        "hostname": data.get("hostname"),
        "accuracy_note": "IP geolocation is approximate and may identify a provider/region rather than a device's physical location."
    }


def my_public_ip() -> dict:
    request = Request(f"{API_BASE}/json/", headers={"User-Agent": "Nexis-Security/0.4"})
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))
