from __future__ import annotations

import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _fetch(url: str, timeout: int = 12):
    request = Request(url, headers={"User-Agent": "Nexis-Security-Auditor/0.5"})
    return urlopen(request, timeout=timeout)


def inspect(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    with _fetch(url) as response:
        headers = dict(response.headers.items())
        body = response.read(250_000).decode("utf-8", errors="replace")
        tech = set()
        server = headers.get("Server")
        powered = headers.get("X-Powered-By")
        if server: tech.add(f"Server: {server}")
        if powered: tech.add(f"X-Powered-By: {powered}")
        if re.search(r"(?i)wp-content|wordpress", body): tech.add("Possible WordPress")
        if re.search(r"(?i)__next|/_next/", body): tech.add("Possible Next.js")
        if re.search(r"(?i)react", body): tech.add("Possible React")
        result = {
            "url": response.geturl(),
            "status": response.status,
            "host": host,
            "headers": {h: headers.get(h) for h in SECURITY_HEADERS},
            "cookies": [v for k, v in response.headers.items() if k.lower() == "set-cookie"],
            "technology_hints": sorted(tech),
            "dns_addresses": sorted({x[4][0] for x in socket.getaddrinfo(host, None)}),
        }
        if parsed.scheme == "https":
            result["tls"] = tls_info(host, parsed.port or 443)
        return result


def tls_info(host: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            return {
                "protocol": ssock.version(),
                "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
            }


def public_files(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    result = {}
    for name, path in {
        "robots_txt": "/robots.txt",
        "security_txt": "/.well-known/security.txt",
        "sitemap": "/sitemap.xml",
    }.items():
        try:
            with _fetch(urljoin(base, path), timeout=8) as response:
                result[name] = {"status": response.status, "url": response.geturl(), "bytes": len(response.read(200_000))}
        except Exception as exc:
            result[name] = {"available": False, "error": str(exc)}
    return result


def archive_history(url: str, limit: int = 20) -> dict:
    """Return public archive metadata; does not retrieve private or gated material."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    query = (
        "https://web.archive.org/cdx/search/cdx?url="
        + url
        + "&output=json&filter=statuscode:200&fl=timestamp,original,statuscode,digest"
        + f"&limit={max(1, min(limit, 50))}&from=1990"
    )
    with _fetch(query, timeout=15) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not data:
        return {"url": url, "captures": []}
    headers, *rows = data
    captures = [dict(zip(headers, row)) for row in rows]
    return {"url": url, "captures": captures}
