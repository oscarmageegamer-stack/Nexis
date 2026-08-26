from __future__ import annotations

import json
import socket
import ssl
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

PUBLIC_PATHS = ("robots.txt", "security.txt", "sitemap.xml")


def _normalise(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else "https://" + url


def inspect(url: str) -> dict:
    url = _normalise(url)
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError("Invalid URL")

    addresses = sorted({item[4][0] for item in socket.getaddrinfo(parsed.hostname, None)})
    result = {"url": url, "hostname": parsed.hostname, "addresses": addresses}

    request = Request(url, headers={"User-Agent": "Nexis-Security/0.6"})
    with urlopen(request, timeout=15) as response:
        result["status"] = response.status
        result["final_url"] = response.geturl()
        result["headers"] = dict(response.headers.items())

    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                result["tls"] = {
                    "version": tls_sock.version(),
                    "cipher": tls_sock.cipher()[0] if tls_sock.cipher() else None,
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
    else:
        result["tls"] = None
    return result


def public_files(url: str) -> dict:
    base = _normalise(url)
    if not base.endswith("/"):
        base += "/"
    result = {"base": base, "files": {}}
    for filename in PUBLIC_PATHS:
        target = urljoin(base, filename)
        try:
            with urlopen(Request(target, headers={"User-Agent": "Nexis-Security/0.6"}), timeout=10) as response:
                data = response.read(256000).decode("utf-8", errors="replace")
                result["files"][filename] = {"status": response.status, "url": response.geturl(), "content_preview": data[:20000]}
        except Exception as exc:
            result["files"][filename] = {"available": False, "error": str(exc)}
    return result


def archive_history(url: str, limit: int = 20) -> dict:
    encoded = url.replace("#", "%23")
    cdx = "https://web.archive.org/cdx/search/cdx?url=" + encoded + "&output=json&filter=statuscode:200&fl=timestamp,original,statuscode,digest&collapse=digest"
    request = Request(cdx, headers={"User-Agent": "Nexis-Security/0.6"})
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not payload:
        return {"url": url, "captures": []}
    fields = payload[0]
    captures = [dict(zip(fields, row)) for row in payload[1:limit + 1]]
    return {"url": url, "captures": captures, "source": "Internet Archive Wayback CDX"}
