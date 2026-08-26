from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import quote_plus, urlparse
from urllib.request import Request, urlopen


class _ResultsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict[str, str]] = []
        self._current: dict[str, str] | None = None
        self._capture = False
        self._buffer: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        href = attrs_dict.get("href", "")
        if tag == "a" and href.startswith("http"):
            self._current = {"url": href}
            self._buffer = []
            self._capture = True

    def handle_data(self, data):
        if self._capture:
            self._buffer.append(data.strip())

    def handle_endtag(self, tag):
        if tag == "a" and self._current is not None:
            title = " ".join(x for x in self._buffer if x)
            if title:
                self._current["title"] = title[:240]
                self.results.append(self._current)
            self._current = None
            self._capture = False


def _search(query: str, limit: int = 8) -> list[dict[str, str]]:
    url = "https://html.duckduckgo.com/html/?q=" + quote_plus(query)
    request = Request(
        url,
        headers={
            "User-Agent": "Nexis/0.4 (+authorised-security-research)",
            "Accept-Language": "en-US,en;q=0.8",
        },
    )
    with urlopen(request, timeout=15) as response:
        html = response.read().decode("utf-8", errors="replace")

    parser = _ResultsParser()
    parser.feed(html)
    output = []
    seen = set()
    for item in parser.results:
        host = urlparse(item["url"]).netloc.lower()
        key = (host, item["title"])
        if host and key not in seen:
            seen.add(key)
            output.append({**item, "host": host})
        if len(output) >= limit:
            break
    return output


def footprint_organization(name: str, country: str, limit_per_query: int = 6) -> dict:
    """Build a public web footprint for an organisation, brand, or project.

    Deliberately avoids person profiling and sensitive personal data collection.
    """
    name = " ".join(name.split()).strip()
    country = " ".join(country.split()).strip()
    if not name or not country:
        raise ValueError("Both an organisation/project name and country are required.")

    searches = {
        "general": f'"{name}" "{country}"',
        "official": f'"{name}" "{country}" official website',
        "github": f'"{name}" "{country}" site:github.com',
        "documentation": f'"{name}" "{country}" documentation',
        "news": f'"{name}" "{country}" news',
    }

    grouped = {}
    all_results = []
    seen_urls = set()
    for category, query in searches.items():
        results = _search(query, limit_per_query)
        grouped[category] = results
        for result in results:
            if result["url"] not in seen_urls:
                seen_urls.add(result["url"])
                all_results.append({"category": category, **result})

    return {
        "target": {"name": name, "country": country, "type": "organization_or_project"},
        "result_count": len(all_results),
        "results": all_results,
        "scope": "public web presence only; no personal address, phone, email, or private-data aggregation",
        "note": "Search-engine results are incomplete and can include false matches. Verify important findings manually.",
    }
