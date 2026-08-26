from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

PLATFORMS = {
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "X": "https://x.com/{username}",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Instagram": "https://www.instagram.com/{username}/",
    "Twitch": "https://www.twitch.tv/{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
}


def _check(platform: str, url: str) -> dict:
    request = Request(url, headers={"User-Agent": "Nexis/0.6 (+public-profile-recon)"})
    try:
        with urlopen(request, timeout=8) as response:
            return {"platform": platform, "url": url, "status": response.status, "found": response.status == 200}
    except HTTPError as exc:
        return {"platform": platform, "url": url, "status": exc.code, "found": False}
    except (URLError, TimeoutError, OSError) as exc:
        return {"platform": platform, "url": url, "status": None, "found": False, "error": str(exc)}


def search_username(username: str) -> dict:
    clean = username.strip().lstrip("@").strip()
    if not clean or len(clean) > 80 or any(ch.isspace() for ch in clean):
        raise ValueError("Enter a single public username/handle without spaces.")

    targets = [(name, template.format(username=quote(clean, safe="._-"))) for name, template in PLATFORMS.items()]
    results = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_check, name, url): (name, url) for name, url in targets}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda item: item["platform"])
    found = [item for item in results if item.get("found")]
    return {
        "username": clean,
        "checked_platforms": len(results),
        "public_profiles_found": len(found),
        "profiles": results,
        "scope": "public profile URL checks only; no login, private-account access, or sensitive-data aggregation",
        "note": "A positive HTTP response does not prove the profile belongs to the same person or organisation; verify manually."
    }
