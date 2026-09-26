"""
subdomain_enum.py
Passive subdomain enumeration using crt.sh (Certificate Transparency logs).
No API key required, and it's passive - no traffic ever hits the target.
"""

import json
import time

import requests

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def enumerate_subdomains(domain: str, timeout: int = 15, retries: int = 2) -> dict:
    """
    Query crt.sh for certificates issued to *.domain and extract unique subdomains.

    Args:
        domain: Root domain to enumerate, e.g. "example.com".
        timeout: Per-request timeout in seconds.
        retries: Number of retry attempts if crt.sh is slow/rate-limiting.

    Returns:
        dict: {
            "domain": str,
            "subdomains": [str, ...]  (sorted, deduplicated),
            "count": int,
            "error": str | None
        }
    """
    result = {"domain": domain, "subdomains": [], "count": 0, "error": None}
    url = CRTSH_URL.format(domain=domain)

    last_error = None
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, timeout=timeout, headers={
                                "User-Agent": "recon-tool/1.0"})
            resp.raise_for_status()
            data = json.loads(resp.text)
            break
        except (requests.RequestException, json.JSONDecodeError) as exc:
            last_error = str(exc)
            if attempt < retries:
                time.sleep(2)
                continue
            result["error"] = f"crt.sh query failed: {last_error}"
            return result

    names = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            line = line.strip().lower()
            if line and not line.startswith("*."):
                names.add(line)
            elif line.startswith("*."):
                names.add(line[2:])  # strip wildcard prefix

    result["subdomains"] = sorted(names)
    result["count"] = len(names)
    return result


if __name__ == "__main__":
    import sys

    d = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(enumerate_subdomains(d), indent=2))
