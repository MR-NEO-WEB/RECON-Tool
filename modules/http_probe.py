"""
http_probe.py
Probes a list of hosts over HTTP/HTTPS to find which are alive and
collects basic fingerprinting info (status code, server header, title).
"""

import re
import concurrent.futures

import requests

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _probe_single(host: str, timeout: int) -> dict:
    """Try HTTPS first, then fall back to HTTP."""
    record = {
        "host": host,
        "url": None,
        "status_code": None,
        "server": None,
        "title": None,
        "alive": False,
        "error": None,
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "recon-tool/1.0"},
                allow_redirects=True,
                verify=False,  # nosec - recon tool intentionally tolerates self-signed certs
            )
            record["url"] = resp.url
            record["status_code"] = resp.status_code
            record["server"] = resp.headers.get("Server", "")
            title_match = TITLE_RE.search(resp.text or "")
            record["title"] = title_match.group(1).strip() if title_match else ""
            record["alive"] = True
            record["_headers"] = dict(resp.headers)  # kept for vuln_check.py
            return record
        except requests.RequestException as exc:
            record["error"] = str(exc)
            continue

    return record


def probe_hosts(hosts: list, timeout: int = 8, max_workers: int = 10) -> list:
    """
    Probe a list of hostnames/IPs concurrently.

    Args:
        hosts: List of hostnames or IPs (no scheme).
        timeout: Per-request timeout in seconds.
        max_workers: Thread pool size for concurrent probing.

    Returns:
        list[dict]: One record per host (see _probe_single for shape).
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_single, h, timeout): h for h in hosts}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    # Keep output order stable for reporting
    order = {h: i for i, h in enumerate(hosts)}
    results.sort(key=lambda r: order.get(r["host"], 999))
    return results


if __name__ == "__main__":
    import json
    import sys
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    targets = sys.argv[1:] if len(sys.argv) > 1 else ["example.com"]
    print(json.dumps(probe_hosts(targets), indent=2, default=str))

