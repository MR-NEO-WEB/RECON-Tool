"""
vuln_check.py
Lightweight, passive checks for common web misconfigurations:
- Missing security headers
- Exposed sensitive paths (.git, .env, backup files, etc.)

These are non-intrusive checks suitable for an authorized recon/assessment scope.
They are NOT a replacement for an active scanner like Burp Suite / Nikto / Nuclei.
"""

import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

SENSITIVE_PATHS = [
    ".git/HEAD",
    ".env",
    "backup.zip",
    "config.php.bak",
    "wp-config.php.bak",
    ".DS_Store",
    "phpinfo.php",
]


def check_security_headers(headers: dict) -> list:
    """Return the list of recommended security headers that are missing."""
    present = {h.lower() for h in (headers or {}).keys()}
    missing = [h for h in SECURITY_HEADERS if h.lower() not in present]
    return missing


def check_exposed_paths(base_url: str, timeout: int = 6) -> list:
    """
    Probe a small set of commonly-sensitive paths under base_url.
    Only flags a path if the server returns 200 with non-trivial content,
    to reduce false positives from catch-all pages.
    """
    findings = []
    for path in SENSITIVE_PATHS:
        url = f"{base_url.rstrip('/')}/{path}"
        try:
            resp = requests.get(
                url, timeout=timeout, headers={"User-Agent": "recon-tool/1.0"}, verify=False
            )
            if resp.status_code == 200 and len(resp.content) > 0:
                findings.append({"path": path, "url": url, "status_code": resp.status_code})
        except requests.RequestException:
            continue
    return findings


def run_checks(probe_record: dict) -> dict:
    """
    Run all passive vuln checks for a single host, using data already
    gathered by http_probe.py (to avoid duplicate requests where possible).

    Args:
        probe_record: One record as returned by http_probe.probe_hosts().

    Returns:
        dict: {
            "host": str,
            "missing_headers": [str, ...],
            "exposed_paths": [dict, ...],
        }
    """
    output = {"host": probe_record.get("host"), "missing_headers": [], "exposed_paths": []}

    if not probe_record.get("alive"):
        return output

    headers = probe_record.get("_headers", {})
    output["missing_headers"] = check_security_headers(headers)

    base_url = probe_record.get("url", "").split("?")[0]
    if base_url:
        # Strip path, keep scheme+host only
        from urllib.parse import urlsplit
        parts = urlsplit(base_url)
        root = f"{parts.scheme}://{parts.netloc}"
        output["exposed_paths"] = check_exposed_paths(root)

    return output


if __name__ == "__main__":
    import json
    import sys
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    from http_probe import probe_hosts  # local import for standalone testing

    targets = sys.argv[1:] if len(sys.argv) > 1 else ["example.com"]
    probes = probe_hosts(targets)
    findings = [run_checks(p) for p in probes]
    print(json.dumps(findings, indent=2, default=str))
