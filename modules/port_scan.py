"""
port_scan.py
Wraps python-nmap to perform a service/version scan against a target.

Requires the `nmap` binary to be installed on the system
(sudo apt install nmap  /  brew install nmap).
"""

import nmap


def scan_target(target: str, ports: str = "1-1000", arguments: str = "-sV -sC -T4") -> dict:
    """
    Run an Nmap scan against a single target.

    Args:
        target: IP address or hostname to scan.
        ports: Port range string, e.g. "1-1000" or "22,80,443".
        arguments: Extra Nmap flags. Default does service/version + default scripts.

    Returns:
        dict: {
            "target": str,
            "host_status": str,
            "open_ports": [
                {"port": int, "protocol": str, "service": str,
                 "product": str, "version": str, "state": str}
            ],
            "error": str | None
        }
    """
    result = {
        "target": target,
        "host_status": "unknown",
        "open_ports": [],
        "error": None,
    }

    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=target, ports=ports, arguments=arguments)
    except nmap.PortScannerError as exc:
        result["error"] = f"Nmap scan failed: {exc}"
        return result
    except Exception as exc:  # noqa: BLE001 - surface any unexpected error to the report
        result["error"] = f"Unexpected scan error: {exc}"
        return result

    if target not in scanner.all_hosts():
        # Nmap sometimes resolves hostnames to IPs; fall back to the first host found.
        hosts = scanner.all_hosts()
        if not hosts:
            result["error"] = "Host appears down or did not respond."
            return result
        host_key = hosts[0]
    else:
        host_key = target

    host_data = scanner[host_key]
    result["host_status"] = host_data.state()

    for protocol in host_data.all_protocols():
        port_list = sorted(host_data[protocol].keys())
        for port in port_list:
            port_info = host_data[protocol][port]
            if port_info.get("state") != "open":
                continue
            result["open_ports"].append({
                "port": port,
                "protocol": protocol,
                "service": port_info.get("name", ""),
                "product": port_info.get("product", ""),
                "version": port_info.get("version", ""),
                "state": port_info.get("state", ""),
            })

    return result


if __name__ == "__main__":
    import json
    import sys

    tgt = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(json.dumps(scan_target(tgt), indent=2))
