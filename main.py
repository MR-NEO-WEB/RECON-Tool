

#!/usr/bin/env python3
"""
recon-tool: Automated Recon Tool
==================================
Chains port scanning, subdomain enumeration, HTTP probing, and basic
misconfiguration checks into a single workflow, then outputs a clean
HTML report.

IMPORTANT: Only run this against targets you own or are explicitly
authorized to test. Unauthorized scanning may be illegal.

Usage:
    python main.py example.com
    python main.py example.com --ports 1-1000 --skip-subdomains
    python main.py 192.168.1.10 --ports 1-65535 --output reports/scan.html
"""

import argparse
import sys
import urllib3

from modules import port_scan, subdomain_enum, http_probe, vuln_check
from report import generator

# Suppress noisy "unverified HTTPS request" warnings - this tool intentionally
# tolerates self-signed certs since recon targets often have them.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def banner():
    print(r"""
  ____                       _____           _
 |  _ \ ___  ___ ___  _ __  |_   _|__   ___ | |
 | |_) / _ \/ __/ _ \| '_ \   | |/ _ \ / _ \| |
 |  _ <  __/ (_| (_) | | | |  | | (_) | (_) | |
 |_| \_\___|\___\___/|_| |_|  |_|\___/ \___/|_|

  Automated Recon Tool - for authorized assessments only
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated recon tool: port scan + subdomain enum + HTTP probe + basic vuln checks."
    )
    parser.add_argument("target", help="Domain or IP address to assess (e.g. example.com)")
    parser.add_argument(
        "--ports", default="1-1000",
        help="Port range for Nmap scan (default: 1-1000)"
    )
    parser.add_argument(
        "--nmap-args", default="-sV -sC -T4",
        help='Extra Nmap arguments (default: "-sV -sC -T4")'
    )
    parser.add_argument(
        "--skip-subdomains", action="store_true",
        help="Skip subdomain enumeration (only useful for domain targets anyway)"
    )
    parser.add_argument(
        "--skip-portscan", action="store_true",
        help="Skip the Nmap port scan (useful if nmap binary isn't installed)"
    )
    parser.add_argument(
        "--output", default=None,
        help="Output HTML report path (default: reports/<target>_report.html)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    target = args.target
    banner()
    print(f"[*] Target: {target}\n")

    # 1. Port scan
    scan_result = {"open_ports": [], "error": None}
    if args.skip_portscan:
        print("[*] Skipping port scan (--skip-portscan)")
    else:
        print("[*] Running port scan (this can take a minute)...")
        scan_result = port_scan.scan_target(target, ports=args.ports, arguments=args.nmap_args)
        if scan_result["error"]:
            print(f"    [!] {scan_result['error']}")
        else:
            print(f"    [+] Found {len(scan_result['open_ports'])} open port(s)")

    # 2. Subdomain enumeration
    subdomain_result = {"domain": target, "subdomains": [], "count": 0, "error": None}
    if args.skip_subdomains:
        print("[*] Skipping subdomain enumeration (--skip-subdomains)")
    else:
        print("[*] Enumerating subdomains via crt.sh...")
        subdomain_result = subdomain_enum.enumerate_subdomains(target)
        if subdomain_result["error"]:
            print(f"    [!] {subdomain_result['error']}")
        else:
            print(f"    [+] Found {subdomain_result['count']} subdomain(s)")

    # 3. HTTP probing - probe the target itself plus any discovered subdomains
    hosts_to_probe = [target]
    if subdomain_result["subdomains"]:
        # Cap to a reasonable number to avoid a very long-running scan
        hosts_to_probe.extend(subdomain_result["subdomains"][:50])
    hosts_to_probe = list(dict.fromkeys(hosts_to_probe))  # dedupe, preserve order

    print(f"[*] Probing {len(hosts_to_probe)} host(s) over HTTP/HTTPS...")
    probe_results = http_probe.probe_hosts(hosts_to_probe)
    live_count = sum(1 for h in probe_results if h["alive"])
    print(f"    [+] {live_count}/{len(hosts_to_probe)} host(s) responded")

    # 4. Vulnerability / misconfiguration checks on live hosts
    print("[*] Running basic misconfiguration checks on live hosts...")
    vuln_findings = []
    for record in probe_results:
        if record["alive"]:
            vuln_findings.append(vuln_check.run_checks(record))
    total_exposed = sum(len(f["exposed_paths"]) for f in vuln_findings)
    print(f"    [+] {total_exposed} exposed sensitive path(s) found across all hosts")

    # 5. Generate report
    output_path = args.output or f"reports/{target.replace('/', '_')}_report.html"
    print(f"\n[*] Generating report -> {output_path}")
    generator.generate_report(
        target=target,
        port_scan=scan_result,
        subdomains=subdomain_result,
        http_probes=probe_results,
        vuln_findings=vuln_findings,
        output_path=output_path,
    )
    print(f"[+] Done. Open {output_path} in a browser to view the report.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)