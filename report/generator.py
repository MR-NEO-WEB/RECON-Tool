"""
generator.py
Renders all collected recon data into a single, clean HTML report.
"""

import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader

TEMPLATE_DIR = os.path.dirname(os.path.abspath(__file__))


def generate_report(
    target: str,
    port_scan: dict,
    subdomains: dict,
    http_probes: list,
    vuln_findings: list,
    output_path: str,
) -> str:
    """
    Render the recon report to an HTML file.

    Args:
        target: The original target passed on the CLI.
        port_scan: Output of modules.port_scan.scan_target().
        subdomains: Output of modules.subdomain_enum.enumerate_subdomains().
        http_probes: Output of modules.http_probe.probe_hosts().
        vuln_findings: List of modules.vuln_check.run_checks() results.
        output_path: File path to write the rendered HTML to.

    Returns:
        str: The output_path that was written.
    """
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
    template = env.get_template("template.html")

    live_host_count = sum(1 for h in http_probes if h.get("alive"))
    hosts_missing_headers_count = sum(1 for f in vuln_findings if f.get("missing_headers"))
    total_exposed_paths = sum(len(f.get("exposed_paths", [])) for f in vuln_findings)

    html = template.render(
        target=target,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        port_scan=port_scan,
        subdomains=subdomains,
        http_probes=http_probes,
        vuln_findings=vuln_findings,
        live_host_count=live_host_count,
        hosts_missing_headers_count=hosts_missing_headers_count,
        total_exposed_paths=total_exposed_paths,
    )

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
