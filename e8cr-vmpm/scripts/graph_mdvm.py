#!/usr/bin/env python3
"""Microsoft Defender Vulnerability Management (MDVM) via Graph Security API.

For E5 customers who already have MDVM — pulls vulnerability data, software inventory,
security recommendations, and machine exposure directly from Defender.

Usage:
    python3 graph_mdvm.py --action vulnerabilities                    # All vulns
    python3 graph_mdvm.py --action vulnerabilities --severity critical # Filter by severity
    python3 graph_mdvm.py --action software                           # Software inventory
    python3 graph_mdvm.py --action software --eol-only                # EOL software only
    python3 graph_mdvm.py --action recommendations                    # Security recommendations
    python3 graph_mdvm.py --action recommendations --status active    # Active only
    python3 graph_mdvm.py --action machines                           # Machine exposure scores
    python3 graph_mdvm.py --action machines --exposure high           # High exposure only
    python3 graph_mdvm.py --action export --output mdvm-export.json   # Full export for reporting

Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars.
Required API permissions (Application):
    - Vulnerability.Read.All
    - Software.Read.All
    - SecurityRecommendation.Read.All
    - Machine.Read.All
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))
from graph_auth import get_env, get_token

# MDVM uses the security API (windowsDefenderATP resource)
SECURITY_BASE = "https://api.securitycenter.microsoft.com/api"


def get_security_token(tenant, client_id, client_secret):
    """Get token scoped to WindowsDefenderATP resource."""
    from urllib.parse import urlencode
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).encode()
    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urlopen(req) as resp:
            body = json.loads(resp.read())
            return body["access_token"]
    except HTTPError as e:
        err = e.read().decode()
        print(f"ERROR: Security API auth failed ({e.code}): {err}", file=sys.stderr)
        sys.exit(1)


def api_get(token, endpoint, params=None):
    """GET with pagination against security API."""
    url = f"{SECURITY_BASE}/{endpoint}"
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())

    results = []
    while url:
        req = Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {token}")
        try:
            with urlopen(req) as resp:
                body = json.loads(resp.read())
                results.extend(body.get("value", []))
                url = body.get("@odata.nextLink")
        except HTTPError as e:
            err = e.read().decode()
            print(f"ERROR: API ({e.code}): {err}", file=sys.stderr)
            sys.exit(1)
    return results


def get_vulnerabilities(token, severity=None):
    """Get all vulnerabilities detected by MDVM."""
    vulns = api_get(token, "vulnerabilities")

    if severity:
        sev_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
        target = sev_map.get(severity.lower(), severity)
        vulns = [v for v in vulns if v.get("severity", "").lower() == target.lower()]

    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    vulns.sort(key=lambda v: sev_order.get(v.get("severity", ""), 99))

    return vulns


def get_software_inventory(token, eol_only=False):
    """Get software inventory from MDVM."""
    software = api_get(token, "Software")

    if eol_only:
        software = [s for s in software if s.get("endOfSupportStatus") in
                     ("EOS Version", "EOS Software", "Upcoming EOS Version", "Upcoming EOS Software")]

    # Sort by exposed machines descending
    software.sort(key=lambda s: s.get("exposedMachines", 0), reverse=True)

    return software


def get_recommendations(token, status=None):
    """Get security recommendations from MDVM."""
    recs = api_get(token, "recommendations")

    if status:
        recs = [r for r in recs if r.get("status", "").lower() == status.lower()]

    # Sort by severity weight
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recs.sort(key=lambda r: sev_order.get(r.get("severityScore", ""), 99))

    return recs


def get_machines(token, exposure=None):
    """Get machine list with exposure and risk scores."""
    machines = api_get(token, "machines")

    if exposure:
        machines = [m for m in machines if
                     m.get("exposureLevel", "").lower() == exposure.lower()]

    # Sort by exposure level
    exp_order = {"High": 0, "Medium": 1, "Low": 2, "None": 3}
    machines.sort(key=lambda m: exp_order.get(m.get("exposureLevel", ""), 99))

    return machines


def get_machine_vulns(token, machine_id):
    """Get vulnerabilities for a specific machine."""
    return api_get(token, f"machines/{machine_id}/vulnerabilities")


def export_all(token, output):
    """Export all MDVM data for reporting/evidence."""
    print("Fetching vulnerabilities...", file=sys.stderr)
    vulns = get_vulnerabilities(token)

    print("Fetching software inventory...", file=sys.stderr)
    software = get_software_inventory(token)

    print("Fetching recommendations...", file=sys.stderr)
    recs = get_recommendations(token)

    print("Fetching machines...", file=sys.stderr)
    machines = get_machines(token)

    # Build summary
    vuln_by_severity = {}
    for v in vulns:
        sev = v.get("severity", "Unknown")
        vuln_by_severity[sev] = vuln_by_severity.get(sev, 0) + 1

    eol_software = [s for s in software if s.get("endOfSupportStatus") in
                     ("EOS Version", "EOS Software")]
    upcoming_eol = [s for s in software if s.get("endOfSupportStatus") in
                     ("Upcoming EOS Version", "Upcoming EOS Software")]

    high_exposure = [m for m in machines if m.get("exposureLevel") == "High"]

    export_data = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": "Microsoft Defender Vulnerability Management",
        "summary": {
            "total_vulnerabilities": len(vulns),
            "vulnerabilities_by_severity": vuln_by_severity,
            "total_software": len(software),
            "eol_software": len(eol_software),
            "upcoming_eol_software": len(upcoming_eol),
            "total_machines": len(machines),
            "high_exposure_machines": len(high_exposure),
            "active_recommendations": len([r for r in recs if r.get("status") == "Active"]),
        },
        "vulnerabilities": vulns,
        "software": software,
        "recommendations": recs,
        "machines": machines,
    }

    with open(output, "w") as f:
        json.dump(export_data, f, indent=2)
    print(f"Exported MDVM data to {output}")
    print(json.dumps(export_data["summary"], indent=2))


def convert_to_scan_results(vulns, machines):
    """Convert MDVM vulns to the same format as greenbone_scan results,
    so vuln_prioritise.py and generate_report.py work with either source."""
    # Build machine lookup
    machine_map = {}
    for m in machines:
        machine_map[m.get("id")] = {
            "name": m.get("computerDnsName", ""),
            "ip": m.get("lastIpAddress", "Unknown"),
            "exposure": m.get("exposureLevel", ""),
        }

    results = []
    for v in vulns:
        severity_map = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5}
        severity = severity_map.get(v.get("severity", ""), 0)

        cve_id = v.get("id", "")  # MDVM uses CVE ID as the vuln ID
        exposed = v.get("exposedMachines", 0)

        results.append({
            "id": cve_id,
            "host": f"{exposed} machines",
            "port": "",
            "severity": severity,
            "severity_label": v.get("severity", "Unknown"),
            "name": v.get("name", cve_id),
            "oid": "",
            "cves": [cve_id] if cve_id.startswith("CVE-") else [],
            "solution": v.get("patchUrl", ""),
            "description": v.get("description", "")[:500],
            "exposed_machines": exposed,
            "published_on": v.get("publishedOn", ""),
            "source": "MDVM",
        })

    results.sort(key=lambda x: x["severity"], reverse=True)
    return results


def format_vulns_table(vulns):
    """Pretty-print vulnerability list."""
    if not vulns:
        print("No vulnerabilities found.")
        return

    sev_counts = {}
    for v in vulns:
        s = v.get("severity", "Unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    print(f"Total: {len(vulns)}  " +
          "  ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items())))
    print()
    print(f"{'CVE':<20} {'Severity':<10} {'Exposed':<10} {'Name':<50}")
    print("-" * 90)
    for v in vulns[:50]:
        cve = (v.get("id") or "?")[:19]
        sev = (v.get("severity") or "?")[:9]
        exposed = str(v.get("exposedMachines", 0))[:9]
        name = (v.get("name") or "?")[:49]
        print(f"{cve:<20} {sev:<10} {exposed:<10} {name:<50}")

    if len(vulns) > 50:
        print(f"\n... and {len(vulns) - 50} more")


def format_software_table(software):
    if not software:
        print("No software found.")
        return

    print(f"{'Software':<40} {'Version':<15} {'Vendor':<20} {'Exposed':<10} {'EOL Status':<20}")
    print("-" * 105)
    for s in software[:50]:
        name = (s.get("name") or "?")[:39]
        ver = (s.get("version") or "?")[:14]
        vendor = (s.get("vendor") or "?")[:19]
        exposed = str(s.get("exposedMachines", 0))[:9]
        eol = (s.get("endOfSupportStatus") or "-")[:19]
        print(f"{name:<40} {ver:<15} {vendor:<20} {exposed:<10} {eol:<20}")


def format_machines_table(machines):
    if not machines:
        print("No machines found.")
        return

    print(f"{'Machine':<30} {'OS':<15} {'Exposure':<12} {'Risk':<10} {'Last Seen':<20}")
    print("-" * 87)
    for m in machines[:50]:
        name = (m.get("computerDnsName") or "?")[:29]
        os_name = (m.get("osPlatform") or "?")[:14]
        exposure = (m.get("exposureLevel") or "?")[:11]
        risk = (m.get("riskScore") or "?")[:9]
        seen = (m.get("lastSeen") or "?")[:19]
        print(f"{name:<30} {os_name:<15} {exposure:<12} {risk:<10} {seen:<20}")


def main():
    parser = argparse.ArgumentParser(description="Microsoft Defender Vulnerability Management")
    parser.add_argument("--action", required=True,
                        choices=["vulnerabilities", "software", "recommendations",
                                 "machines", "machine-vulns", "export", "convert"])
    parser.add_argument("--severity", help="Filter: critical/high/medium/low")
    parser.add_argument("--eol-only", action="store_true", help="EOL software only")
    parser.add_argument("--status", help="Recommendation status filter")
    parser.add_argument("--exposure", help="Machine exposure filter: high/medium/low")
    parser.add_argument("--machine-id", help="Machine ID for machine-vulns")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_security_token(tenant, client_id, client_secret)

    if args.action == "vulnerabilities":
        vulns = get_vulnerabilities(token, args.severity)
        if args.json:
            print(json.dumps(vulns, indent=2))
        else:
            format_vulns_table(vulns)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(vulns, f, indent=2)

    elif args.action == "software":
        software = get_software_inventory(token, args.eol_only)
        if args.json:
            print(json.dumps(software, indent=2))
        else:
            format_software_table(software)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(software, f, indent=2)

    elif args.action == "recommendations":
        recs = get_recommendations(token, args.status)
        if args.json:
            print(json.dumps(recs, indent=2))
        else:
            print(f"Total recommendations: {len(recs)}")
            for r in recs[:20]:
                sev = r.get("severityScore", "?")
                status = r.get("status", "?")
                name = r.get("recommendationName", "?")
                exposed = r.get("exposedMachinesCount", 0)
                print(f"  [{sev}] [{status}] {name} ({exposed} machines)")
        if args.output:
            with open(args.output, "w") as f:
                json.dump(recs, f, indent=2)

    elif args.action == "machines":
        machines = get_machines(token, args.exposure)
        if args.json:
            print(json.dumps(machines, indent=2))
        else:
            format_machines_table(machines)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(machines, f, indent=2)

    elif args.action == "machine-vulns":
        if not args.machine_id:
            print("ERROR: --machine-id required", file=sys.stderr)
            sys.exit(1)
        vulns = get_machine_vulns(token, args.machine_id)
        print(json.dumps(vulns, indent=2))

    elif args.action == "export":
        output = args.output or "mdvm-export.json"
        export_all(token, output)

    elif args.action == "convert":
        # Convert MDVM export to scan-results format for prioritisation pipeline
        if not args.output:
            print("ERROR: --output required for convert", file=sys.stderr)
            sys.exit(1)
        vulns = get_vulnerabilities(token)
        machines = get_machines(token)
        results = convert_to_scan_results(vulns, machines)
        output_data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "source": "MDVM",
            "total_findings": len(results),
            "results": results,
        }
        with open(args.output, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"Converted {len(results)} MDVM vulns to scan-results format → {args.output}")


if __name__ == "__main__":
    main()
