#!/usr/bin/env python3
"""Query Intune patch/update compliance via Microsoft Graph.

Usage:
    python3 graph_patches.py --action compliance-report     # Patch compliance overview
    python3 graph_patches.py --action update-rings          # List Windows Update rings
    python3 graph_patches.py --action stale-devices --days 14  # Devices not patched in N days
    python3 graph_patches.py --action software-inventory    # Discovered apps/versions
    python3 graph_patches.py --action export --output patches.json

Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))
from graph_auth import get_env, get_token

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


def graph_get(token, url):
    """GET with pagination."""
    results = []
    while url:
        req = Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("ConsistencyLevel", "eventual")
        try:
            with urlopen(req) as resp:
                body = json.loads(resp.read())
                results.extend(body.get("value", []))
                url = body.get("@odata.nextLink")
        except HTTPError as e:
            err = e.read().decode()
            print(f"ERROR: Graph API ({e.code}): {err}", file=sys.stderr)
            sys.exit(1)
    return results


def get_update_rings(token):
    """List Windows Update for Business update rings."""
    url = f"{GRAPH_BASE}/deviceManagement/deviceConfigurations"
    configs = graph_get(token, url)
    # Filter for Windows Update rings
    rings = [c for c in configs if c.get("@odata.type", "").endswith("windowsUpdateForBusinessConfiguration")]
    return rings


def get_compliance_report(token):
    """Build patch compliance report from device data."""
    url = (f"{GRAPH_BASE}/deviceManagement/managedDevices?"
           f"$select=id,deviceName,operatingSystem,osVersion,complianceState,"
           f"lastSyncDateTime,userPrincipalName")
    devices = graph_get(token, url)

    now = datetime.now(timezone.utc)
    report = {
        "generated_at": now.isoformat(),
        "total_devices": len(devices),
        "os_versions": {},
        "patch_compliance": {
            "compliant": 0,
            "noncompliant": 0,
            "unknown": 0,
        },
        "stale_devices": [],  # Not synced in 14+ days
        "eol_devices": [],    # Running unsupported OS
        "details": [],
    }

    # Known EOL Windows versions
    eol_versions = {
        "10.0.10240",  # Win 10 1507
        "10.0.10586",  # Win 10 1511
        "10.0.14393",  # Win 10 1607
        "10.0.15063",  # Win 10 1703
        "10.0.16299",  # Win 10 1709
        "10.0.17134",  # Win 10 1803
        "10.0.17763",  # Win 10 1809
        "10.0.18362",  # Win 10 1903
        "10.0.18363",  # Win 10 1909
        "10.0.19041",  # Win 10 2004
        "10.0.19042",  # Win 10 20H2
        "10.0.19043",  # Win 10 21H1
    }

    cutoff_14d = now - timedelta(days=14)

    for d in devices:
        state = d.get("complianceState", "unknown")
        os_ver = d.get("osVersion", "Unknown")
        os_name = d.get("operatingSystem", "Unknown")

        # Count compliance states
        if state == "compliant":
            report["patch_compliance"]["compliant"] += 1
        elif state == "noncompliant":
            report["patch_compliance"]["noncompliant"] += 1
        else:
            report["patch_compliance"]["unknown"] += 1

        # OS version distribution
        ver_key = f"{os_name} {os_ver}"
        report["os_versions"][ver_key] = report["os_versions"].get(ver_key, 0) + 1

        # Stale check
        last_sync = d.get("lastSyncDateTime")
        is_stale = False
        if last_sync:
            sync_dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
            if sync_dt < cutoff_14d:
                is_stale = True
                report["stale_devices"].append({
                    "deviceName": d.get("deviceName"),
                    "lastSync": last_sync,
                    "daysSinceSync": (now - sync_dt).days,
                    "user": d.get("userPrincipalName"),
                })

        # EOL check
        is_eol = any(os_ver.startswith(eol) for eol in eol_versions)
        if is_eol:
            report["eol_devices"].append({
                "deviceName": d.get("deviceName"),
                "osVersion": os_ver,
                "user": d.get("userPrincipalName"),
            })

        report["details"].append({
            "deviceName": d.get("deviceName"),
            "os": os_name,
            "osVersion": os_ver,
            "compliance": state,
            "lastSync": last_sync,
            "stale": is_stale,
            "eol": is_eol,
            "user": d.get("userPrincipalName"),
        })

    # Calculate compliance rate
    total = report["total_devices"]
    if total > 0:
        report["compliance_rate"] = round(
            (report["patch_compliance"]["compliant"] / total) * 100, 1
        )
    else:
        report["compliance_rate"] = 0

    report["stale_count"] = len(report["stale_devices"])
    report["eol_count"] = len(report["eol_devices"])

    return report


def get_software_inventory(token):
    """Get discovered applications from Intune (beta endpoint)."""
    url = f"{GRAPH_BETA}/deviceManagement/detectedApps?$top=100"
    apps = graph_get(token, url)
    # Sort by device count descending
    apps.sort(key=lambda a: a.get("deviceCount", 0), reverse=True)
    return apps


def format_compliance_report(report):
    """Pretty-print compliance report."""
    print("=" * 60)
    print("  PATCH COMPLIANCE REPORT")
    print(f"  Generated: {report['generated_at'][:19]}")
    print("=" * 60)
    print(f"\n  Total Devices: {report['total_devices']}")
    print(f"  Compliance Rate: {report['compliance_rate']}%")
    print(f"  Compliant: {report['patch_compliance']['compliant']}")
    print(f"  Non-Compliant: {report['patch_compliance']['noncompliant']}")
    print(f"  Unknown: {report['patch_compliance']['unknown']}")
    print(f"  Stale (14+ days): {report['stale_count']}")
    print(f"  End-of-Life OS: {report['eol_count']}")

    if report["os_versions"]:
        print("\n  OS Version Distribution:")
        for ver, count in sorted(report["os_versions"].items(), key=lambda x: -x[1]):
            print(f"    {ver}: {count}")

    if report["eol_devices"]:
        print(f"\n  ⚠️  END-OF-LIFE DEVICES ({report['eol_count']}):")
        for d in report["eol_devices"]:
            print(f"    - {d['deviceName']} ({d['osVersion']}) — {d['user']}")

    if report["stale_devices"]:
        print(f"\n  ⚠️  STALE DEVICES ({report['stale_count']}):")
        for d in report["stale_devices"][:10]:  # Show top 10
            print(f"    - {d['deviceName']} — {d['daysSinceSync']} days since sync — {d['user']}")
        if len(report["stale_devices"]) > 10:
            print(f"    ... and {len(report['stale_devices']) - 10} more")

    print()


def main():
    parser = argparse.ArgumentParser(description="Intune patch compliance")
    parser.add_argument("--action", required=True,
                        choices=["compliance-report", "update-rings",
                                 "stale-devices", "software-inventory", "export"],
                        help="Action to perform")
    parser.add_argument("--days", type=int, default=14,
                        help="Days threshold for stale (default: 14)")
    parser.add_argument("--output", help="Output file for export")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if args.action == "compliance-report":
        report = get_compliance_report(token)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            format_compliance_report(report)

    elif args.action == "update-rings":
        rings = get_update_rings(token)
        if not rings:
            print("No Windows Update rings found.")
        else:
            print(json.dumps(rings, indent=2))

    elif args.action == "stale-devices":
        report = get_compliance_report(token)
        stale = [d for d in report["details"]
                 if d.get("stale") or
                 (d.get("lastSync") and
                  (datetime.now(timezone.utc) -
                   datetime.fromisoformat(d["lastSync"].replace("Z", "+00:00"))).days > args.days)]
        if args.json:
            print(json.dumps(stale, indent=2))
        else:
            print(f"Devices not synced in {args.days}+ days: {len(stale)}")
            for d in stale:
                print(f"  - {d['deviceName']} ({d['os']} {d['osVersion']}) — {d['user']}")

    elif args.action == "software-inventory":
        apps = get_software_inventory(token)
        if args.json:
            print(json.dumps(apps, indent=2))
        else:
            print(f"{'Application':<50} {'Version':<20} {'Devices':<10}")
            print("-" * 80)
            for a in apps[:50]:
                name = (a.get("displayName") or "?")[:49]
                ver = (a.get("version") or "?")[:19]
                count = a.get("deviceCount", 0)
                print(f"{name:<50} {ver:<20} {count:<10}")

    elif args.action == "export":
        report = get_compliance_report(token)
        output = args.output or "patch-compliance.json"
        with open(output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Exported patch compliance report to {output}")


if __name__ == "__main__":
    main()
