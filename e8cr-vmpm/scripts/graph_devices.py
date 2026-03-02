#!/usr/bin/env python3
"""Query Intune managed devices via Microsoft Graph.

Usage:
    python3 graph_devices.py --action list                          # All devices
    python3 graph_devices.py --action list --filter noncompliant    # Non-compliant only
    python3 graph_devices.py --action list --filter stale --days 30 # Not seen in 30 days
    python3 graph_devices.py --action detail --device-id <id>       # Single device detail
    python3 graph_devices.py --action summary                       # Compliance summary
    python3 graph_devices.py --action export --output devices.json  # Export full inventory

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
DEVICE_FIELDS = (
    "id,deviceName,operatingSystem,osVersion,complianceState,"
    "lastSyncDateTime,enrolledDateTime,manufacturer,model,"
    "serialNumber,userPrincipalName,managedDeviceOwnerType,"
    "deviceEnrollmentType,managementAgent"
)


def graph_get(token, url):
    """GET request to Graph API with pagination support."""
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


def list_devices(token, filter_type=None, days=30):
    """List managed devices with optional filtering."""
    url = f"{GRAPH_BASE}/deviceManagement/managedDevices?$select={DEVICE_FIELDS}"

    if filter_type == "noncompliant":
        url += "&$filter=complianceState eq 'noncompliant'"
    elif filter_type == "compliant":
        url += "&$filter=complianceState eq 'compliant'"

    devices = graph_get(token, url)

    if filter_type == "stale":
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        devices = [
            d for d in devices
            if d.get("lastSyncDateTime") and
            datetime.fromisoformat(d["lastSyncDateTime"].replace("Z", "+00:00")) < cutoff
        ]

    return devices


def device_detail(token, device_id):
    """Get detailed info for a single device."""
    url = f"{GRAPH_BASE}/deviceManagement/managedDevices/{device_id}"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(req) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode()
        print(f"ERROR: Device detail ({e.code}): {err}", file=sys.stderr)
        sys.exit(1)


def compliance_summary(token):
    """Generate compliance summary statistics."""
    devices = list_devices(token)
    total = len(devices)
    if total == 0:
        return {"total": 0, "message": "No managed devices found"}

    states = {}
    os_breakdown = {}
    stale_count = 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=14)

    for d in devices:
        # Compliance state
        state = d.get("complianceState", "unknown")
        states[state] = states.get(state, 0) + 1

        # OS breakdown
        os_name = d.get("operatingSystem", "Unknown")
        if os_name not in os_breakdown:
            os_breakdown[os_name] = {"total": 0, "compliant": 0, "noncompliant": 0}
        os_breakdown[os_name]["total"] += 1
        if state == "compliant":
            os_breakdown[os_name]["compliant"] += 1
        elif state == "noncompliant":
            os_breakdown[os_name]["noncompliant"] += 1

        # Stale check
        last_sync = d.get("lastSyncDateTime")
        if last_sync:
            sync_dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
            if sync_dt < cutoff:
                stale_count += 1

    compliant = states.get("compliant", 0)
    compliance_pct = round((compliant / total) * 100, 1) if total > 0 else 0

    return {
        "total_devices": total,
        "compliance_rate": f"{compliance_pct}%",
        "by_state": states,
        "by_os": os_breakdown,
        "stale_devices_14d": stale_count,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }


def format_device_table(devices):
    """Format devices as a readable table."""
    if not devices:
        print("No devices found.")
        return

    print(f"{'Device Name':<25} {'OS':<12} {'Version':<15} {'Compliance':<15} {'Last Sync':<20} {'User':<30}")
    print("-" * 117)
    for d in devices:
        name = (d.get("deviceName") or "Unknown")[:24]
        os_name = (d.get("operatingSystem") or "?")[:11]
        version = (d.get("osVersion") or "?")[:14]
        state = (d.get("complianceState") or "?")[:14]
        last_sync = (d.get("lastSyncDateTime") or "?")[:19]
        user = (d.get("userPrincipalName") or "?")[:29]
        print(f"{name:<25} {os_name:<12} {version:<15} {state:<15} {last_sync:<20} {user:<30}")

    print(f"\nTotal: {len(devices)} devices")


def main():
    parser = argparse.ArgumentParser(description="Intune device management")
    parser.add_argument("--action", required=True,
                        choices=["list", "detail", "summary", "export"],
                        help="Action to perform")
    parser.add_argument("--filter", choices=["noncompliant", "compliant", "stale"],
                        help="Filter devices")
    parser.add_argument("--days", type=int, default=30,
                        help="Days threshold for stale filter (default: 30)")
    parser.add_argument("--device-id", help="Device ID for detail action")
    parser.add_argument("--output", help="Output file for export")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if args.action == "list":
        devices = list_devices(token, args.filter, args.days)
        if args.json:
            print(json.dumps(devices, indent=2))
        else:
            format_device_table(devices)

    elif args.action == "detail":
        if not args.device_id:
            print("ERROR: --device-id required for detail action", file=sys.stderr)
            sys.exit(1)
        detail = device_detail(token, args.device_id)
        print(json.dumps(detail, indent=2))

    elif args.action == "summary":
        summary = compliance_summary(token)
        print(json.dumps(summary, indent=2))

    elif args.action == "export":
        devices = list_devices(token)
        output = args.output or "devices.json"
        with open(output, "w") as f:
            json.dump({"exported_at": datetime.now(timezone.utc).isoformat(),
                        "device_count": len(devices),
                        "devices": devices}, f, indent=2)
        print(f"Exported {len(devices)} devices to {output}")


if __name__ == "__main__":
    main()
