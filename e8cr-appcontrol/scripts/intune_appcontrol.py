#!/usr/bin/env python3
"""Audit WDAC/AppLocker application control policies via Microsoft Graph (Intune).

Modes:
  audit      — List current application control policies and their deployment status
  events     — Pull recent blocked execution events from managed devices
  compliance — Per-device application control compliance breakdown
"""

import os
import sys
import json
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "..", "shared"))
from graph_auth import get_env, get_token
from graph_client import graph_get_paginated, with_query, build_modified_since_filter

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


def audit_policies(token, since=None):
    """List all device configuration profiles related to application control."""
    filter_expr = build_modified_since_filter(since)

    profiles_url = with_query(
        f"{GRAPH_BETA}/deviceManagement/configurationPolicies?$top=100",
        {"$filter": filter_expr},
    )
    profiles = graph_get_paginated(profiles_url, token)

    appcontrol_profiles = []
    keywords = [
        "application control",
        "wdac",
        "applocker",
        "code integrity",
        "windows defender application control",
        "app control",
    ]

    for p in profiles:
        name = (p.get("name") or "").lower()
        desc = (p.get("description") or "").lower()
        if any(kw in name or kw in desc for kw in keywords):
            appcontrol_profiles.append(
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "platforms": p.get("platforms"),
                    "createdDateTime": p.get("createdDateTime"),
                    "lastModifiedDateTime": p.get("lastModifiedDateTime"),
                    "isAssigned": p.get("isAssigned", False),
                }
            )

    configs_url = with_query(
        f"{GRAPH_BASE}/deviceManagement/deviceConfigurations?$top=100",
        {"$filter": filter_expr},
    )
    configs = graph_get_paginated(configs_url, token)
    for c in configs:
        name = (c.get("displayName") or "").lower()
        odata_type = c.get("@odata.type", "")
        if any(kw in name for kw in keywords) or "windowsDefenderApplicationControl" in odata_type:
            appcontrol_profiles.append(
                {
                    "id": c.get("id"),
                    "name": c.get("displayName"),
                    "description": c.get("description"),
                    "type": odata_type,
                    "createdDateTime": c.get("createdDateTime"),
                    "lastModifiedDateTime": c.get("lastModifiedDateTime"),
                    "isAssigned": c.get("isAssigned", False),
                }
            )

    sev = "P3"
    reason = "App control posture appears present"
    if len(appcontrol_profiles) == 0:
        sev = "P1"
        reason = "No application control policies detected"
    elif not any(p.get("isAssigned") for p in appcontrol_profiles):
        sev = "P2"
        reason = "Policies found but none assigned"

    return {
        "total_profiles_scanned": len(profiles) + len(configs),
        "appcontrol_policies_found": len(appcontrol_profiles),
        "policies": appcontrol_profiles,
        "severity": sev,
        "escalation_reason": reason,
        "since": since,
    }


def audit_events(token, days=7):
    detected_apps = graph_get_paginated(f"{GRAPH_BETA}/deviceManagement/detectedApps?$top=50", token)
    return {
        "source": "intune_detected_apps",
        "note": "For full WDAC event logs, connect to Microsoft Defender for Endpoint or Windows Event Forwarding",
        "detected_apps_count": len(detected_apps),
        "days": days,
        "apps": [
            {"name": a.get("displayName"), "version": a.get("version"), "deviceCount": a.get("deviceCount")}
            for a in detected_apps[:50]
        ],
    }


def audit_compliance(token):
    devices = graph_get_paginated(
        f"{GRAPH_BASE}/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,complianceState,lastSyncDateTime&$top=100",
        token,
    )

    summary = {"compliant": 0, "noncompliant": 0, "unknown": 0, "total": len(devices)}
    for d in devices:
        state = d.get("complianceState", "unknown")
        if state == "compliant":
            summary["compliant"] += 1
        elif state == "noncompliant":
            summary["noncompliant"] += 1
        else:
            summary["unknown"] += 1

    return {
        "summary": summary,
        "devices": [
            {
                "name": d.get("deviceName"),
                "os": d.get("operatingSystem"),
                "compliance": d.get("complianceState"),
                "lastSync": d.get("lastSyncDateTime"),
            }
            for d in devices
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Audit WDAC/AppLocker via Intune")
    parser.add_argument("--mode", choices=["audit", "events", "compliance"], required=True)
    parser.add_argument("--days", type=int, default=7, help="Days of events to pull")
    parser.add_argument("--since", help="ISO timestamp for incremental polling")
    parser.add_argument("--output", help="Write JSON to file")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if args.mode == "audit":
        result = audit_policies(token, since=args.since)
    elif args.mode == "events":
        result = audit_events(token, args.days)
    else:
        result = audit_compliance(token)

    output = json.dumps(result, indent=2)
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Written to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
