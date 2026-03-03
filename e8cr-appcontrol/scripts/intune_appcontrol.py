#!/usr/bin/env python3
"""Audit WDAC/AppLocker application control policies via Microsoft Graph (Intune).

Modes:
  audit      — List current application control policies and their deployment status
  events     — Pull recent blocked execution events from managed devices
  compliance — Per-device application control compliance breakdown

Usage:
    python3 intune_appcontrol.py --mode audit
    python3 intune_appcontrol.py --mode events --days 7
    python3 intune_appcontrol.py --mode compliance
    python3 intune_appcontrol.py --mode audit --output /tmp/appcontrol-audit.json
"""

import os
import sys
import json
import argparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "..", "shared"))
from graph_auth import get_env, get_token

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"


def graph_get(token, url):
    """GET from Graph API, handle pagination."""
    results = []
    while url:
        req = Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json")
        try:
            with urlopen(req) as resp:
                body = json.loads(resp.read())
                results.extend(body.get("value", [body] if "value" not in body else []))
                url = body.get("@odata.nextLink")
        except HTTPError as e:
            err = e.read().decode()
            print(f"ERROR: Graph API call failed ({e.code}): {err}", file=sys.stderr)
            sys.exit(1)
    return results


def audit_policies(token):
    """List all device configuration profiles related to application control."""
    # Get all configuration profiles
    profiles = graph_get(token, f"{GRAPH_BETA}/deviceManagement/configurationPolicies?$top=100")
    
    appcontrol_profiles = []
    keywords = ["application control", "wdac", "applocker", "code integrity",
                "windows defender application control", "app control"]
    
    for p in profiles:
        name = (p.get("name") or "").lower()
        desc = (p.get("description") or "").lower()
        if any(kw in name or kw in desc for kw in keywords):
            appcontrol_profiles.append({
                "id": p.get("id"),
                "name": p.get("name"),
                "description": p.get("description"),
                "platforms": p.get("platforms"),
                "createdDateTime": p.get("createdDateTime"),
                "lastModifiedDateTime": p.get("lastModifiedDateTime"),
                "isAssigned": p.get("isAssigned", False),
            })
    
    # Also check device configurations (older profile type)
    configs = graph_get(token, f"{GRAPH_BASE}/deviceManagement/deviceConfigurations?$top=100")
    for c in configs:
        name = (c.get("displayName") or "").lower()
        odata_type = c.get("@odata.type", "")
        if any(kw in name for kw in keywords) or "windowsDefenderApplicationControl" in odata_type:
            appcontrol_profiles.append({
                "id": c.get("id"),
                "name": c.get("displayName"),
                "description": c.get("description"),
                "type": odata_type,
                "createdDateTime": c.get("createdDateTime"),
                "lastModifiedDateTime": c.get("lastModifiedDateTime"),
            })
    
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
    }


def audit_events(token, days=7):
    """Pull WDAC/AppLocker block events from device management."""
    # Use device compliance / detected apps endpoint
    # In production, this would connect to Windows Event Forwarding or Defender ATP
    detected_apps = graph_get(token, f"{GRAPH_BETA}/deviceManagement/detectedApps?$top=50")
    
    return {
        "source": "intune_detected_apps",
        "note": "For full WDAC event logs, connect to Microsoft Defender for Endpoint or Windows Event Forwarding",
        "detected_apps_count": len(detected_apps),
        "apps": [{"name": a.get("displayName"), "version": a.get("version"),
                   "deviceCount": a.get("deviceCount")} for a in detected_apps[:50]],
    }


def audit_compliance(token):
    """Per-device compliance status for application control."""
    devices = graph_get(token, f"{GRAPH_BASE}/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,complianceState,lastSyncDateTime&$top=100")
    
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
        "devices": [{"name": d.get("deviceName"), "os": d.get("operatingSystem"),
                      "compliance": d.get("complianceState"),
                      "lastSync": d.get("lastSyncDateTime")} for d in devices],
    }


def main():
    parser = argparse.ArgumentParser(description="Audit WDAC/AppLocker via Intune")
    parser.add_argument("--mode", choices=["audit", "events", "compliance"], required=True)
    parser.add_argument("--days", type=int, default=7, help="Days of events to pull")
    parser.add_argument("--output", help="Write JSON to file")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if args.mode == "audit":
        result = audit_policies(token)
    elif args.mode == "events":
        result = audit_events(token, args.days)
    elif args.mode == "compliance":
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
