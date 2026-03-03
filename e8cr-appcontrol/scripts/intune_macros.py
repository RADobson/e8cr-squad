#!/usr/bin/env python3
"""Audit Office macro restriction policies via Microsoft Graph (Intune)."""

import os
import sys
import json
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "..", "shared"))
from graph_auth import get_env, get_token
from graph_client import graph_get_paginated, with_query, build_modified_since_filter

GRAPH_BETA = "https://graph.microsoft.com/beta"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def audit(token, since=None):
    filter_expr = build_modified_since_filter(since)
    url = with_query(
        f"{GRAPH_BETA}/deviceManagement/configurationPolicies?$top=200",
        {"$filter": filter_expr},
    )
    profiles = graph_get_paginated(url, token)
    keywords = ["macro", "office", "vba", "win32 api", "trusted locations", "motw"]
    matches = []
    for p in profiles:
        text = f"{p.get('name','')} {p.get('description','')}".lower()
        if any(k in text for k in keywords):
            matches.append(
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "platforms": p.get("platforms"),
                    "isAssigned": p.get("isAssigned", False),
                    "lastModifiedDateTime": p.get("lastModifiedDateTime"),
                }
            )
    sev = "P3"
    reason = "Macro controls present"
    if len(matches) == 0:
        sev = "P1"
        reason = "No Office macro restriction policies detected"
    elif not any(m.get("isAssigned") for m in matches):
        sev = "P2"
        reason = "Macro policies found but not assigned"
    return {
        "macro_policies_found": len(matches),
        "policies": matches,
        "severity": sev,
        "escalation_reason": reason,
        "since": since,
    }


def compliance(token):
    devices = graph_get_paginated(
        f"{GRAPH_BASE}/deviceManagement/managedDevices?$select=deviceName,complianceState,operatingSystem&$top=100",
        token,
    )
    return {
        "note": "Macro-specific per-device state requires custom setting-state expansion by policy assignment.",
        "devices": devices,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["audit", "compliance"], required=True)
    parser.add_argument("--since", help="ISO timestamp for incremental polling")
    parser.add_argument("--output")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)
    result = audit(token, since=args.since) if args.mode == "audit" else compliance(token)
    out = json.dumps(result, indent=2)
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(out)
    else:
        print(out)


if __name__ == "__main__":
    main()
