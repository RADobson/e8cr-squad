#!/usr/bin/env python3
"""Audit Office macro restriction policies via Microsoft Graph (Intune)."""

import os
import sys
import json
import argparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "..", "shared"))
from graph_auth import get_env, get_token

GRAPH_BETA = "https://graph.microsoft.com/beta"


def graph_get(token, url):
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
            print(f"ERROR: {e.code} {e.read().decode()}", file=sys.stderr)
            sys.exit(1)
    return results


def audit(token):
    profiles = graph_get(token, f"{GRAPH_BETA}/deviceManagement/configurationPolicies?$top=200")
    keywords = ["macro", "office", "vba", "win32 api", "trusted locations", "motw"]
    matches = []
    for p in profiles:
        text = f"{p.get('name','')} {p.get('description','')}".lower()
        if any(k in text for k in keywords):
            matches.append({
                "id": p.get("id"),
                "name": p.get("name"),
                "description": p.get("description"),
                "platforms": p.get("platforms"),
                "isAssigned": p.get("isAssigned", False),
                "lastModifiedDateTime": p.get("lastModifiedDateTime"),
            })
    return {"macro_policies_found": len(matches), "policies": matches}


def compliance(token):
    # Placeholder summary from managed device compliance state.
    req = Request("https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=deviceName,complianceState,operatingSystem&$top=100", method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    with urlopen(req) as resp:
        body = json.loads(resp.read())
    devices = body.get("value", [])
    return {
        "note": "Macro-specific per-device state requires custom setting-state expansion by policy assignment.",
        "devices": devices,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["audit", "compliance"], required=True)
    parser.add_argument("--output")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)
    result = audit(token) if args.mode == "audit" else compliance(token)
    out = json.dumps(result, indent=2)
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(out)
    else:
        print(out)


if __name__ == "__main__":
    main()
