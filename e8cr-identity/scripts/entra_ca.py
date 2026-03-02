#!/usr/bin/env python3
"""Audit Conditional Access policies via Microsoft Graph.

Usage:
    python3 entra_ca.py --action list                     # All CA policies
    python3 entra_ca.py --action audit                    # Check for baseline policy gaps
    python3 entra_ca.py --action legacy-auth-blocked      # Verify legacy auth is blocked
    python3 entra_ca.py --action export --output ca.json

Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars.
Permissions: Policy.Read.All
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

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# ML2 baseline CA policies that should exist
BASELINE_POLICIES = {
    "require_mfa_all_users": {
        "name": "Require MFA for all users",
        "description": "All users must complete MFA for all cloud apps",
        "check": lambda p: _checks_mfa_all_users(p),
    },
    "block_legacy_auth": {
        "name": "Block legacy authentication",
        "description": "Block sign-ins using legacy auth protocols (IMAP, POP3, SMTP, etc.)",
        "check": lambda p: _checks_legacy_block(p),
    },
    "require_mfa_admins": {
        "name": "Require MFA for admin roles",
        "description": "Admin/privileged roles must complete MFA",
        "check": lambda p: _checks_mfa_admins(p),
    },
    "block_high_risk_signin": {
        "name": "Block high-risk sign-ins",
        "description": "Block sign-ins flagged as high risk (requires Entra ID P2)",
        "check": lambda p: _checks_risk_block(p),
    },
}


def _checks_mfa_all_users(policy):
    """Check if policy requires MFA for all users."""
    conditions = policy.get("conditions", {})
    users = conditions.get("users", {})
    apps = conditions.get("applications", {})
    grant = policy.get("grantControls", {})

    all_users = "All" in (users.get("includeUsers") or [])
    all_apps = "All" in (apps.get("includeApplications") or [])
    requires_mfa = "mfa" in (grant.get("builtInControls") or [])

    return all_users and all_apps and requires_mfa


def _checks_legacy_block(policy):
    """Check if policy blocks legacy auth."""
    conditions = policy.get("conditions", {})
    client_apps = conditions.get("clientAppTypes", [])
    grant = policy.get("grantControls", {})

    targets_legacy = any(t in client_apps for t in
                         ["exchangeActiveSync", "other"])
    blocks = "block" in (grant.get("builtInControls") or [])

    # Also check if grant is simply "Block"
    if not blocks and grant.get("operator") == "OR":
        blocks = "block" in (grant.get("builtInControls") or [])

    return targets_legacy and blocks


def _checks_mfa_admins(policy):
    """Check if policy requires MFA for admin roles."""
    conditions = policy.get("conditions", {})
    users = conditions.get("users", {})
    grant = policy.get("grantControls", {})

    has_roles = bool(users.get("includeRoles"))
    requires_mfa = "mfa" in (grant.get("builtInControls") or [])

    return has_roles and requires_mfa


def _checks_risk_block(policy):
    """Check if policy blocks high-risk sign-ins."""
    conditions = policy.get("conditions", {})
    risk = conditions.get("signInRiskLevels", [])
    grant = policy.get("grantControls", {})

    targets_high_risk = "high" in risk
    blocks_or_mfa = any(c in (grant.get("builtInControls") or [])
                         for c in ["block", "mfa"])

    return targets_high_risk and blocks_or_mfa


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
            err = e.read().decode()
            print(f"ERROR: Graph API ({e.code}): {err}", file=sys.stderr)
            sys.exit(1)
    return results


def get_ca_policies(token):
    """Get all Conditional Access policies."""
    url = f"{GRAPH_BASE}/identity/conditionalAccess/policies"
    return graph_get(token, url)


def audit_baseline(policies):
    """Check which baseline policies exist."""
    results = {}

    for policy_key, baseline in BASELINE_POLICIES.items():
        found = False
        matching_policy = None

        for p in policies:
            if p.get("state") != "enabled":
                continue
            if baseline["check"](p):
                found = True
                matching_policy = p.get("displayName")
                break

        results[policy_key] = {
            "name": baseline["name"],
            "description": baseline["description"],
            "found": found,
            "matchingPolicy": matching_policy,
        }

    return results


def format_policies(policies):
    """Pretty-print CA policies."""
    if not policies:
        print("No Conditional Access policies found.")
        return

    enabled = [p for p in policies if p.get("state") == "enabled"]
    disabled = [p for p in policies if p.get("state") != "enabled"]

    print(f"Total CA Policies: {len(policies)} ({len(enabled)} enabled, {len(disabled)} disabled)")
    print()

    for p in policies:
        state_icon = "✅" if p.get("state") == "enabled" else "⚪"
        name = p.get("displayName", "Unnamed")
        state = p.get("state", "unknown")
        created = (p.get("createdDateTime") or "?")[:10]
        modified = (p.get("modifiedDateTime") or "?")[:10]

        grant = p.get("grantControls", {})
        controls = ", ".join(grant.get("builtInControls", [])) if grant else "none"

        print(f"  {state_icon} {name}")
        print(f"     State: {state} | Created: {created} | Modified: {modified}")
        print(f"     Controls: {controls}")
        print()


def format_audit(audit_results):
    """Pretty-print baseline audit."""
    print("=" * 60)
    print("  CONDITIONAL ACCESS BASELINE AUDIT")
    print("=" * 60)

    all_found = True
    for key, result in audit_results.items():
        found = result["found"]
        icon = "✅" if found else "❌"
        if not found:
            all_found = False

        print(f"\n  {icon} {result['name']}")
        print(f"     {result['description']}")
        if found:
            print(f"     Matched: {result['matchingPolicy']}")
        else:
            print(f"     ⚠️  NOT FOUND — ML2 requirement gap")

    if all_found:
        print(f"\n  ✅ All baseline CA policies are in place.")
    else:
        missing = sum(1 for r in audit_results.values() if not r["found"])
        print(f"\n  ⚠️  {missing} baseline policy gap(s) detected.")

    print()


def main():
    parser = argparse.ArgumentParser(description="Entra ID Conditional Access audit")
    parser.add_argument("--action", required=True,
                        choices=["list", "audit", "legacy-auth-blocked", "export"])
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    policies = get_ca_policies(token)

    if args.action == "list":
        if args.json:
            print(json.dumps(policies, indent=2))
        else:
            format_policies(policies)

    elif args.action == "audit":
        audit_results = audit_baseline(policies)
        if args.json:
            print(json.dumps(audit_results, indent=2))
        else:
            format_audit(audit_results)

    elif args.action == "legacy-auth-blocked":
        audit_results = audit_baseline(policies)
        legacy = audit_results.get("block_legacy_auth", {})
        if legacy.get("found"):
            print(f"✅ Legacy auth is blocked by policy: {legacy['matchingPolicy']}")
        else:
            print("❌ No CA policy blocking legacy authentication detected!")
            print("   This is a critical ML2 gap — legacy auth bypasses MFA.")

    elif args.action == "export":
        audit_results = audit_baseline(policies)
        output = args.output or "ca-audit.json"
        export_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_policies": len(policies),
            "enabled_policies": len([p for p in policies if p.get("state") == "enabled"]),
            "baseline_audit": audit_results,
            "policies": policies,
        }
        with open(output, "w") as f:
            json.dump(export_data, f, indent=2)
        print(f"Exported CA audit to {output}")


if __name__ == "__main__":
    main()
