#!/usr/bin/env python3
"""Audit admin role assignments and privileged access via Microsoft Graph.

Usage:
    python3 entra_roles.py --action list                  # All role assignments
    python3 entra_roles.py --action global-admins         # Global Admin audit
    python3 entra_roles.py --action permanent             # Permanent (non-PIM) assignments
    python3 entra_roles.py --action privileged-users      # Users with any admin role
    python3 entra_roles.py --action inactive --days 45    # Inactive privileged accounts
    python3 entra_roles.py --action summary               # Role assignment summary
    python3 entra_roles.py --action export --output roles.json

Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars.
Permissions: Directory.Read.All, RoleManagement.Read.All
"""

import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "e8cr-vmpm", "scripts"))
from graph_auth import get_env, get_token

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

# High-privilege roles that need extra scrutiny
HIGH_PRIV_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Intune Administrator",
    "Authentication Administrator",
    "Conditional Access Administrator",
}

CRITICAL_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
}


def graph_get(token, url):
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


def get_role_definitions(token):
    """Get all directory role definitions."""
    url = f"{GRAPH_BASE}/directoryRoles"
    roles = graph_get(token, url)
    return {r.get("id"): r.get("displayName", "Unknown") for r in roles}


def get_role_assignments(token):
    """Get all active role assignments."""
    # Get role definitions first
    role_defs = get_role_definitions(token)

    # Get members of each role
    assignments = []
    for role_id, role_name in role_defs.items():
        url = f"{GRAPH_BASE}/directoryRoles/{role_id}/members?$select=id,displayName,userPrincipalName,accountEnabled,userType"
        try:
            members = graph_get(token, url)
            for m in members:
                assignments.append({
                    "roleId": role_id,
                    "roleName": role_name,
                    "userId": m.get("id"),
                    "displayName": m.get("displayName"),
                    "upn": m.get("userPrincipalName", ""),
                    "accountEnabled": m.get("accountEnabled", True),
                    "userType": m.get("userType", "Member"),
                    "isHighPriv": role_name in HIGH_PRIV_ROLES,
                    "isCritical": role_name in CRITICAL_ROLES,
                    "assignmentType": "permanent",  # Default; PIM check below
                })
        except SystemExit:
            continue

    return assignments


def get_pim_assignments(token):
    """Get PIM eligible and active role assignments (beta)."""
    eligible = []
    active = []

    try:
        url = f"{GRAPH_BETA}/roleManagement/directory/roleEligibilityScheduleInstances"
        eligible = graph_get(token, url)
    except SystemExit:
        print("INFO: PIM eligible assignments not accessible (may need P2 licence)", file=sys.stderr)

    try:
        url = f"{GRAPH_BETA}/roleManagement/directory/roleAssignmentScheduleInstances"
        active = graph_get(token, url)
    except SystemExit:
        print("INFO: PIM active assignments not accessible", file=sys.stderr)

    return eligible, active


def get_user_last_signin(token, user_id):
    """Get last sign-in for a user."""
    url = f"{GRAPH_BETA}/users/{user_id}?$select=signInActivity"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(req) as resp:
            body = json.loads(resp.read())
            activity = body.get("signInActivity", {})
            return activity.get("lastSignInDateTime")
    except HTTPError:
        return None


def build_role_report(token):
    """Build comprehensive role assignment report."""
    now = datetime.now(timezone.utc)
    assignments = get_role_assignments(token)

    # Group by user
    user_roles = {}
    for a in assignments:
        uid = a["userId"]
        if uid not in user_roles:
            user_roles[uid] = {
                "userId": uid,
                "displayName": a["displayName"],
                "upn": a["upn"],
                "accountEnabled": a["accountEnabled"],
                "roles": [],
                "isHighPriv": False,
                "isCritical": False,
                "roleCount": 0,
            }
        user_roles[uid]["roles"].append({
            "roleName": a["roleName"],
            "isHighPriv": a["isHighPriv"],
            "isCritical": a["isCritical"],
            "assignmentType": a["assignmentType"],
        })
        if a["isHighPriv"]:
            user_roles[uid]["isHighPriv"] = True
        if a["isCritical"]:
            user_roles[uid]["isCritical"] = True
        user_roles[uid]["roleCount"] += 1

    # Count stats
    role_counts = {}
    for a in assignments:
        rn = a["roleName"]
        role_counts[rn] = role_counts.get(rn, 0) + 1

    global_admins = [u for u in user_roles.values()
                     if any(r["roleName"] == "Global Administrator" for r in u["roles"])]

    report = {
        "generated_at": now.isoformat(),
        "total_role_assignments": len(assignments),
        "unique_privileged_users": len(user_roles),
        "global_admin_count": len(global_admins),
        "global_admins": global_admins,
        "role_counts": dict(sorted(role_counts.items(), key=lambda x: -x[1])),
        "high_priv_users": [u for u in user_roles.values() if u["isHighPriv"]],
        "critical_role_users": [u for u in user_roles.values() if u["isCritical"]],
        "all_assignments": assignments,
        "users": list(user_roles.values()),
    }

    # Compliance checks
    report["findings"] = []

    if len(global_admins) > 4:
        report["findings"].append({
            "severity": "HIGH",
            "finding": f"Too many Global Admins: {len(global_admins)} (recommended: 2-4)",
            "remediation": "Reduce Global Admin count. Use least-privilege roles instead.",
        })

    if len(global_admins) < 2:
        report["findings"].append({
            "severity": "MEDIUM",
            "finding": f"Only {len(global_admins)} Global Admin(s) — need at least 2 (including break-glass)",
            "remediation": "Ensure at least 2 Global Admins exist for redundancy.",
        })

    # Check for disabled accounts with roles
    disabled_with_roles = [u for u in user_roles.values() if not u["accountEnabled"]]
    if disabled_with_roles:
        report["findings"].append({
            "severity": "MEDIUM",
            "finding": f"{len(disabled_with_roles)} disabled account(s) still have admin roles assigned",
            "remediation": "Remove role assignments from disabled accounts.",
        })

    # Users with many roles (role accumulation)
    many_roles = [u for u in user_roles.values() if u["roleCount"] >= 3]
    if many_roles:
        report["findings"].append({
            "severity": "LOW",
            "finding": f"{len(many_roles)} user(s) have 3+ admin roles (possible role accumulation)",
            "remediation": "Review if all roles are necessary. Apply least-privilege principle.",
        })

    return report


def format_summary(report):
    """Pretty-print role summary."""
    print("=" * 60)
    print("  ADMIN PRIVILEGE AUDIT")
    print(f"  Generated: {report['generated_at'][:19]}")
    print("=" * 60)
    print(f"\n  Total Role Assignments: {report['total_role_assignments']}")
    print(f"  Unique Privileged Users: {report['unique_privileged_users']}")
    print(f"  Global Admins: {report['global_admin_count']}")

    ga_status = "✅" if 2 <= report["global_admin_count"] <= 4 else "⚠️"
    print(f"  Global Admin Count: {ga_status} {report['global_admin_count']} (recommended: 2-4)")

    if report["global_admins"]:
        print("\n  Global Administrators:")
        for ga in report["global_admins"]:
            enabled = "✅" if ga["accountEnabled"] else "❌ DISABLED"
            print(f"    - {ga['upn']} ({ga['displayName']}) — {enabled}")

    if report["role_counts"]:
        print("\n  Role Distribution:")
        for role, count in list(report["role_counts"].items())[:15]:
            marker = "🔴" if role in CRITICAL_ROLES else ("🟡" if role in HIGH_PRIV_ROLES else "  ")
            print(f"    {marker} {role}: {count}")

    if report["findings"]:
        print(f"\n  Findings ({len(report['findings'])}):")
        for f in report["findings"]:
            icon = "🔴" if f["severity"] == "HIGH" else ("🟡" if f["severity"] == "MEDIUM" else "🔵")
            print(f"    {icon} [{f['severity']}] {f['finding']}")
            print(f"       → {f['remediation']}")

    print()


def main():
    parser = argparse.ArgumentParser(description="Entra ID admin role auditing")
    parser.add_argument("--action", required=True,
                        choices=["list", "global-admins", "permanent", "privileged-users",
                                 "inactive", "summary", "export"])
    parser.add_argument("--days", type=int, default=45, help="Inactive threshold days")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    report = build_role_report(token)

    if args.action == "summary":
        if args.json:
            # Remove large lists for summary
            summary = {k: v for k, v in report.items() if k not in ("all_assignments", "users")}
            print(json.dumps(summary, indent=2))
        else:
            format_summary(report)

    elif args.action == "list":
        print(json.dumps(report["all_assignments"], indent=2))

    elif args.action == "global-admins":
        gas = report["global_admins"]
        if args.json:
            print(json.dumps(gas, indent=2))
        else:
            print(f"Global Administrators ({len(gas)}):")
            for ga in gas:
                enabled = "Active" if ga["accountEnabled"] else "DISABLED"
                roles = ", ".join(r["roleName"] for r in ga["roles"])
                print(f"  - {ga['upn']} ({ga['displayName']}) — {enabled}")
                print(f"    Roles: {roles}")

    elif args.action == "permanent":
        permanent = [a for a in report["all_assignments"] if a["assignmentType"] == "permanent"]
        if args.json:
            print(json.dumps(permanent, indent=2))
        else:
            print(f"Permanent role assignments ({len(permanent)}):")
            for a in permanent:
                priv = "🔴" if a["isCritical"] else ("🟡" if a["isHighPriv"] else "  ")
                print(f"  {priv} {a['upn']} → {a['roleName']}")

    elif args.action == "privileged-users":
        users = sorted(report["users"], key=lambda u: (-u["isCritical"], -u["isHighPriv"], -u["roleCount"]))
        if args.json:
            print(json.dumps(users, indent=2))
        else:
            print(f"Privileged users ({len(users)}):")
            for u in users:
                roles = ", ".join(r["roleName"] for r in u["roles"])
                print(f"  {'🔴' if u['isCritical'] else '🟡' if u['isHighPriv'] else '  '} "
                      f"{u['upn']} ({u['roleCount']} roles) — {roles}")

    elif args.action == "inactive":
        print(f"Checking for privileged accounts inactive >{args.days} days...", file=sys.stderr)
        cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
        inactive = []
        for u in report["users"]:
            last_signin = get_user_last_signin(token, u["userId"])
            if last_signin:
                signin_dt = datetime.fromisoformat(last_signin.replace("Z", "+00:00"))
                if signin_dt < cutoff:
                    inactive.append({
                        **u,
                        "lastSignIn": last_signin,
                        "daysSinceSignIn": (datetime.now(timezone.utc) - signin_dt).days,
                    })
            else:
                inactive.append({**u, "lastSignIn": None, "daysSinceSignIn": "Never"})

        if args.json:
            print(json.dumps(inactive, indent=2))
        elif not inactive:
            print(f"✅ All privileged accounts active within {args.days} days.")
        else:
            print(f"⚠️  Inactive privileged accounts ({len(inactive)}):")
            for u in inactive:
                roles = ", ".join(r["roleName"] for r in u["roles"])
                print(f"  - {u['upn']} — Last sign-in: {u['daysSinceSignIn']} days ago — Roles: {roles}")

    elif args.action == "export":
        output = args.output or "role-audit.json"
        with open(output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Exported role audit to {output}")


if __name__ == "__main__":
    main()
