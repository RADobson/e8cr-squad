#!/usr/bin/env python3
"""Analyse Entra ID sign-in logs for ML2 identity auditing.

Usage:
    python3 entra_signin.py --action legacy              # Legacy auth sign-ins (last 7 days)
    python3 entra_signin.py --action risky               # Risky sign-ins
    python3 entra_signin.py --action break-glass          # Break-glass account usage
    python3 entra_signin.py --action admin-activity       # Admin account sign-in activity
    python3 entra_signin.py --action inactive --days 45   # Inactive privileged accounts
    python3 entra_signin.py --action export --output signin-audit.json

Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars.
Permissions: AuditLog.Read.All, Directory.Read.All, RoleManagement.Read.All
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

# Well-known legacy auth client app strings
LEGACY_CLIENTS = {
    "exchange activesync", "autodiscover", "imap4", "pop3", "smtp",
    "exchange online powershell", "exchange web services",
    "mapi over http", "offline address book",
    "outlook anywhere", "other clients",
    "reporting web services",
}

# Common break-glass naming patterns
BREAK_GLASS_PATTERNS = ["breakglass", "break-glass", "emergency", "bg-", "bg_"]


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
            return results
    return results


def get_admin_user_ids(token):
    """Get set of user IDs that hold any directory role."""
    assignments = graph_get(token,
        f"{GRAPH_BASE}/roleManagement/directory/roleAssignments"
        f"?$select=principalId,roleDefinitionId")
    return {a["principalId"] for a in assignments if a.get("principalId")}


def get_admin_users_map(token):
    """Return dict of admin user_id → {upn, displayName, roles}."""
    roles_raw = graph_get(token,
        f"{GRAPH_BASE}/roleManagement/directory/roleDefinitions"
        f"?$select=id,displayName")
    role_names = {r["id"]: r["displayName"] for r in roles_raw}

    assignments = graph_get(token,
        f"{GRAPH_BASE}/roleManagement/directory/roleAssignments"
        f"?$select=principalId,roleDefinitionId")

    admin_roles = {}  # principal_id → [role_names]
    for a in assignments:
        pid = a.get("principalId")
        rid = a.get("roleDefinitionId")
        if pid and rid:
            admin_roles.setdefault(pid, []).append(role_names.get(rid, rid))

    # Fetch user details
    admin_map = {}
    for pid, roles in admin_roles.items():
        try:
            req = Request(f"{GRAPH_BASE}/users/{pid}?$select=userPrincipalName,displayName",
                          method="GET")
            req.add_header("Authorization", f"Bearer {token}")
            with urlopen(req) as resp:
                user = json.loads(resp.read())
                admin_map[pid] = {
                    "userPrincipalName": user.get("userPrincipalName", pid),
                    "displayName": user.get("displayName", ""),
                    "roles": roles,
                }
        except HTTPError:
            admin_map[pid] = {
                "userPrincipalName": pid,
                "displayName": "",
                "roles": roles,
            }
    return admin_map


def audit_legacy_signins(token, days=7):
    """Find sign-ins using legacy authentication protocols."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    signins = graph_get(token,
        f"{GRAPH_BASE}/auditLogs/signIns"
        f"?$filter=createdDateTime ge {cutoff}"
        f"&$select=userPrincipalName,clientAppUsed,ipAddress,createdDateTime,"
        f"status,resourceDisplayName"
        f"&$top=500")

    legacy = []
    for s in signins:
        client = (s.get("clientAppUsed") or "").lower()
        if client in LEGACY_CLIENTS or client == "":
            legacy.append({
                "user": s.get("userPrincipalName", "?"),
                "client": s.get("clientAppUsed", "unknown"),
                "ip": s.get("ipAddress", "?"),
                "time": s.get("createdDateTime", ""),
                "resource": s.get("resourceDisplayName", ""),
                "status": "success" if s.get("status", {}).get("errorCode") == 0 else "failed",
            })
    return {"days_checked": days, "count": len(legacy), "signins": legacy}


def audit_risky_signins(token, days=7):
    """Fetch risky sign-in events."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    signins = graph_get(token,
        f"{GRAPH_BASE}/identityProtection/riskyUsers"
        f"?$filter=riskLastUpdatedDateTime ge {cutoff}"
        f"&$select=userPrincipalName,riskLevel,riskState,riskDetail,"
        f"riskLastUpdatedDateTime")

    return {
        "days_checked": days,
        "count": len(signins),
        "risky_users": [{
            "user": s.get("userPrincipalName", "?"),
            "risk_level": s.get("riskLevel", "?"),
            "risk_state": s.get("riskState", "?"),
            "detail": s.get("riskDetail", ""),
            "last_updated": s.get("riskLastUpdatedDateTime", ""),
        } for s in signins]
    }


def audit_break_glass(token, days=30):
    """Check for break-glass account sign-in activity."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    signins = graph_get(token,
        f"{GRAPH_BASE}/auditLogs/signIns"
        f"?$filter=createdDateTime ge {cutoff}"
        f"&$select=userPrincipalName,createdDateTime,ipAddress,status,appDisplayName"
        f"&$top=999")

    bg_signins = []
    for s in signins:
        upn = (s.get("userPrincipalName") or "").lower()
        if any(p in upn for p in BREAK_GLASS_PATTERNS):
            bg_signins.append({
                "user": s.get("userPrincipalName", "?"),
                "time": s.get("createdDateTime", ""),
                "ip": s.get("ipAddress", "?"),
                "app": s.get("appDisplayName", "?"),
                "status": "success" if s.get("status", {}).get("errorCode") == 0 else "failed",
            })
    return {"days_checked": days, "count": len(bg_signins), "signins": bg_signins}


def audit_admin_activity(token, days=7):
    """Show recent sign-in activity for all admin accounts."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    admin_map = get_admin_users_map(token)

    signins = graph_get(token,
        f"{GRAPH_BASE}/auditLogs/signIns"
        f"?$filter=createdDateTime ge {cutoff}"
        f"&$select=userId,userPrincipalName,createdDateTime,ipAddress,appDisplayName,status"
        f"&$top=999")

    admin_signins = {}
    for s in signins:
        uid = s.get("userId", "")
        if uid in admin_map:
            upn = s.get("userPrincipalName", "?")
            admin_signins.setdefault(upn, []).append({
                "time": s.get("createdDateTime", ""),
                "ip": s.get("ipAddress", "?"),
                "app": s.get("appDisplayName", "?"),
                "status": "success" if s.get("status", {}).get("errorCode") == 0 else "failed",
            })

    results = []
    for upn, info in admin_map.items():
        u = info["userPrincipalName"]
        results.append({
            "user": u,
            "displayName": info["displayName"],
            "roles": info["roles"],
            "signins_last_7d": len(admin_signins.get(u, [])),
            "last_signin": admin_signins.get(u, [{}])[0].get("time", "none") if admin_signins.get(u) else "none",
        })
    return {"days_checked": days, "admin_count": len(results), "admins": results}


def audit_inactive_admins(token, days=45):
    """Find privileged accounts that haven't signed in recently."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    admin_map = get_admin_users_map(token)

    # Get last sign-in for each admin
    inactive = []
    for pid, info in admin_map.items():
        try:
            req = Request(
                f"{GRAPH_BETA}/users/{pid}?$select=userPrincipalName,signInActivity",
                method="GET")
            req.add_header("Authorization", f"Bearer {token}")
            with urlopen(req) as resp:
                user = json.loads(resp.read())
                last_signin_str = (user.get("signInActivity") or {}).get("lastSignInDateTime")
                if last_signin_str:
                    last_signin = datetime.fromisoformat(last_signin_str.replace("Z", "+00:00"))
                    if last_signin < cutoff:
                        inactive.append({
                            "user": info["userPrincipalName"],
                            "displayName": info["displayName"],
                            "roles": info["roles"],
                            "last_signin": last_signin_str,
                            "days_inactive": (datetime.now(timezone.utc) - last_signin).days,
                        })
                else:
                    inactive.append({
                        "user": info["userPrincipalName"],
                        "displayName": info["displayName"],
                        "roles": info["roles"],
                        "last_signin": "never",
                        "days_inactive": 999,
                    })
        except HTTPError:
            continue

    inactive.sort(key=lambda x: -x["days_inactive"])
    return {"threshold_days": days, "count": len(inactive), "inactive_admins": inactive}


def format_legacy(result):
    print(f"\n🔓 Legacy Authentication Sign-Ins (last {result['days_checked']} days)")
    print(f"   Total: {result['count']}")
    if result["signins"]:
        print(f"\n   {'User':<35} {'Client':<25} {'IP':<16} {'Status'}")
        print(f"   {'─'*35} {'─'*25} {'─'*16} {'─'*8}")
        for s in result["signins"][:20]:
            print(f"   {s['user']:<35} {s['client']:<25} {s['ip']:<16} {s['status']}")
        if len(result["signins"]) > 20:
            print(f"   ... and {len(result['signins']) - 20} more")
    else:
        print("   ✅ No legacy auth sign-ins detected.")


def format_risky(result):
    print(f"\n⚠️  Risky Users (last {result['days_checked']} days)")
    print(f"   Total: {result['count']}")
    for u in result["risky_users"][:20]:
        print(f"   - {u['user']} | Level: {u['risk_level']} | State: {u['risk_state']}")


def format_break_glass(result):
    print(f"\n🚨 Break-Glass Account Activity (last {result['days_checked']} days)")
    print(f"   Sign-ins: {result['count']}")
    if result["signins"]:
        for s in result["signins"]:
            print(f"   - {s['user']} | {s['time'][:16]} | IP: {s['ip']} | {s['status']}")
    else:
        print("   ✅ No break-glass sign-in activity detected.")


def format_admin_activity(result):
    print(f"\n👑 Admin Account Activity (last {result['days_checked']} days)")
    print(f"   Admins: {result['admin_count']}")
    for a in result["admins"]:
        roles = ", ".join(a["roles"][:3])
        print(f"   - {a['user']} ({roles}) — {a['signins_last_7d']} sign-ins, last: {a['last_signin'][:10] if a['last_signin'] != 'none' else 'none'}")


def format_inactive(result):
    print(f"\n💤 Inactive Privileged Accounts (>{result['threshold_days']} days)")
    print(f"   Count: {result['count']}")
    for a in result["inactive_admins"]:
        roles = ", ".join(a["roles"][:3])
        days = a["days_inactive"] if a["days_inactive"] < 999 else "never"
        print(f"   ⚠️  {a['user']} ({roles}) — {days} days inactive")
    if not result["inactive_admins"]:
        print("   ✅ No inactive privileged accounts.")


def main():
    parser = argparse.ArgumentParser(description="Entra ID sign-in analysis")
    parser.add_argument("--action", required=True,
                        choices=["legacy", "risky", "break-glass",
                                 "admin-activity", "inactive", "export"])
    parser.add_argument("--days", type=int, default=7, help="Lookback period in days")
    parser.add_argument("--output", help="Export output file")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if args.action == "legacy":
        result = audit_legacy_signins(token, args.days)
        format_legacy(result)
    elif args.action == "risky":
        result = audit_risky_signins(token, args.days)
        format_risky(result)
    elif args.action == "break-glass":
        result = audit_break_glass(token, args.days)
        format_break_glass(result)
    elif args.action == "admin-activity":
        result = audit_admin_activity(token, args.days)
        format_admin_activity(result)
    elif args.action == "inactive":
        result = audit_inactive_admins(token, args.days)
        format_inactive(result)
    elif args.action == "export":
        all_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "legacy_auth": audit_legacy_signins(token, args.days),
            "risky_users": audit_risky_signins(token, args.days),
            "break_glass": audit_break_glass(token, args.days),
            "admin_activity": audit_admin_activity(token, args.days),
            "inactive_admins": audit_inactive_admins(token, args.days),
        }
        out = json.dumps(all_data, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(out)
            print(f"Exported to {args.output}")
        else:
            print(out)


if __name__ == "__main__":
    main()
