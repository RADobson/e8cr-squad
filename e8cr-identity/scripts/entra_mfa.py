#!/usr/bin/env python3
"""Audit MFA registration, methods, and enforcement via Microsoft Graph.

Usage:
    python3 entra_mfa.py --action coverage                # MFA status for all users
    python3 entra_mfa.py --action gaps                    # Users without MFA
    python3 entra_mfa.py --action methods                 # MFA method breakdown
    python3 entra_mfa.py --action phishing-resistant      # Phishing-resistant adoption
    python3 entra_mfa.py --action legacy-auth             # Legacy auth sign-ins
    python3 entra_mfa.py --action export --output mfa.json

Requires AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars.
Permissions: User.Read.All, UserAuthenticationMethod.Read.All, AuditLog.Read.All
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


def get_users(token):
    """Get all users with basic profile info."""
    url = (f"{GRAPH_BASE}/users?"
           f"$select=id,displayName,userPrincipalName,accountEnabled,userType,"
           f"createdDateTime,lastSignInDateTime&$top=999")
    return graph_get(token, url)


def get_auth_methods(token, user_id):
    """Get authentication methods for a user."""
    url = f"{GRAPH_BASE}/users/{user_id}/authentication/methods"
    try:
        return graph_get(token, url)
    except SystemExit:
        return []  # Permission error for some users, skip


def get_registration_details(token):
    """Get MFA registration details for all users (beta endpoint)."""
    url = (f"{GRAPH_BETA}/reports/authenticationMethods/userRegistrationDetails"
           f"?$top=999")
    return graph_get(token, url)


def classify_method(method_type):
    """Classify auth method as phishing-resistant, standard, or weak."""
    phishing_resistant = {
        "#microsoft.graph.fido2AuthenticationMethod",
        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",  # passkey mode
    }
    standard = {
        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
        "#microsoft.graph.softwareOathAuthenticationMethod",
    }
    weak = {
        "#microsoft.graph.phoneAuthenticationMethod",
        "#microsoft.graph.smsAuthenticationMethod",
    }

    if method_type in phishing_resistant:
        return "phishing-resistant"
    elif method_type in standard:
        return "standard"
    elif method_type in weak:
        return "weak"
    return "other"


def mfa_coverage(token):
    """Generate MFA coverage report."""
    print("Fetching user registration details...", file=sys.stderr)
    registrations = get_registration_details(token)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_users": len(registrations),
        "mfa_registered": 0,
        "mfa_not_registered": 0,
        "mfa_capable": 0,
        "methods_breakdown": {},
        "phishing_resistant_count": 0,
        "users": [],
    }

    for reg in registrations:
        upn = reg.get("userPrincipalName", "")
        display = reg.get("userDisplayName", "")
        is_mfa = reg.get("isMfaRegistered", False)
        is_capable = reg.get("isMfaCapable", False)
        methods = reg.get("methodsRegistered", [])
        is_admin = reg.get("isAdmin", False)

        if is_mfa:
            report["mfa_registered"] += 1
        else:
            report["mfa_not_registered"] += 1

        if is_capable:
            report["mfa_capable"] += 1

        # Track methods
        for method in methods:
            report["methods_breakdown"][method] = report["methods_breakdown"].get(method, 0) + 1

        # Check phishing-resistant
        pr_methods = {"fido2", "windowsHelloForBusiness", "passKeyDeviceBound"}
        has_pr = bool(set(methods) & pr_methods)
        if has_pr:
            report["phishing_resistant_count"] += 1

        report["users"].append({
            "upn": upn,
            "displayName": display,
            "mfaRegistered": is_mfa,
            "mfaCapable": is_capable,
            "methods": methods,
            "phishingResistant": has_pr,
            "isAdmin": is_admin,
        })

    total = report["total_users"]
    if total > 0:
        report["mfa_coverage_pct"] = round((report["mfa_registered"] / total) * 100, 1)
        report["phishing_resistant_pct"] = round((report["phishing_resistant_count"] / total) * 100, 1)
    else:
        report["mfa_coverage_pct"] = 0
        report["phishing_resistant_pct"] = 0

    return report


def mfa_gaps(report):
    """Extract users without MFA from coverage report."""
    gaps = [u for u in report["users"] if not u["mfaRegistered"]]
    # Prioritise: admins without MFA first
    gaps.sort(key=lambda u: (not u.get("isAdmin", False), u["upn"]))
    return gaps


def legacy_auth_signins(token, days=7):
    """Find sign-ins using legacy authentication protocols."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (f"{GRAPH_BASE}/auditLogs/signIns?"
           f"$filter=createdDateTime ge {cutoff} and "
           f"clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'"
           f"&$select=userPrincipalName,clientAppUsed,ipAddress,createdDateTime,"
           f"status,appDisplayName&$top=500")

    try:
        signins = graph_get(token, url)
    except SystemExit:
        print("WARNING: Could not access sign-in logs. Need AuditLog.Read.All permission.", file=sys.stderr)
        return []

    # Group by user
    legacy_users = {}
    legacy_protocols = {"IMAP4", "POP3", "SMTP", "MAPI", "Exchange ActiveSync",
                        "Exchange Online PowerShell", "Exchange Web Services",
                        "Authenticated SMTP", "AutoDiscover", "Other clients"}

    for s in signins:
        client = s.get("clientAppUsed", "")
        if client in legacy_protocols or "legacy" in client.lower():
            upn = s.get("userPrincipalName", "Unknown")
            if upn not in legacy_users:
                legacy_users[upn] = {
                    "upn": upn,
                    "protocols": set(),
                    "count": 0,
                    "last_seen": s.get("createdDateTime"),
                    "ips": set(),
                }
            legacy_users[upn]["protocols"].add(client)
            legacy_users[upn]["count"] += 1
            if s.get("ipAddress"):
                legacy_users[upn]["ips"].add(s["ipAddress"])

    # Convert sets to lists for JSON
    results = []
    for upn, data in legacy_users.items():
        results.append({
            "upn": data["upn"],
            "protocols": list(data["protocols"]),
            "signInCount": data["count"],
            "lastSeen": data["last_seen"],
            "ips": list(data["ips"]),
        })

    results.sort(key=lambda x: -x["signInCount"])
    return results


def format_coverage(report):
    """Pretty-print MFA coverage."""
    print("=" * 60)
    print("  MFA COVERAGE REPORT")
    print(f"  Generated: {report['generated_at'][:19]}")
    print("=" * 60)
    print(f"\n  Total Users: {report['total_users']}")
    print(f"  MFA Registered: {report['mfa_registered']} ({report['mfa_coverage_pct']}%)")
    print(f"  MFA Not Registered: {report['mfa_not_registered']}")
    print(f"  Phishing-Resistant: {report['phishing_resistant_count']} ({report['phishing_resistant_pct']}%)")

    if report["methods_breakdown"]:
        print("\n  Method Breakdown:")
        for method, count in sorted(report["methods_breakdown"].items(), key=lambda x: -x[1]):
            print(f"    {method}: {count}")

    # Highlight admins without MFA
    admin_gaps = [u for u in report["users"] if u.get("isAdmin") and not u["mfaRegistered"]]
    if admin_gaps:
        print(f"\n  🚨 CRITICAL: {len(admin_gaps)} ADMIN(S) WITHOUT MFA:")
        for u in admin_gaps:
            print(f"    - {u['upn']} ({u['displayName']})")

    print()


def format_gaps(gaps):
    """Pretty-print MFA gaps."""
    if not gaps:
        print("✅ All users have MFA registered.")
        return

    admins = [u for u in gaps if u.get("isAdmin")]
    regular = [u for u in gaps if not u.get("isAdmin")]

    if admins:
        print(f"🚨 ADMIN ACCOUNTS WITHOUT MFA ({len(admins)}):")
        for u in admins:
            print(f"  ⚠️  {u['upn']} ({u['displayName']})")
        print()

    print(f"Users without MFA ({len(gaps)} total):")
    print(f"{'User':<45} {'Display Name':<25} {'Admin':<8}")
    print("-" * 78)
    for u in gaps[:50]:
        admin = "⚠️ YES" if u.get("isAdmin") else ""
        print(f"{u['upn']:<45} {u['displayName']:<25} {admin:<8}")
    if len(gaps) > 50:
        print(f"\n... and {len(gaps) - 50} more")


def main():
    parser = argparse.ArgumentParser(description="Entra ID MFA auditing")
    parser.add_argument("--action", required=True,
                        choices=["coverage", "gaps", "methods", "phishing-resistant",
                                 "legacy-auth", "export"])
    parser.add_argument("--days", type=int, default=7, help="Days for legacy auth lookback")
    parser.add_argument("--output", help="Output file")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if args.action in ("coverage", "gaps", "methods", "phishing-resistant", "export"):
        report = mfa_coverage(token)

        if args.action == "coverage":
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                format_coverage(report)

        elif args.action == "gaps":
            gaps = mfa_gaps(report)
            if args.json:
                print(json.dumps(gaps, indent=2))
            else:
                format_gaps(gaps)

        elif args.action == "methods":
            print(json.dumps(report["methods_breakdown"], indent=2))

        elif args.action == "phishing-resistant":
            pr_users = [u for u in report["users"] if u["phishingResistant"]]
            non_pr = [u for u in report["users"] if u["mfaRegistered"] and not u["phishingResistant"]]
            print(f"Phishing-resistant MFA: {len(pr_users)}/{report['total_users']} users ({report['phishing_resistant_pct']}%)")
            if non_pr:
                print(f"\nUsers with MFA but NOT phishing-resistant ({len(non_pr)}):")
                for u in non_pr[:20]:
                    print(f"  {u['upn']} — methods: {', '.join(u['methods'])}")

        elif args.action == "export":
            output = args.output or "mfa-audit.json"
            # Add legacy auth data
            report["legacy_auth"] = legacy_auth_signins(token, args.days)
            with open(output, "w") as f:
                json.dump(report, f, indent=2)
            print(f"Exported MFA audit to {output}")

    elif args.action == "legacy-auth":
        legacy = legacy_auth_signins(token, args.days)
        if args.json:
            print(json.dumps(legacy, indent=2))
        elif not legacy:
            print("✅ No legacy authentication sign-ins detected.")
        else:
            print(f"⚠️  Legacy auth sign-ins in last {args.days} days: {len(legacy)} users")
            print(f"\n{'User':<40} {'Protocols':<30} {'Count':<8} {'IPs':<20}")
            print("-" * 98)
            for l in legacy:
                protos = ", ".join(l["protocols"])
                ips = ", ".join(list(l["ips"])[:3])
                print(f"{l['upn']:<40} {protos:<30} {l['signInCount']:<8} {ips:<20}")


if __name__ == "__main__":
    main()
