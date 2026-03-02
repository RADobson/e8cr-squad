#!/usr/bin/env python3
"""Generate realistic synthetic data for E8CR Identity Bot demo.

Uses the same fictional company (Meridian Civil Group) as the VM+PM demo.

Usage:
    python3 demo_generate.py --output /tmp/e8cr-demo/identity/
    python3 demo_generate.py --output /tmp/e8cr-demo/identity/ --full-pipeline

Produces:
    - mfa-audit.json (MFA registration status for all users)
    - role-audit.json (Admin role assignments)
    - ca-audit.json (Conditional Access policy audit)
    - identity-report.html (if --full-pipeline)
"""

import json
import os
import sys
import random
import argparse
import subprocess
from datetime import datetime, timedelta, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COMPANY = "Meridian Civil Group"
DOMAIN = "meridiancivil.com.au"

# User list (matching VM+PM demo)
USERS = [
    # Executives
    ("ceo", "David Morrison", True, True),
    ("cfo", "Sarah Chen", True, True),
    ("coo", "Mark Williams", True, False),
    ("gm.projects", "James Taylor", True, False),
    ("gm.operations", "Lisa Brown", False, False),  # No MFA!
    ("ea.ceo", "Emma Wilson", True, False),
    # IT
    ("it.manager", "Tom Nguyen", True, True),
    ("sysadmin", "Alex Cooper", True, True),
    ("helpdesk.1", "Jake Reed", True, False),
    ("helpdesk.2", "Mia Santos", True, False),
    # Finance
    ("finance.mgr", "Rachel Kim", True, False),
    ("accounts.payable", "Sophie Turner", True, False),
    ("accounts.receivable", "Ben Harris", True, False),
    ("payroll", "Grace Lee", True, False),
    ("bookkeeper.1", "Hannah Moore", False, False),  # No MFA
    ("bookkeeper.2", "Olivia Scott", True, False),
    ("procurement.1", "Daniel White", True, False),
    ("procurement.2", "Amy Clark", False, False),  # No MFA
    # HR
    ("hr.manager", "Karen Davis", True, False),
    ("recruitment", "Nina Patel", True, False),
    ("whs.officer", "Steve Robinson", True, False),
    ("training", "Chloe Martin", False, False),  # No MFA
    # Engineering
    ("chief.engineer", "Robert Zhang", True, False),
    ("structural.1", "Michael Park", True, False),
    ("civil.1", "Jessica Huang", True, False),
    ("civil.2", "Andrew Walsh", True, False),
    ("bim.mgr", "Peter Okafor", True, False),
    # Projects
    *[(f"pm.{n}", f"PM {n.title()}", random.random() > 0.15, False)
      for n in ["smith", "jones", "chen", "williams", "brown", "taylor", "wilson", "anderson"]],
    # Site (many without MFA — field workers with tablets)
    *[(f"supervisor.{i}", f"Supervisor {i}", random.random() > 0.4, False) for i in range(1, 11)],
    *[(f"foreman.{i}", f"Foreman {i}", random.random() > 0.5, False) for i in range(1, 11)],
    *[(f"safety.{i}", f"Safety Officer {i}", random.random() > 0.3, False) for i in range(1, 6)],
    # Fleet & Warehouse
    *[(f"logistics.{i}", f"Logistics {i}", random.random() > 0.5, False) for i in range(1, 4)],
    *[(f"warehouse.{i}", f"Warehouse {i}", random.random() > 0.6, False) for i in range(1, 3)],
    # Shared/service
    ("svc.backup", "Backup Service Account", False, False),
    ("svc.intune", "Intune Service Account", False, False),
    ("breakglass.1", "Break Glass 1", True, True),
    ("breakglass.2", "Break Glass 2", True, True),
]

MFA_METHODS = {
    "strong": ["microsoftAuthenticator", "fido2"],
    "standard": ["microsoftAuthenticator"],
    "weak": ["sms", "voice"],
    "none": [],
}

ADMIN_ROLES = [
    # (user_prefix, role, is_permanent)
    ("ceo", "Global Administrator", True),         # CEO as GA — common bad practice
    ("it.manager", "Global Administrator", True),   # IT manager as GA
    ("sysadmin", "Global Administrator", True),     # Sysadmin as GA
    ("cfo", "Global Administrator", True),          # CFO as GA — unnecessary!
    ("gm.operations", "Global Administrator", True),# GM Ops as GA — 5th GA, too many!
    ("helpdesk.1", "User Administrator", True),
    ("helpdesk.2", "Helpdesk Administrator", True),
    ("it.manager", "Intune Administrator", True),
    ("it.manager", "Security Administrator", True),
    ("sysadmin", "Exchange Administrator", True),
    ("sysadmin", "SharePoint Administrator", True),
    ("svc.intune", "Intune Administrator", True),   # Service account with admin — bad
    ("breakglass.1", "Global Administrator", True),
    ("breakglass.2", "Global Administrator", True),
]

CA_POLICIES = [
    {
        "displayName": "Require MFA for Admins",
        "state": "enabled",
        "conditions": {
            "users": {"includeRoles": ["62e90394-69f5-4237-9190-012177145e10"]},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    },
    {
        "displayName": "Require MFA for All Users",
        "state": "enabledForReportingButNotEnforced",  # Report-only, not enforced!
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    },
    {
        "displayName": "Block Legacy Auth",
        "state": "disabled",  # DISABLED — critical gap!
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["exchangeActiveSync", "other"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["block"]},
    },
    {
        "displayName": "Require Compliant Device",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "clientAppTypes": ["browser", "mobileAppsAndDesktopClients"],
        },
        "grantControls": {"operator": "OR", "builtInControls": ["compliantDevice"]},
    },
]

LEGACY_AUTH_USERS = [
    {"upn": f"payroll@{DOMAIN}", "protocols": ["IMAP4"], "signInCount": 47, "ips": ["203.45.67.89"]},
    {"upn": f"accounts.receivable@{DOMAIN}", "protocols": ["POP3"], "signInCount": 23, "ips": ["203.45.67.90"]},
    {"upn": f"bookkeeper.1@{DOMAIN}", "protocols": ["SMTP", "IMAP4"], "signInCount": 156, "ips": ["203.45.67.91", "10.20.11.3"]},
    {"upn": f"procurement.2@{DOMAIN}", "protocols": ["Exchange ActiveSync"], "signInCount": 12, "ips": ["172.16.5.44"]},
    {"upn": f"svc.backup@{DOMAIN}", "protocols": ["Authenticated SMTP"], "signInCount": 340, "ips": ["10.20.1.7"]},
]


def generate_mfa_data():
    """Generate MFA audit data."""
    now = datetime.now(timezone.utc)
    users_data = []
    mfa_registered = 0
    mfa_not_registered = 0
    pr_count = 0
    methods_breakdown = {}

    for prefix, display, has_mfa, is_admin in USERS:
        upn = f"{prefix}@{DOMAIN}"

        if has_mfa:
            mfa_registered += 1
            if is_admin and random.random() > 0.3:
                methods = MFA_METHODS["strong"]
            elif random.random() > 0.6:
                methods = MFA_METHODS["standard"]
            else:
                methods = MFA_METHODS["weak"]
        else:
            mfa_not_registered += 1
            methods = MFA_METHODS["none"]

        has_pr = any(m in methods for m in ["fido2", "windowsHelloForBusiness"])
        if has_pr:
            pr_count += 1

        for m in methods:
            methods_breakdown[m] = methods_breakdown.get(m, 0) + 1

        users_data.append({
            "upn": upn,
            "displayName": display,
            "mfaRegistered": has_mfa,
            "mfaCapable": has_mfa,
            "methods": methods,
            "phishingResistant": has_pr,
            "isAdmin": is_admin,
        })

    total = len(users_data)
    return {
        "generated_at": now.isoformat(),
        "company": COMPANY,
        "total_users": total,
        "mfa_registered": mfa_registered,
        "mfa_not_registered": mfa_not_registered,
        "mfa_coverage_pct": round((mfa_registered / total) * 100, 1),
        "mfa_capable": mfa_registered,
        "phishing_resistant_count": pr_count,
        "phishing_resistant_pct": round((pr_count / total) * 100, 1),
        "methods_breakdown": methods_breakdown,
        "users": users_data,
        "legacy_auth": LEGACY_AUTH_USERS,
    }


def generate_role_data():
    """Generate admin role audit data."""
    now = datetime.now(timezone.utc)

    assignments = []
    user_lookup = {prefix: (display, is_admin) for prefix, display, _, is_admin in USERS}

    for prefix, role, is_permanent in ADMIN_ROLES:
        display = user_lookup.get(prefix, ("Unknown", False))[0]
        upn = f"{prefix}@{DOMAIN}"

        critical_roles = {"Global Administrator", "Privileged Role Administrator"}
        high_priv_roles = {"Security Administrator", "Exchange Administrator",
                          "SharePoint Administrator", "User Administrator", "Intune Administrator"}

        assignments.append({
            "roleName": role,
            "userId": f"uid-{prefix}",
            "displayName": display,
            "upn": upn,
            "accountEnabled": True,
            "assignmentType": "permanent" if is_permanent else "eligible",
            "isHighPriv": role in high_priv_roles or role in critical_roles,
            "isCritical": role in critical_roles,
        })

    # Build user summary
    user_roles = {}
    for a in assignments:
        uid = a["userId"]
        if uid not in user_roles:
            user_roles[uid] = {
                "userId": uid, "displayName": a["displayName"], "upn": a["upn"],
                "accountEnabled": True, "roles": [], "isHighPriv": False,
                "isCritical": False, "roleCount": 0,
            }
        user_roles[uid]["roles"].append({"roleName": a["roleName"], "isHighPriv": a["isHighPriv"],
                                          "isCritical": a["isCritical"], "assignmentType": a["assignmentType"]})
        if a["isHighPriv"]: user_roles[uid]["isHighPriv"] = True
        if a["isCritical"]: user_roles[uid]["isCritical"] = True
        user_roles[uid]["roleCount"] += 1

    global_admins = [u for u in user_roles.values()
                     if any(r["roleName"] == "Global Administrator" for r in u["roles"])]

    role_counts = {}
    for a in assignments:
        role_counts[a["roleName"]] = role_counts.get(a["roleName"], 0) + 1

    findings = []
    if len(global_admins) > 4:
        findings.append({
            "severity": "HIGH",
            "finding": f"Too many Global Admins: {len(global_admins)} (recommended: 2-4, you have {len(global_admins)} including break-glass)",
            "remediation": "Remove GA from CEO, CFO, and GM Ops. Use least-privilege roles.",
        })

    # Check service accounts
    svc_admins = [a for a in assignments if a["upn"].startswith("svc.") and a["isHighPriv"]]
    if svc_admins:
        findings.append({
            "severity": "MEDIUM",
            "finding": f"{len(svc_admins)} service account(s) with admin roles",
            "remediation": "Service accounts should use minimal permissions. Review necessity.",
        })

    # All permanent
    permanent = [a for a in assignments if a["assignmentType"] == "permanent"]
    if permanent:
        findings.append({
            "severity": "MEDIUM",
            "finding": f"All {len(permanent)} role assignments are permanent (no PIM)",
            "remediation": "Enable PIM for just-in-time admin access. ML2 prefers time-limited privileges.",
        })

    return {
        "generated_at": now.isoformat(),
        "company": COMPANY,
        "total_role_assignments": len(assignments),
        "unique_privileged_users": len(user_roles),
        "global_admin_count": len(global_admins),
        "global_admins": global_admins,
        "role_counts": role_counts,
        "high_priv_users": [u for u in user_roles.values() if u["isHighPriv"]],
        "critical_role_users": [u for u in user_roles.values() if u["isCritical"]],
        "all_assignments": assignments,
        "users": list(user_roles.values()),
        "findings": findings,
    }


def generate_ca_data():
    """Generate Conditional Access audit data."""
    now = datetime.now(timezone.utc)

    for p in CA_POLICIES:
        p["id"] = f"ca-{hash(p['displayName']) % 10000:04d}"
        p["createdDateTime"] = (now - timedelta(days=random.randint(30, 180))).isoformat()
        p["modifiedDateTime"] = (now - timedelta(days=random.randint(1, 30))).isoformat()

    enabled = [p for p in CA_POLICIES if p["state"] == "enabled"]

    baseline_audit = {
        "require_mfa_all_users": {
            "name": "Require MFA for all users",
            "description": "All users must complete MFA for all cloud apps",
            "found": False,  # It's report-only, not enforced!
            "matchingPolicy": None,
            "note": "Policy exists but is in report-only mode — NOT enforcing",
        },
        "block_legacy_auth": {
            "name": "Block legacy authentication",
            "description": "Block sign-ins using legacy auth protocols",
            "found": False,  # DISABLED
            "matchingPolicy": None,
            "note": "Policy exists but is DISABLED",
        },
        "require_mfa_admins": {
            "name": "Require MFA for admin roles",
            "description": "Admin/privileged roles must complete MFA",
            "found": True,
            "matchingPolicy": "Require MFA for Admins",
        },
        "block_high_risk_signin": {
            "name": "Block high-risk sign-ins",
            "description": "Block sign-ins flagged as high risk",
            "found": False,
            "matchingPolicy": None,
            "note": "No policy exists — may need Entra ID P2",
        },
    }

    return {
        "generated_at": now.isoformat(),
        "company": COMPANY,
        "total_policies": len(CA_POLICIES),
        "enabled_policies": len(enabled),
        "baseline_audit": baseline_audit,
        "policies": CA_POLICIES,
    }


def generate_report_html(mfa_data, role_data, ca_data, output):
    """Generate identity readiness report HTML."""
    now = datetime.now(timezone.utc)

    # Calculate overall identity score
    mfa_score = mfa_data["mfa_coverage_pct"]
    ga_ok = 2 <= role_data["global_admin_count"] <= 4
    baseline_found = sum(1 for v in ca_data["baseline_audit"].values() if v["found"])
    baseline_total = len(ca_data["baseline_audit"])

    def color(pct):
        if pct >= 95: return "green"
        if pct >= 80: return "yellow"
        if pct >= 60: return "orange"
        return "red"

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>E8 ML2 Identity Readiness — {now.strftime('%d %b %Y')}</title>
<style>
:root {{ --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
  --green: #22c55e; --yellow: #eab308; --orange: #f97316; --red: #ef4444; --blue: #3b82f6; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }}
.container {{ max-width: 900px; margin: 0 auto; }}
h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
h2 {{ font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
.subtitle {{ color: var(--muted); margin-bottom: 2rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 1rem 0; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; }}
.card .label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }}
.card .value {{ font-size: 2rem; font-weight: 700; margin-top: 0.3rem; }}
.green {{ color: var(--green); }} .yellow {{ color: var(--yellow); }} .orange {{ color: var(--orange); }} .red {{ color: var(--red); }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
th, td {{ text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); }}
th {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
.badge.critical {{ background: var(--red); color: white; }}
.badge.high {{ background: var(--orange); color: white; }}
.badge.medium {{ background: var(--yellow); color: #1e293b; }}
.badge.ok {{ background: var(--green); color: white; }}
.footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.85rem; }}
</style></head><body><div class="container">
<h1>🔑 Essential Eight — Identity Readiness Report</h1>
<p class="subtitle">{COMPANY} — {now.strftime('%d %B %Y')}</p>

<div class="grid">
<div class="card"><div class="label">MFA Coverage</div><div class="value {color(mfa_score)}">{mfa_score}%</div></div>
<div class="card"><div class="label">Users Without MFA</div><div class="value {"red" if mfa_data["mfa_not_registered"] > 0 else "green"}">{mfa_data["mfa_not_registered"]}</div></div>
<div class="card"><div class="label">Phishing-Resistant</div><div class="value {"green" if mfa_data["phishing_resistant_pct"] > 50 else "orange"}">{mfa_data["phishing_resistant_pct"]}%</div></div>
<div class="card"><div class="label">Global Admins</div><div class="value {"red" if role_data["global_admin_count"] > 4 else "green"}">{role_data["global_admin_count"]}</div></div>
<div class="card"><div class="label">CA Baseline</div><div class="value {"green" if baseline_found == baseline_total else "red"}">{baseline_found}/{baseline_total}</div></div>
<div class="card"><div class="label">Legacy Auth Users</div><div class="value {"red" if len(mfa_data.get("legacy_auth", [])) > 0 else "green"}">{len(mfa_data.get("legacy_auth", []))}</div></div>
</div>

<h2>🚨 Critical Findings</h2>"""

    # Admin MFA gaps
    admin_no_mfa = [u for u in mfa_data["users"] if u["isAdmin"] and not u["mfaRegistered"]]
    if admin_no_mfa:
        html += f'<p class="red">⚠️ {len(admin_no_mfa)} admin account(s) have NO MFA registered:</p><table><tr><th>Account</th><th>Name</th></tr>'
        for u in admin_no_mfa:
            html += f'<tr><td>{u["upn"]}</td><td>{u["displayName"]}</td></tr>'
        html += '</table>'

    # Too many GAs
    if role_data["global_admin_count"] > 4:
        html += f'<p class="orange">⚠️ {role_data["global_admin_count"]} Global Admins (recommended: 2-4)</p>'
        html += '<table><tr><th>Account</th><th>Name</th><th>Roles</th></tr>'
        for ga in role_data["global_admins"]:
            roles = ", ".join(r["roleName"] for r in ga["roles"])
            html += f'<tr><td>{ga["upn"]}</td><td>{ga["displayName"]}</td><td>{roles}</td></tr>'
        html += '</table>'

    # CA policy gaps
    html += '<h2>Conditional Access Baseline</h2><table><tr><th>Policy</th><th>Status</th><th>Notes</th></tr>'
    for key, audit in ca_data["baseline_audit"].items():
        status = '<span class="badge ok">✅ Found</span>' if audit["found"] else '<span class="badge critical">❌ Gap</span>'
        note = audit.get("note", audit.get("matchingPolicy", ""))
        html += f'<tr><td>{audit["name"]}</td><td>{status}</td><td>{note}</td></tr>'
    html += '</table>'

    # Legacy auth
    legacy = mfa_data.get("legacy_auth", [])
    if legacy:
        html += f'<h2>⚠️ Legacy Authentication ({len(legacy)} users)</h2>'
        html += '<p>These users are signing in via protocols that bypass MFA entirely.</p>'
        html += '<table><tr><th>User</th><th>Protocols</th><th>Sign-ins</th></tr>'
        for l in legacy:
            protos = ", ".join(l["protocols"])
            html += f'<tr><td>{l["upn"]}</td><td>{protos}</td><td>{l["signInCount"]}</td></tr>'
        html += '</table>'

    # MFA gaps
    mfa_gaps = [u for u in mfa_data["users"] if not u["mfaRegistered"]]
    if mfa_gaps:
        html += f'<h2>Users Without MFA ({len(mfa_gaps)})</h2><table><tr><th>User</th><th>Name</th><th>Admin</th></tr>'
        for u in mfa_gaps[:20]:
            admin_flag = '<span class="badge critical">ADMIN</span>' if u["isAdmin"] else ""
            html += f'<tr><td>{u["upn"]}</td><td>{u["displayName"]}</td><td>{admin_flag}</td></tr>'
        if len(mfa_gaps) > 20:
            html += f'<tr><td colspan="3">... and {len(mfa_gaps) - 20} more</td></tr>'
        html += '</table>'

    # Role findings
    if role_data["findings"]:
        html += '<h2>Admin Privilege Findings</h2>'
        for f in role_data["findings"]:
            sev_class = "critical" if f["severity"] == "HIGH" else "medium"
            html += f'<p><span class="badge {sev_class}">{f["severity"]}</span> {f["finding"]}</p>'
            html += f'<p style="color:var(--muted);margin-bottom:1rem">→ {f["remediation"]}</p>'

    # ML2 readiness
    html += '<h2>ML2 Readiness — Identity Controls</h2><table><tr><th>Control</th><th>Status</th><th>Notes</th></tr>'

    mfa_status = "ok" if mfa_score >= 95 and not admin_no_mfa else ("medium" if mfa_score >= 80 else "critical")
    mfa_label = "✅ On Track" if mfa_status == "ok" else ("⚠️ Gaps" if mfa_status == "medium" else "❌ Non-Compliant")
    html += f'<tr><td>Multi-factor Authentication</td><td><span class="badge {mfa_status}">{mfa_label}</span></td><td>{mfa_score}% coverage, {len(admin_no_mfa)} admin gaps</td></tr>'

    admin_status = "ok" if ga_ok and not role_data["findings"] else "critical"
    admin_label = "✅ On Track" if admin_status == "ok" else "❌ Non-Compliant"
    html += f'<tr><td>Restrict Admin Privileges</td><td><span class="badge {admin_status}">{admin_label}</span></td><td>{role_data["global_admin_count"]} GAs, all permanent (no PIM)</td></tr>'

    html += '</table>'

    html += f'<div class="footer"><p>Generated by E8CR Identity Bot — {now.strftime("%Y-%m-%d %H:%M UTC")}</p>'
    html += '<p>Essential Eight Control Room — Dobson Development</p></div></div></body></html>'

    with open(output, "w") as f:
        f.write(html)
    print(f"Report written to {output}")


def main():
    parser = argparse.ArgumentParser(description="Generate Identity Bot demo data")
    parser.add_argument("--output", default="/tmp/e8cr-demo/identity", help="Output directory")
    parser.add_argument("--full-pipeline", action="store_true", help="Generate report too")
    args = parser.parse_args()

    out = args.output
    os.makedirs(out, exist_ok=True)

    print(f"Generating Identity Bot demo data for {COMPANY}...")

    mfa_data = generate_mfa_data()
    with open(os.path.join(out, "mfa-audit.json"), "w") as f:
        json.dump(mfa_data, f, indent=2)
    print(f"  MFA: {mfa_data['mfa_coverage_pct']}% coverage, "
          f"{mfa_data['mfa_not_registered']} without MFA, "
          f"{mfa_data['phishing_resistant_pct']}% phishing-resistant")

    role_data = generate_role_data()
    with open(os.path.join(out, "role-audit.json"), "w") as f:
        json.dump(role_data, f, indent=2)
    print(f"  Roles: {role_data['global_admin_count']} Global Admins, "
          f"{role_data['unique_privileged_users']} privileged users, "
          f"{len(role_data['findings'])} findings")

    ca_data = generate_ca_data()
    with open(os.path.join(out, "ca-audit.json"), "w") as f:
        json.dump(ca_data, f, indent=2)
    baseline_ok = sum(1 for v in ca_data["baseline_audit"].values() if v["found"])
    print(f"  CA: {ca_data['enabled_policies']}/{ca_data['total_policies']} policies enabled, "
          f"{baseline_ok}/{len(ca_data['baseline_audit'])} baseline checks pass")

    if args.full_pipeline:
        print("\nGenerating identity readiness report...")
        report_file = os.path.join(out, "identity-report.html")
        generate_report_html(mfa_data, role_data, ca_data, report_file)
        print(f"\n✅ Identity Bot demo complete!")
        print(f"   Output: {out}/")
        print(f"   Open: {report_file}")
    else:
        print(f"\nData written to {out}/")
        print("Run with --full-pipeline to generate the report.")


if __name__ == "__main__":
    main()
