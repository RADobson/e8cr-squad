#!/usr/bin/env python3
"""Fetch and triage Defender for Endpoint alerts via Microsoft Graph Security API.

Real mode: Uses Graph API with AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET.
Demo mode: Generates realistic synthetic alerts when --demo flag is passed.

Required Graph permissions (Application):
  - SecurityAlert.Read.All
  - SecurityAlert.ReadWrite.All (for status updates)
  - Device.Read.All (for device context)
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# Reuse graph_auth from vmpm bot
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../shared"))
from graph_auth import get_env, get_token

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SECURITY_BASE = "https://graph.microsoft.com/v1.0/security"


def fetch_alerts_real(token: str, days: int = 7, top: int = 100):
    """Fetch recent security alerts from Microsoft Graph Security API."""
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (
        f"{SECURITY_BASE}/alerts_v2"
        f"?$filter=createdDateTime ge {since}"
        f"&$top={top}"
        f"&$orderby=createdDateTime desc"
    )
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")

    try:
        with urlopen(req) as resp:
            body = json.loads(resp.read())
            return body.get("value", [])
    except HTTPError as e:
        err = e.read().decode()
        print(f"ERROR: Failed to fetch alerts ({e.code}): {err}", file=sys.stderr)
        return []


def fetch_device_context(token: str, device_id: str):
    """Get device details for enrichment."""
    url = f"{GRAPH_BASE}/deviceManagement/managedDevices/{device_id}"
    req = Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(req) as resp:
            return json.loads(resp.read())
    except HTTPError:
        return None


def _changes_enabled() -> bool:
    return os.getenv("E8CR_ENABLE_CHANGES", "").lower() in {"1", "true", "yes", "y"}


def update_alert_status(token: str, alert_id: str, status: str, comment: str = ""):
    """Update alert status (new, inProgress, resolved) and add comment.

    Guardrail: This is a write action to Microsoft Graph. Disabled by default.
    """
    if not _changes_enabled():
        # Don't fail the run; just skip writes.
        return False

    url = f"{SECURITY_BASE}/alerts_v2/{alert_id}"
    body = {"status": status}
    if comment:
        body["comments"] = [{"comment": comment, "createdByDisplayName": "E8CR EDR Bot"}]
    data = json.dumps(body).encode()
    req = Request(url, data=data, method="PATCH")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req) as resp:
            return True
    except HTTPError as e:
        print(f"ERROR: Failed to update alert {alert_id} ({e.code})", file=sys.stderr)
        return False


# ─── Known false positive patterns ───────────────────────────────────────────

KNOWN_FP_PATTERNS = [
    {"title_contains": "test alert", "reason": "Known test alert pattern"},
    {"title_contains": "microsoft defender atp test", "reason": "Defender ATP test alert"},
    {"category": "SuspiciousActivity", "severity": "informational", "reason": "Low-severity suspicious activity — typically benign"},
]


def is_known_fp(alert: dict) -> tuple[bool, str]:
    """Check if an alert matches a known false positive pattern."""
    title = (alert.get("title") or "").lower()
    category = alert.get("category", "")
    severity = alert.get("severity", "").lower()

    for pattern in KNOWN_FP_PATTERNS:
        if "title_contains" in pattern and pattern["title_contains"] in title:
            return True, pattern["reason"]
        if pattern.get("category") == category and pattern.get("severity") == severity:
            return True, pattern["reason"]
    return False, ""


# ─── Triage logic ────────────────────────────────────────────────────────────

SEVERITY_WEIGHT = {"high": 4, "medium": 3, "low": 2, "informational": 1}

# Critical asset keywords — alerts on these get severity boost
CRITICAL_ASSET_KEYWORDS = ["dc", "domain controller", "exchange", "sql", "backup", "admin", "server"]


def triage_alert(alert: dict) -> dict:
    """Enrich and classify a single alert. Returns triage result."""
    title = alert.get("title", "Unknown")
    severity = alert.get("severity", "informational").lower()
    category = alert.get("category", "Unknown")
    status = alert.get("status", "new")
    created = alert.get("createdDateTime", "")
    alert_id = alert.get("id", "")

    # Check false positive
    is_fp, fp_reason = is_known_fp(alert)
    if is_fp:
        return {
            "id": alert_id,
            "title": title,
            "severity": severity,
            "category": category,
            "action": "auto_resolve",
            "reason": f"Known FP: {fp_reason}",
            "priority": 0,
            "created": created,
        }

    # Extract device info
    evidence = alert.get("evidence", [])
    devices = [e for e in evidence if e.get("@odata.type", "").endswith("deviceEvidence")]
    device_names = [d.get("deviceDnsName", d.get("mdeDeviceId", "unknown")) for d in devices]

    # Check if critical asset
    is_critical = any(
        kw in name.lower()
        for name in device_names
        for kw in CRITICAL_ASSET_KEYWORDS
    )

    # Calculate priority score
    base_score = SEVERITY_WEIGHT.get(severity, 1)
    priority = base_score * 10
    if is_critical:
        priority += 20  # Boost for critical assets

    # Determine action
    if severity == "high" and is_critical:
        action = "escalate_immediate"
    elif severity == "high":
        action = "escalate"
    elif severity == "medium":
        action = "investigate"
    else:
        action = "monitor"

    # Extract user context
    users = [e for e in evidence if e.get("@odata.type", "").endswith("userEvidence")]
    user_names = [u.get("userAccount", {}).get("accountName", "unknown") for u in users]
    is_admin = any("admin" in u.lower() for u in user_names)
    if is_admin:
        priority += 15

    return {
        "id": alert_id,
        "title": title,
        "severity": severity,
        "category": category,
        "action": action,
        "priority": priority,
        "devices": device_names,
        "users": user_names,
        "is_critical_asset": is_critical,
        "is_admin_account": is_admin,
        "created": created,
        "mitre_techniques": [t.get("techniqueId", "") for t in alert.get("mitreTechniques", [])],
    }


# ─── Demo data ───────────────────────────────────────────────────────────────

def generate_demo_alerts():
    """Generate realistic synthetic Defender alerts for demo mode."""
    now = datetime.now()
    return [
        {
            "id": "da-alert-001",
            "title": "Suspicious PowerShell command line",
            "severity": "high",
            "category": "Execution",
            "status": "new",
            "createdDateTime": (now - timedelta(hours=2)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-FINANCE-01"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1059.001"}],
        },
        {
            "id": "da-alert-002",
            "title": "Credential dumping activity detected",
            "severity": "high",
            "category": "CredentialAccess",
            "status": "new",
            "createdDateTime": (now - timedelta(hours=1)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "DC01.contoso.local"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "admin-svc"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1003.001"}],
        },
        {
            "id": "da-alert-003",
            "title": "Suspicious network connection",
            "severity": "medium",
            "category": "CommandAndControl",
            "status": "new",
            "createdDateTime": (now - timedelta(hours=5)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-SALES-03"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "m.jones"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1071.001"}],
        },
        {
            "id": "da-alert-004",
            "title": "Microsoft Defender ATP test alert",
            "severity": "informational",
            "category": "SuspiciousActivity",
            "status": "new",
            "createdDateTime": (now - timedelta(hours=8)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-IT-TEST"},
            ],
            "mitreTechniques": [],
        },
        {
            "id": "da-alert-005",
            "title": "Ransomware-related behavior detected",
            "severity": "high",
            "category": "Impact",
            "status": "new",
            "createdDateTime": (now - timedelta(minutes=30)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "SQL-PROD-01"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "backup-admin"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1486"}],
        },
        {
            "id": "da-alert-006",
            "title": "Unusual login from unfamiliar location",
            "severity": "medium",
            "category": "InitialAccess",
            "status": "new",
            "createdDateTime": (now - timedelta(hours=3)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "ceo@contoso.com"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1078"}],
        },
        {
            "id": "da-alert-007",
            "title": "Lateral movement using WMI",
            "severity": "medium",
            "category": "LateralMovement",
            "status": "new",
            "createdDateTime": (now - timedelta(hours=1, minutes=15)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-FINANCE-01"},
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-HR-02"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "j.smith"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1047"}],
        },
        {
            "id": "da-alert-008",
            "title": "Persistence via scheduled task creation",
            "severity": "low",
            "category": "Persistence",
            "status": "new",
            "createdDateTime": (now - timedelta(hours=6)).isoformat() + "Z",
            "evidence": [
                {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "WKS-DEV-04"},
                {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "d.developer"}},
            ],
            "mitreTechniques": [{"techniqueId": "T1053.005"}],
        },
    ]


def main():
    p = argparse.ArgumentParser(description="Defender for Endpoint alert ingestion and triage")
    p.add_argument("--demo", action="store_true", help="Use synthetic demo data")
    p.add_argument("--days", type=int, default=7, help="Look back N days for alerts")
    p.add_argument("--top", type=int, default=100, help="Max alerts to fetch")
    p.add_argument("--output", help="Output file (default: stdout)")
    args = p.parse_args()

    if args.demo:
        alerts = generate_demo_alerts()
    else:
        tenant, client_id, client_secret = get_env()
        token = get_token(tenant, client_id, client_secret)
        alerts = fetch_alerts_real(token, days=args.days, top=args.top)

    # Triage all alerts
    triaged = [triage_alert(a) for a in alerts]
    triaged.sort(key=lambda x: x["priority"], reverse=True)

    # Summary stats
    actions = {}
    for t in triaged:
        actions[t["action"]] = actions.get(t["action"], 0) + 1

    result = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "alertCount": len(alerts),
        "summary": actions,
        "triaged": triaged,
    }

    out = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        print(f"Written to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
