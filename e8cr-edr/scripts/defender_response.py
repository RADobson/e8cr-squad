#!/usr/bin/env python3
"""Defender for Endpoint automated response actions.

Actions: isolate device, unisolate, block IOC, restrict app execution.
All actions are logged with full justification for audit trail.

Required Graph permissions (Application):
  - Machine.Isolate
  - Machine.RestrictExecution
  - Ti.ReadWrite (for IOC submission)
"""

import argparse
import json
import os
import sys
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../shared"))
from graph_auth import get_env, get_token

MDE_BASE = "https://api.securitycenter.microsoft.com/api"


def _changes_enabled() -> bool:
    """SAFE MODE guardrail.

    By default, this repo is intended to run in audit-only mode.
    To enable response actions (writes), set:
      E8CR_ENABLE_CHANGES=true
    """
    return os.getenv("E8CR_ENABLE_CHANGES", "").lower() in {"1", "true", "yes", "y"}


def _require_changes_enabled(action: str):
    if not _changes_enabled():
        raise SystemExit(
            f"SAFE MODE: Refusing to perform '{action}'. Set E8CR_ENABLE_CHANGES=true to allow write actions."
        )


def _mde_post(token: str, endpoint: str, body: dict) -> dict:
    """POST to MDE API."""
    url = f"{MDE_BASE}/{endpoint}"
    data = json.dumps(body).encode()
    req = Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode()
        return {"error": True, "code": e.code, "message": err}


def isolate_device(token: str, machine_id: str, comment: str, isolation_type: str = "Full"):
    """Isolate a machine from the network. Types: Full, Selective."""
    _require_changes_enabled("isolate_device")
    return _mde_post(token, f"machines/{machine_id}/isolate", {
        "Comment": comment,
        "IsolationType": isolation_type,
    })


def unisolate_device(token: str, machine_id: str, comment: str):
    """Release device from isolation."""
    _require_changes_enabled("unisolate_device")
    return _mde_post(token, f"machines/{machine_id}/unisolate", {
        "Comment": comment,
    })


def restrict_app_execution(token: str, machine_id: str, comment: str):
    """Restrict app execution to Microsoft-signed binaries only."""
    _require_changes_enabled("restrict_app_execution")
    return _mde_post(token, f"machines/{machine_id}/restrictCodeExecution", {
        "Comment": comment,
    })


def remove_app_restriction(token: str, machine_id: str, comment: str):
    """Remove app execution restriction."""
    _require_changes_enabled("remove_app_restriction")
    return _mde_post(token, f"machines/{machine_id}/unrestrictCodeExecution", {
        "Comment": comment,
    })


def submit_indicator(token: str, indicator_value: str, indicator_type: str,
                     action: str = "AlertAndBlock", title: str = "", description: str = ""):
    """Submit IOC (IP, URL, domain, file hash) as indicator.

    indicator_type: FileSha1, FileSha256, IpAddress, DomainName, Url
    action: Allowed, Audit, AlertAndBlock, Alert, Block
    """
    _require_changes_enabled("submit_indicator")
    return _mde_post(token, "indicators", {
        "indicatorValue": indicator_value,
        "indicatorType": indicator_type,
        "action": action,
        "title": title or f"E8CR EDR Bot - {indicator_type}",
        "description": description or f"Auto-blocked by E8CR EDR Bot at {datetime.now().isoformat()}",
        "severity": "High",
        "generateAlert": True,
    })


# ─── Action log ──────────────────────────────────────────────────────────────

def log_action(action_type: str, target: str, reason: str, result: dict, log_file: str = None):
    """Log every automated action with full audit trail."""
    entry = {
        "timestamp": datetime.now().isoformat() + "Z",
        "action": action_type,
        "target": target,
        "reason": reason,
        "result": "success" if not result.get("error") else "failed",
        "details": result,
    }

    if log_file:
        existing = []
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                existing = json.load(f)
        existing.append(entry)
        with open(log_file, "w") as f:
            json.dump(existing, f, indent=2)

    return entry


# ─── Demo mode ───────────────────────────────────────────────────────────────

def demo_response_actions():
    """Generate sample response action log for demo mode."""
    now = datetime.now()
    return [
        {
            "timestamp": now.isoformat() + "Z",
            "action": "isolate_device",
            "target": "SQL-PROD-01",
            "reason": "Ransomware-related behavior detected (T1486). Critical asset auto-isolated.",
            "result": "success",
            "details": {"machineId": "demo-001", "status": "Succeeded", "type": "Full"},
            "requiresApproval": False,
        },
        {
            "timestamp": now.isoformat() + "Z",
            "action": "restrict_app_execution",
            "target": "WKS-FINANCE-01",
            "reason": "Suspicious PowerShell + lateral movement detected. App execution restricted pending investigation.",
            "result": "success",
            "details": {"machineId": "demo-002", "status": "Succeeded"},
            "requiresApproval": False,
        },
        {
            "timestamp": now.isoformat() + "Z",
            "action": "submit_indicator",
            "target": "185.220.101.42",
            "reason": "C2 IP identified from alert da-alert-003. Blocked tenant-wide.",
            "result": "success",
            "details": {"indicatorType": "IpAddress", "action": "AlertAndBlock"},
            "requiresApproval": False,
        },
        {
            "timestamp": now.isoformat() + "Z",
            "action": "escalate",
            "target": "da-alert-002",
            "reason": "Credential dumping on DC01 by admin-svc account. Requires human review — potential compromise of domain controller.",
            "result": "pending",
            "details": {"severity": "critical", "escalatedTo": "security-team"},
            "requiresApproval": True,
        },
    ]


def main():
    p = argparse.ArgumentParser(description="EDR automated response actions")
    p.add_argument("--demo", action="store_true", help="Generate demo response log")
    p.add_argument("--action", choices=["isolate", "unisolate", "restrict", "unrestrict", "block-ioc"])
    p.add_argument("--target", help="Machine ID or IOC value")
    p.add_argument("--comment", default="E8CR EDR Bot automated action")
    p.add_argument("--ioc-type", choices=["FileSha1", "FileSha256", "IpAddress", "DomainName", "Url"])
    p.add_argument("--output", help="Output file")
    args = p.parse_args()

    if args.demo:
        result = {
            "generatedAt": datetime.now().isoformat() + "Z",
            "actions": demo_response_actions(),
        }
        out = json.dumps(result, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(out)
        else:
            print(out)
        return

    tenant, client_id, client_secret = get_env()
    token = get_token(tenant, client_id, client_secret)

    if not args.action or not args.target:
        print("ERROR: --action and --target required in live mode", file=sys.stderr)
        sys.exit(1)

    action_map = {
        "isolate": lambda: isolate_device(token, args.target, args.comment),
        "unisolate": lambda: unisolate_device(token, args.target, args.comment),
        "restrict": lambda: restrict_app_execution(token, args.target, args.comment),
        "unrestrict": lambda: remove_app_restriction(token, args.target, args.comment),
        "block-ioc": lambda: submit_indicator(token, args.target, args.ioc_type or "IpAddress"),
    }

    result = action_map[args.action]()
    entry = log_action(args.action, args.target, args.comment, result, args.output)
    print(json.dumps(entry, indent=2))


if __name__ == "__main__":
    main()
