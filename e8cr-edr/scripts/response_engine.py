#!/usr/bin/env python3
"""Autonomous response engine with bounded containment decisions."""

import argparse
import json
from datetime import datetime


def can_auto_contain(alert, policy):
    """Determine if alert meets auto-containment policy criteria."""
    risk_score = alert.get("risk_score", 0)
    severity = alert.get("severity", "low")
    
    # Autonomous containment policy (bounded):
    # - Critical + known_malware + risk > 85 → auto-isolate
    # - Critical + reputation=malicious → auto-isolate
    # - High + risk > 80 + known_malware → human approval first
    # - All others → human review
    
    if severity == "critical":
        intel = alert.get("threat_intel", {})
        if intel.get("known_malware") and risk_score >= 85:
            return True, "auto_isolate", "Known malware on critical alert"
        if intel.get("reputation") == "malicious":
            return True, "auto_isolate", "Malicious reputation + critical severity"
    
    return False, "escalate_human", "Requires human analyst review"


def generate_incident_record(alert, action):
    """Create an incident record for evidence/audit trail."""
    return {
        "incident_id": f"INC-{alert['id']}-{datetime.now().strftime('%s')}",
        "alert_id": alert["id"],
        "device": alert.get("device"),
        "user": alert.get("user"),
        "title": alert.get("title"),
        "severity": alert.get("severity"),
        "risk_score": alert.get("risk_score"),
        "action_taken": action["action"],
        "action_reason": action["reason"],
        "timestamp": datetime.now().isoformat() + "Z",
        "evidence": {
            "threat_intel": alert.get("threat_intel", {}),
            "policy_applied": "Essential Eight EDR Policy v1",
        },
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="Alert JSON file")
    p.add_argument("--mode", choices=["evaluate", "execute"], default="evaluate")
    args = p.parse_args()

    with open(args.input, "r") as f:
        alert = json.load(f)

    policy = {"auto_iso_threshold": 85}
    can_auto, action_type, reason = can_auto_contain(alert, policy)

    action = {
        "action": action_type,
        "reason": reason,
        "auto_approved": can_auto,
        "executed": False,
    }

    if args.mode == "execute" and can_auto:
        # In real deployment: call Defender API to isolate device
        # For now: just mark as executed
        action["executed"] = True
        action["containment_method"] = "device_isolation"
        action["executed_at"] = datetime.now().isoformat() + "Z"

    incident = generate_incident_record(alert, action)
    out = {
        "generatedAt": datetime.now().isoformat() + "Z",
        "alert_id": alert["id"],
        "decision": action,
        "incident": incident,
    }

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
