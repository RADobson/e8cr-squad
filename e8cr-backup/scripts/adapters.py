#!/usr/bin/env python3
"""Backup platform adapters (MVP): Veeam + Azure Backup.

Current mode: sample-mode with provider-shaped output and unified normalization.
Drop-in points for real API integration are marked TODO.
"""

import json
import os
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    requests = None


# ─── Real API calls ───────────────────────────────────────────────────────────

def veeam_fetch_jobs_real(base_url: str, username: str, password: str, verify_ssl: bool = True):
    """Fetch recent backup sessions from Veeam Backup & Replication REST API (v1)."""
    if not requests:
        raise RuntimeError("requests library required for real API mode: pip install requests")

    # Authenticate — POST /api/sessionMngr/?v=latest
    auth_url = f"{base_url}/api/sessionMngr/?v=latest"
    headers = {"Accept": "application/json"}
    auth_resp = requests.post(auth_url, auth=(username, password), headers=headers, verify=verify_ssl)
    auth_resp.raise_for_status()
    session_id = auth_resp.headers.get("X-RestSvcSessionId")
    if not session_id:
        raise RuntimeError("Veeam auth succeeded but no session ID returned")

    headers["X-RestSvcSessionId"] = session_id

    # Fetch recent backup sessions — GET /api/backupSessions?format=Entity
    sessions_url = f"{base_url}/api/backupSessions?format=Entity"
    resp = requests.get(sessions_url, headers=headers, verify=verify_ssl)
    resp.raise_for_status()
    sessions = resp.json()

    # Normalise into our provider shape
    jobs = []
    for s in sessions.get("BackupTaskSessions", sessions.get("data", [])):
        # Handle both v1 and v1.1 response shapes
        if isinstance(s, dict):
            name = s.get("Name", s.get("JobName", "unknown"))
            result = s.get("Result", s.get("Status", "Unknown"))
            end_time = s.get("EndTimeUTC", s.get("EndTime", ""))
            duration = s.get("DurationSeconds", s.get("Duration", 0))
            message = s.get("Reason", s.get("Details", ""))
            jobs.append({
                "name": name,
                "result": result,
                "endedAt": end_time,
                "durationSec": int(duration) if duration else 0,
                "message": message if result not in ("Success", "Completed") else None,
            })

    # Logout
    try:
        requests.delete(f"{base_url}/api/sessionMngr/{session_id}", headers=headers, verify=verify_ssl)
    except Exception:
        pass

    return {"provider": "veeam", "jobs": jobs}


def azure_fetch_jobs_real(subscription_id: str, vault_name: str, resource_group: str,
                          tenant_id: str, client_id: str, client_secret: str):
    """Fetch backup jobs from Azure Recovery Services vault via ARM API."""
    if not requests:
        raise RuntimeError("requests library required for real API mode: pip install requests")

    # Get OAuth2 token
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_resp = requests.post(token_url, data={
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://management.azure.com/.default",
    })
    token_resp.raise_for_status()
    access_token = token_resp.json()["access_token"]

    # List backup jobs (last 7 days)
    api_version = "2023-06-01"
    jobs_url = (
        f"https://management.azure.com/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group}"
        f"/providers/Microsoft.RecoveryServices/vaults/{vault_name}"
        f"/backupJobs?api-version={api_version}"
        f"&$filter=startTime eq '{(datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d')} 12:00:00 AM'"
    )
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    resp = requests.get(jobs_url, headers=headers)
    resp.raise_for_status()

    return {"provider": "azure_backup", "value": resp.json().get("value", [])}


# ─── Sample data (demo mode) ─────────────────────────────────────────────────

def veeam_fetch_jobs_sample():
    now = datetime.now()
    return {
        "provider": "veeam",
        "jobs": [
            {"name": "VEEAM-M365", "result": "Success", "endedAt": (now - timedelta(hours=2)).isoformat() + "Z", "durationSec": 1032},
            {"name": "VEEAM-SQL01", "result": "Warning", "endedAt": (now - timedelta(hours=9)).isoformat() + "Z", "durationSec": 811, "message": "Retry count exceeded"},
            {"name": "VEEAM-FS01", "result": "Failed", "endedAt": (now - timedelta(hours=11)).isoformat() + "Z", "durationSec": 422, "message": "Repository unavailable"},
        ],
    }


def azure_fetch_jobs_sample():
    now = datetime.now()
    return {
        "provider": "azure_backup",
        "value": [
            {"properties": {"entityFriendlyName": "AZ-SQL01", "status": "Completed", "endTime": (now - timedelta(hours=3)).isoformat() + "Z", "duration": "PT11M"}},
            {"properties": {"entityFriendlyName": "AZ-APP01", "status": "Failed", "endTime": (now - timedelta(hours=8)).isoformat() + "Z", "duration": "PT4M", "errorDetails": "Vault unreachable"}},
            {"properties": {"entityFriendlyName": "AZ-M365", "status": "InProgress", "endTime": (now - timedelta(hours=1)).isoformat() + "Z", "duration": "PT1M"}},
        ],
    }


def normalize_jobs(raw):
    provider = raw.get("provider")
    out = []

    if provider == "veeam":
        for j in raw.get("jobs", []):
            result = str(j.get("result", "Unknown")).lower()
            if result in ("success", "succeeded", "completed"):
                status = "success"
            elif result in ("warning", "failed", "error"):
                status = "failed"
            else:
                status = "missed"

            out.append(
                {
                    "job": j.get("name", "unknown"),
                    "status": status,
                    "lastRun": j.get("endedAt"),
                    "durationMin": round((j.get("durationSec", 0) or 0) / 60),
                    "error": j.get("message") if status != "success" else None,
                    "provider": provider,
                }
            )

    elif provider == "azure_backup":
        for item in raw.get("value", []):
            p = item.get("properties", {})
            s = str(p.get("status", "Unknown")).lower()
            if s in ("completed", "succeeded", "success"):
                status = "success"
            elif s in ("failed", "cancelled", "warning"):
                status = "failed"
            else:
                status = "missed"

            out.append(
                {
                    "job": p.get("entityFriendlyName", "unknown"),
                    "status": status,
                    "lastRun": p.get("endTime"),
                    "durationMin": 0,
                    "error": p.get("errorDetails") if status != "success" else None,
                    "provider": provider,
                }
            )

    return out


# Real API functions available above:
# - veeam_fetch_jobs_real(base_url, username, password, verify_ssl)
# - azure_fetch_jobs_real(subscription_id, vault_name, resource_group, tenant_id, client_id, client_secret)
