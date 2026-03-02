#!/usr/bin/env python3
"""Smart provider dispatch — select which adapter to use based on configuration."""

import argparse
import json
from auth_scaffold import VeeamAuth, AzureBackupAuth
from adapters import (
    veeam_fetch_jobs_sample, azure_fetch_jobs_sample,
    veeam_fetch_jobs_real, azure_fetch_jobs_real,
    normalize_jobs,
)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["detect", "fetch-jobs", "info"], default="detect")
    p.add_argument("--force-provider", choices=["veeam", "azure"], help="Force use of specific provider")
    args = p.parse_args()

    veeam = VeeamAuth.from_env()
    azure = AzureBackupAuth.from_env()

    configured = {
        "veeam": veeam.is_configured(),
        "azure": azure.is_configured(),
    }

    if args.mode == "detect":
        out = {
            "detected_providers": [p for p, cfg in configured.items() if cfg],
            "veeam_configured": configured["veeam"],
            "azure_configured": configured["azure"],
        }
        print(json.dumps(out, indent=2))
        return

    if args.mode == "info":
        out = {
            "veeam": {
                "configured": configured["veeam"],
                "base_url": veeam.base_url if configured["veeam"] else None,
                "username": veeam.username if configured["veeam"] else None,
            },
            "azure": {
                "configured": configured["azure"],
                "subscription_id": azure.subscription_id if configured["azure"] else None,
                "vault_name": azure.vault_name if configured["azure"] else None,
                "resource_group": azure.resource_group if configured["azure"] else None,
            },
        }
        print(json.dumps(out, indent=2))
        return

    if args.mode == "fetch-jobs":
        provider = args.force_provider
        if not provider:
            if configured["veeam"]:
                provider = "veeam"
            elif configured["azure"]:
                provider = "azure"
            else:
                print(json.dumps({"error": "No backup providers configured"}, indent=2))
                return

        if provider == "veeam":
            if configured["veeam"]:
                raw = veeam_fetch_jobs_real(veeam.base_url, veeam.username, veeam.password, veeam.verify_ssl)
            else:
                raw = veeam_fetch_jobs_sample()
        else:
            if configured["azure"]:
                raw = azure_fetch_jobs_real(
                    azure.subscription_id, azure.vault_name, azure.resource_group,
                    azure.tenant_id, azure.client_id, azure.client_secret,
                )
            else:
                raw = azure_fetch_jobs_sample()

        jobs = normalize_jobs(raw)
        out = {
            "provider": provider,
            "jobs": jobs,
            "count": len(jobs),
        }
        print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
